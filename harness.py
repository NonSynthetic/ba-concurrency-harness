#!/usr/bin/env python3
"""BA concurrency-bug hunt harness v3 — 50 synthetic agents, structured race
rounds, full invariant checker. Target: LOCAL instance only.

Phases:
  seed      — register N synthetic agents (ed25519 + PoW), create M tasks
  race      — structured collision rounds per class, barrier-synchronized:
              claim/claim, deliver/cancel, accept/revision, double deliver,
              double accept, timer-expiry vs human (DB backdate + cron tick)
  drive     — volume op-mix for action count + overlap depth
  lifecycle — walk tasks to 'verified' (claim->deliver->accept)
  tick      — invoke the exported scheduled task handler (runTaskCron) on the
              live DB via tick_cron.ts
  check     — invariant assertions over actions_log + final server state
  all       — seed + race + lifecycle + drive + check

Usage: python harness.py <phase> [phase...]
Env:   BA_BASE (default http://127.0.0.1:3000), BA_DB (SQLite file for
       backdating), BA_API_DIR (repo dir holding tick_cron.ts), DRIVE_S.
"""
import json, os, sys, time, base64, hashlib, random, threading, subprocess
import urllib.request, urllib.error, urllib.parse, datetime, pathlib
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get("BA_BASE", "http://127.0.0.1:3000")
ROOT = pathlib.Path(__file__).resolve().parent
STATE = ROOT / "harness_state.json"
FINDINGS = ROOT / "findings.jsonl"
ACTIONS = ROOT / "actions_log.jsonl"
RACES = ROOT / "races.jsonl"
DB_PATH = os.environ.get("BA_DB", "")
API_DIR = os.environ.get("BA_API_DIR", "")
MAX_REVISIONS = 3  # MAX_REVISIONS in src/tasks/service.ts

# ── Localhost hard guard: parsed-hostname check, not an assert ──
# `assert` disappears under `python -O`; substring checks accept userinfo
# tricks like https://127.0.0.1@api.basedagents.ai. Only the parsed hostname
# is trusted.
def _guard_local_base(base):
    try:
        host = (urllib.parse.urlparse(base).hostname or "").lower()
    except Exception:
        host = ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        sys.stderr.write(
            f"FATAL: LOCALHOST GUARD — refusing non-local target {base!r} "
            f"(parsed hostname={host!r}). This harness may only run against a "
            "local instance.\n")
        sys.exit(2)


_guard_local_base(BASE)

_lock = threading.Lock()
_stats = {"actions": 0, "overlaps": 0, "errors": 0, "max_inflight": 0}
_inflight = 0


def _log(path, row):
    row = {"ts": datetime.datetime.utcnow().isoformat() + "Z", **row}
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")


def b58e(b):
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + (s or "1")


def http(method, path, body=None, key=None, agent_id=None, retries=0):
    data = json.dumps(body).encode() if body is not None else None
    h = {"content-type": "application/json", "user-agent": "ba-concurrency-harness/3"}
    if key and agent_id:
        # AgentSig: Authorization: AgentSig <b58pub>:<b64sig>
        # msg = "METHOD:PATH:TS:SHA256HEX(raw_body):NONCE" (nonce -> unique sig,
        # dodges the 120s replay cache on repeated identical ops)
        import nacl.signing
        sk = nacl.signing.SigningKey(key[:32])
        ts = str(int(time.time()))
        nonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        body_hash = hashlib.sha256(data or b"").hexdigest()
        msg = f"{method}:{path}:{ts}:{body_hash}:{nonce}"
        sig = sk.sign(msg.encode()).signature
        h["authorization"] = f"AgentSig {b58e(bytes(sk.verify_key))}:{base64.b64encode(sig).decode()}"
        h["x-timestamp"] = ts
        h["x-nonce"] = nonce
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    global _inflight
    with _lock:
        _inflight += 1
        if _inflight > 1:
            _stats["overlaps"] += 1
        if _inflight > _stats["max_inflight"]:
            _stats["max_inflight"] = _inflight
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            out = (r.status, json.loads(r.read().decode("utf-8", "replace")), time.time() - t0)
        return out
    except urllib.error.HTTPError as e:
        if e.code == 429 and retries < 3:
            ra = int(e.headers.get("Retry-After", "2") or 2)
            time.sleep(min(ra, 10))
            return http(method, path, body, key, agent_id, retries + 1)
        try: return e.code, json.loads(e.read().decode("utf-8", "replace")), time.time() - t0
        except Exception: return e.code, {}, time.time() - t0
    except Exception as e:
        if retries < 2 and ("10053" in str(e) or "10054" in str(e)):
            time.sleep(0.25 * (retries + 1))
            return http(method, path, body, key, agent_id, retries + 1)
        return -1, {"error": str(e)[:120]}, time.time() - t0
    finally:
        with _lock:
            if _inflight > 0:
                _inflight -= 1


def register_agent(name, _tries=0):
    """ed25519 keypair -> register/init (PoW) -> register/complete.
    PoW: sha256(pubkey_bytes || challenge_utf8 || nonce_hex_bytes) >= diff
    leading zero bits. Names are globally unique; retry with a suffix on 409.
    """
    import nacl.signing
    sk = nacl.signing.SigningKey.generate()
    pub_bytes = bytes(sk.verify_key)
    pub = b58e(pub_bytes)
    code, r, _ = http("POST", "/v1/register/init", {"public_key": pub})
    if code != 200:
        return None, (code, r)
    chal_id = r.get("challenge_id")
    chal = r.get("challenge", ""); diff = int(r.get("difficulty", 22))
    threshold = 1 << (32 - diff) if diff <= 32 else 0
    chal_utf8 = chal.encode()
    nonce = 0
    while True:
        hx = f"{nonce:016x}"
        if int.from_bytes(hashlib.sha256(pub_bytes + chal_utf8 + bytes.fromhex(hx)).digest()[:4], "big") < threshold:
            break
        nonce += 1
    sig = base64.b64encode(sk.sign(chal_utf8).signature).decode()
    code, r, _ = http("POST", "/v1/register/complete",
                      {"challenge_id": chal_id, "public_key": pub, "signature": sig,
                       "nonce": hx,
                       "profile": {"name": name,
                                   "description": "synthetic concurrency-probe agent (local test)",
                                   "capabilities": ["testing", "automation"],
                                   "protocols": ["https"]}})
    if code == 409 and "name" in str(r.get("message", "")).lower() and _tries < 6:
        return register_agent(f"{name}-{_tries}{os.urandom(2).hex()}", _tries + 1)
    if code not in (200, 201):
        return None, (code, r)
    aid = r.get("agent_id") or r.get("agent", {}).get("agent_id") or r.get("id")
    return {"name": name, "agent_id": aid, "secret": bytes(sk).hex(), "pub": pub}, (code, r)


def create_task(poster, title):
    code, r, _ = http("POST", "/v1/tasks", {
        "title": title,
        "description": "synthetic task for race hunting (local)",
        "category": "automation",
        "required_capabilities": ["testing"], "output_format": "json",
        "expected_output": "json result"}, key=bytes.fromhex(poster["secret"]), agent_id=poster["agent_id"])
    _log(ACTIONS, {"op": "task_create", "agent": poster["agent_id"], "http": code})
    if code in (200, 201):
        return r.get("task_id") or r.get("id") or r.get("task", {}).get("task_id") or r.get("task", {}).get("id")
    return None


def op_call(agent, op, task_id, log_body_keys=None):
    """One lifecycle op. Returns (http_code, elapsed_ms). Optionally logs
    selected response-body keys (e.g. accepted_by for accept idempotency)."""
    key = bytes.fromhex(agent["secret"]); aid = agent["agent_id"]
    if op == "claim":
        c, r, dt = http("POST", f"/v1/tasks/{task_id}/claim", {}, key=key, agent_id=aid)
    elif op == "deliver":
        c, r, dt = http("POST", f"/v1/tasks/{task_id}/deliver",
                        {"summary": "synthetic", "submission_type": "json",
                         "submission_content": "{}"}, key=key, agent_id=aid)
    elif op == "cancel":
        c, r, dt = http("POST", f"/v1/tasks/{task_id}/cancel", {}, key=key, agent_id=aid)
    elif op == "revision":
        c, r, dt = http("POST", f"/v1/tasks/{task_id}/revision",
                        {"note": "rev-req"}, key=key, agent_id=aid)
    elif op == "accept":
        c, r, dt = http("POST", f"/v1/tasks/{task_id}/accept", {}, key=key, agent_id=aid)
    elif op == "dispute":
        c, r, dt = http("POST", f"/v1/tasks/{task_id}/dispute",
                        {"reason": "dispute-reason"}, key=key, agent_id=aid)
    else:
        c, r, dt = http("GET", f"/v1/tasks/{task_id}", key=key, agent_id=aid)
    with _lock:
        _stats["actions"] += 1
        if c == -1:
            _stats["errors"] += 1
    row = {"op": op, "task": task_id, "agent": aid,
           "http": c, "ms": round(dt * 1000), "err": r.get("error") if isinstance(r, dict) else None}
    if log_body_keys and isinstance(r, dict):
        for k in log_body_keys:
            if k in r:
                row[k] = r[k]
    _log(ACTIONS, row)
    return c, dt


def seed(n_agents=50, n_tasks=80, n_posters=6):
    st = {"agents": [], "posters": [], "tasks": [], "task_poster": {}}
    if STATE.exists():
        st = json.loads(STATE.read_text())
    need_posters = max(0, n_posters - len(st["posters"]))
    need_workers = max(0, n_agents - len(st["agents"]))
    # poster agents are just agents flagged as posters
    with ThreadPoolExecutor(2) as x:
        total = need_posters + need_workers
        for res in x.map(lambda i: (time.sleep(random.random() * 0.3), register_agent(f"syn-{len(st['agents']) + len(st['posters']) + i:03d}"))[1],
                         range(total)):
            a, info = res
            _log(ACTIONS, {"op": "register", "ok": a is not None, "info": str(info)[:120]})
            if a:
                if len(st["posters"]) < n_posters:
                    st["posters"].append(a)
                else:
                    st["agents"].append(a)
    if st["posters"]:
        for i in range(len(st["tasks"]), n_tasks):
            p = st["posters"][i % len(st["posters"])]
            tid = create_task(p, f"concurrency-probe-{i:03d}")
            if tid:
                st["tasks"].append(tid)
                st["task_poster"][tid] = p["agent_id"]
    STATE.write_text(json.dumps(st))
    return st


# ── Structured race rounds ──────────────────────────────────────────────
# A "genuine collision" = competing ops fired on the same task while it was in
# the contested precondition state, overlapping in-flight. Barrier-start makes
# them simultaneous; we log both results + measured overlap.

def _race_pair(name, rnd, task, jobs):
    """jobs = [(agent, op), ...] fired simultaneously at a barrier."""
    bar = threading.Barrier(len(jobs))
    results = [None] * len(jobs)
    t_start = [None] * len(jobs)

    def go(i, agent, op):
        bar.wait()
        t_start[i] = time.time()
        c, dt = op_call(agent, op, task, log_body_keys=("accepted_by", "status", "revision_count"))
        results[i] = {"agent": agent["agent_id"], "op": op, "http": c,
                      "ms": round(dt * 1000), "t0": t_start[i], "t1": time.time()}

    ths = [threading.Thread(target=go, args=(i, a, o)) for i, (a, o) in enumerate(jobs)]
    for t in ths: t.start()
    for t in ths: t.join()
    latest_start = max(r["t0"] for r in results)
    earliest_end = min(r["t1"] for r in results)
    overlap_ms = max(0, round((earliest_end - latest_start) * 1000))
    _log(RACES, {"race": name, "round": rnd, "task": task,
                 "results": [{k: r[k] for k in ("agent", "op", "http", "ms")} for r in results],
                 "overlap_ms": overlap_ms})
    return results


def _walk_to(agent, poster, task, target):
    """Drive a task into the contested precondition state.
    'claimed'   -> poster task + worker claim
    'submitted' -> + worker deliver
    Returns True when the precondition holds."""
    c, _ = op_call(agent, "claim", task)
    if target == "claimed":
        return c == 200
    if c != 200:
        return False
    c, _ = op_call(agent, "deliver", task)
    return c == 200


def race(st, rounds=12):
    """Structured collisions: >=rounds per class. Fresh tasks per round so the
    precondition state is exactly controlled."""
    posters, workers = st["posters"], st["agents"]
    created = []

    def fresh_task(i):
        p = posters[i % len(posters)]
        tid = create_task(p, f"race-{i:04d}")
        if tid:
            created.append(tid)
            st["task_poster"][tid] = p["agent_id"]
            st["tasks"].append(tid)
        return p, tid

    def poster_of(tid):
        pid = st["task_poster"].get(tid)
        return next((p for p in posters if p["agent_id"] == pid), posters[0])

    rnd = 0
    # 1. claim/claim — K workers race one open task
    for i in range(rounds):
        p, t = fresh_task(rnd); rnd += 1
        if not t: continue
        racers = random.sample(workers, min(4, len(workers)))
        _race_pair("claim_claim", i, t, [(a, "claim") for a in racers])
    # 2. deliver/cancel — claimer delivers vs poster cancels
    for i in range(rounds):
        p, t = fresh_task(rnd); rnd += 1
        if not t: continue
        w = random.choice(workers)
        if _walk_to(w, p, t, "claimed"):
            _race_pair("deliver_cancel", i, t, [(w, "deliver"), (poster_of(t), "cancel")])
    # 3. accept/revision — poster's two review ops race on submitted task
    for i in range(rounds):
        p, t = fresh_task(rnd); rnd += 1
        if not t: continue
        w = random.choice(workers)
        if _walk_to(w, p, t, "submitted"):
            po = poster_of(t)
            _race_pair("accept_revision", i, t, [(po, "accept"), (po, "revision")])
    # 4. double deliver — claimer fires two concurrent delivers
    for i in range(rounds):
        p, t = fresh_task(rnd); rnd += 1
        if not t: continue
        w = random.choice(workers)
        if _walk_to(w, p, t, "claimed"):
            _race_pair("double_deliver", i, t, [(w, "deliver"), (w, "deliver")])
    # 5. double accept — poster fires two concurrent accepts
    for i in range(rounds):
        p, t = fresh_task(rnd); rnd += 1
        if not t: continue
        w = random.choice(workers)
        if _walk_to(w, p, t, "submitted"):
            po = poster_of(t)
            _race_pair("double_accept", i, t, [(po, "accept"), (po, "accept")])
    STATE.write_text(json.dumps(st))
    return {"rounds": rnd, "tasks": len(created)}


# ── Timer-expiry vs human action ────────────────────────────────────────
# Backdate timer columns directly in the SQLite file, then race the exported
# scheduled task handler (runTaskCron via tick_cron.ts) against the human op.

def db_exec(sql, params=()):
    import sqlite3
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.execute("PRAGMA busy_timeout = 15000")
    cur = con.execute(sql, params)
    con.commit(); n = cur.rowcount
    con.close()
    return n


def tick_once():
    """One runTaskCron pass on the live DB (the exported scheduled task
    handler — same function src/index.ts `scheduled` calls)."""
    if not API_DIR:
        return {"error": "BA_API_DIR unset"}
    tsx = os.environ.get("BA_TSX", "")
    if not tsx:
        # hoisted monorepo: node_modules/.bin/tsx.cmd at repo root
        tsx = str(pathlib.Path(API_DIR) / ".." / ".." / "node_modules" / ".bin" / "tsx.cmd")
    try:
        out = subprocess.run(
            ["cmd", "/c", str(tsx), "tick_cron.ts"],
            cwd=API_DIR, env={**os.environ, "DATABASE_PATH": DB_PATH},
            capture_output=True, text=True, timeout=60)
        line = next((l for l in out.stdout.splitlines() if l.startswith("[tick]")), "")
        _log(ACTIONS, {"op": "cron_tick", "http": 200 if out.returncode == 0 else -1,
                       "summary": line[:400]})
        return {"rc": out.returncode, "stdout": out.stdout[-400:], "stderr": out.stderr[-300:]}
    except Exception as e:
        return {"error": str(e)[:200]}


def race_timer(st, rounds=12):
    """Three timer classes: claim-expiry vs deliver, auto-release vs accept,
    open-expiry vs claim. A loop-tick subprocess runs runTaskCron every 250ms
    for the whole phase — each human op lands mid-tick, a true concurrent race.
    Claim-side ops use POSTER agents (workers exhaust their claim budget inside
    the atomic gate during the structured races)."""
    if not DB_PATH:
        print("BA_DB unset — cannot backdate timer columns"); return {}
    posters, workers = st["posters"], st["agents"]
    past = (datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat() + "Z"
    tsx = os.environ.get("BA_TSX") or str(
        pathlib.Path(API_DIR) / ".." / ".." / "node_modules" / ".bin" / "tsx.cmd")
    # continuous tick loop for the whole phase (~rounds*3 ops, ~20s margin)
    proc = subprocess.Popen(
        ["cmd", "/c", str(tsx), "tick_cron.ts", "250", str(rounds * 25000)],
        cwd=API_DIR, env={**os.environ, "DATABASE_PATH": DB_PATH},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)  # tsx compile + first tick
    try:
        for i in range(rounds):
            # Half the rounds fire the human op immediately (human usually wins
            # the 250ms sweep window); half wait ~400ms (sweeper usually wins).
            # Both directions are genuine races on the live backdated row.
            delay = 0.4 if i % 2 else 0.0
            # claim_expires_at past -> cron flips claimed->open vs claimer deliver
            p = posters[i % len(posters)]
            t = create_task(p, f"timer-ce-{i:03d}")
            if not t: continue
            st["tasks"].append(t); st["task_poster"][t] = p["agent_id"]
            w = random.choice(workers)
            c, _ = op_call(w, "claim", t)
            if c != 200: continue
            db_exec("UPDATE tasks SET claim_expires_at = ? WHERE task_id = ?", (past, t))
            if delay: time.sleep(delay)
            c2, dt = op_call(w, "deliver", t)
            _log(RACES, {"race": "timer_claimexpiry_vs_deliver", "round": i, "task": t,
                         "results": [{"agent": w["agent_id"], "op": "deliver", "http": c2}],
                         "overlap_ms": -1, "delay_s": delay,
                         "note": "backdated claim_expires_at; tick loop 250ms in-flight"})
            # auto_release_at past -> cron auto-accept vs poster accept
            p2 = posters[(i + 1) % len(posters)]
            t2 = create_task(p2, f"timer-ar-{i:03d}")
            if not t2: continue
            st["tasks"].append(t2); st["task_poster"][t2] = p2["agent_id"]
            w2 = random.choice(workers)
            if not _walk_to(w2, p2, t2, "submitted"): continue
            db_exec("UPDATE tasks SET auto_release_at = ? WHERE task_id = ?", (past, t2))
            if delay: time.sleep(delay)
            c3, dt = op_call(p2, "accept", t2)
            _log(RACES, {"race": "timer_autorelease_vs_accept", "round": i, "task": t2,
                         "results": [{"agent": p2["agent_id"], "op": "accept", "http": c3}],
                         "overlap_ms": -1, "delay_s": delay,
                         "note": "backdated auto_release_at; tick loop 250ms in-flight"})
            # expires_at past -> open-expiry vs claim (poster claims other poster's task)
            p3 = posters[(i + 2) % len(posters)]
            t3 = create_task(p3, f"timer-oe-{i:03d}")
            if not t3: continue
            st["tasks"].append(t3); st["task_poster"][t3] = p3["agent_id"]
            w3 = posters[(i + 3) % len(posters)]
            db_exec("UPDATE tasks SET expires_at = ? WHERE task_id = ?", (past, t3))
            c4, dt = op_call(w3, "claim", t3)
            _log(RACES, {"race": "timer_openexpiry_vs_claim", "round": i, "task": t3,
                         "results": [{"agent": w3["agent_id"], "op": "claim", "http": c4}],
                         "overlap_ms": -1, "note": "backdated expires_at; tick loop 250ms in-flight"})
    finally:
        proc.terminate()
    STATE.write_text(json.dumps(st))
    return {"timer_rounds": rounds * 3}


def lifecycle(st, n=8):
    """Walk tasks through the full happy path to 'verified':
    claim -> deliver -> accept (poster only — the accept rate bucket is
    10/min/IP, so accepts are serialized here, never sprayed by non-posters)."""
    posters, workers = st["posters"], st["agents"]
    ok = 0
    for i in range(n):
        p = posters[i % len(posters)]
        t = create_task(p, f"lifecycle-{i:03d}")
        if not t: continue
        st["tasks"].append(t); st["task_poster"][t] = p["agent_id"]
        w = random.choice(workers)
        c1, _ = op_call(w, "claim", t)
        c2, _ = op_call(w, "deliver", t) if c1 == 200 else (0, 0)
        c3, _ = op_call(p, "accept", t) if c2 == 200 else (0, 0)
        _log(RACES, {"race": "lifecycle_to_verified", "round": i, "task": t,
                     "results": [{"op": "claim", "http": c1}, {"op": "deliver", "http": c2},
                                 {"op": "accept", "http": c3}], "overlap_ms": -1})
        if c3 == 200: ok += 1
    STATE.write_text(json.dumps(st))
    return {"verified": ok}


def drive(st, seconds=120, workers=40):
    """Volume adversarial op-mix. Poster-only ops (accept/revision/cancel) go to
    the task's actual poster — spraying them from non-posters just 403s and
    drains the shared per-IP accept bucket (10/min)."""
    end = time.time() + seconds
    agents, tasks = st["agents"], st["tasks"]
    posters = st["posters"]
    if not agents or not tasks:
        print("nothing to drive"); return

    def poster_of(tid):
        pid = st["task_poster"].get(tid)
        return next((p for p in posters if p["agent_id"] == pid), None)

    def worker(wid):
        rnd = random.Random(wid * 7919)
        while time.time() < end:
            t = rnd.choice(tasks)
            roll = rnd.choices(
                ["claim", "deliver", "cancel", "revision", "accept", "get"],
                weights=[30, 20, 8, 12, 12, 18])[0]
            if roll in ("cancel", "revision", "accept"):
                a = poster_of(t)
                if not a:
                    continue
            else:
                a = rnd.choice(agents)
            op_call(a, roll, t)

    with ThreadPoolExecutor(workers) as x:
        list(x.map(worker, range(workers)))
    return _stats


def check(st):
    """Invariant checker v3 — every invariant has executable code below.
    Response-vs-truth analysis over the action/race logs + final server state.

      multi_claimer_ok        >1 distinct agent got HTTP 200 claiming one task
      phantom_claim           claim-200 agent != final claimed_by
      deliver_by_nonclaimer   deliver-200 from agent != current claimer
      double_deliver          same agent delivered 200 twice w/o revision between
      double_accept           >1 accept-200 is LEGAL (handleAccept is
                              idempotent on already-verified tasks); the check
                              is accepted_by/verified_at single-valued and the
                              second 200 returned the SAME accepted_by
      mutation_after_cancel   deliver/accept-200 after a cancel-200
      no_verified_after_cancelled  final status contradiction
      single_active_claimer   final claimed_by must be exactly one claim-200
                              winner with no later release op
      revision_monotone_bounded  revision_count == #revision-200s, <= 3, >= 0
      money_flags_consistent  status/payment_status combination legality
      verified_path           tasks that reached verified have accepted_by+verified_at
      timer_consistency       backdated-expiry rounds resolved to one winner
    """
    findings = []
    claim_ok, deliver_ok, accept_ok, revision_ok, cancel_ok = {}, {}, {}, {}, {}
    events = {}
    if ACTIONS.exists():
        for line in open(ACTIONS, encoding="utf-8", errors="replace"):
            try:
                row = json.loads(line)
            except Exception:
                continue
            op, t, a, c = row.get("op"), row.get("task"), row.get("agent"), row.get("http")
            if not t or not a:
                continue
            if op == "claim" and c == 200: claim_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "deliver" and c == 200: deliver_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "accept" and c == 200: accept_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "revision" and c == 200: revision_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "cancel" and c == 200: cancel_ok.setdefault(t, []).append(row.get("ts"))
            if c == 200 and op in ("claim", "deliver", "cancel", "revision", "accept"):
                events.setdefault(t, []).append((row.get("ts") or "", op, a))

    for t, winners in claim_ok.items():
        uniq = {a for a, _ in winners}
        if len(uniq) > 1:
            findings.append({"invariant": "multi_claimer_ok", "task": t,
                             "evidence": {"ok_claimers": sorted(uniq), "count": len(uniq)}})
    for t, evs in events.items():
        evs.sort(key=lambda e: e[0])
        last_deliver = {}
        for ts, op, a in evs:
            if op == "deliver":
                if a in last_deliver:
                    findings.append({"invariant": "double_deliver", "task": t,
                                     "evidence": {"agent": a, "at": ts}})
                last_deliver[a] = ts
            else:
                last_deliver = {}
    # accept idempotency: gather accepted_by per accept-200 (logged in actions)
    accept_by_log = {}
    if ACTIONS.exists():
        for line in open(ACTIONS, encoding="utf-8", errors="replace"):
            try:
                row = json.loads(line)
            except Exception:
                continue
            if row.get("op") == "accept" and row.get("http") == 200 and row.get("task"):
                accept_by_log.setdefault(row["task"], []).append(row.get("accepted_by"))

    verified_count = 0
    for t in st["tasks"]:
        code, task, _ = http("GET", f"/v1/tasks/{t}")
        if code != 200 or not isinstance(task, dict):
            continue
        task = task.get("task", task)
        st_flag = task.get("status")
        claimer = task.get("claimed_by_agent_id")
        if st_flag == "verified":
            verified_count += 1
        # phantom-claim: agent got 200 on claim but someone else owns it now
        if t in claim_ok and claimer:
            phantoms = [a for a, _ in claim_ok[t] if a != claimer]
            if phantoms:
                findings.append({"invariant": "phantom_claim", "task": t,
                                 "evidence": {"real_claimer": claimer, "phantoms": phantoms}})
        if t in deliver_ok and claimer:
            bad = [a for a, _ in deliver_ok[t] if a != claimer]
            if bad:
                findings.append({"invariant": "deliver_by_nonclaimer", "task": t,
                                 "evidence": {"claimer": claimer, "delivered_by": bad}})
        if st_flag in ("verified", "accepted") and task.get("cancelled_at"):
            findings.append({"invariant": "no_verified_after_cancelled", "task": t,
                             "evidence": {"status": st_flag, "cancelled_at": task.get("cancelled_at")}})
        if t in cancel_ok:
            first_cancel = min(cancel_ok[t])
            for a, ts in deliver_ok.get(t, []) + accept_ok.get(t, []):
                if ts and ts > first_cancel:
                    findings.append({"invariant": "mutation_after_cancel", "task": t,
                                     "evidence": {"agent": a, "at": ts, "cancelled_at": first_cancel}})
        # single_active_claimer — from the ACTUAL returned claimer field, not a
        # nonexistent `claims` array. While status is claimed/submitted the
        # claimer must be one of the observed claim-200 winners (the latest).
        if st_flag in ("claimed", "submitted"):
            winners = claim_ok.get(t, [])
            if claimer and winners:
                latest_winner = winners[-1][0]
                if claimer != latest_winner:
                    findings.append({"invariant": "single_active_claimer", "task": t,
                                     "evidence": {"claimed_by": claimer, "latest_claim_200": latest_winner,
                                                  "note": "server claimer not the last accepted claimer"}})
            elif claimer and not winners:
                findings.append({"invariant": "single_active_claimer", "task": t,
                                 "evidence": {"claimed_by": claimer,
                                              "note": "server holds a claimer we never saw claim"}})
        # revision_monotone_bounded: count must equal observed revision-200s
        # (each revision-200 is the only path that bumps the counter) and stay
        # within MAX_REVISIONS.
        rc = task.get("revision_count") or 0
        observed = len(revision_ok.get(t, []))
        if rc != observed:
            findings.append({"invariant": "revision_monotone_bounded", "task": t,
                             "evidence": {"server_revision_count": rc, "observed_revision_200s": observed}})
        if rc > MAX_REVISIONS:
            findings.append({"invariant": "revision_monotone_bounded", "task": t,
                             "evidence": {"server_revision_count": rc, "bound": MAX_REVISIONS,
                                          "note": "revision_count exceeded MAX_REVISIONS"}})
        # money_flags_consistent: status/payment combination must be legal.
        ps = task.get("payment_status")
        if st_flag == "verified" and ps == "expired":
            findings.append({"invariant": "money_flags_consistent", "task": t,
                             "evidence": {"status": st_flag, "payment_status": ps,
                                          "note": "verified task holds expired payment flag"}})
        if st_flag == "cancelled" and ps == "settled":
            findings.append({"invariant": "money_flags_consistent", "task": t,
                             "evidence": {"status": st_flag, "payment_status": ps,
                                          "note": "cancelled task holds settled payment"}})
        if st_flag == "open" and ps in ("authorized", "settling", "settled"):
            findings.append({"invariant": "money_flags_consistent", "task": t,
                             "evidence": {"status": st_flag, "payment_status": ps,
                                          "note": "open task holds in-flight/settled payment"}})
        # verified_path: verified implies accepted_by + verified_at present
        if st_flag == "verified":
            if not task.get("accepted_by") or not task.get("verified_at"):
                findings.append({"invariant": "verified_path", "task": t,
                                 "evidence": {"accepted_by": task.get("accepted_by"),
                                              "verified_at": task.get("verified_at")}})
        # double_accept: ≥2 accept-200s is legal only as idempotent replay —
        # every 200 must report the same accepted_by, and the final task must
        # be verified with exactly that accepted_by.
        if len(accept_ok.get(t, [])) > 1:
            bys = set(accept_by_log.get(t, [])) - {None}
            if len(bys) > 1:
                findings.append({"invariant": "double_accept", "task": t,
                                 "evidence": {"distinct_accepted_by": sorted(bys),
                                              "note": "two accepts reported different accepters"}})
            if st_flag != "verified" or (bys and task.get("accepted_by") not in bys):
                findings.append({"invariant": "double_accept", "task": t,
                                 "evidence": {"status": st_flag, "accepted_by": task.get("accepted_by"),
                                              "logged_accepted_by": sorted(bys)}})

    # timer_consistency — every backdated-expiry race round must end with a
    # coherent final state: deliver-200 on an expired claim => task NOT open;
    # claim-200 on an expired open => task NOT expired.
    if RACES.exists():
        timer_tasks = {}
        for line in open(RACES, encoding="utf-8", errors="replace"):
            try:
                row = json.loads(line)
            except Exception:
                continue
            if not str(row.get("race", "")).startswith("timer_"):
                continue
            timer_tasks.setdefault(row["task"], []).append(row)
        for t, rows in timer_tasks.items():
            code, task, _ = http("GET", f"/v1/tasks/{t}")
            if code != 200:
                continue
            task = task.get("task", task)
            st_flag = task.get("status")
            for row in rows:
                for r in row["results"]:
                    if r.get("op") == "deliver" and r.get("http") == 200 and st_flag == "open":
                        findings.append({"invariant": "timer_consistency", "task": t,
                                         "evidence": {"race": row["race"],
                                                      "note": "deliver succeeded yet task is open (claim expired under it)"}})
                    if r.get("op") == "claim" and r.get("http") == 200 and st_flag == "expired":
                        findings.append({"invariant": "timer_consistency", "task": t,
                                         "evidence": {"race": row["race"],
                                                      "note": "claim succeeded on an expired task"}})
                    if r.get("op") == "accept" and r.get("http") == 200 and st_flag not in ("verified",):
                        findings.append({"invariant": "timer_consistency", "task": t,
                                         "evidence": {"race": row["race"], "status": st_flag,
                                                      "note": "accept succeeded yet task not verified"}})

    for f in findings:
        _log(FINDINGS, f)
    summary = {"findings": findings, "verified_tasks": verified_count,
               "tasks_checked": len(st["tasks"])}
    return summary


if __name__ == "__main__":
    modes = sys.argv[1:] or ["all"]
    st = json.loads(STATE.read_text()) if STATE.exists() else {"agents": [], "posters": [], "tasks": [], "task_poster": {}}
    if "seed" in modes or "all" in modes:
        st = seed()
        print("agents:", len(st["agents"]), "posters:", len(st["posters"]), "tasks:", len(st["tasks"]))
    if "race" in modes or "all" in modes:
        print("race:", race(st))
    if "timer" in modes or "all" in modes:
        print("timer:", race_timer(st))
    if "lifecycle" in modes or "all" in modes:
        print("lifecycle:", lifecycle(st))
    if "drive" in modes or "all" in modes:
        print(drive(st, seconds=int(os.environ.get("DRIVE_S", "120"))))
    if "check" in modes or "all" in modes:
        out = check(st)
        print("findings:", len(out["findings"]), "verified:", out["verified_tasks"], "checked:", out["tasks_checked"])
        for f in out["findings"]:
            print(" -", f["invariant"], f["task"], str(f["evidence"])[:140])
