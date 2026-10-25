#!/usr/bin/env python3
"""BA concurrency-bug hunt harness — 50 synthetic agents, adversarial timing,
invariant checker. Target: LOCAL instance only (localhost hard-guard).

Phases:
  seed   — register N synthetic agents (ed25519 + PoW), create M tasks
  drive  — concurrent adversarial ops: claim races, deliver/cancel races,
           accept-vs-revision, double-deliver, rapid claim-release
  check  — continuous invariant assertions -> findings.jsonl

Usage: python harness.py seed|drive|check|all [--agents 50] [--base http://127.0.0.1:3000]
"""
import json, os, sys, time, base64, hashlib, random, threading, urllib.request, urllib.error, datetime, pathlib
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get("BA_BASE", "http://127.0.0.1:3000")
ROOT = pathlib.Path(__file__).resolve().parent
STATE = ROOT / "harness_state.json"
FINDINGS = ROOT / "findings.jsonl"
ACTIONS = ROOT / "actions_log.jsonl"

assert "localhost" in BASE or "127.0.0.1" in BASE, "LOCALHOST GUARD: refuse non-local target"

_lock = threading.Lock()
_stats = {"actions": 0, "overlaps": 0, "errors": 0, "max_inflight": 0}
_inflight = 0


def _log(path, row):
    row = {"ts": datetime.datetime.utcnow().isoformat() + "Z", **row}
    with _lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")


def b58e(b):  # base58 encode
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + (s or "1")


def b58d(s):
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in s: n = n * 58 + A.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + b


def http(method, path, body=None, key=None, agent_id=None, retries=0):
    data = json.dumps(body).encode() if body is not None else None
    h = {"content-type": "application/json", "user-agent": "ba-concurrency-harness/1"}
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
        with urllib.request.urlopen(req, timeout=15) as r:
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
        if retries < 2 and "10053" in str(e):
            time.sleep(0.25 * (retries + 1))
            return http(method, path, body, key, agent_id, retries + 1)
        return -1, {"error": str(e)[:120]}, time.time() - t0
    finally:
        with _lock:
            if _inflight > 0:
                _inflight -= 1


def register_agent(name, _tries=0):
    """ed25519 keypair -> register/init (PoW) -> register/complete.

    Server contract (register.ts + crypto/index.ts):
      PoW: sha256(pubkey_bytes || challenge_utf8 || nonce_hex_bytes) >= diff leading zero bits
      sig: ed25519 over utf8(challenge_b64_string)
    Names are globally unique; a lost response can leave the name taken
    server-side — retry with a suffix on 409 name-conflict.
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
    # PoW fast path: diff<=32 -> first 4 bytes < 2^(32-diff) ⟺ >=diff leading zeros
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


def seed(n_agents, n_tasks):
    st = {"agents": [], "tasks": []}
    if STATE.exists():
        st = json.loads(STATE.read_text())
    # seed phase is gentle (2 threads + jitter) — the BURST lives in drive()
    with ThreadPoolExecutor(2) as x:
        for res in x.map(lambda i: (time.sleep(random.random() * 0.3), register_agent(f"syn-{i:03d}"))[1],
                         range(len(st["agents"]), n_agents)):
            a, info = res
            _log(ACTIONS, {"op": "register", "ok": a is not None, "info": str(info)[:120]})
            if a: st["agents"].append(a)
    # create tasks from first agent (poster)
    if st["agents"]:
        p = st["agents"][0]
        for i in range(len(st["tasks"]), n_tasks):
            code, r, _ = http("POST", "/v1/tasks", {
                "title": f"concurrency-probe-{i:03d}",
                "description": "synthetic task for race hunting (local)",
                "category": "automation",
                "required_capabilities": ["testing"], "output_format": "json",
                "expected_output": "json result"}, key=bytes.fromhex(p["secret"]), agent_id=p["agent_id"])
            _log(ACTIONS, {"op": "task_create", "http": code})
            if code in (200, 201):
                st["tasks"].append(r.get("task_id") or r.get("id") or r.get("task", {}).get("id"))
    STATE.write_text(json.dumps(st))
    return st


def drive(st, seconds=120, workers=50):
    """Adversarial concurrent ops across all agents against all tasks."""
    end = time.time() + seconds
    agents, tasks = st["agents"], st["tasks"]
    if not agents or not tasks:
        print("nothing to drive"); return

    def worker(wid):
        rnd = random.Random(wid)
        while time.time() < end:
            a = rnd.choice(agents); t = rnd.choice(tasks)
            op = rnd.choices(
                ["claim", "deliver", "cancel", "revision", "accept", "get"],
                weights=[30, 20, 10, 15, 10, 15])[0]
            key = bytes.fromhex(a["secret"]); aid = a["agent_id"]
            if op == "claim":
                c, r, dt = http("POST", f"/v1/tasks/{t}/claim", {}, key=key, agent_id=aid)
            elif op == "deliver":
                c, r, dt = http("POST", f"/v1/tasks/{t}/deliver",
                                {"summary": "synthetic", "submission_type": "json",
                                 "submission_content": "{}"}, key=key, agent_id=aid)
            elif op == "cancel":
                c, r, dt = http("POST", f"/v1/tasks/{t}/cancel", {}, key=key, agent_id=aid)
            elif op == "revision":
                c, r, dt = http("POST", f"/v1/tasks/{t}/revision",
                                {"note": "rev-req"}, key=key, agent_id=aid)
            elif op == "accept":
                c, r, dt = http("POST", f"/v1/tasks/{t}/accept", {}, key=key, agent_id=aid)
            else:
                c, r, dt = http("GET", f"/v1/tasks/{t}", key=key, agent_id=aid)
            with _lock:
                _stats["actions"] += 1
                if c == -1: _stats["errors"] += 1
            _log(ACTIONS, {"op": op, "task": t, "agent": aid,
                           "http": c, "ms": round(dt * 1000), "err": r.get("error") if isinstance(r, dict) else None})

    with ThreadPoolExecutor(workers) as x:
        list(x.map(worker, range(workers)))
    return _stats


def check(st):
    """Invariant checker v2 — response-vs-truth analysis over the action log.

    Catches divergences the final-state-only check cannot see:
      multi_claimer_ok      >1 distinct agent got HTTP 200 claiming one task
      phantom_claim         200-claim agent != final claimed_by (believes it holds task)
      deliver_by_nonclaimer 200 on deliver from agent != current claimer
      double_deliver        same agent delivered 200 twice on one task
      deliver_after_cancel  200 on deliver/accept after a successful cancel
    Plus final-state reads for cancelled/verified contradiction.
    """
    findings = []
    # ── pass 1: action-log evidence ──
    claim_ok = {}      # task -> [(agent,ts),...] with HTTP 200 on claim
    deliver_ok = {}    # task -> [(agent,ts),...]
    accept_ok = {}     # task -> [(agent,ts),...]
    cancel_ok = {}     # task -> [ts,...]
    events = {}        # task -> [(ts, op, agent)] mutating 200s, ts-ordered
    if ACTIONS.exists():
        for line in open(ACTIONS, encoding="utf-8", errors="replace"):
            try:
                row = json.loads(line)
            except Exception:
                continue
            op, t, a, c = row.get("op"), row.get("task"), row.get("agent"), row.get("http")
            if not t or not a:
                continue
            if op == "claim" and c == 200:
                claim_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "deliver" and c == 200:
                deliver_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "accept" and c == 200:
                accept_ok.setdefault(t, []).append((a, row.get("ts")))
            elif op == "cancel" and c == 200:
                cancel_ok.setdefault(t, []).append(row.get("ts"))
            if c == 200 and op in ("claim", "deliver", "cancel", "revision", "accept"):
                events.setdefault(t, []).append((row.get("ts") or "", op, a))
    for t, winners in claim_ok.items():
        uniq = {a for a, _ in winners}
        if len(uniq) > 1:
            findings.append({"invariant": "multi_claimer_ok", "task": t,
                             "evidence": {"ok_claimers": sorted(uniq), "count": len(uniq),
                                          "note": "multiple agents told they hold the claim"}})
    # double-deliver = two deliver-200s by same agent with NO intervening
    # revision/cancel/claim event (deliver→revision→re-deliver is legal)
    for t, evs in events.items():
        evs.sort(key=lambda e: e[0])
        last_deliver = {}
        for ts, op, a in evs:
            if op == "deliver":
                if a in last_deliver:
                    findings.append({"invariant": "double_deliver", "task": t,
                                     "evidence": {"agent": a, "at": ts,
                                                  "note": "re-delivered without revision/cancel/reclaim between"}})
                last_deliver[a] = ts
            else:
                last_deliver = {}
    # ── pass 2: server-truth final state ──
    for t in st["tasks"]:
        code, task, _ = http("GET", f"/v1/tasks/{t}")
        if code != 200 or not isinstance(task, dict):
            continue
        task = task.get("task", task)
        st_flag = task.get("status")
        claimer = task.get("claimed_by_agent_id")
        claims = task.get("claims") or []
        active = [c for c in claims if c.get("status") in ("active", "claimed")]
        if len(active) > 1:
            findings.append({"invariant": "single_active_claimer", "task": t,
                             "evidence": [c.get("claim_id") or c.get("agent_id") for c in active]})
        # phantom-claim: agent got 200 on claim but someone else owns it
        if t in claim_ok and claimer:
            phantoms = [a for a, _ in claim_ok[t] if a != claimer]
            if phantoms:
                findings.append({"invariant": "phantom_claim", "task": t,
                                 "evidence": {"real_claimer": claimer, "phantoms": phantoms,
                                              "note": "agents hold false belief of ownership"}})
        # deliver by non-claimer
        if t in deliver_ok and claimer:
            bad = [a for a, _ in deliver_ok[t] if a != claimer]
            if bad:
                findings.append({"invariant": "deliver_by_nonclaimer", "task": t,
                                 "evidence": {"claimer": claimer, "delivered_by": bad}})
        if st_flag in ("verified", "accepted") and task.get("cancelled_at"):
            findings.append({"invariant": "no_verified_after_cancelled", "task": t,
                             "evidence": {"status": st_flag, "cancelled_at": task.get("cancelled_at")}})
        # deliver/accept after successful cancel
        if t in cancel_ok:
            first_cancel = min(cancel_ok[t])
            for a, ts in deliver_ok.get(t, []) + accept_ok.get(t, []):
                if ts and ts > first_cancel:
                    findings.append({"invariant": "mutation_after_cancel", "task": t,
                                     "evidence": {"agent": a, "at": ts, "cancelled_at": first_cancel}})
    for f in findings:
        _log(FINDINGS, f)
    return findings


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    st = json.loads(STATE.read_text()) if STATE.exists() else {"agents": [], "tasks": []}
    if mode in ("seed", "all"):
        st = seed(50, 20)
        print("agents:", len(st["agents"]), "tasks:", len(st["tasks"]))
    if mode in ("drive", "all"):
        print(drive(st, seconds=int(os.environ.get("DRIVE_S", "120"))))
    if mode in ("check", "all"):
        print("findings:", check(st))
