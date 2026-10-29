#!/usr/bin/env python3
"""Minimal reproducer: 6 agents race POST /v1/tasks/:id/claim on ONE open task.

On a correct build exactly one agent wins (the claim gate is a single atomic
UPDATE ... WHERE status='open' AND claimed_by_agent_id IS NULL). On the
SEED_RACE=1 build (see seeded_race.patch — atomic UPDATE replaced with a
check-then-act SELECT -> 40ms sleep -> unconditional UPDATE) all racers that
observed 'open' win: multiple HTTP 200s, one DB row.

Local-only: same parsed-hostname guard as harness.py.

Usage: python repro_multi_claimer.py [--base http://127.0.0.1:3001]
Exit: 0 when the checker fires (multi-claimer observed), 1 otherwise,
      2 for a non-local base.
"""
import json, os, sys, time, base64, hashlib, threading
import urllib.request, urllib.error, urllib.parse

BASE = os.environ.get("BA_BASE", "http://127.0.0.1:3001")
for i, a in enumerate(sys.argv):
    if a == "--base" and i + 1 < len(sys.argv):
        BASE = sys.argv[i + 1]

host = (urllib.parse.urlparse(BASE).hostname or "").lower()
if host not in ("127.0.0.1", "localhost", "::1"):
    sys.stderr.write(f"FATAL: LOCALHOST GUARD — refusing non-local target {BASE!r}\n")
    sys.exit(2)


def b58e(b):
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + (s or "1")


def http(method, path, body=None, key=None, agent_id=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"content-type": "application/json"}
    if key and agent_id:
        import nacl.signing
        sk = nacl.signing.SigningKey(key[:32])
        ts = str(int(time.time()))
        nonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        msg = f"{method}:{path}:{ts}:{hashlib.sha256(data or b'').hexdigest()}:{nonce}"
        sig = sk.sign(msg.encode()).signature
        h["authorization"] = f"AgentSig {b58e(bytes(sk.verify_key))}:{base64.b64encode(sig).decode()}"
        h["x-timestamp"] = ts
        h["x-nonce"] = nonce
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {}


def register(name):
    import nacl.signing
    sk = nacl.signing.SigningKey.generate()
    pub = b58e(bytes(sk.verify_key)); pub_bytes = bytes(sk.verify_key)
    code, r = http("POST", "/v1/register/init", {"public_key": pub})
    if code != 200: return None
    chal_id, chal = r["challenge_id"], r.get("challenge", "")
    diff = int(r.get("difficulty", 22))
    threshold = 1 << (32 - diff)
    nonce = 0
    while True:
        hx = f"{nonce:016x}"
        if int.from_bytes(hashlib.sha256(pub_bytes + chal.encode() + bytes.fromhex(hx)).digest()[:4], "big") < threshold:
            break
        nonce += 1
    sig = base64.b64encode(sk.sign(chal.encode()).signature).decode()
    code, r = http("POST", "/v1/register/complete",
                   {"challenge_id": chal_id, "public_key": pub, "signature": sig, "nonce": hx,
                    "profile": {"name": name, "description": "repro agent", "capabilities": ["testing"], "protocols": ["https"]}})
    if code not in (200, 201): return None
    return {"agent_id": r.get("agent_id") or r.get("agent", {}).get("agent_id"), "secret": bytes(sk).hex()}


def main():
    print(f"[repro] base={BASE}")
    agents = [a for a in (register(f"race-repro-{i}-{os.urandom(3).hex()}") for i in range(6)) if a]
    print(f"[repro] registered {len(agents)}/6 agents")
    poster = agents[0]
    code, r = http("POST", "/v1/tasks", {
        "title": "repro-multi-claimer", "description": "repro", "category": "automation",
        "required_capabilities": ["testing"], "output_format": "json", "expected_output": "x"},
        key=bytes.fromhex(poster["secret"]), agent_id=poster["agent_id"])
    task = r.get("task_id") or r.get("task", {}).get("task_id") or r.get("id")
    print(f"[repro] task={task} (http {code})")
    bar = threading.Barrier(5)
    out = [None] * 5

    def go(i, a):
        bar.wait()
        c, _ = http("POST", f"/v1/tasks/{task}/claim", {},
                    key=bytes.fromhex(a["secret"]), agent_id=a["agent_id"])
        out[i] = (a["agent_id"], c)

    ths = [threading.Thread(target=go, args=(i, a)) for i, a in enumerate(agents[1:6])]
    for t in ths: t.start()
    for t in ths: t.join()
    winners = [a for a, c in out if c == 200]
    for a, c in out:
        print(f"[repro] claim {a[:20]}... -> {c}")
    code, r = http("GET", f"/v1/tasks/{task}")
    t = r.get("task", {})
    print(f"[repro] DB truth: status={t.get('status')} claimed_by={t.get('claimed_by_agent_id')}")
    if len(winners) > 1:
        print(f"[repro] MULTI-CLAIMER: {len(winners)} agents hold HTTP-200 claims on one task")
        print("[repro] checker: multi_claimer_ok + phantom_claim FIRED")
        sys.exit(0)
    print(f"[repro] single winner — atomic gate held ({len(winners)} winner)")
    sys.exit(1)


if __name__ == "__main__":
    main()
