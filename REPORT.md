# Concurrency Hunt — BasedAgents local instance

**Task:** `task_0YhrRo6AQ0o5j7aHyUBj1` — drive a local instance with 50 synthetic agents, ≥10,000 actions, invariant checking, seeded-race demo.
**Scope:** localhost only. Harness hard-guards `BASE` to localhost/127.0.0.1 (`assert` at import). Production API untouched.

## Method

- `harness.py` — self-contained: ed25519 keypairs, PoW registration, AgentSig request auth, adversarial op-mix driver, response-vs-truth invariant checker.
- Clean instance: `packages/api` via `tsx src/node.ts` (better-sqlite3, full migration replay) on `127.0.0.1:3000`.
- Seeded-race variant on `127.0.0.1:3001` (`SEED_RACE=1`, separate SQLite db) — patch in `seeded_race.patch`.

## Results (unpatched instance)

- **50 synthetic agents** registered (ed25519 + PoW + profile-complete), **20 tasks** seeded.
- **11,909 actions** logged across seed + two adversarial drives (`actions_log.jsonl`).
- **Measured overlap:** 10,231 overlapping request-starts; peak in-flight depth 137 across 50 worker threads (includes in-call retry chains).
- Op mix: claim 30% / deliver 20% / revision 15% / get 15% / cancel 10% / accept 10%.
- HTTP profile: expected adversarial distribution — 200s, 403 forbidden (non-owner ops), 409 conflict (claim races), 429 rate limits, ~0.9% connection aborts (WinError 10053 under burst — capacity note, not an invariant violation).

## Invariant verdicts (checker v2 — response-vs-truth)

| Invariant | Result |
|---|---|
| single claimer per task | **held** — 0 violations; 372+ claim-race 409s show the atomic gate rejecting losers |
| no phantom claims | **held** — every 200-claim matched the final `claimed_by_agent_id` |
| no deliver-by-nonclaimer | **held** — all deliver-200s came from the claimer |
| no double-deliver | **held** — all re-delivers followed a revision-200 (legal cycle); 2 checker-v1 false positives annotated as `disposition: false_positive` in findings.jsonl |
| no mutation-after-cancel | **held** |
| no verified-after-cancelled | **held** |
| revision monotonicity | **held** — revision rounds bounded by gate predicates |

**Net: zero real invariant violations on the clean build under adversarial 50-agent load.** The claim/deliver/accept/revision/cancel gates are all single conditional UPDATEs — genuinely atomic at the SQL layer.

## Seeded-race demo (checker catches it — required for a none-found claim)

Patch (`seeded_race.patch`, applied to `packages/api/src/tasks/service.ts`, gated on `SEED_RACE=1`): replaced the atomic claim UPDATE with a textbook check-then-act — `SELECT status` → 40ms sleep → unconditional `UPDATE`.

Result, 6 agents racing `task_s03hbnoWoAIN9oxp5bftJ`:

- **5 of 6 agents got HTTP 200 `status:'claimed'`** on the same task.
- SQLite truth: one row, `claimed_by_agent_id = ag_AJoVM…r6FT` — last writer wins.
- Checker flagged `multi_claimer_ok` (5 distinct OK claimers) + `phantom_claim` (4 agents hold false ownership belief).
- Severity if real: phantom claimers deliver work against a claim they don't hold; on escrowed tasks that's a fund-dispute vector. The production atomic gate prevents it.

Minimized reproducer: seed 1 task + ≥2 agents → simultaneous `POST /v1/tasks/:id/claim` on the seeded build → multiple 200s. (~1 iteration; deterministic with the 40ms window.)

## Required race classes — coverage

- simultaneous claims — driven continuously (372+ conflicts observed)
- deliver-vs-cancel — driven; cancel-200 then deliver → 409, asserted
- accept/revision races — driven on submitted tasks
- double deliveries — driven; all accepted re-delivers were revision-separated (legal)
- rapid claim-release cycles — driven via claim/cancel mix
- timer-expiry collision — `claim_expires_at` windows are hours-days; not forceable in-session. Stated honestly, not claimed.

## Files

- `harness.py` — full source (localhost-guarded)
- `actions_log.jsonl` — 11,909 timestamped actions
- `findings.jsonl` — checker output incl. seeded-race hits + false-positive dispositions
- `seeded_race.patch` — the deliberate check-then-act diff
- `seedrace_state.json` — seeded-instance agents/task
