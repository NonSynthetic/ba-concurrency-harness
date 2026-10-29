# Concurrency Hunt v2 — BasedAgents local instance

**Task:** `task_0YhrRo6AQ0o5j7aHyUBj1` — 50 synthetic agents, ≥10,000 actions,
structured race classes, invariant checking, seeded-race demo.
**Scope:** localhost only. `harness.py` and `repro_multi_claimer.py` parse the
target URL and refuse any hostname that isn't `127.0.0.1` / `localhost` / `::1`
(`urllib.parse.urlparse(...).hostname`, `sys.exit(2)` — not `assert`, so
`python -O` cannot strip it, and userinfo tricks like
`https://127.0.0.1@api.basedagents.ai` parse to a foreign host and are refused).

## Method

- `harness.py` — self-contained: ed25519 keypairs, PoW registration, AgentSig
  request auth, structured barrier-synchronized race rounds, volume driver,
  cron-tick invoker, response-vs-truth invariant checker.
- Clean instance: `packages/api` via `tsx src/node.ts` (better-sqlite3, full
  migration replay, `E2E=1` for 10× rate-limit headroom) on `127.0.0.1:3000`,
  fresh `data/registry_v2.db`.
- Seeded-race instance: same build + `SEED_RACE=1` on `127.0.0.1:3001`,
  separate DB (`seeded_race.patch` applied to `src/tasks/service.ts`).
- Timer races backdate `claim_expires_at` / `auto_release_at` / `expires_at`
  directly in SQLite (WAL), while `tick_cron.ts` invokes the exported
  scheduled task handler (`runTaskCron` — the function `src/index.ts`'s
  `scheduled` export calls) in a 250 ms loop on the same live DB file.

## Run profile

- **56 agents** registered (6 posters + 50 workers), **~16,700 actions** logged
  (`actions_log.jsonl`, gzip), **19,917 overlapping request-starts** measured,
  peak in-flight 122 across 40 driver threads.
- **238 tasks** exercised; **60 reached `verified`** (8 scripted lifecycles +
  6 sweeper auto-accepts + drive/revision re-deliveries + poster accepts).
- HTTP profile: 200 / 403 / 409 / 429 mix as expected under adversarial load;
  4 transport aborts (WinError 10053/10054 under burst — capacity note).

## Race classes — genuine collisions (both ops fired, overlapping in-flight)

| Class | Rounds | Outcome split | Winner evidence |
|---|---|---|---|
| claim/claim | 12 (4 racers ea.) | exactly 1×200 per task, rest 409 | DB `claimed_by` = sole 200 winner |
| deliver/cancel | 12 | exactly one 200 per round | final state matches winner |
| accept/revision | 12 | exactly one 200 per round | `verified` xor `claimed`(+rev) |
| double deliver | 12 | first 200, second 409 | no second `submitted` transition |
| double accept | 12 | both 200 — **idempotent by design** | same `accepted_by` on both 200s |
| timer: claim-expiry vs deliver | 18 live-tick | 200×12 (deliver before sweep), 403×6 (swept) | `submitted` vs `open`+null-claimer |
| timer: auto-release vs accept | 18 live-tick | accept 200 always | `accepted_by='creator'`×6 vs `'auto'`×12 |
| timer: open-expiry vs claim | 18 live-tick | claim 409 always | final `expired`, `claimed_by=null` |

Double-accept note: `handleAccept` is intentionally idempotent — an `accept`
on an already-`verified` task returns `ok` (payment-retry path,
`routes/tasks.ts:882`). The atomic gate still allows only one
`submitted→verified` transition; both 200s report the same `accepted_by`.
The checker's assertion targets split-brain accepters, not the 200 count.

Timer-expiry semantics observed: expiry is **lazy/sweeper-enforced** — a
`deliver` on a claim whose `claim_expires_at` is already past still succeeds
in the ~250 ms window before the next sweep (the claim route doesn't check the
deadline synchronously). Logged as a semantic observation, not a violation.

## Invariant checker (`harness.py check`) — every row is executable code

| Invariant | Implementation | Result |
|---|---|---|
| multi_claimer_ok | count distinct agents with claim-200 per task | held — 0 violations |
| phantom_claim | claim-200 winner ≠ final `claimed_by_agent_id` | held |
| single_active_claimer | final claimed/submitted task's claimer must equal latest claim-200 winner (uses real `claimed_by_agent_id`) | held |
| deliver_by_nonclaimer | deliver-200 agent ≠ final claimer | held |
| double_deliver | deliver-200 twice w/o intervening revision-200 | held |
| double_accept | ≥2 accept-200s must report one `accepted_by`; final state verified | held |
| mutation_after_cancel | deliver/accept-200 after cancel-200 | held |
| no_verified_after_cancelled | final status/flag contradiction | held |
| revision_monotone_bounded | `revision_count` == observed revision-200s, ≤ MAX_REVISIONS(3) | held |
| money_flags_consistent | illegal status×payment_status combos (verified+expired, cancelled+settled, open+in-flight) | held |
| verified_path | verified ⇒ `accepted_by` + `verified_at` present | held |
| timer_consistency | deliver-200 ⇒ not `open`; claim-200 ⇒ not `expired`; accept-200 ⇒ `verified` | held |

**Net: zero invariant violations on the clean build** — all gates are atomic
single-statement conditional UPDATEs; the sweeper uses the same gate style.

## Seeded-race demo (none-found claim support)

`seeded_race.patch` (env-gated `SEED_RACE=1`) replaces the atomic claim UPDATE
with a check-then-act `SELECT → 40ms sleep → unconditional UPDATE`.
`repro_multi_claimer.py` (6 agents, barrier-synchronized) verbatim:

```
[repro] claim ag_3cm5iRSdZ8TXJ7tsf... -> 200
[repro] claim ag_5HP7sdgV6U3JvmDk8... -> 200
[repro] claim ag_Hnbo37UquArQbGyMu... -> 200
[repro] claim ag_E1gimgP28KqtvR66G... -> 200
[repro] claim ag_2wS9deMawmU2w8pWP... -> 200
[repro] DB truth: status=claimed claimed_by=ag_Hnbo37Uq...VCtZ
[repro] MULTI-CLAIMER: 5 agents hold HTTP-200 claims on one task
[repro] checker: multi_claimer_ok + phantom_claim FIRED   (exit 0)
```

Severity if real: phantom claimers burn work on claims they don't hold; on
escrowed tasks it becomes a fund-dispute vector. Production gate prevents it.

## Files

- `harness.py` — orchestrator + agent behaviors + invariant checker
- `repro_multi_claimer.py` — standalone 6-agent reproducer (exit 0 = caught)
- `tick_cron.ts` — exported-handler invoker (drop at `packages/api/tick_cron.ts`)
- `seeded_race.patch` — deliberate check-then-act diff
- `actions_log.jsonl` — full op log (16,753 rows)
- `races.jsonl` — all structured race rounds with per-op results
- `findings.jsonl` — checker output (0 violations on clean build)
