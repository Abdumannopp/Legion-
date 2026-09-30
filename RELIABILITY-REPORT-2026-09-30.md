# Legion — Alert Pipeline Reliability Report (2026-09-30)

Phase 3 of the production-readiness work (after `PRODUCTION-READINESS-AUDIT-2026-09-29.md` and
`SECURITY-HARDENING-2026-09-29.md`). It covers what is durable, what can still be lost or duplicated, how
recovery works, and the evidence behind each claim.

```
Wazuh manager ──custom-legion.py──► POST /security-events/webhook ──► PostgreSQL transaction ──► 202
   │  retries, then SPOOL on disk      (HMAC verified before parse)      alert + asset + email job
   │  (per credential)                                                    + realtime job + seq
   └─ re-sent oldest-first ◄─ next alert / drain timer                    │
                                                                           ▼
                                  outbox worker(s) — every instance, SKIP LOCKED + fenced leases
                                     │                                 │
                               SMTP (retries,                   Redis pub/sub ──► every instance ──► WebSocket
                               dead letter,                     (a HINT only)                         │
                               requeue)                                                               ▼
                                                    dashboard: hello/ping cursor from Postgres ──► /alerts/sync
```

**PostgreSQL is the only source of truth.** Redis, WebSocket frames and process memory are accelerators. Losing
any of them delays the dashboard by seconds; it never loses an alert.

---

## 1. Guarantees by stage

| Stage | Guarantee | Mechanism | Evidence |
|---|---|---|---|
| Wazuh → Legion | **At-least-once**, bounded by the spool size | Retries (4, backoff). Then a durable on-disk spool (fsync + atomic rename), per credential, drained oldest-first by the next alert or a 1-minute timer. Every re-send is signed afresh with a new nonce. | `test_custom_legion.py` (23), failover "database restart…", "total outage…" |
| Webhook | **202 means committed.** Answers are 202 (stored or duplicate), 401 (refused), or 503 + `Retry-After` (DB down) | Signature verified over raw bytes, then one transaction. A DB error yields 503, never a half-stored alert. | `reliability-ingestion` "database outage…", failover "database restart…" |
| Idempotency | **Exactly-once storage per event** | Alert id = HMAC(tenant, provider, event id or content). `INSERT … WHERE NOT EXISTS … ON CONFLICT DO NOTHING`. Duplicates burn no version and queue no jobs. | `alert-delivery-durability` "duplicate…", failover "same Wazuh event hitting two instances" |
| Alert + follow-ups | **Atomic**: the alert, its asset upsert, its email job and its realtime job commit together or not at all | `outbox.insertAlertAndNotify` in a single transaction | `alert-delivery-durability` "database rollback…", failover "SIGKILL mid-burst: no partial alert" |
| Ordering | Per-tenant gapless version `seq`, visible in commit order. `created_at` is when Legion stored the event; **new**: `occurred_at` is when it happened at the source. | `alerts_assign_seq` trigger; `eventTime()` | `alert-cursor` (27), `reliability-ingestion` "event time" |
| Email | **At-least-once**, retried with backoff (30 s × 2ⁿ, capped at 1 h, 8 attempts), then dead-lettered, visible, requeueable | Transactional outbox; claims use `SKIP LOCKED` with a lease fenced by the attempt number. Every retry carries the same `Message-ID`. | `notification-outbox`, `alert-delivery-durability`, failover "retry exhaustion…" |
| Dashboard frames | Best effort (6 attempts, then dead). **The dashboard view is exactly-once**, because it converges on Postgres. | Frames carry `seq`; `hello`/`ping` carry the Postgres cursor every 5–20 s; `/alerts/sync` fills gaps; the client drops duplicates and stale versions | `realtime-recovery` (40), failover "several instances, Redis restart…" |
| Worker crash | Queued work survives, and is delivered by any instance | Rows stay `pending`, or `sending` with a lease that expires and is reclaimed. A job that crashed the worker on its last attempt is dead-lettered, not looped. | failover "SIGKILL…" (3 scenarios) |

---

## 2. What this phase changed

| Change | Why | Files |
|---|---|---|
| **The API no longer crashes when the database restarts.** A pooled client checked out mid-transaction when its connection died emitted an `error` event with no listener, which killed the process on every DB restart or failover. Every connection now gets a permanent listener, and `transaction()` destroys a client whose ROLLBACK failed. | Found by the new failure-injection harness | `server/src/db/pool.ts` |
| **Sensor-side durable spool** (per credential) and a drain timer | The integration dropped events after ~7 s of retries (audit P1-1) | `integrations/custom-legion.py`, `deploy/wazuh-legion-drain.*`, `WAZUH.md` |
| DB unavailable → **503 + Retry-After**, not 500 | Senders and load balancers retry instead of treating it as a bug | `server/src/index.ts` |
| **Outbox settles in-flight work after DB loss.** A known outcome (SMTP accepted) is written later, so no duplicate email is sent. Claims never attempted are handed back at once instead of waiting out the 120 s lease. | A DB blip used to strand jobs for 2 minutes, and could re-send an already-delivered email | `server/src/outbox.ts` |
| `alerts.occurred_at` (the sensor's timestamp) | Spooled events arrive late; analysts need the real time | `schema.sql`, `store.ts`, `index.ts` |
| **Silent-sensor alert** ("Wazuh unavailable") | A dead manager used to look like "all quiet" | `server/src/sensor-monitor.ts` |
| Dead-letter **requeue** (one job, or all of an organisation's) | After a long SMTP outage, dead jobs had no way back | `index.ts`, `outbox.ts` |
| Worker liveness in `/health/outbox` | A stopped worker is as bad as a stuck queue | `outbox.ts` |
| CI installs `redis-server` and `age` and **requires** the failure-injection suites; it also runs the Python integration tests; the agent-identity lockfile is synced | Redis scenarios used to skip silently in CI, and `npm ci` failed there | `.github/workflows/ci.yml`, `packages/agent-identity/package-lock.json` |

Schema change: `ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurred_at timestamptz`. It is nullable with no
default, so it is metadata-only with no table rewrite, and old rows stay null.

---

## 3. What can still be lost or duplicated (honestly)

| Case | Effect | Mitigation / what to do |
|---|---|---|
| The Wazuh manager's disk is lost, or the spool write fails (disk full) | Events not yet delivered are lost. The integration log says `could not be spooled … lost`. | Monitor the manager's disk. Keep the spool on persistent storage. |
| The spool exceeds `LEGION_SPOOL_MAX_FILES` (50 000) during a very long outage | The **oldest** events are dropped, loudly (`spool full … dropped`) | Size it for your outage budget (≈ events/min × minutes). |
| Events Wazuh never hands to the integration (below the `<level>` filter, or integratord overload) | Never reach Legion | Wazuh-side configuration |
| Legion's database volume is destroyed | Alerts committed since the last backup are lost. **RPO ≤ 24 h** (nightly `pg_dump`, no PITR — audit P1-13) | Managed Postgres with PITR, or WAL archiving. This is the largest remaining loss window. |
| Process crash between "SMTP accepted" and "marked sent" | **Duplicate email** after the lease (120 s), with the same `Message-ID` so a mail system can drop it | Inherent to SMTP. A DB-side failure no longer causes it (§2); only a process crash can. |
| An email dead-lettered after 8 attempts (~1 h of retries) | Not sent until an admin requeues it (`POST /notifications/deliveries/retry-dead`) | Watch `dead` in `/notifications/health` or `/health/outbox` |
| More than `ALERT_EMAIL_HOURLY_CAP` (100) alert emails per tenant per hour | Emails beyond the cap are **deliberately not queued** (the alert itself is stored and shown). This is an abuse cap, not a fault. | Raise the cap per deployment |
| Realtime frames dead-lettered while Redis is down for more than ~3 min | No loss. Tabs catch up from Postgres within one heartbeat (≤ `WS_HEARTBEAT_SECONDS`). | none needed |
| A dashboard more than `ALERT_SYNC_MAX_CATCHUP` (1000) versions behind | Reloads the list instead of paging (correct, just not incremental) | none needed |
| In-memory state (rate-limit counters without Redis, AI quota, AI circuit breaker, outbox held outcomes) | Reset on restart. A held outcome lost to a crash falls back to the lease. | By design |

---

## 4. How recovery works

| Failure | Behaviour | Recovery | Time to recover |
|---|---|---|---|
| **Wazuh unavailable** | No events. After `SENSOR_SILENCE_MINUTES` (120), a **"Sensor silent"** alert is raised once per silence (idempotent across instances). | Automatic. The alert resolves itself when the sensor sends again, and the manager drains its own spool. | Detection ≤ threshold + 5 min |
| **Legion API down / restarting** | The sensor retries, then spools | The next alert or the drain timer re-sends, oldest first, with a fresh signature. Duplicates collapse. | ≤ 1 min after Legion is back (timer) |
| **DB restart / failover** | Webhook answers 503 + `Retry-After`; `/health` 503; the API **stays up** | The pool reconnects on demand. The sensor spools, then drains. The outbox settles held outcomes on its first pass. | Seconds after the DB accepts connections |
| **Redis outage** | Rate limits count per instance. Frames cannot fan out, so their jobs stay `pending`. | Tabs converge from Postgres via the heartbeat cursor. When Redis returns: `resync` to sockets, queued frames published, client dedupes. | Dashboard: ≤ one heartbeat; frames: on reconnect |
| **Worker / app crash** | Queued jobs stay in Postgres | Any instance's worker reclaims `sending` rows after the lease (120 s). A crash on the final attempt is dead-lettered, not looped. | ≤ 120 s |
| **WebSocket disconnect / client reconnect** | Missed frames | Reconnect with backoff; `hello` carries the cursor; `/alerts/sync` fills the gap; polling if WebSocket is blocked | Seconds |
| **Multiple instances** | Any instance ingests; every instance's sockets get every frame via Redis | Workers share the queue safely (`SKIP LOCKED`, fenced leases) | — |
| **SMTP failure / slow mail** | Retry with backoff; each attempt is capped at 60 s (connect 15 s, socket 45 s) | Delivered on recovery; dead after 8 attempts → requeue | Next retry slot |
| **AI provider timeout / error** | 15 s timeout, typed failure, circuit breaker after 5 failures (60 s cool-down) | **Deterministic local analysis** is returned and stored as `source: "local"`, clearly labelled not-AI. A later request retries the provider. | Immediate (fallback) |
| **Slow downstreams generally** | Ingestion calls no external service (SMTP, Redis and AI are only touched by the worker or on request), so a slow downstream never slows or fails ingestion | — | — |

Monitoring signals (all exist now):

- `/health`: 503 when the DB is unreachable.
- `/health/outbox` (token): pending, retrying, dead, the oldest pending age, and worker liveness.
- `/notifications/health` (per-tenant admin view).
- The "Sensor silent" alert.
- The integration log (`SPOOLED`, `spool full`, `could not be spooled`).
- `/health/backup`.

---

## 5. Test evidence

**Failure-injection suite** (`server/tests/reliability-failover.test.ts`). Real API processes, real Postgres
through a fault proxy, real `redis-server`, the real `custom-legion.py`, a fake SMTP server that counts
`Message-ID`s, and the dashboard's own sync client:

| Requirement | Scenario | Result |
|---|---|---|
| DB restart | "events sent while Postgres is down are spooled by the sensor and land exactly once when it returns" (503 → spool → drain; `occurred_at` kept; 8 emails, 0 duplicates) | pass |
| DB restart (mid-burst) | "a database blip in the middle of a burst loses nothing and duplicates nothing" | pass (**failed before the pool fix: the API crashed**) |
| App restart | "work queued when the process dies is delivered by the next process, exactly once" | pass |
| Worker restart | "a worker killed in the middle of sending: the job is reclaimed after its lease and sent once" | pass |
| App crash, duplicate/partial alert | "a SIGKILL in the middle of a burst of webhooks: no partial alert…" | pass |
| Redis restart, multiple instances, reconnect recovery, duplicate notification delivery | "fan-out across instances; a Redis outage delays frames but the tab never misses or duplicates an alert" (including the tab's instance crashing and it reconnecting to the other) | pass |
| Duplicate webhook | "the same Wazuh event hitting two instances at once is stored, emailed and pushed exactly once" | pass |
| Notification failure, retry exhaustion | "a mail server that stays down exhausts the retries: dead, visible, and requeued after the fix — sent once" | pass |
| Recovery after outage | "database, Redis and mail all down while the sensor keeps producing: everything arrives exactly once afterwards" | pass |

**In-process suites** (`reliability-ingestion.test.ts`, 22 tests):

- event time;
- 503 on a DB outage;
- silent-sensor raise, idempotency (6 concurrent checks → 1 alert), auto-resolve, and isolation;
- dead-letter requeue, including tenant isolation and no double send;
- a DB lost mid-batch → the known outcome is written with no re-send, and untouched claims are handed back without
  burning an attempt;
- worker liveness.

**Pre-existing reliability suites** (still green): `alert-delivery-durability`, `notification-outbox`,
`realtime-recovery`, `alert-cursor`, `disaster-recovery`, `ai-hardening` (AI timeout, stall, error, breaker, local
fallback).

**Sensor** (`integrations/test_custom_legion.py`, 23 tests):

- spool on an outage; spool privacy; the backlog is sent in order before the new event;
- drain mode, including credentials from the environment; drain stops at the first failure;
- a refused credential is kept and re-sent with `--from`;
- **no cross-credential send**;
- concurrent drains never double-send; stale claims are recovered; a full spool drops the oldest.

### Run results (this commit)

See `§6`, filled in from the final run.

---

## 6. Final verification run

_(Filled in below.)_
