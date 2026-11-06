# Legion controlled pilot — readiness package (Task 12)

**Status: prepared, NOT deployed.** Nothing here has been started on a real host, exposed to a network, or switched to real actions. Every deploy step below needs explicit approval from the person responsible for the pilot (§12 records who).

**Scope of the pilot:** one isolated test workspace, read-only integration (a Wazuh feed into Legion), every response action in **shadow/simulation** (computed and recorded, never executed), human approval for anything above low risk, and every workflow and execution attempt monitored.

Evidence for every claim is in `pilot-results/rehearsal.json` (a live rehearsal against the real built server — §4, §7, §8), `ops/pilot-preflight.mjs` (the checklist as code), the test suites named in §4, and `E2E-REPORT.md`.

## 1. What the pilot is allowed to do — fixed in `docker-compose.pilot.yml`, not in `.env`

| Setting | Pilot value | Effect |
|---|---|---|
| `POLICY_ENGINE_MODE` | `shadow` | Existing paths (blocks, alert status, payments) are *also* evaluated by the policy engine and the would-be decision is recorded. It never changes what happens. There is no enforcing value. |
| `ORCHESTRATOR_AUTO_MODE` | `shadow` | Each new alert queues the alert workflow in shadow: decisions recorded, no approval requests, nothing done. |
| Action modes | `shadow`, `simulation` only | `live` is refused in the API (422), in the engine, and by a database `CHECK`. There is no code that executes an action. |
| Autonomy | no policy ⇒ `OBSERVE` | Agents' proposals are recorded only. `ASSIST` (ask a person) may be set by the pilot owner. **`AUTONOMOUS` is not part of this pilot** (§12.3). |
| Critical actions (R4) | always two other people + a fresh second factor | Enforced in code and by a database `CHECK`; no policy can lower it. |
| High-risk (R3) by an agent, Legion, or anything model-proposed | always a person's approval | Policy floor. |
| Demo data, public sign-up, billing | off | `DEPLOYMENT_MODE=self-hosted`, `SEED_DEMO_DATA=false`. |
| AI provider | empty | Alert text stays on your infrastructure. If you enable one, keep the workspace in **strict** data mode and have the terms signed first. |

## 2. Deployment checklist

`[auto]` = checked by `node ops/pilot-preflight.mjs`; `[manual]` = a person must do and sign it off. Do not proceed past a gate with an open item.

### Gate A — before anything is installed (T-7 days)
- [ ] [manual] Pilot owner named; approver(s) named (≥2 people with admin role, each with two-factor, so the critical-action quorum is possible); on-call contact for each alert severity.
- [ ] [manual] Host: Linux, Docker Engine ≥ 25 with Compose v2, NTP running (webhook timestamps and TOTP break on clock drift), disk ≥ 20 GB, backups target off the host.
- [ ] [manual] Domain and DNS for the pilot hostname; certificate path decided (certbot or the CDN).
- [ ] [manual] Wazuh manager reachable; the integration is the signed webhook only (Legion makes no call into the customer's systems).
- [ ] [manual] SMTP account for Legion (resets, invitations, alert mail). Delivery tested.
- [ ] [manual] Backup recipients: two `age` public keys generated; **private keys stored off the host, in two places**.
- [ ] [manual] Alert destination for Alertmanager exists (chat webhook or pager) and a human has confirmed they receive a test message (§9.3).
- [ ] [manual] Customer/data owner has accepted what leaves their network (nothing, with no AI provider) and the retention defaults (`DATA-RETENTION.md`).

### Gate B — configuration (T-2 days)
- [ ] [manual] `cp deploy/pilot.env.example .env.pilot && chmod 600 .env.pilot`; fill every `CHANGE-ME` with `openssl rand -hex 32` (all different). Keep `.env.pilot` out of git (it is git-ignored — preflight checks).
- [ ] [manual] **Back up `SOC_AUDIT_KEY`, `LEGION_ENCRYPTION_KEYS` and `JWT_SECRET` separately from the database backup** (password manager / HSM). Without the first, the audit chain cannot be verified after a restore; without the second, MFA seeds and webhook secrets are unreadable (§6).
- [ ] [auto] `node ops/pilot-preflight.mjs --env .env.pilot --compose docker-compose.pilot.yml` → **0 FAIL**. Record each WARN and the decision in §12.2.
- [ ] [manual] Build the images on the host (`docker compose --env-file .env.pilot -f docker-compose.pilot.yml build`); record the image digests, then pin them (R-2).
- [ ] [manual] nginx installed from `deploy/nginx.conf`; `nginx -t` passes; certificate issued; only 80/443 open on the host firewall (§5).

### Gate C — dry run on a staging host or the target host before opening any listener (T-1 day)
- [ ] [manual] `docker compose … up -d`; all five containers `healthy` (`docker compose ps`).
- [ ] [manual] **Container checks I could not run here (no Docker daemon in the build environment — R-1):**
  `docker compose exec backend id` → `uid=1000(node)`; `docker compose exec backend sh -c 'touch /x'` → *Read-only file system*; `docker inspect --format '{{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}}' $(docker compose ps -q backend)` → `[ALL] [no-new-privileges:true]`; `ss -ltn` shows 8000/3000 on `127.0.0.1` only and nothing on 5432/6379; from a second machine `nc -vz HOST 8000` and `nc -vz HOST 5432` both fail.
- [ ] [auto] `node ops/pilot-preflight.mjs --db --database-url postgresql://legion_app:…@127.0.0.1:…` (through `docker compose exec` or a loopback tunnel) → 0 FAIL.
- [ ] [manual] Run the rehearsal against a **copy** of the database cluster: `ADMIN_DATABASE_URL=… node ops/tests/pilot-rehearsal.mjs` → 22/22.
- [ ] [manual] Backup + restore drill on the target (§7.3) with the real `age` keys: `ops/backup.sh`, then `ops/restore.sh` into a scratch database, then `/soc/audit/verify`.
- [ ] [manual] Monitoring up (`docker-compose.monitoring.yml`), Prometheus target `UP`, the dashboard shows data, a **test alert is received by a human** (§9.3).

### Gate D — go-live (Day 0), only with the approval recorded in §12.1
- [ ] [manual] Open the public listener (nginx → 127.0.0.1) — the first time anything is reachable from outside.
- [ ] [manual] First-run setup: read the one-time token (`docker compose exec backend cat /var/lib/legion/.legion-setup-token`), create the first administrator, **enable two-factor immediately**, create the second administrator.
- [ ] [manual] Create the Wazuh webhook credential in the dashboard; configure the Wazuh integration (`integrations/`, `WAZUH.md`); send the built-in sample alert.
- [ ] [manual] Leave the policy empty (observe) for the first 48 h; then, if the owner decides, set `ASSIST` (§12.3).
- [ ] [manual] Confirm on the dashboard: `Live actions = 0`, `SOC worker running = YES`, no alerts firing.

### Gate E — daily during the pilot
- [ ] Dashboard glance (§9.1): live actions 0, worker heartbeat < 30 s, no dead jobs, no approvals older than 1 h.
- [ ] `GET /soc/audit/verify` returns `ok: true` (daily; also scripted weekly).
- [ ] Review `GET /policy/decisions` and `legion_soc_shadow_divergent_24h`.
- [ ] Backup status green (`GET /health/backup`); weekly: restore into scratch (§7).

## 3. Infrastructure configuration

```
Internet ─► host nginx :443 (TLS, rate limits)  ──►  127.0.0.1:3000  frontend  (container, edge net)
                                                 └►  127.0.0.1:8000  backend   (container, edge + data nets)
                                                                        │
                                                    internal docker network "data" (no inbound, no outbound)
                                                         ├─ postgres:5432   (no published port)
                                                         └─ redis:6379      (no published port)
Monitoring (loopback only): prometheus :9090, alertmanager :9093, grafana :3001  ◄─ SSH tunnel
```

| File | Purpose |
|---|---|
| `docker-compose.pilot.yml` | The pilot stack (postgres, redis, one-shot `db-provision`, backend, frontend). |
| `deploy/pilot.env.example` | Every setting the operator supplies. Git-ignored once copied to `.env.pilot`. |
| `docker-compose.monitoring.yml`, `monitoring/*` | Prometheus + Alertmanager + Grafana, 20 alert rules, a 32-panel dashboard. Replaces an earlier compose file that mounted a file that did not exist. |
| `deploy/nginx.conf` | TLS termination, rate limits, WebSocket and webhook paths (already in the repo; reviewed). |
| `deploy/legion-backup*.{service,timer}`, `ops/backup.sh`, `ops/restore.sh`, `ops/check-backup.sh` | Nightly encrypted backup with automatic restore test. |
| `ops/pilot-preflight.mjs` | The checklist as code (config, containers, host, database). |
| `ops/tests/pilot-rehearsal.mjs` | The live rehearsal (22 steps). |
| `server/src/metrics.ts`, `GET /metrics` | The monitoring surface (token-protected, counts only). |

**Container hardening (every service):** non-root user, read-only root filesystem, all capabilities dropped (Postgres included: since Task 15 it runs as `postgres`, uid 70, from the start, from `deploy/postgres/Dockerfile`, which also removes the `gosu` binary that carried a CRITICAL Go vulnerability), `no-new-privileges`, memory/CPU/process limits, init process, log rotation, healthchecks, images pinned by tag. The API never receives the database admin password (it gets an explicit list of variables, not the whole env file — the preflight caught a draft that did).

## 4. Security verification

Legend: ✅ verified by a command I ran this session · 🟡 verified statically or by tests, needs the manual step on the host · ⚠️ finding.

| # | Requirement | Result | Evidence |
|---|---|---|---|
| 1 | Production configuration reviewed | ✅ | `config.ts` refuses to start in production without a strong `JWT_SECRET`, secure cookies, https `FRONTEND_URL`, SMTP, explicit `DATABASE_URL`, no insecure DB TLS. Preflight adds: distinct secrets, audit key, metrics token, explicit CORS and proxy lists, TLS public URLs, file mode. 19 tests prove it: a good config passes, and each of 16 unsafe variants fails by name. |
| 2 | Docker/container security | 🟡 | Compose resolves; preflight checks every service (read-only, caps, no-new-privileges, limits, loopback ports, internal network, no admin credentials in the API, fixed safety modes) → 79 checks, 0 FAIL (3 warnings: two image-digest notes, TLS is manual). Dockerfiles: final stage `USER node`, explicit tags, no remote `ADD`. **No Docker daemon here — containers were not built or run (R-1).** |
| 3 | Non-root runtime identities | ✅ | Rehearsal ran the *built server* in production mode as uid/gid **65534**, `CapEff = 0`, `NoNewPrivs = 1`. Containers use user `node` (uid 1000), Redis `999`, Postgres drops to `postgres`. |
| 4 | Database least privilege | ✅⚠️ | The API role (`legion_app`, created by `db/provision-cli.js`): not superuser/CREATEROLE/CREATEDB/BYPASSRLS/REPLICATION; member of no role; **cannot** `pg_read_file`, `COPY … TO PROGRAM`, `CREATE ROLE`, create extensions; could connect to another database but could neither read nor create anything in it. ⚠️ **R-3:** it *owns* its tables, so it can `DISABLE TRIGGER` on the append-only tables. See below. |
| 5 | TLS and network restrictions | ✅🟡 | API listens on `127.0.0.1` only (read from `/proc/net/tcp`; refused on the LAN address). Compose: data network `internal: true`, no published DB/Redis ports. nginx config reviewed. **Public TLS is the host's job — manual checks in §5.** |
| 6 | Encrypted secrets | ✅ | Webhook secrets and MFA seeds are sealed with `LEGION_ENCRYPTION_KEYS` (the plaintext webhook secret was not found anywhere in the database); passwords bcrypt; backups `age`-encrypted (ciphertext contains no `PGDMP`/`CREATE TABLE`); preflight never prints a value (tested). Secrets are env-injected, `chmod 600`, git-ignored. |
| 7 | Backups and restoration tests | ✅ | §7. |
| 8 | Monitoring and alerts | ✅🟡 | `/metrics` live in the rehearsed process; 20 rules and 32 panels, **every metric they name is proven to exist by a test**; delivery to a human must be tested on the host (§9.3). Rule *syntax* was not run through `promtool` (not available here) — run `promtool check rules monitoring/alerts.yml` at Gate C. |
| 9 | Worker health and recovery | ✅ | §8. |
| 10 | Tenant isolation | ✅ | Live process: a second workspace saw 0 alerts, got 404 on all 9 cross-tenant probes (action read, approval read, approval decision, for three of the first workspace's actions), had an empty audit/policy view and its own valid audit chain. Plus `tenant-isolation-sweep`, `cross-tenant-attacks`, and the recursive `tenant-query-guard` (every query on a tenant table is scoped or a reviewed exception). Isolation is enforced by the application, not Postgres row-level security (R-4). |
| 11 | Disaster recovery | ✅ | §7.2. |
| 12 | Deployment and rollback procedures | ✅ | §2 and §11; rollback switches rehearsed live. |

**R-3 in detail.** Postgres lets a table owner switch off its triggers, so a fully compromised API could in principle disable the append-only guard on `audit_log`, `policy_decisions`, `action_events`. What still holds: (a) the *SOC audit chain* is keyed (HMAC) so edits are detectable by anyone with the key, and the engine now **fails closed** if the key differs from the one the chain was signed with — proven in the rehearsal; (b) `legion_app` cannot reach the key. What does not: the plain `audit_log` is not keyed. **Before the pilot ends:** split a *migrator* role (owns the schema, used only at deploy) from the *runtime* role (DML only) — planned in §13; **during the pilot:** run `GET /soc/audit/verify` daily and store the chain head off-host (`/soc/audit` → last `seq` and `hash`), which makes a rebuilt chain detectable.

## 5. Network and TLS

1. Host firewall: allow 22 (from the admin network only), 80, 443; deny everything else. Docker publishes only on `127.0.0.1`; confirm with `ss -ltn`.
2. nginx: `deploy/nginx.conf` (TLS, `limit_req` zones, upstream keep-alive tuned below Node's, WebSocket upgrade). Behind a CDN follow `DEPLOY-ONLINE.md` §12 and `ops/update-cloudflare-ips.sh`; lock the origin to the CDN's ranges.
3. Verify TLS before go-live: `curl -sI https://HOST | head -5` (expect `Strict-Transport-Security`), `testssl.sh --quiet --severity MEDIUM https://HOST` (no MEDIUM or worse), `openssl s_client -connect HOST:443 -servername HOST </dev/null | openssl x509 -noout -dates`. Record the output in §12.2.
4. The Wazuh feed: only the manager's address may reach `/api/security-events/webhook`; every request is HMAC-signed with a timestamp and nonce (replay refused). Restrict at nginx with `allow <manager-ip>; deny all;` for that location.
5. `TRUSTED_PROXIES` must be exactly the proxy (loopback + the docker bridge). Never `true`/`*` — the preflight fails on it.
6. Monitoring and admin UIs are loopback-only; reach them through `ssh -L`. Never publish 9090/9093/3001.

## 6. Secrets

| Secret | Generated | Lives | Loss means |
|---|---|---|---|
| `POSTGRES_ADMIN_PASSWORD` | `openssl rand -hex 32` | `.env.pilot` only; used by Postgres and the one-shot provision container, never the API | reset via the data volume |
| `APP_DB_PASSWORD` | same | `.env.pilot` | re-run `db-provision` |
| `JWT_SECRET` | same | `.env.pilot` + secret store | everyone signs in again |
| `LEGION_ENCRYPTION_KEYS` (`k1:<64 hex>`) | same | `.env.pilot` **+ separate secret store** | **MFA seeds and webhook secrets unreadable** |
| `SOC_AUDIT_KEY` | same | `.env.pilot` **+ separate secret store** | **audit chain cannot be verified; a wrong key makes audited actions fail (fail-closed)** |
| `HEALTH_METRICS_TOKEN` | same | `.env.pilot` + `monitoring/secrets/metrics-token` | monitoring blind; regenerate |
| `age` private keys | `age-keygen` | **off the host**, two copies | backups unreadable |

Rotation: `JWT_SECRET` (`JWT_PREVIOUS_SECRETS` keeps old sessions valid), encryption keys (add `k2:…` first in the list; old ones stay for decryption — `INSTALL.md`). **Do not rotate `SOC_AUDIT_KEY` during the pilot** — no rotation procedure exists yet (§13).

## 7. Backup and restore

### 7.1 Configuration
`deploy/legion-backup.timer` nightly 02:40 → `ops/backup.sh`: dump → **restore into a throwaway database and compare** → encrypt with `age` (public keys only on the host) → checksum → off-host upload (`BACKUP_UPLOAD_CMD`) → prune (14 daily / 8 weekly / 12 monthly). `deploy/legion-backup-check.timer` + `GET /health/backup` + `HEALTHCHECK_PING_URL` report staleness. The backup connects as the table-owning role; `DATABASE_ADMIN_URL` (CREATEDB) enables the automatic restore test and must be given to the **backup unit only**, never the API.

### 7.2 Measured on the rehearsal (this environment: PostgreSQL 16, tiny dataset)

| Measure | Result |
|---|---|
| Backup (dump + automatic restore test + encrypt) | 1.1 s, 428 KB, ciphertext contains no plaintext |
| Restore into an empty database + re-provision role + boot + verify | **RTO 2.0 s** (a production dataset will be larger; measure at Gate C) |
| Data written after the last backup, then the database destroyed | 3 alerts lost = **RPO = the backup interval** (nightly ⇒ up to 24 h). Shorten with more frequent dumps or WAL archiving if the owner needs it. |
| After restore | login works; alerts restored; **audit chain 245 events valid with the same key**; the sensor's signed webhook accepted (secret decrypts with the same keys); preflight 0 FAIL |
| Wrong `SOC_AUDIT_KEY` | verification reports the key mismatch; the chain is **not extended** (an audited action returned 500); metric `legion_soc_audit_key_mismatch_workspaces=1`; with the right key everything verifies again |

### 7.3 Restore drill (do at Gate C and then weekly)
```
ops/backup.sh                                         # or take the latest nightly file
createdb legion_drill
DATABASE_URL=postgresql://admin@…/legion_drill BACKUP_AGE_IDENTITY_FILE=/safe/private.key ops/restore.sh backups/legion-….dump.age --yes
APP_DB_PASSWORD=… DATABASE_ADMIN_URL=…/legion_drill node server/dist/db/provision-cli.js
# start a throwaway API against legion_drill, then:  GET /soc/audit/verify  → ok:true
```
Full disaster procedure: `RECOVERY.md` (updated for containers).

## 8. Worker health and recovery (rehearsal, real process)

| Scenario | Result |
|---|---|
| Boot as unprivileged user, migrations 7/7 applied by the app role | healthy in 1.4 s |
| `SIGTERM` | exit 0 in 50 ms |
| `kill -9` with 60 concurrent action requests | 15 answered; at the kill: 32 mid-simulation, 12 queued, 15 done. Restart healthy in 1.2 s. **All 60 actions ended simulated exactly once**, replaying all 60 idempotency keys created no duplicate, 0 dead jobs, audit chain valid. Full recovery took **66 s** (idle window 60 s + recheck 15 s). |
| Action stuck `running` + job whose worker died | reclaimed 1.1 s after restart (it was already past the idle window) |
| Poison job | backoff → dead letter after max attempts → audited, other work unaffected |
| An action that keeps killing its worker | failed after 5 attempts, audited (no endless loop) |

**Two defects were found and fixed by this rehearsal** (they were in Task 11's own crash fix): a job could mark itself done while its action was still `running`, stranding it; the idle window (300 s) was longer than the job lease (120 s). Now a recovered job never completes while its action is unresolved, and the window is 60 s. Regression tests: `e2e-soc-resilience.test.ts`.

## 9. Monitoring

### 9.1 Dashboard — "Legion pilot" (Grafana, `monitoring/grafana/dashboards/legion-pilot.json`)
Rows: **Pilot safety** (live actions must be 0; emergency stop; API up; worker running) · **Workers and recovery** (seconds since worker pass, oldest due job, dead jobs, lapsed leases, stuck actions, worker errors; jobs by status) · **Workflows, approvals and execution attempts** (approvals waiting and oldest wait, approved-but-unused, workflow runs and failures, **every action request by status**, policy decisions, shadow divergence, audit events) · **Dependencies** (notification queue, AI circuit, DB pool, uptime). Start it: `docker-compose.monitoring.yml` header lists the commands; open via `ssh -L 3001:127.0.0.1:3001 host`.

### 9.2 Alerts (`monitoring/alerts.yml`, routed by `monitoring/alertmanager.yml`)
| Severity | Alert | Fires when | First action |
|---|---|---|---|
| page | `LegionLiveActionDetected` | any action not in shadow/simulation | **Stop the pilot (§10, level 5)**, preserve the DB, investigate |
| page | `LegionApiDown` | `/metrics` unreachable 2 min | §9.4 "API down" |
| page | `LegionSocWorkerStopped` / `…Stale` | worker not running / no pass for 60 s | restart backend; check logs |
| page | `LegionSocJobsBacklog` | a due job waits > 5 min | worker stalled or DB slow |
| page | `LegionAuditKeyMismatch` | audit key ≠ chain's key | restore the original `SOC_AUDIT_KEY`; **do not** start a new chain |
| ticket | `LegionSocDeadJobs`, `…LeasesLapsed`, `…ActionStuckRunning`, `…WorkerErrors`, `…WorkflowFailures` | see rule annotations | `GET /runtime/status`, logs |
| ticket | `LegionApprovalWaitingTooLong`, `…ApprovedButUnused` | approval waiting > 1 h / unused 15 min | page an approver; check pause state |
| ticket | `LegionNotificationsDead/Backlog`, `LegionDbPoolWaiting`, `LegionRestarted` | | SMTP / DB / crash loop |
| info | `LegionWorkspacePaused`, `LegionShadowDivergenceHigh`, `LegionAiCircuitOpen` | | confirm intent / review evidence |

### 9.3 Prove the alert path (Gate C)
1. Stop the backend (`docker compose stop backend`), wait 3 minutes, and confirm a human received **LegionApiDown**; start it again and confirm the *resolved* message.
2. Prove the page route for the safety alert: temporarily change the rule to `expr: legion_soc_actions_live >= 0` (always true), reload Prometheus, confirm a human received **LegionLiveActionDetected**, then revert the rule. (A real live action cannot be created — the database refuses it — so the test must use the threshold.)

### 9.4 Runbooks
- **API down:** `docker compose ps`; `docker compose logs --tail 100 backend` (a refusal to start prints the exact reason); `curl -s 127.0.0.1:8000/health`; if the database is down, §11 level B/C. The worker is in the same process.
- **Approve / reject an action (no dashboard screen exists yet — R-5):** list `GET /approvals?status=pending`; read `GET /approvals/{id}` (action, risk, summary, digest); decide with `POST /approvals/{id}/decision {"decision":"approve","action_digest":"<from the request>","mfa_code":"123456"}` (the code is required for critical actions). Simulated actions then show `status: simulated`.
- **Dead job:** `GET /runtime/status?status=dead`; the cause is in `last_error`; fix, then it can be re-proposed (jobs are never silently retried forever).
- **Audit verify:** `GET /soc/audit/verify` → `{ok:true,events:N,head:…}`. The backend logs a `soc_audit_checkpoint` line (workspace, `seq`, `hash`) every 6 hours: **ship the container log off the host** (or copy one line a day). To check, pass a stored line back: `GET /soc/audit/verify?checkpoint_seq=<seq>&checkpoint_hash=<hash>` → `checkpoint.status` `match` (good), `pruned` (removed by retention), `missing` (events were cut from the end) or `mismatch` (history rewritten). The plain verify cannot see a cut end; the checkpoint can.

## 10. Kill switches (use the lowest level that stops the harm)

| Level | Action | Effect | Rehearsed |
|---|---|---|---|
| 1 | `POST /actions/controls {"paused":true}` (admin) | New actions refused (423); approved ones held; queued jobs deferred without spending attempts | ✅ |
| 2 | `POST /agents/{id}/suspend` | That agent's tokens stop working immediately | ✅ (Task 11) |
| 3 | `PUT /policy` with `{"default_autonomy":"OBSERVE","rules":[{"id":"freeze","effect":"DENY","actions":["*"]}]}`; `POST /policy/rollback` to undo | Every proposal denied | ✅ (Task 11) |
| 4 | `.env`: `ORCHESTRATOR_AUTO_MODE=off POLICY_ENGINE_MODE=off RUNTIME_WORKER=off`, restart backend | No new workflow jobs or shadow decisions; ingest keeps working | ✅ (flags 1–2) |
| 5 | `docker compose stop backend` | Everything stops; Wazuh buffers or drops events (check its queue) | — |

## 11. Deployment and rollback

### 11.1 Deploy (after Gate D approval)
1. `git fetch && git checkout <approved tag>`; confirm `git status` clean and the commit equals the approved one.
2. Preflight (Gate B) → build → **take a backup** (`ops/backup.sh`) and record its file name and checksum.
3. `docker compose --env-file .env.pilot -f docker-compose.pilot.yml up -d` — `db-provision` runs first, then the backend applies versioned migrations (checksummed; a changed applied migration refuses to start).
4. Verify: all containers healthy; dashboard green; `GET /soc/audit/verify` ok; send a sample alert; preflight `--db` 0 FAIL.

### 11.2 Rollback (decide with the table; write the decision in §12.2)
| Problem | Level | Steps | Data impact |
|---|---|---|---|
| Behaviour wrong, data fine | **A. Switches** | §10 levels 1–4 | none |
| New build misbehaves, schema unchanged or additive | **B. Previous image** | `docker compose … up -d` with the previous image tag/digest (keep the last two). Migrations are forward-only; the previous build ignores tables it does not know. If the previous build *refuses to start* because a recorded migration is unknown to it, use C. | none |
| Data damaged / schema must go back | **C. Restore the pre-deploy backup** | stop backend → create empty DB → `ops/restore.sh <pre-deploy file> --yes` → `provision-cli` → start previous image → verify | **loses everything since the backup** (RPO) |
| Host lost | **D. Disaster recovery** | `RECOVERY.md` on a replacement host with the off-host backup + the separately stored keys | up to one backup interval |

Never edit an applied migration (checksum guard) and never "fix" a chain by deleting audit rows.

## 12. Acceptance criteria, approvals and decisions

### 12.1 Approvals to be recorded (name, date) — none given yet
- [ ] Deploy the pilot stack to host ______ (Gate D)
- [ ] Expose the public listener
- [ ] Connect the Wazuh feed of ______ (read-only)
- [ ] Set autonomy to ASSIST on day ___ (optional)

### 12.2 Decision log (every preflight WARN, every manual check result)
| Item | Decision / evidence | By | Date |
|---|---|---|---|
| Base images pinned by tag, not digest (R-2) | | | |
| `owner-can-disable-triggers` (R-3) | accept for pilot with daily verify + off-host head | | |
| DB connection not TLS (internal network) | | | |
| TLS scan result | | | |
| Alert delivery test | | | |

### 12.3 Pilot acceptance criteria (run ≥ 14 days; ALL must hold to extend or to *ask* for more autonomy)
**Safety (zero tolerance — any breach pauses the pilot):**
1. `legion_soc_actions_live` was 0 throughout; no action existed outside shadow/simulation.
2. No real block, alert change or payment resolution was made by an agent or by Legion (compare `ip_blocks`/`audit_log` against human actions).
3. Every critical-action proposal waited for the required approvers; none ran without.
4. `GET /soc/audit/verify` `ok:true` every day; no key mismatch alert.
5. No cross-workspace data exposure (isolation probes weekly: 0 findings).

**Reliability:**
6. API availability ≥ 99.5 % of the pilot hours (excluding announced maintenance).
7. SOC worker heartbeat < 60 s for ≥ 99.9 % of scrapes; 0 dead jobs unexplained; 0 actions stuck > 5 min.
8. p95 time from alert ingest to first agent proposal recorded < 5 s (workflow in shadow).
9. Backups: 14/14 nightly succeeded with automatic restore test; at least 2 manual restore drills passed; measured RTO within the owner's target.
10. Alerts: every page-level test and real page reached a human within 5 min.

**Quality (the evidence for any future enforcement decision):**
11. Shadow divergence reviewed weekly; every divergent decision explained and either the policy or the code fixed.
12. Approvers: median approval wait < 1 h; ≥ 90 % of reviewed proposals judged "sensible" by the approvers; false-positive proposals recorded as memory.
13. Alert mail and Wazuh ingestion lossless: events sent = alerts stored (reconcile on 3 sampled days).

**To ask for autonomous actions (separate, explicit approval; not part of this pilot):** criteria 1–13 met; the dashboard has approval and action screens (R-5); the migrator/runtime role split is done (R-3); the live executor design for a *single* low-risk, reversible action (e.g. block an address for ≤ 60 min) is reviewed; connector credentials are scoped to that action; a rollback of that action is rehearsed; and the pilot owner signs.

## 13. Risk and limitation register

| ID | Risk / gap | Severity for pilot | Plan |
|---|---|---|---|
| R-1 | ~~Containers never built or run~~ **Closed in Task 13:** the CI job `pilot-stack` builds and starts this compose file on a real Docker host and checks hardening, Redis, DB role, `/metrics`, audit chain and crash restart. (Gate C on the real host is still required.) | Low | Run Gate C; record in §12.2 |
| R-2 | Base images pinned by tag, not digest | Low | Pin digests at first build |
| R-3 | App DB role owns tables ⇒ can disable append-only triggers | Medium | Migrator/runtime split; daily chain verify + off-host head meanwhile |
| R-4 | Tenant isolation is application-enforced (no Postgres row-level security) | Low (well tested; one workspace in pilot) | Consider RLS before multi-tenant production |
| R-5 | No dashboard screens for SOC approvals/actions/policy; approvers use the API | **Medium** (usability) | Build screens before extending the pilot |
| R-6 | Approval expiry and "approved while paused" are applied lazily (when read) | Low | Add a periodic reconciler (E2E-REPORT G-05) |
| R-7 | Hunter/Guardian are not wired into a production workflow; only the 3-step alert workflow runs | Low for pilot | E2E-REPORT G-02/G-04 |
| R-8 | Single process runs API and worker | Low | Split worker process when load requires |
| R-9 | Redis and Postgres traffic is plaintext on the internal network | Low | TLS for any managed/remote DB (`DB_SSL=true`) |
| R-10 | No `SOC_AUDIT_KEY` rotation procedure; no off-host chain checkpoint automation | Medium | Daily manual head record now; automate and add rotation |
| R-11 | Recovery from an abrupt kill takes up to ~75 s for in-flight simulations | Info | Acceptable (simulation only) |
| R-12 | ~~Rules not executed by promtool~~ **Closed in Task 13:** `promtool check rules` and `promtool test rules` (`monitoring/alerts.test.yml`) run in CI. Delivery to a human is still untested | Low | Gate C alert-path test |
| R-13 | Real AI provider and real connector behaviour were not tested (none configured) | Info | Out of pilot scope |

## 14. Evidence index
`pilot-results/rehearsal.json` (22 steps, measurements) · `pilot-results/rehearsal-server.log` (server log, credentials scrubbed) · `E2E-REPORT.md`, `e2e-results/` (Task 11) · `SOC-CORE.md` · tests: `pilot-preflight`, `pilot-monitoring`, `metrics`, `soc-audit`, `e2e-soc-*`, `tenant-query-guard`, `tenant-isolation-sweep`, `cross-tenant-attacks`, `disaster-recovery`, `backup-scripts`.

Task 13 (production readiness): see `PRODUCTION-READINESS-ASSESSMENT.md`. Verdict: pilot GO (conditional), general production NO-GO.
