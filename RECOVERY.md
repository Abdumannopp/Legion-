# Legion — Disaster recovery

> A backup that has never been restored is a guess. Everything below is
> exercised by `server/tests/disaster-recovery.test.ts` (see "The drill").

## What is protected, and what is not

| Thing | Where it lives | If lost |
|---|---|---|
| Alerts, users, tenants, audit log, sensor credentials, MFA config | **PostgreSQL** (the only source of truth) | Restore from backup. |
| Encrypted secrets *inside* the database (2FA seeds, webhook secrets) | PostgreSQL, sealed with `LEGION_ENCRYPTION_KEYS` | **Unreadable without the keys** — see "Secrets". |
| Rate-limit counters, realtime fan-out | **Redis** | Nothing to restore. Start an empty Redis. Verified by the drill. |
| Sessions | refresh tokens in PostgreSQL, access tokens signed with `JWT_SECRET` | New `JWT_SECRET` ⇒ everyone signs in again. Nothing else is lost. |
| Code | the release you deployed | Redeploy it. |

There is no Docker/compose deployment in this repository: Legion runs under
systemd (`deploy/legion.service`) behind nginx. If you containerise it, the
same scripts run unchanged inside the container that has `pg_dump` and `age`.

## Architecture

```
 Legion server ──pg_dump──► plaintext dump (private temp dir, mode 700)
                               │  1. restore into a throwaway database, compare tables  ← every night
                               │  2. encrypt with age to PUBLIC key(s)                  ← key NOT on this server
                               ▼
              /var/backups/legion/legion-<UTC>.dump.age  + .sha256      (local copies, GFS retention)
                               │  3. BACKUP_UPLOAD_CMD (S3 / rclone / scp …)             ← off-server copy
                               ▼
                    off-server storage (versioned, object-locked, its own retention)
 status ──► /var/lib/legion-backup/backup-status.json ─► GET /health/backup · ops/check-backup.sh · alerts
```

* **Schedule:** `deploy/legion-backup.timer` nightly 02:40 (persistent: runs at boot if missed).
* **Encryption:** [age](https://age-encryption.org) public-key encryption. The server has only the
  public key (`BACKUP_AGE_RECIPIENTS`); it can create backups but **cannot read them**. Nothing
  unencrypted is written to the backup directory or uploaded. The scripts *refuse* to run with a
  private key as recipient, or with a private key found inside `BACKUP_DIR`. Give two or more
  recipients so one lost private key is not lost backups.
* **Retention (local):** newest backup of each of the last 14 days, 8 weeks and 12 months
  (`BACKUP_KEEP_DAILY/WEEKLY/MONTHLY`), and never fewer than the newest 3. Decided from the
  timestamp in the file name; pruning runs only after a backup succeeded. **Off-server retention** is
  the storage's job — set a lifecycle rule (e.g. S3: keep 35 days + monthly for 12 months) and turn
  on versioning and Object Lock so ransomware on the server cannot delete history.
* **RPO** ≤ 24 h (nightly). For minutes, use a managed Postgres with PITR *in addition*.
  **RTO:** see "The drill" for measured times; measure yours with your data volume.

## Set up backups (once)

1. On **your workstation** (not the server): `age-keygen -o legion-recovery.key` (do this twice, for two
   keys). The line `Public key: age1…` is what the server gets. Store each private key file as in
   "Secrets" below. Remove them from the workstation's disk once stored.
2. On the server: `apt install age postgresql-client`; follow the header of `deploy/legion-backup.service`
   (creates `/var/backups/legion`, installs `/etc/legion/backup.env` from `deploy/backup.env.example`).
   Put the **public** keys in `BACKUP_AGE_RECIPIENTS`, set `DATABASE_ADMIN_URL` (enables the
   restore test on every backup), `BACKUP_UPLOAD_CMD`, and an alert channel.
3. Set `BACKUP_STATUS_FILE` (and `HEALTH_METRICS_TOKEN`) in `server/.env` so `GET /health/backup` works.
4. `sudo systemctl start legion-backup.service` and read `journalctl -u legion-backup`. Expect
   `restore test OK`, `off-server copy OK`. Then `sudo -u legion ops/check-backup.sh --test-alert`
   and confirm the message arrives — an untested alert channel is not an alert.
5. **Do the full restore drill below on a different machine before you trust any of it.**

## Restore — exact procedure

Have ready: the **private key**, the **secrets** (below), access to the off-server storage.
Total hands-on time on a small database: minutes; the drill measures it.

1. **New server.** Install PostgreSQL, Node, nginx, `age`, `postgresql-client`; deploy the same Legion
   release into `/opt/legion` (`npm ci`, `npm run build`).
2. **Secrets first.** Create `server/.env` and put in it, *before* running `npm run setup`
   (which keeps values that already exist): `LEGION_ENCRYPTION_KEYS` (the ORIGINAL keys — all of
   them, same ids), `JWT_SECRET` (original, or a new one: users then sign in again),
   `FRONTEND_URL`, `COOKIE_SECURE`, SMTP settings. Check: `ops/secrets-fingerprint.sh server/.env`
   and compare with the fingerprints you recorded.
3. **Empty database and owner role.** (`npm run setup` can do this for you: it creates the role and database,
   keeps your `LEGION_ENCRYPTION_KEYS`, but writes a **new** `JWT_SECRET` and `DATABASE_URL` — sessions end, nothing
   else. If you use it, skip this step.) By hand:
   `sudo -u postgres createuser --pwprompt legion && sudo -u postgres createdb -O legion legion`
   and set `DATABASE_URL` accordingly.
4. **Fetch and check the backup** from off-server storage: the newest `legion-*.dump.age` **and** its
   `.sha256` into one directory, then `sha256sum -c legion-….dump.age.sha256`. If it fails, take the
   next-newest.
5. **Stop the API** if it is running (`systemctl stop legion`), then restore (needs the private key
   file, present only for this step):
   ```bash
   DATABASE_URL=postgresql://legion:…@127.0.0.1/legion \
   BACKUP_AGE_IDENTITY_FILE=/safe/place/legion-recovery.key \
     ops/restore.sh /path/legion-<UTC>.dump.age --yes
   ```
   It verifies the checksum, decrypts to a private temp dir, restores in ONE transaction (all or
   nothing) and prints `OK — N tables present`. Delete the private key file from the server afterwards.
6. **App role (only if you use a separate one):**
   `DATABASE_ADMIN_URL=… APP_DB_USER=legion_app APP_DB_PASSWORD=… node server/dist/db/provision-cli.js`
   and point `DATABASE_URL` at that role. Restoring gives ownership to the connecting role; this step
   moves it (idempotent).
7. **Redis:** install and start an *empty* Redis (or leave `REDIS_URL` unset). Do not restore Redis.
8. **Start and verify:** `systemctl start legion`, then
   `curl -s https://YOUR-DOMAIN/api/health` → `"database":"up"`; sign in; open the alerts page and
   check the newest alert time; sign in as a 2FA user (proves the encryption keys are right; a wrong
   key gives *"Two-factor sign-in is temporarily unavailable"* and changes nothing — fix the key and retry);
   check that a sensor still delivers (`WAZUH.md`).
9. **Re-arm backups:** re-install the timers, run `legion-backup.service` once, confirm `/health/backup` = 200.
10. **Write down** what happened, the backup used, the time it took.

If the restore reports an error, **nothing was applied**. Try the next-older backup.

## Secrets — what recovery needs and where to keep it

Backups deliberately do **not** contain these. Losing them turns a backup into unreadable data, so
they are stored **separately from the backups**, in at least two places you control.

| Secret | Needed for | If lost |
|---|---|---|
| Backup **private key(s)** (`age`) | decrypting any backup | **Backups are permanently unreadable.** Keep ≥ 2, in different places. |
| `LEGION_ENCRYPTION_KEYS` (all ids) | 2FA seeds, webhook secrets in the database | Those secrets become unreadable: users must re-enrol 2FA, sensors need new credentials. MFA is *refused*, never disabled. |
| `DATABASE_URL` password / admin URL | connecting | Reset in Postgres. |
| `JWT_SECRET` | session signing | Everyone signs in again. |
| `HEALTH_METRICS_TOKEN`, SMTP password, Paddle/AI keys, alert URLs | monitoring, email, billing, AI | Re-issue at each provider. |
| Storage credentials (S3 etc.) | fetching the off-server copy | Re-issue; keep a second admin who has them. |

**How to hold them:** a team password manager (shared vault with two named owners) plus an offline copy
(printed or on an encrypted drive in a safe) for the private key and `LEGION_ENCRYPTION_KEYS`. Never in the
repository, a chat, a ticket, the backup bucket or the backup directory. Do not write the values into this
document: record only **fingerprints** — `ops/secrets-fingerprint.sh server/.env` prints a 12-hex SHA-256
prefix per secret, which identifies a value without revealing it. Store that output with your runbook and
compare after a recovery. Review who has access every quarter; rotate the private key by adding a new public
key to `BACKUP_AGE_RECIPIENTS` (old backups stay readable with the old key — keep it).

## Monitoring and alerts

* **Every run** records `backup-status.json` (times, size, encrypted?, restore-test result, off-server result).
* **Failure alerts:** the backup and verify scripts alert (`ALERT_WEBHOOK_URL` — Slack/Discord/Mattermost
  compatible — and/or `ALERT_EMAIL_TO`, plus syslog) on any failure, with the stage and a scrubbed reason
  (never a connection string or key). `HEALTHCHECK_PING_URL` gets a ping on success and `/fail` on failure.
* **The backup that stopped running:** `deploy/legion-backup-check.timer` runs `ops/check-backup.sh` hourly:
  alerts if the last success is older than `BACKUP_MAX_AGE_HOURS` (30), the last run failed, the last backup
  was unencrypted, no restore test passed within `RESTORE_TEST_MAX_AGE_DAYS` (8), or the off-server copy failed
  (`BACKUP_REQUIRE_OFFSITE=true` also alerts if none exists). A dead-man's-switch monitor covers the case where
  the whole server is down.
* **Uptime monitors:** `GET /health/backup` with `Authorization: Bearer $HEALTH_METRICS_TOKEN` → 200 healthy /
  503 with reasons (never file names or hosts).

## Verifying restores

* **Nightly, automatic (on the server):** with `DATABASE_ADMIN_URL` set, `backup.sh` restores each dump into a
  throwaway database, checks the table list equals the live database's, and drops it. A dump that does not
  restore **fails the backup** and alerts. This needs no private key.
* **Weekly, from a machine that holds the private key:** `ops/verify-backup.sh` decrypts the newest
  off-server copy and restores it. Only this proves the *encrypted* file and your key work together. Run it
  from a recovery host or your workstation (cron on a machine that pulls the newest backup); it writes the
  same status/alerts.
* **Quarterly, full drill:** follow "Restore" on a fresh machine and time it.

## The drill (automated)

`cd server && npx vitest run tests/disaster-recovery.test.ts tests/backup-scripts.test.ts` (needs Postgres,
Redis, `age`). The drill: seeds users (one with 2FA), alerts and a sensor credential → encrypted backup →
destroys the database → restores from the encrypted file into a brand-new database → starts the **real
server** on it → checks sign-in, every alert, the realtime cursor, 2FA → kills Redis, starts an empty one,
checks nothing in Postgres changed and the realtime cursor still works → provisions the app role and runs as
it → boots with a wrong encryption key (2FA refused, data untouched) and a new `JWT_SECRET` (sessions end,
sign-in works). `ops/tests/test-backup-restore.sh` is the same for the scripts alone, without the server.

## Known limits

* RPO is one night unless you add PITR/WAL archiving.
* A compromised server can still delete local backups and the *status file*; off-server copies with object
  lock, and the external dead-man's switch, are what protect against that.
* The restore test on the server needs a `CREATEDB` connection; without `DATABASE_ADMIN_URL` only the
  weekly external verification proves restorability (and `/health/backup` will say no restore was tested).
* Off-server upload is your command (`BACKUP_UPLOAD_CMD`); Legion does not verify what the storage does with it.
* `age` must be installed on the recovery machine, and the private key must exist somewhere other than the server.
