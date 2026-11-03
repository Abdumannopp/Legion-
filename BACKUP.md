# Legion — Backup and disaster recovery

> **Update:** backups are now **encrypted** (age, with a public key), copied off
> the server, test-restored every time, and monitored with alerts.
> The full, current guide is **[RECOVERY.md](RECOVERY.md)**. The text below describes
> the older (unencrypted) procedure; where it disagrees with `RECOVERY.md`, `RECOVERY.md` is right.

> A backup that has never been restored is not a backup, it is a guess.

## What is protected

Since 2.0, PostgreSQL is the **single** source of truth. It holds all of the
customer's security telemetry, accounts and the audit log. There is no copy
anywhere else. Losing the database means losing the customer.

## Targets (RPO / RTO)

| Measure | Target | Notes |
|---|---|---|
| **RPO** (how much data can be lost) | ≤ 24 hours | With a daily dump. With PITR — minutes |
| **RTO** (how fast it can be restored) | ≤ 1 hour | With the `-Fc` format and `pg_restore -j` |

**Measure** these before promising them to a customer — write down how long each drill takes.

## Recommended: managed PostgreSQL

The most reliable option is a managed PostgreSQL with automatic backups (RDS,
Neon, Supabase, Cloud SQL). They offer point-in-time recovery, so RPO drops to
minutes.

Switch on:

- Automatic daily backups, kept for at least 14 days
- Point-in-time recovery (PITR)
- Copying backups **to another region**
- Deletion protection

**Important:** the provider taking backups does not mean you can restore them.
Do the drill below anyway.

## Scripts

```bash
DATABASE_URL=... ./ops/backup.sh                  # take a dump + check it is readable + prune old ones
DATABASE_URL=... ./ops/verify-backup.sh           # restore into a temporary database and check the data
DATABASE_URL=... ./ops/restore.sh <dump> --yes    # restore OVER the existing database (destructive)
```

- `backup.sh` checks the dump can be read, but does not restore it — it is the
  fast, daily job.
- `verify-backup.sh` **really restores** the dump into a temporary database and
  prints the row count of every table — run it once a month, because a backup
  that was never restored is only a guess. It needs a connection that can create
  databases (`CREATEDB`); the role `npm run setup` creates deliberately cannot
  (see below), so give this script alone a `DATABASE_ADMIN_URL` (a superuser connection).
- `restore.sh` **changes** the live database: it runs in a single transaction
  (`--single-transaction`) — on any error **nothing** is applied and the
  database stays as it was. Every dump has a `.sha256` file beside it;
  `restore.sh` checks it and refuses a dump that does not match.

Variables: `DATABASE_URL` (required — exactly the value your server uses),
`DATABASE_ADMIN_URL` (optional, only for `verify-backup.sh`), `BACKUP_DIR`
(default `./backups`), `RETENTION_DAYS` (default 14).

Test: `DATABASE_URL=... bash ops/tests/test-backup-restore.sh` — on a real
PostgreSQL: backup → drop a table → restore, refusing broken and modified
dumps, and a backup error when the database is down.

### Daily backup (cron)

```cron
0 3 * * * cd /opt/legion && DATABASE_URL=... BACKUP_DIR=/var/backups/legion ./ops/backup.sh >> /var/log/legion-backup.log 2>&1
```

### Monthly verification (required)

```cron
0 4 1 * * cd /opt/legion && DATABASE_URL=... BACKUP_DIR=/var/backups/legion ./ops/verify-backup.sh >> /var/log/legion-verify.log 2>&1
```

`verify-backup.sh` does **not touch** the running database — it creates a
temporary database, restores, checks and drops it.

## Copy backups off the server

A backup on the server is lost with the server. After `backup.sh`:

```bash
aws s3 cp "$TARGET" "s3://legion-backups/$(date -u +%Y/%m)/" --storage-class STANDARD_IA
```

Turn on **versioning** and **object lock** in S3 — ransomware tries to delete backups too.

## Restoring after a disaster

```bash
# 1. Stop writes — nothing new should arrive during the restore
sudo systemctl stop legion        # or stop the API process another way

# 2. Find the newest backup and VERIFY it (before restoring!)
DATABASE_ADMIN_URL=... ./ops/verify-backup.sh /var/backups/legion/legion-20260820T030000Z.dump

# 3. Restore
DATABASE_URL=... ./ops/restore.sh /var/backups/legion/legion-20260820T030000Z.dump --yes

# 4. Bring the API back
sudo systemctl start legion

# 5. Check
curl -s https://api.legion.example/health
```

`restore.sh` runs with `--single-transaction`: on any error **nothing** is
applied and the database stays as it was. A half-restored database is the worst
case, because it looks as if it works.

## Drill result

This procedure was tested (2026-08-21):

| Step | Result |
|---|---|
| 40 alerts + 2 tenants + 2 users created | ✅ |
| `backup.sh` — dump taken and confirmed readable | ✅ 20K |
| `DROP SCHEMA public CASCADE` — **everything destroyed** | ✅ |
| `restore.sh` — restored from the backup | ✅ 43 alerts, 2 tenants, 2 users |
| Sign-in + reading alerts (without restarting the server) | ✅ worked |
| `verify-backup.sh` detected a schema mismatch | ✅ caught a missing table |

The last row matters: the script does not just say "restored"; it checks that
the expected tables and data exist and **returns an error** on a mismatch.

## Not covered here

- **PITR** — with a daily dump, RPO is 24 hours. Enable it on a managed PostgreSQL.
- Encryption and automatic off-site copies are covered in [RECOVERY.md](RECOVERY.md).
