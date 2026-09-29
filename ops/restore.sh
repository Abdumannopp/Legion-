#!/usr/bin/env bash
#
# Restore Legion's database IN PLACE from a backup made by ops/backup.sh.
# DESTRUCTIVE: every table in the target database is dropped and recreated
# from the backup. The full procedure, in order, is RECOVERY.md.
#
#   DATABASE_URL=postgresql://… BACKUP_AGE_IDENTITY_FILE=/safe/private.key \
#     ./ops/restore.sh backups/legion-….dump.age --yes
#
# DATABASE_URL is the TARGET: a brand-new empty database on a replacement
# server works exactly like the old one. Use a connection that may create
# tables (the owner/admin role), then run provisioning again if you use a
# separate app role (RECOVERY.md, step 6).
#
# Runs in a single transaction (pg_restore --single-transaction): if anything
# fails to apply, Postgres rolls the whole thing back. A half-restored database
# that looks healthy is the worst outcome, and this cannot produce one.
# Stop Legion's API first.

set -euo pipefail
cd "$(dirname "$0")/.."
source ops/lib/common.sh

: "${DATABASE_URL:?DATABASE_URL must be set to the database to restore INTO}"

DUMP="${1:-}"
[[ -n "$DUMP" && -f "$DUMP" ]] || { echo "usage: $0 <backup-file> --yes" >&2; exit 2; }
[[ "${2:-}" == "--yes" ]] || {
  echo "This replaces every table in the target database with the contents of $DUMP." >&2
  echo "Stop Legion's API first. Re-run with --yes to proceed." >&2
  exit 2
}

die() { log "RESTORE FAILED: $*" >&2; exit 1; }
command -v pg_restore >/dev/null 2>&1 || die "pg_restore is not installed (the postgresql-client package)"

if [[ -f "$DUMP.sha256" ]]; then
  (cd "$(dirname "$DUMP")" && sha256sum -c --quiet "$(basename "$DUMP").sha256") \
    || die "$DUMP does not match its recorded checksum — the file is damaged. Try an older backup"
  log "checksum OK"
fi

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT
rc=0; materialise_dump "$DUMP" "$WORK/plain.dump" || rc=$?
(( rc == 0 )) || die "$(explain_materialise "$rc")"
pg_restore -l < "$WORK/plain.dump" > /dev/null || die "$DUMP is not a readable pg_restore archive"

log "restoring into the target database inside a single transaction"
if pg_restore -d "$DATABASE_URL" --clean --if-exists --no-owner --no-privileges --single-transaction --exit-on-error < "$WORK/plain.dump" 2> "$WORK/restore.err"; then
  log "restore applied"
else
  die "restore failed; Postgres rolled back the whole transaction — the database is unchanged. $(head -c 300 "$WORK/restore.err" | scrub | tr '\n' ' ')"
fi

TABLES="$(psql "$DATABASE_URL" -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")"
[[ "$TABLES" -gt 0 ]] || die "the database has no tables after restore — restore from an earlier backup immediately"
log "OK — $TABLES tables present. Next: provisioning (if you use a separate app role), then start Legion (RECOVERY.md)."
