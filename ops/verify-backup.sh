#!/usr/bin/env bash
#
# Prove a backup restores, without touching the live database.
#
#   DATABASE_ADMIN_URL=postgresql://… BACKUP_AGE_IDENTITY_FILE=/path/to/private.key \
#     ./ops/verify-backup.sh [backups/legion-….dump.age]
#
# Decrypts (if encrypted), restores into a throwaway database — never the live
# one — checks the tables came back, then drops it. Records the result in the
# backup status file and alerts on failure, so a backup that stops restoring is
# noticed by monitoring rather than at 3 a.m. during an outage.
#
# The PRIVATE key is needed only here and in a real recovery. Do not leave it on
# the production server: run this from the machine that holds it (a workstation
# or a recovery host that pulls the latest backup), or rely on the per-backup
# restore test in ops/backup.sh (DATABASE_ADMIN_URL) on the server itself.
#
# Environment: DATABASE_ADMIN_URL (CREATEDB; falls back to DATABASE_URL),
# BACKUP_DIR, BACKUP_AGE_IDENTITY_FILE, plus the alert variables of backup.sh.

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ops/lib/common.sh
source ops/lib/common.sh

ADMIN_URL="${DATABASE_ADMIN_URL:-${DATABASE_URL:-}}"
[[ -n "$ADMIN_URL" ]] || { echo "set DATABASE_ADMIN_URL (or DATABASE_URL) to a connection that can create databases" >&2; exit 2; }

REASON=""; OK=0; WORK=""
on_exit() {
  if [[ -n "$WORK" && -d "$WORK" ]]; then rm -rf "${WORK:?}"; fi
  if (( ! OK )); then
    REASON="$(printf '%s' "${REASON:-unexpected error}" | scrub | tr '\n' ' ' | head -c 400)"
    status_set "restore_test_result=failed" "restore_test_failed_at=$(now_iso)" "restore_test_failure=$REASON"
    send_alert "Legion backup restore test FAILED on $(hostname)" "$REASON"
    ping_monitor /fail
  fi
}
trap on_exit EXIT
die() { REASON="$*"; log "VERIFY FAILED: $REASON" >&2; exit 1; }

for c in pg_restore psql; do command -v "$c" >/dev/null 2>&1 || die "$c is not installed (postgresql-client)"; done

DUMP="${1:-}"
if [[ -z "$DUMP" ]]; then
  DUMP="$(find "$BACKUP_DIR" -maxdepth 1 \( -name 'legion-*.dump' -o -name 'legion-*.dump.age' \) 2>/dev/null | sort | tail -1 || true)"
  [[ -n "$DUMP" ]] || die "no backup found in $BACKUP_DIR — pass one explicitly, or run ops/backup.sh first"
  log "verifying the newest backup: $(basename "$DUMP")"
fi
[[ -f "$DUMP" ]] || die "$DUMP not found"

if [[ -f "$DUMP.sha256" ]]; then
  (cd "$(dirname "$DUMP")" && sha256sum -c --quiet "$(basename "$DUMP").sha256") \
    || die "$(basename "$DUMP") does not match its recorded checksum — the file is damaged"
  log "checksum OK"
fi

umask 077
WORK="$(mktemp -d)"
rc=0; materialise_dump "$DUMP" "$WORK/plain.dump" || rc=$?
(( rc == 0 )) || die "$(explain_materialise "$rc")"
pg_restore -l < "$WORK/plain.dump" > /dev/null || die "$(basename "$DUMP") is not a readable pg_restore archive"

log "restoring into a temporary database"
if MSG="$(restore_check "$WORK/plain.dump" "$ADMIN_URL" "")"; then
  log "OK — $(basename "$DUMP") restores cleanly ($MSG)"
else
  die "$MSG"
fi
OK=1
status_set "restore_tested_at=$(now_iso)" "restore_test_result=ok" "restore_test_source=verify-backup" \
  "restore_test_file=$(basename "$DUMP")" "restore_test_failure=null"
ping_monitor ""
