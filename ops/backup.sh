#!/usr/bin/env bash
#
# Back up Legion's database: dump → prove it restores → encrypt → copy off the
# server → prune. Any failure exits non-zero, leaves no file that looks like a
# good backup, records the failure in the status file and sends an alert.
#
#   DATABASE_URL=postgresql://... BACKUP_AGE_RECIPIENTS=age1... ./ops/backup.sh
#
# ENCRYPTION. Backups are encrypted with `age` to PUBLIC keys. The server holds
# only the public key, so a stolen server or a stolen backup cannot decrypt
# anything; the private key lives elsewhere (RECOVERY.md). Nothing unencrypted
# is ever written to BACKUP_DIR or sent off the server.
#
# Environment
#   DATABASE_URL            required — the same value the server uses
#   BACKUP_AGE_RECIPIENTS   comma-separated age public keys (age1…)        } one of
#   BACKUP_AGE_RECIPIENTS_FILE  file with one public key per line          } these
#   BACKUP_ALLOW_UNENCRYPTED=true   local experiments only; disables upload, marks status unhealthy
#   DATABASE_ADMIN_URL      superuser/CREATEDB connection: enables the automatic restore test
#   BACKUP_RESTORE_TEST     auto (default: run when DATABASE_ADMIN_URL is set) | required | off
#   BACKUP_UPLOAD_CMD       shell command run with $BACKUP_FILE and $BACKUP_CHECKSUM_FILE set (see RECOVERY.md)
#   BACKUP_DIR (./backups)  BACKUP_STATUS_FILE  BACKUP_KEEP_DAILY/WEEKLY/MONTHLY (14/8/12)
#   ALERT_WEBHOOK_URL / ALERT_EMAIL_TO / HEALTHCHECK_PING_URL — where failures are reported

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=ops/lib/common.sh
source ops/lib/common.sh

STAGE="startup"
SUCCESS=0
REASON=""
WORK=""

fail() { REASON="$*"; log "BACKUP FAILED [$STAGE]: $REASON" >&2; exit 1; }

on_exit() {
  local rc=$?
  if [[ -n "$WORK" && -d "$WORK" ]]; then rm -rf "${WORK:?}"; fi
  if (( ! SUCCESS )); then
    [[ -n "$REASON" ]] || REASON="unexpected error (exit $rc)"
    REASON="$(printf '%s' "$REASON" | scrub | tr '\n' ' ' | head -c 400)"
    status_set "last_attempt_at=$(now_iso)" "last_failure_at=$(now_iso)" "last_failure_stage=$STAGE" "last_failure_reason=$REASON"
    send_alert "Legion backup FAILED on $(hostname)" "Stage: $STAGE. Reason: $REASON"
    ping_monitor /fail
  fi
}
trap on_exit EXIT

: "${DATABASE_URL:?DATABASE_URL must be set to the same value the Legion server uses}"
RETENTION_DAYS_LEGACY="${RETENTION_DAYS:-}"

STAGE="preflight"
for c in pg_dump pg_restore psql node sha256sum; do
  command -v "$c" >/dev/null 2>&1 || fail "$c is not installed"
done

umask 077
mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"

# --- encryption settings ------------------------------------------------------
RECIPIENTS=()
if [[ -n "${BACKUP_AGE_RECIPIENTS:-}" ]]; then
  IFS=',' read -r -a RECIPIENTS <<< "$BACKUP_AGE_RECIPIENTS"
fi
if [[ -n "${BACKUP_AGE_RECIPIENTS_FILE:-}" ]]; then
  [[ -f "$BACKUP_AGE_RECIPIENTS_FILE" ]] || fail "BACKUP_AGE_RECIPIENTS_FILE does not exist"
  while IFS= read -r line; do
    line="${line%%#*}"; line="${line//[[:space:]]/}"; [[ -n "$line" ]] && RECIPIENTS+=("$line")
  done < "$BACKUP_AGE_RECIPIENTS_FILE"
fi
ENCRYPT=1
if (( ${#RECIPIENTS[@]} == 0 )); then
  [[ "${BACKUP_ALLOW_UNENCRYPTED:-}" == "true" ]] || fail "no encryption key configured: set BACKUP_AGE_RECIPIENTS (a PUBLIC age key, 'age1…') — see RECOVERY.md. Refusing to write an unencrypted backup"
  ENCRYPT=0
fi
if (( ENCRYPT )); then
  command -v age >/dev/null 2>&1 || fail "age is not installed (apt install age)"
  for r in "${RECIPIENTS[@]}"; do
    [[ "$r" != AGE-SECRET-KEY-* ]] || fail "a PRIVATE age key was given as a recipient. Only public keys (age1…) belong on this server; the private key must be kept elsewhere"
    [[ "$r" =~ ^age1[a-z0-9]{50,}$ ]] || fail "a backup recipient is not a valid age public key"
  done
fi

# The keys must never sit next to the backups: if a private key turns up in the
# backup directory, the encryption is decoration.
if grep -rIl --exclude='*.age' --exclude='*.dump' --exclude='*.sha256' -e 'AGE-SECRET-KEY-' "$BACKUP_DIR" >/dev/null 2>&1; then
  fail "a private age key was found inside BACKUP_DIR — move it off this server; backups and their keys must never be stored together"
fi

# --- dump ---------------------------------------------------------------------
STAGE="dump"
WORK="$(mktemp -d "$BACKUP_DIR/.work.XXXXXX")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PLAIN="$WORK/plain.dump"
log "dumping database"
pg_dump "$DATABASE_URL" -Fc > "$PLAIN" 2> "$WORK/dump.err" || fail "pg_dump failed: $(head -c 300 "$WORK/dump.err")"
[[ -s "$PLAIN" ]] || fail "pg_dump produced an empty file"
pg_restore -l < "$PLAIN" > /dev/null || fail "the dump is not a readable pg_restore archive"

# --- restore test (real restore into a throwaway database) ----------------------
STAGE="restore-test"
MODE="${BACKUP_RESTORE_TEST:-auto}"
RT_RESULT="skipped"
if [[ "$MODE" != "off" && -n "${DATABASE_ADMIN_URL:-}" ]]; then
  log "restore test: restoring the dump into a throwaway database"
  if MSG="$(restore_check "$PLAIN" "$DATABASE_ADMIN_URL" "$DATABASE_URL")"; then
    RT_RESULT="ok"
    log "restore test OK — $MSG"
  else
    status_set "restore_test_result=failed"
    fail "the dump does NOT restore: $MSG"
  fi
elif [[ "$MODE" == "required" ]]; then
  fail "BACKUP_RESTORE_TEST=required but DATABASE_ADMIN_URL is not set"
else
  log "restore test skipped (set DATABASE_ADMIN_URL to test every backup; ops/verify-backup.sh does it separately)"
fi

# --- encrypt --------------------------------------------------------------------
STAGE="encrypt"
if (( ENCRYPT )); then
  TARGET="$BACKUP_DIR/legion-$STAMP.dump.age"
  args=(); for r in "${RECIPIENTS[@]}"; do args+=(-r "$r"); done
  age "${args[@]}" -o "$WORK/out.age" "$PLAIN" || fail "encryption failed"
  [[ "$(head -c 21 "$WORK/out.age")" == "age-encryption.org/v1" ]] || fail "encrypted output does not look like an age file"
  FINAL="$WORK/out.age"
else
  TARGET="$BACKUP_DIR/legion-$STAMP.dump"
  FINAL="$PLAIN"
  log "WARNING: writing an UNENCRYPTED backup (BACKUP_ALLOW_UNENCRYPTED=true). It will not be uploaded."
fi
BYTES="$(stat -c %s "$FINAL")"
mv "$FINAL" "$TARGET"
(cd "$BACKUP_DIR" && sha256sum "$(basename "$TARGET")" > "$(basename "$TARGET").sha256")
chmod 600 "$TARGET" "$TARGET.sha256"
rm -rf "${WORK:?}"; WORK=""
log "OK $TARGET ($(du -h "$TARGET" | cut -f1))"

status_set "last_attempt_at=$(now_iso)" "last_success_at=$(now_iso)" "last_backup_file=$(basename "$TARGET")" \
  "last_backup_bytes=n:$BYTES" "encrypted=$([[ $ENCRYPT == 1 ]] && echo true || echo false)" \
  "last_failure_reason=null" "last_failure_stage=null"
if [[ "$RT_RESULT" == "ok" ]]; then
  status_set "restore_tested_at=$(now_iso)" "restore_test_result=ok" "restore_test_source=backup-run"
fi

# --- off-server copy --------------------------------------------------------------
STAGE="upload"
if [[ -n "${BACKUP_UPLOAD_CMD:-}" ]]; then
  if (( ! ENCRYPT )); then
    log "not uploading: the backup is unencrypted"
  else
    log "copying off this server"
    if BACKUP_FILE="$TARGET" BACKUP_CHECKSUM_FILE="$TARGET.sha256" bash -c "$BACKUP_UPLOAD_CMD" > "$BACKUP_DIR/.upload.log" 2>&1; then
      status_set "offsite_uploaded_at=$(now_iso)" "offsite_result=ok"
      log "off-server copy OK"
    else
      status_set "offsite_result=failed"
      # The local backup is good and kept; but a backup that never leaves the server is not a backup.
      fail "the off-server copy failed (BACKUP_UPLOAD_CMD): $(tail -c 300 "$BACKUP_DIR/.upload.log" | scrub)"
    fi
  fi
else
  log "warning: BACKUP_UPLOAD_CMD is not set — this backup exists only on this server (RECOVERY.md)"
fi

# --- retention (only after a good backup exists) -----------------------------------
STAGE="retention"
"$(dirname "$0")/prune-backups.sh" "$BACKUP_DIR" | sed 's/^/retention: /' || log "warning: pruning failed (backups are kept)"
[[ -z "$RETENTION_DAYS_LEGACY" ]] || log "note: RETENTION_DAYS is ignored; use BACKUP_KEEP_DAILY/WEEKLY/MONTHLY"

SUCCESS=1
ping_monitor ""
