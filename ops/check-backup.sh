#!/usr/bin/env bash
#
# Backup health check for cron / systemd timer / any monitor. Exits 0 when the
# backups are healthy, 1 (and alerts) when not. Catches the failure the backup
# script cannot report about itself: the backup that silently STOPPED RUNNING.
#
#   ops/check-backup.sh            # human output, exit code
#   ops/check-backup.sh --quiet    # alert only, no output when healthy
#   ops/check-backup.sh --test-alert   # prove the alert channel works (do this once, and after changing it)
#
# Healthy means: last success < BACKUP_MAX_AGE_HOURS (30) ago, the last run did
# not fail, the last backup was encrypted, a restore test passed within
# RESTORE_TEST_MAX_AGE_DAYS (8), and no off-server copy failed
# (BACKUP_REQUIRE_OFFSITE=true also requires that one has succeeded).
# The same rules answer GET /health/backup on the API.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
# shellcheck source=ops/lib/common.sh
source ops/lib/common.sh
if [[ "${1:-}" == "--test-alert" ]]; then
  send_alert "Legion backup alert TEST from $(hostname)" "If you can read this, backup failures will reach you."
  log "test alert sent to the configured channels (check that it arrived)"; exit 0
fi
PROBLEMS="$(node ops/lib/status.mjs "$STATUS_FILE" check)"; RC=$?
if (( RC == 0 )); then
  [[ "${1:-}" == "--quiet" ]] || log "backups healthy ($(node ops/lib/status.mjs "$STATUS_FILE" get last_backup_file))"
  ping_monitor ""
  exit 0
fi
log "BACKUP UNHEALTHY:"; printf '  - %s\n' "$PROBLEMS" >&2
send_alert "Legion backups UNHEALTHY on $(hostname)" "$PROBLEMS"
ping_monitor /fail
exit 1
