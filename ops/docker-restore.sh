#!/usr/bin/env bash
#
# Restore the Docker installation's database from a dump made by
# ops/docker-backup.sh.
#
#   ./ops/docker-restore.sh backups/legion-20260925T030000Z.dump --yes
#
# The live database is never modified in place. The dump is restored into a
# NEW database; only if that restore succeeds is it swapped in by renaming,
# and the previous database is kept (renamed legion_before_restore_<time>) so
# a bad restore can be undone with two renames. A half-restored database that
# looks healthy is the worst outcome, and this procedure cannot produce one.

set -euo pipefail

cd "$(dirname "$0")/.."

DUMP="${1:-}"
[[ -n "$DUMP" && -f "$DUMP" ]] || { echo "usage: $0 <dump-file> --yes" >&2; exit 2; }
[[ "${2:-}" == "--yes" ]] || {
  echo "This replaces the live Legion database with $DUMP." >&2
  echo "Legion's API is stopped during the swap. Re-run with --yes to proceed." >&2
  exit 2
}

if [[ -z "${COMPOSE:-}" ]]; then
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"; else COMPOSE="docker-compose"; fi
fi

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "RESTORE FAILED: $*" >&2; exit 1; }

env_value() {
  [[ -f .env ]] || return 0
  sed -n "s/^$1=//p" .env | head -1
}
PGUSER_="$(env_value POSTGRES_USER)"; PGUSER_="${PGUSER_:-legion}"
PGDB_="$(env_value POSTGRES_DB)";     PGDB_="${PGDB_:-legion}"
pg() { $COMPOSE exec -T postgres "$@"; }
sql() { pg psql -U "$PGUSER_" -d postgres -v ON_ERROR_STOP=1 -Atc "$1"; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ | tr '[:upper:]' '[:lower:]')"
STAGING="legion_restore_$STAMP"
PREVIOUS="${PGDB_}_before_restore_$STAMP"

if [[ -f "$DUMP.sha256" ]] && command -v sha256sum >/dev/null 2>&1; then
  (cd "$(dirname "$DUMP")" && sha256sum -c --quiet "$(basename "$DUMP").sha256") \
    || die "$DUMP does not match its recorded checksum — the file is damaged"
  log "checksum OK"
fi

$COMPOSE up -d postgres >/dev/null
for _ in $(seq 1 30); do pg pg_isready -U "$PGUSER_" >/dev/null 2>&1 && break; sleep 1; done
pg pg_isready -U "$PGUSER_" >/dev/null 2>&1 || die "postgres did not become ready"

log "restoring $DUMP into staging database $STAGING (live data untouched)"
sql "CREATE DATABASE \"$STAGING\"" >/dev/null
if ! pg pg_restore -U "$PGUSER_" -d "$STAGING" --no-owner --exit-on-error < "$DUMP"; then
  sql "DROP DATABASE IF EXISTS \"$STAGING\"" >/dev/null || true
  die "the dump did not restore cleanly; the live database was not changed"
fi
TABLES="$(pg psql -U "$PGUSER_" -d "$STAGING" -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")"
if [[ "$TABLES" -lt 1 ]]; then
  sql "DROP DATABASE IF EXISTS \"$STAGING\"" >/dev/null || true
  die "the restored database has no tables; the live database was not changed"
fi
log "staging restore OK ($TABLES tables)"

log "stopping the API for the swap"
$COMPOSE stop backend >/dev/null 2>&1 || true

sql "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
      WHERE datname = '$PGDB_' AND pid <> pg_backend_pid()" >/dev/null
sql "ALTER DATABASE \"$PGDB_\" RENAME TO \"$PREVIOUS\"" >/dev/null \
  || die "could not set the live database aside; nothing was changed (start the API: $COMPOSE start backend)"
if ! sql "ALTER DATABASE \"$STAGING\" RENAME TO \"$PGDB_\"" >/dev/null; then
  sql "ALTER DATABASE \"$PREVIOUS\" RENAME TO \"$PGDB_\"" >/dev/null || true
  die "swap failed; the previous database was put back"
fi
log "swapped in; previous database kept as $PREVIOUS"

if [[ -n "$($COMPOSE ps -a -q backend 2>/dev/null || true)" ]]; then
  $COMPOSE start backend >/dev/null || die "restored, but the API did not start: $COMPOSE logs --tail=50 backend"
  log "API started. Check it:  $COMPOSE ps   and log in."
else
  log "no API container exists yet; start Legion with ./install.sh"
fi
log "Once you are satisfied, reclaim the space:"
log "  $COMPOSE exec postgres dropdb -U $PGUSER_ $PREVIOUS"
log "To undo this restore instead:"
log "  $COMPOSE stop backend"
log "  $COMPOSE exec postgres psql -U $PGUSER_ -d postgres -c 'ALTER DATABASE \"$PGDB_\" RENAME TO \"${PGDB_}_bad\"' -c 'ALTER DATABASE \"$PREVIOUS\" RENAME TO \"$PGDB_\"'"
log "  $COMPOSE start backend"
