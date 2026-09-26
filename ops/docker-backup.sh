#!/usr/bin/env bash
#
# Back up the Docker installation's database, and prove the backup restores.
#
#   ./ops/docker-backup.sh               dump + restore test + retention
#   ./ops/docker-backup.sh --no-verify   dump + structural check only
#
# Why this exists next to ops/backup.sh: the Docker install does not publish
# Postgres to the host (on purpose), so a DATABASE_URL-based backup from the
# host cannot reach it. This script runs pg_dump/pg_restore inside the postgres
# container, where the matching Postgres version is guaranteed.
#
# A dump that has never been restored is a guess, so by default every backup
# is restored into a throwaway database in the same container and its tables
# are compared with the live ones. Any failure exits non-zero and leaves no
# file that looks like a good backup — cron mail or your monitoring sees it.
#
# Environment: BACKUP_DIR (default ./backups), RETENTION_DAYS (default 14),
# COMPOSE (default "docker compose").

set -euo pipefail

cd "$(dirname "$0")/.."

BACKUP_DIR="${BACKUP_DIR:-./backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
VERIFY=true
[[ "${1:-}" == "--no-verify" ]] && VERIFY=false

if [[ -z "${COMPOSE:-}" ]]; then
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"; else COMPOSE="docker-compose"; fi
fi

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "BACKUP FAILED: $*" >&2; exit 1; }

env_value() {
  [[ -f .env ]] || return 0
  sed -n "s/^$1=//p" .env | head -1
}
PGUSER_="$(env_value POSTGRES_USER)"; PGUSER_="${PGUSER_:-legion}"
PGDB_="$(env_value POSTGRES_DB)";     PGDB_="${PGDB_:-legion}"

pg() { $COMPOSE exec -T postgres "$@"; }

PG_ID="$($COMPOSE ps -q postgres 2>/dev/null || true)"
[[ -n "$PG_ID" && "$(docker inspect --format '{{.State.Running}}' "$PG_ID" 2>/dev/null)" == true ]] \
  || die "the postgres container is not running ($COMPOSE up -d postgres)"

umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$BACKUP_DIR/legion-$STAMP.dump"
PARTIAL="$TARGET.partial"
VERIFY_DB="legion_verify_$(echo "$STAMP" | tr '[:upper:]' '[:lower:]')"

cleanup() {
  rm -f "$PARTIAL"
  if [[ "$VERIFY" == true ]]; then
    pg dropdb -U "$PGUSER_" --if-exists "$VERIFY_DB" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

log "dumping database '$PGDB_'"
pg pg_dump -U "$PGUSER_" -d "$PGDB_" -Fc > "$PARTIAL" || die "pg_dump exited non-zero"
[[ -s "$PARTIAL" ]] || die "pg_dump produced an empty file"

# Structural check: the archive's table of contents must be readable.
pg pg_restore -l < "$PARTIAL" > /dev/null || die "dump is not a readable pg_restore archive"

tables_in() {
  pg psql -U "$PGUSER_" -d "$1" -Atc \
    "SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1"
}

if [[ "$VERIFY" == true ]]; then
  log "restore test into temporary database '$VERIFY_DB'"
  pg createdb -U "$PGUSER_" "$VERIFY_DB" || die "could not create the verification database"
  pg pg_restore -U "$PGUSER_" -d "$VERIFY_DB" --no-owner --exit-on-error < "$PARTIAL" \
    || die "the dump does not restore cleanly"

  LIVE_TABLES="$(tables_in "$PGDB_")"
  RESTORED_TABLES="$(tables_in "$VERIFY_DB")"
  [[ -n "$RESTORED_TABLES" ]] || die "the restored database has no tables"
  [[ "$LIVE_TABLES" == "$RESTORED_TABLES" ]] \
    || die "restored tables differ from the live database (live: ${LIVE_TABLES//$'\n'/ }; restored: ${RESTORED_TABLES//$'\n'/ })"

  for t in $RESTORED_TABLES; do
    log "  restored $t: $(pg psql -U "$PGUSER_" -d "$VERIFY_DB" -Atc "SELECT count(*) FROM \"$t\"") rows"
  done
  pg dropdb -U "$PGUSER_" "$VERIFY_DB" >/dev/null
fi

mv "$PARTIAL" "$TARGET"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$BACKUP_DIR" && sha256sum "$(basename "$TARGET")" > "$(basename "$TARGET").sha256")
fi
log "OK $TARGET ($(du -h "$TARGET" | cut -f1))"

# Retention: only after a good backup exists, and never the one just written.
find "$BACKUP_DIR" -maxdepth 1 -name 'legion-*.dump*' -mtime +"$RETENTION_DAYS" \
  ! -name "$(basename "$TARGET")*" -print -delete | sed 's/^/removed old backup: /' || true

log "copy $TARGET off this server — a backup on the same disk dies with it (see BACKUP.md)"
