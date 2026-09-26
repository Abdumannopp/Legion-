#!/usr/bin/env bash
#
# End-to-end test of the Docker backup/restore path and the installer's
# data-lockout guards, against a real postgres container from
# docker-compose.yml. Needs a working Docker daemon; touches nothing outside
# its own throwaway Compose project.
#
#   bash ops/tests/test-backup-restore.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
PROJECT="legione2e$$"
FAILS=0

pass() { printf '  \033[0;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[0;31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

APP="$WORK/$PROJECT"
mkdir -p "$APP"
cp -r "$REPO/docker-compose.yml" "$REPO/install.sh" "$REPO/ops" "$APP/"
cd "$APP"

cat > .env <<EOF
COMPOSE_PROJECT_NAME=$PROJECT
POSTGRES_PASSWORD=e2e-$(date +%s)
JWT_SECRET=e2e-jwt-secret-that-is-long-enough-000000
EOF
chmod 600 .env

teardown() {
  cd "$APP" 2>/dev/null && docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap teardown EXIT

psql_() { docker compose exec -T postgres psql -U legion -d "${2:-legion}" -v ON_ERROR_STOP=1 -Atc "$1"; }

echo "▶ starting postgres from docker-compose.yml"
docker compose up -d postgres >/dev/null
for _ in $(seq 1 60); do docker compose exec -T postgres pg_isready -U legion >/dev/null 2>&1 && break; sleep 1; done
sleep 2

psql_ "CREATE TABLE tenants (id uuid PRIMARY KEY, name text NOT NULL);
       CREATE TABLE alerts (tenant_id uuid REFERENCES tenants(id), id text,
                            severity text NOT NULL, PRIMARY KEY (tenant_id, id));
       INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001','a'),
                                  ('00000000-0000-0000-0000-000000000002','b');
       INSERT INTO alerts SELECT '00000000-0000-0000-0000-000000000001', 'SEC-'||g, 'high'
         FROM generate_series(1,40) g;" >/dev/null

echo "▶ 1. backup with restore test"
OUT="$(./ops/docker-backup.sh 2>&1)"; RC=$?
check "backup exits 0" test "$RC" -eq 0
DUMP="$(find backups -maxdepth 1 -name 'legion-*.dump' | head -1)"
check "a .dump file was written" test -n "$DUMP"
check "a .sha256 checksum was written" test -f "$DUMP.sha256"
check "restore test counted all 40 alerts" grep -q "restored alerts: 40 rows" <<<"$OUT"
check "no .partial file left behind" bash -c '! ls backups/*.partial 2>/dev/null'
check "backup dir is private (700)" test "$(stat -c %a backups)" = 700
check "dump is private (600)" test "$(stat -c %a "$DUMP")" = 600
check "no verification database left behind" \
  test "$(psql_ "SELECT count(*) FROM pg_database WHERE datname LIKE 'legion_verify_%'" postgres)" = 0

echo "▶ 2. disaster: alerts table destroyed"
psql_ "DROP TABLE alerts" >/dev/null
check "alerts table is gone" bash -c "! docker compose exec -T postgres psql -U legion -d legion -Atc 'SELECT 1 FROM alerts' >/dev/null 2>&1"

echo "▶ 3. restore refuses without --yes"
set +e; ./ops/docker-restore.sh "$DUMP" >/dev/null 2>&1; RC=$?; set -e
check "restore without --yes exits 2" test "$RC" -eq 2

echo "▶ 4. a truncated dump never replaces the live database"
head -c 200 "$DUMP" > backups/broken.dump
set +e; ./ops/docker-restore.sh backups/broken.dump --yes >/dev/null 2>&1; RC=$?; set -e
check "restore of truncated dump fails" test "$RC" -ne 0
check "live database untouched (tenants still 2)" test "$(psql_ 'SELECT count(*) FROM tenants')" = 2
check "failed staging database was cleaned up" \
  test "$(psql_ "SELECT count(*) FROM pg_database WHERE datname LIKE 'legion_restore_%'" postgres)" = 0

echo "▶ 5. a dump that fails its checksum is rejected"
cp "$DUMP" backups/tampered.dump; cp "$DUMP.sha256" backups/tampered.dump.sha256
sed -i "s/$(basename "$DUMP")/tampered.dump/" backups/tampered.dump.sha256
printf 'x' >> backups/tampered.dump
set +e; OUT="$(./ops/docker-restore.sh backups/tampered.dump --yes 2>&1)"; RC=$?; set -e
check "tampered dump rejected" test "$RC" -ne 0
check "rejection names the checksum" grep -q "checksum" <<<"$OUT"

echo "▶ 6. real restore"
set +e; OUT="$(./ops/docker-restore.sh "$DUMP" --yes 2>&1)"; RC=$?; set -e
check "restore exits 0" test "$RC" -eq 0
check "all 40 alerts are back" test "$(psql_ 'SELECT count(*) FROM alerts')" = 40
check "tenants are back" test "$(psql_ 'SELECT count(*) FROM tenants')" = 2
check "previous database kept for rollback" \
  test "$(psql_ "SELECT count(*) FROM pg_database WHERE datname LIKE 'legion_before_restore_%'" postgres)" = 1

echo "▶ 7. backup fails loudly when the database is down"
BEFORE="$(find backups -maxdepth 1 -name 'legion-*.dump' | wc -l)"
docker compose stop postgres >/dev/null 2>&1
set +e; ./ops/docker-backup.sh >/dev/null 2>&1; RC=$?; set -e
check "backup exits non-zero with postgres stopped" test "$RC" -ne 0
check "no new .dump file was created" test "$(find backups -maxdepth 1 -name 'legion-*.dump' | wc -l)" = "$BEFORE"
docker compose start postgres >/dev/null 2>&1

echo "▶ 8. installer refuses to lock itself out of existing data"
mv .env env.saved
set +e; OUT="$(./install.sh 2>&1)"; RC=$?; set -e
check "install.sh with no .env but existing volume exits non-zero" test "$RC" -ne 0
check "it explains the database volume already exists" grep -q "database volume" <<<"$OUT"
check "it did not create a new .env" test ! -f .env
mv env.saved .env

cp .env env.before
sed -i '/^JWT_SECRET=/d' .env
cp .env env.edited
set +e; OUT="$(./install.sh 2>&1)"; RC=$?; set -e
check "install.sh with a damaged .env exits non-zero" test "$RC" -ne 0
check "the damaged .env was not overwritten" cmp -s .env env.edited
mv env.before .env

echo
if (( FAILS )); then echo "✗ $FAILS check(s) failed"; exit 1; fi
echo "✓ all checks passed"
