#!/usr/bin/env bash
#
# End-to-end test of ops/backup.sh, ops/verify-backup.sh and ops/restore.sh
# against a real Postgres — the same scripts a self-hosted install runs, no
# Docker involved. ops/verify-backup.sh needs a role that can create a
# database (CREATEDB) — a Postgres superuser has it; the plain role
# `npm run setup` creates deliberately does not (see INSTALL.md), so a real
# install would pass DATABASE_ADMIN_URL for just that script. This test uses
# one throwaway role with CREATEDB for everything, which exercises the same
# code paths with less setup.
#
#   DATABASE_URL=postgresql://legion:legion@localhost:5432/legion_backup_test \
#     bash ops/tests/test-backup-restore.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database for this test (its role needs CREATEDB)}"

for tool in age age-keygen pg_dump pg_restore psql; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is not installed (apt install age postgresql-client)" >&2; exit 1; }
done

WORK="$(mktemp -d)"
export BACKUP_DIR="$WORK/backups"
export BACKUP_STATUS_FILE="$WORK/status.json"
# Backups are always encrypted: a throwaway key pair for the test. Only the
# PUBLIC key is given to backup.sh; the private one is used to restore.
age-keygen -o "$WORK/private.key" >/dev/null 2>&1
BACKUP_AGE_RECIPIENTS="$(age-keygen -y "$WORK/private.key")"
export BACKUP_AGE_RECIPIENTS
export BACKUP_AGE_IDENTITY_FILE="$WORK/private.key"
FAILS=0

pass() { printf '  \033[0;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[0;31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

cd "$REPO"
teardown() { rm -rf "$WORK"; }
trap teardown EXIT

psql_() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -Atc "$1"; }

echo "▶ seeding the database"
psql_ "DROP TABLE IF EXISTS alerts, tenants CASCADE;
       CREATE TABLE tenants (id uuid PRIMARY KEY, name text NOT NULL);
       CREATE TABLE alerts (tenant_id uuid REFERENCES tenants(id), id text,
                            severity text NOT NULL, PRIMARY KEY (tenant_id, id));
       INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001','a'),
                                  ('00000000-0000-0000-0000-000000000002','b');
       INSERT INTO alerts SELECT '00000000-0000-0000-0000-000000000001', 'SEC-'||g, 'high'
         FROM generate_series(1,40) g;" >/dev/null

echo "▶ 1. backup (dump + readability check, no restore)"
OUT="$(./ops/backup.sh 2>&1)"; RC=$?
check "backup exits 0" test "$RC" -eq 0
DUMP="$(find "$BACKUP_DIR" -maxdepth 1 -name 'legion-*.dump.age' | head -1)"
check "an encrypted .dump.age file was written" test -n "$DUMP"
check "a .sha256 checksum was written" test -f "$DUMP.sha256"
check "no .partial file left behind" bash -c "! ls '$BACKUP_DIR'/*.partial 2>/dev/null"
check "backup dir is private (700)" test "$(stat -c %a "$BACKUP_DIR")" = 700
check "dump is private (600)" test "$(stat -c %a "$DUMP")" = 600
check "no verification database created (backup.sh does not restore)" \
  test "$(psql_ "SELECT count(*) FROM pg_database WHERE datname LIKE 'legion_verify_%'")" = 0

echo "▶ 2. verify-backup.sh checks the same dump independently"
OUT="$(./ops/verify-backup.sh "$DUMP" 2>&1)"; RC=$?
check "verify exits 0" test "$RC" -eq 0
check "reports the restored tables and rows" grep -q "restores cleanly (2 tables, 42 rows)" <<<"$OUT"
check "no verification database left behind" \
  test "$(psql_ "SELECT count(*) FROM pg_database WHERE datname LIKE 'legion_verify_%'")" = 0
check "live database untouched (tenants still 2)" test "$(psql_ 'SELECT count(*) FROM tenants')" = 2

echo "▶ 3. verify-backup.sh with no argument finds the newest dump"
OUT="$(./ops/verify-backup.sh 2>&1)"; RC=$?
check "verify (no arg) exits 0" test "$RC" -eq 0
check "found and verified the dump" grep -q "restores cleanly" <<<"$OUT"

echo "▶ 4. disaster: alerts table destroyed"
psql_ "DROP TABLE alerts" >/dev/null
check "alerts table is gone" bash -c "! psql \"$DATABASE_URL\" -Atc 'SELECT 1 FROM alerts' >/dev/null 2>&1"

echo "▶ 5. restore refuses without --yes"
set +e; ./ops/restore.sh "$DUMP" >/dev/null 2>&1; RC=$?; set -e
check "restore without --yes exits 2" test "$RC" -eq 2
check "table is still gone (nothing happened)" bash -c "! psql \"$DATABASE_URL\" -Atc 'SELECT 1 FROM alerts' >/dev/null 2>&1"

echo "▶ 6. a truncated dump never touches the live database"
head -c 200 "$DUMP" > "$WORK/broken.dump.age"
set +e; ./ops/restore.sh "$WORK/broken.dump.age" --yes >/dev/null 2>&1; RC=$?; set -e
check "restore of truncated dump fails" test "$RC" -ne 0
check "alerts table is still gone (unchanged, not half-restored)" bash -c "! psql \"$DATABASE_URL\" -Atc 'SELECT 1 FROM alerts' >/dev/null 2>&1"
check "tenants untouched" test "$(psql_ 'SELECT count(*) FROM tenants')" = 2

echo "▶ 7. a dump that fails its checksum is rejected"
cp "$DUMP" "$WORK/tampered.dump.age"; cp "$DUMP.sha256" "$WORK/tampered.dump.age.sha256"
sed -i "s/$(basename "$DUMP")/tampered.dump.age/" "$WORK/tampered.dump.age.sha256"
printf 'x' >> "$WORK/tampered.dump.age"
set +e; OUT="$(./ops/restore.sh "$WORK/tampered.dump.age" --yes 2>&1)"; RC=$?; set -e
check "tampered dump rejected" test "$RC" -ne 0
check "rejection names the checksum" grep -q "checksum" <<<"$OUT"

echo "▶ 8. real restore, in place, inside one transaction"
set +e; OUT="$(./ops/restore.sh "$DUMP" --yes 2>&1)"; RC=$?; set -e
check "restore exits 0" test "$RC" -eq 0
check "all 40 alerts are back" test "$(psql_ 'SELECT count(*) FROM alerts')" = 40
check "tenants are back" test "$(psql_ 'SELECT count(*) FROM tenants')" = 2

echo "▶ 9. backup fails loudly when it cannot reach the database"
BEFORE="$(find "$BACKUP_DIR" -maxdepth 1 -name 'legion-*.dump.age' | wc -l)"
set +e; DATABASE_URL="postgresql://nope:nope@localhost:1/nope" ./ops/backup.sh >/dev/null 2>&1; RC=$?; set -e
check "backup exits non-zero when the database is unreachable" test "$RC" -ne 0
check "no new dump file was created" test "$(find "$BACKUP_DIR" -maxdepth 1 -name 'legion-*.dump.age' | wc -l)" = "$BEFORE"

echo "▶ 10. missing DATABASE_URL fails cleanly, for every script"
for script in backup.sh verify-backup.sh restore.sh; do
  set +e; env -u DATABASE_URL ./ops/"$script" >/dev/null 2>&1; RC=$?; set -e
  check "$script without DATABASE_URL exits non-zero" test "$RC" -ne 0
done

echo
if (( FAILS )); then echo "✗ $FAILS check(s) failed"; exit 1; fi
echo "✓ all checks passed"
