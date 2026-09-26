#!/usr/bin/env bash
#
# Tests install.sh's decisions — secret handling, configuration checks,
# pre-upgrade backup ordering, readiness — with a fake `docker` on PATH, so it
# runs anywhere (CI included) without a daemon or the application images.
#
#   bash ops/tests/test-install.sh

set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
FAILS=0

pass() { printf '  \033[0;32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[0;31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS + 1)); }
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

# Fake docker: records every call; behaviour driven by FAKE_* variables.
mkdir -p "$ROOT/bin"
cat > "$ROOT/bin/docker" <<'EOF'
#!/usr/bin/env bash
echo "docker $*" >> "$CALLS"
case "$*" in
  "info") exit 0 ;;
  "compose version") exit 0 ;;
  "volume inspect "*) [[ "${FAKE_VOLUME_EXISTS:-0}" == 1 ]] && exit 0 || exit 1 ;;
  "compose ps -q postgres") [[ "${FAKE_PG_RUNNING:-0}" == 1 ]] && echo pgid; exit 0 ;;
  "compose ps -q backend") echo beid; exit 0 ;;
  "inspect --format {{.State.Running}} pgid") echo true ;;
  "inspect --format "*" beid") echo "${FAKE_HEALTH:-healthy}" ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$ROOT/bin/docker"
cat > "$ROOT/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$ROOT/bin/sleep"

# Each case gets a fresh copy of the installer with a stub backup script.
new_case() {
  CASE="$ROOT/case$RANDOM$RANDOM"
  mkdir -p "$CASE/ops"
  cp "$REPO/install.sh" "$CASE/"
  cat > "$CASE/ops/docker-backup.sh" <<'EOF'
#!/usr/bin/env bash
echo "BACKUP" >> "$CALLS"
exit "${FAKE_BACKUP_RC:-0}"
EOF
  chmod +x "$CASE/ops/docker-backup.sh"
  export CALLS="$CASE/calls.log"
  : > "$CALLS"
}
run() { (cd "$CASE" && PATH="$ROOT/bin:$PATH" ./install.sh) > "$CASE/out.log" 2>&1; }
env_file() {
  cat > "$CASE/.env" <<EOF
JWT_SECRET=existing-jwt
POSTGRES_PASSWORD=existing-pg
$*
EOF
}
called() { grep -q -- "$1" "$CALLS"; }
said() { grep -q -- "$1" "$CASE/out.log"; }
line_of() { grep -n -m1 -- "$1" "$CALLS" | cut -d: -f1; }

echo "▶ fresh install"
new_case
run; RC=$?
check "exits 0" test "$RC" -eq 0
check ".env created with mode 600" test "$(stat -c %a "$CASE/.env")" = 600
check ".env binds to loopback by default" grep -q '^LEGION_BIND_ADDRESS=127.0.0.1$' "$CASE/.env"
check "JWT secret is 64 hex chars" grep -Eq '^JWT_SECRET=[0-9a-f]{64}$' "$CASE/.env"
check "webhook secret generated" grep -Eq '^SECURITY_EVENT_WEBHOOK_SECRET=[0-9a-f]{64}$' "$CASE/.env"
check "no pre-upgrade backup on a fresh install" bash -c "! grep -q BACKUP '$CALLS'"
check "pulls postgres and redis updates" called "compose pull postgres redis"
check "rebuilds with fresh base images" called "compose build --pull"
check "readiness taken from Docker healthcheck" called "inspect --format"

echo "▶ re-run keeps secrets and settings"
new_case
env_file "FRONTEND_URL=https://legion.example.com
NEXT_PUBLIC_API_URL=https://api.legion.example.com
COOKIE_SECURE=true
SMTP_HOST=smtp.example.com"
cp "$CASE/.env" "$CASE/env.before"
run; RC=$?
check "exits 0" test "$RC" -eq 0
check ".env byte-for-byte unchanged" cmp -s "$CASE/.env" "$CASE/env.before"

echo "▶ damaged .env is never rewritten"
new_case
printf 'POSTGRES_PASSWORD=existing-pg\nSMTP_HOST=smtp.example.com\n' > "$CASE/.env"
cp "$CASE/.env" "$CASE/env.before"
run; RC=$?
check "exits non-zero" test "$RC" -ne 0
check ".env unchanged" cmp -s "$CASE/.env" "$CASE/env.before"
check "nothing was built or started" bash -c "! grep -Eq 'compose (build|up)' '$CALLS'"

echo "▶ missing .env with an existing database volume"
new_case
FAKE_VOLUME_EXISTS=1 run; RC=$?
check "exits non-zero" test "$RC" -ne 0
check "no .env was invented" test ! -f "$CASE/.env"
check "explains the volume" said "database volume"

echo "▶ configuration mistakes are caught before building"
new_case
env_file "FRONTEND_URL=https://legion.example.com
NEXT_PUBLIC_API_URL=http://localhost:8000
COOKIE_SECURE=true"
run; RC=$?
check "remote dashboard + localhost API: exits non-zero" test "$RC" -ne 0
check "  explains the localhost API" said "call its OWN localhost"
check "  nothing was built" bash -c "! grep -q 'compose build' '$CALLS'"

new_case
env_file "FRONTEND_URL=https://legion.example.com
NEXT_PUBLIC_API_URL=http://legion.example.com:8000
COOKIE_SECURE=true"
run; RC=$?
check "https dashboard + http API (mixed content): exits non-zero" test "$RC" -ne 0
check "  explains mixed content" said "Browsers block http calls"

new_case
env_file "FRONTEND_URL=https://legion.example.com
NEXT_PUBLIC_API_URL=https://api.legion.example.com
COOKIE_SECURE=false"
run; RC=$?
check "https + COOKIE_SECURE=false: exits non-zero" test "$RC" -ne 0

new_case
env_file "FRONTEND_URL=http://192.168.1.10:3000
NEXT_PUBLIC_API_URL=http://192.168.1.10:8000"
run; RC=$?
check "plain-HTTP LAN address with loopback bind: exits non-zero" test "$RC" -ne 0
check "  tells the operator about LEGION_BIND_ADDRESS" said "LEGION_BIND_ADDRESS=0.0.0.0"

new_case
env_file "FRONTEND_URL=http://192.168.1.10:3000
NEXT_PUBLIC_API_URL=http://192.168.1.10:8000
LEGION_BIND_ADDRESS=0.0.0.0"
run; RC=$?
check "same LAN setup with explicit 0.0.0.0 opt-in: exits 0" test "$RC" -eq 0

echo "▶ upgrade takes a backup first"
new_case
env_file ""
FAKE_PG_RUNNING=1 run; RC=$?
check "exits 0" test "$RC" -eq 0
check "backup ran" called "BACKUP"
check "backup ran before the build" test "$(line_of BACKUP)" -lt "$(line_of 'compose build')"

new_case
env_file ""
FAKE_PG_RUNNING=1 FAKE_BACKUP_RC=1 run; RC=$?
check "failed backup aborts the upgrade" test "$RC" -ne 0
check "  nothing was built or started" bash -c "! grep -Eq 'compose (build|up)' '$CALLS'"

new_case
env_file ""
FAKE_PG_RUNNING=1 FAKE_BACKUP_RC=1 LEGION_SKIP_BACKUP=1 run; RC=$?
check "LEGION_SKIP_BACKUP=1 overrides a failed backup" test "$RC" -eq 0
check "  and warns about it" said "WITHOUT a backup"

echo "▶ readiness"
new_case
FAKE_HEALTH=unhealthy run; RC=$?
check "unhealthy backend reported as failure" test "$RC" -ne 0
check "  points at the logs" said "logs --tail=50 backend"

echo
if (( FAILS )); then echo "✗ $FAILS check(s) failed"; exit 1; fi
echo "✓ all checks passed"
