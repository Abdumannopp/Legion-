#!/usr/bin/env bash
# CI helper: puts PostgreSQL 16 client tools first on PATH.
#
# The CI database containers are PostgreSQL 16. A newer pg_dump (the runner image
# updates its own) writes settings such as `SET transaction_timeout`, which a
# 16 server refuses on restore, so the backup tests would fail for a reason that
# has nothing to do with Legion. Matching the client to the server removes it.
set -euo pipefail
if [ -x /usr/lib/postgresql/16/bin/pg_dump ]; then
  echo "/usr/lib/postgresql/16/bin" >> "${GITHUB_PATH:-/dev/null}"
  exit 0
fi
# Every step below reaches a package server. A mirror that answers badly for a few seconds failed this job once
# (the same commit passed on the next run), so the network commands are tried up to four times, with a pause.
# A command that keeps failing still fails the job: nothing is skipped or ignored.
retry() {
  local n=1
  until "$@"; do
    if [ "$n" -ge 4 ]; then echo "giving up after $n attempts: $*" >&2; return 1; fi
    echo "attempt $n failed: $*; retrying in $((n * 5)) s" >&2
    sleep $((n * 5))
    n=$((n + 1))
  done
}
retry sudo apt-get update
retry sudo apt-get install -y curl ca-certificates gnupg lsb-release
sudo install -d /usr/share/postgresql-common/pgdg
retry sudo curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
retry sudo apt-get update
retry sudo apt-get install -y postgresql-client-16
echo "/usr/lib/postgresql/16/bin" >> "${GITHUB_PATH:-/dev/null}"
