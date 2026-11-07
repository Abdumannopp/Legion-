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
sudo apt-get update
sudo apt-get install -y curl ca-certificates gnupg lsb-release
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
sudo apt-get update
sudo apt-get install -y postgresql-client-16
echo "/usr/lib/postgresql/16/bin" >> "${GITHUB_PATH:-/dev/null}"
