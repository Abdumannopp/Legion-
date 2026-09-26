#!/usr/bin/env bash
#
# Guards the Compose files against regressions that are invisible until
# production: a port published to every interface, an unauthenticated
# monitoring port, unbounded logs.
#
#   bash ops/tests/test-compose.sh

set -euo pipefail
cd "$(dirname "$0")/../.."

export POSTGRES_PASSWORD=test JWT_SECRET=test
FILES=(-f docker-compose.yml -f docker-compose.monitoring.yml -f docker-compose.prod.yml)

docker compose "${FILES[@]}" config --format json | python3 -c '
import json, sys
cfg = json.load(sys.stdin)["services"]
fails = []
for name, svc in cfg.items():
    for p in svc.get("ports", []):
        if p.get("host_ip") != "127.0.0.1":
            where = p.get("host_ip") or "every interface"
            fails.append(name + ": port " + str(p.get("published")) + " is published on " + where)
for name in ("postgres", "redis"):
    if cfg[name].get("ports"):
        fails.append(f"{name}: must not publish any port")
for name in ("postgres", "redis", "backend", "frontend"):
    opts = (cfg[name].get("logging") or {}).get("options") or {}
    if "max-size" not in opts:
        fails.append(f"{name}: logs are not rotated")
if cfg["frontend"]["depends_on"]["backend"]["condition"] != "service_healthy":
    fails.append("frontend: should wait for a healthy backend")
for f in fails:
    print("FAIL", f)
if fails:
    sys.exit(1)
print("✓ compose: loopback-only ports, no database/redis ports, rotated logs")
'

# An operator who opts in to 0.0.0.0 must get exactly that.
LEGION_BIND_ADDRESS=0.0.0.0 docker compose config --format json | python3 -c '
import json, sys
ips = {p.get("host_ip") for s in json.load(sys.stdin)["services"].values() for p in s.get("ports", [])}
assert ips == {"0.0.0.0"}, ips
print("✓ compose: LEGION_BIND_ADDRESS opt-in is honoured")
'
