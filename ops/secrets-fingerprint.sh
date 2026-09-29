#!/usr/bin/env bash
#
# Prints NON-SECRET fingerprints of the secrets a recovery needs, so you can
# record them next to the recovery instructions and, after a rebuild, confirm
# the secrets you restored are the right ones — without ever writing the
# secrets themselves into a document, ticket or chat.
#
#   ops/secrets-fingerprint.sh [path/to/server/.env]
#
# A fingerprint is the first 12 hex characters of SHA-256 of the value: enough
# to tell "same" from "different", useless for recovering the value.
# Exit code 1 if a secret Legion cannot recover without is missing.
set -euo pipefail
ENV_FILE="${1:-server/.env}"
[[ -f "$ENV_FILE" ]] || { echo "no such file: $ENV_FILE" >&2; exit 2; }

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/' || true; }
fp() { printf '%s' "$1" | sha256sum | cut -c1-12; }
missing=0

need() {
  local name="$1" why="$2" v; v="$(get "$name")"
  if [[ -z "$v" ]]; then printf '%-28s MISSING   (%s)\n' "$name" "$why"; missing=1
  else printf '%-28s %s   length=%s   (%s)\n' "$name" "$(fp "$v")" "${#v}" "$why"; fi
}
want() {
  local name="$1" why="$2" v; v="$(get "$name")"
  if [[ -z "$v" ]]; then printf '%-28s not set    (%s)\n' "$name" "$why"
  else printf '%-28s %s   length=%s   (%s)\n' "$name" "$(fp "$v")" "${#v}" "$why"; fi
}

echo "Fingerprints (SHA-256, first 12 hex) — safe to record; the values are not."
need JWT_SECRET "lost = every session ends; users sign in again"
want DATABASE_URL "database login (fingerprint of the whole URL)"
want SECURITY_EVENT_WEBHOOK_SECRET "legacy; alert ids"
want WEBHOOK_ENCRYPTION_KEY "legacy key that sealed webhook secrets"
want HEALTH_METRICS_TOKEN "monitoring"

keys="$(get LEGION_ENCRYPTION_KEYS)"
if [[ -z "$keys" ]]; then
  printf '%-28s MISSING   (lost = 2FA seeds and webhook secrets in backups are UNREADABLE)\n' "LEGION_ENCRYPTION_KEYS"; missing=1
else
  IFS=',' read -r -a entries <<< "$keys"
  for e in "${entries[@]}"; do
    id="${e%%:*}"; val="${e#*:}"
    printf '%-28s id=%s   %s   length=%s   (key %s)\n' "LEGION_ENCRYPTION_KEYS" "$id" "$(fp "$val")" "${#val}" "$id"
  done
fi
exit $missing
