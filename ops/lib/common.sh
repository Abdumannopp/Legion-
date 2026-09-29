# Shared by the ops/ scripts. Source it; do not run it.
#
# Nothing here ever prints DATABASE_URL, a passphrase or a key: connection
# strings carry passwords, and these messages go to logs, chat and email.

OPS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
STATUS_FILE="${BACKUP_STATUS_FILE:-$BACKUP_DIR/backup-status.json}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Removes anything shaped like a credential from text bound for logs or alerts.
scrub() { sed -E 's#(postgres(ql)?|redis|rediss|https?)://[^[:space:]@/]*@#\1://***@#g; s#AGE-SECRET-KEY-[A-Z0-9]+#[key removed]#g'; }

status_set() { node "$OPS_DIR/lib/status.mjs" "$STATUS_FILE" set "$@" 2>/dev/null || log "warning: could not update $STATUS_FILE"; }

# Tell a human. Best effort and never fatal: an alert channel that is down must
# not turn a good backup into a failed one — but it is logged loudly.
send_alert() {
  local subject="$1" body="${2:-}" text sent=0
  text="$(printf '%s\n%s' "$subject" "$body" | scrub)"
  if [[ -n "${ALERT_WEBHOOK_URL:-}" ]]; then
    local payload
    payload="$(node -e 'const t=process.argv[1];console.log(JSON.stringify({text:t,content:t}))' "$text")"
    if curl -fsS -m 15 -H 'Content-Type: application/json' -d "$payload" "$ALERT_WEBHOOK_URL" >/dev/null 2>&1; then sent=1
    else log "warning: alert webhook delivery failed"; fi
  fi
  if [[ -n "${ALERT_EMAIL_TO:-}" ]]; then
    if command -v mail >/dev/null 2>&1 && printf '%s\n' "$text" | mail -s "$subject" "$ALERT_EMAIL_TO" 2>/dev/null; then sent=1
    elif command -v sendmail >/dev/null 2>&1 && printf 'To: %s\nSubject: %s\n\n%s\n' "$ALERT_EMAIL_TO" "$subject" "$text" | sendmail -t 2>/dev/null; then sent=1
    else log "warning: alert email could not be sent (no working mail/sendmail)"; fi
  fi
  command -v logger >/dev/null 2>&1 && logger -t legion-backup -p user.err -- "$subject" 2>/dev/null || true
  (( sent )) || log "warning: no alert channel delivered (set ALERT_WEBHOOK_URL or ALERT_EMAIL_TO)"
  return 0
}

# Dead-man's switch (healthchecks.io, Uptime Kuma push, …): success pings, and
# silence is itself the alarm when the job never runs at all.
ping_monitor() {
  local suffix="${1:-}"
  [[ -n "${HEALTHCHECK_PING_URL:-}" ]] || return 0
  curl -fsS -m 10 -o /dev/null "${HEALTHCHECK_PING_URL%/}${suffix}" 2>/dev/null || log "warning: monitor ping failed"
  return 0
}

# Postgres URL with a different database name (same host, credentials, options).
with_db() {
  local url="$1" newdb="$2"
  if [[ "$url" =~ ^(postgres(ql)?://[^/]*)(/[^?]*)?(\?.*)?$ ]]; then
    printf '%s/%s%s\n' "${BASH_REMATCH[1]}" "$newdb" "${BASH_REMATCH[4]}"
  else
    return 1
  fi
}

# Decrypts an .age backup into $2 using BACKUP_AGE_IDENTITY_FILE. Plain dumps are copied through.
materialise_dump() {
  local src="$1" dest="$2"
  if [[ "$src" == *.age ]]; then
    command -v age >/dev/null 2>&1 || return 10
    [[ -n "${BACKUP_AGE_IDENTITY_FILE:-}" && -f "$BACKUP_AGE_IDENTITY_FILE" ]] || return 11
    age -d -i "$BACKUP_AGE_IDENTITY_FILE" -o "$dest" "$src" 2>/dev/null || return 12
  else
    cp "$src" "$dest"
  fi
}

explain_materialise() {
  case "$1" in
    10) echo "the 'age' tool is not installed (apt install age)";;
    11) echo "this backup is encrypted: set BACKUP_AGE_IDENTITY_FILE to the PRIVATE key (kept off this server — see RECOVERY.md)";;
    12) echo "could not decrypt: wrong private key, or the file is damaged";;
    *) echo "could not read the backup";;
  esac
}

# Restores $1 (plain pg_dump -Fc) into a brand-new throwaway database, checks
# it has the same tables as the source, prints per-table row counts, and drops
# it. $2 = admin URL (needs CREATEDB), $3 = optional source URL to compare tables against.
restore_check() {
  local dump="$1" admin="$2" source_url="${3:-}" stamp db maint url tables t n=0
  stamp="$(date -u +%Y%m%dt%H%M%S)$RANDOM"
  db="legion_verify_$stamp"
  maint="$(with_db "$admin" postgres)" || { echo "could not parse the database URL"; return 1; }
  url="$(with_db "$admin" "$db")"
  psql "$maint" -v ON_ERROR_STOP=1 -Atqc "CREATE DATABASE \"$db\"" >/dev/null 2>&1 \
    || { echo "could not create a temporary database (does DATABASE_ADMIN_URL have CREATEDB?)"; return 1; }
  local rc=0
  if ! pg_restore -d "$url" --no-owner --no-privileges --exit-on-error < "$dump" >/dev/null 2>"$dump.restore.err"; then
    echo "the dump does not restore cleanly: $(head -c 300 "$dump.restore.err" | scrub | tr '\n' ' ')"; rc=1
  fi
  rm -f "$dump.restore.err"
  if (( rc == 0 )); then
    tables="$(psql "$url" -Atqc "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1")"
    if [[ -z "$tables" ]]; then echo "the restored database has no tables"; rc=1
    elif [[ -n "$source_url" ]]; then
      local src_tables
      src_tables="$(psql "$source_url" -Atqc "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1" 2>/dev/null || true)"
      if [[ -n "$src_tables" && "$src_tables" != "$tables" ]]; then
        echo "the restored tables differ from the live database's: $(diff <(echo "$src_tables") <(echo "$tables") | grep '^[<>]' | head -5 | tr '\n' ' ')"; rc=1
      fi
    fi
  fi
  if (( rc == 0 )); then
    for t in $tables; do n=$((n+1)); done
    rows="$(psql "$url" -Atqc "SELECT COALESCE(sum((xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name), false, true, '')))[1]::text::bigint),0) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")"
  summary="$n tables, $rows rows"
  fi
  psql "$maint" -Atqc "DROP DATABASE IF EXISTS \"$db\"" >/dev/null 2>&1 || true
  (( rc == 0 )) && echo "$summary"
  return $rc
}
