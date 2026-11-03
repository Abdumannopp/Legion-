#!/usr/bin/env bash
#
# After following DEPLOY-ONLINE.md section 12: is Legion really behind
# Cloudflare, and does everything still work through it? Read-only — it
# changes nothing anywhere.
#
#   ops/check-cloudflare-setup.sh --domain legion.example.uz
#       from any computer: DNS, HTTPS through Cloudflare, the dashboard, the
#       Wazuh webhook path (is bot protection blocking the sensor?)
#   ops/check-cloudflare-setup.sh --domain legion.example.uz --server-ip 203.0.113.5
#       also: can the server be reached directly, bypassing Cloudflare? (run it
#       from a computer that is NOT the server)
#   sudo ops/check-cloudflare-setup.sh --domain legion.example.uz --local
#       ON the server: nginx trusts only Cloudflare for the visitor address, the
#       range list is fresh and its timer is on, the firewall, and whether the
#       access log shows real visitor addresses
#
# Prints OK / WARN / FAIL per check, and exits 1 when anything FAILED.
#
# Options for testing and unusual setups:
#   --base-url URL       talk to URL instead of https://DOMAIN (e.g. a staging port)
#   --ranges-dir DIR     Cloudflare ranges from DIR/ips-v4 (default: the nginx
#                        snippet if present, else downloaded from cloudflare.com)
#   --origin-ports "P.." ports that must be closed on --server-ip (default "80 443")
#   --skip-dns           do not check where the domain points

set -uo pipefail

DOMAIN=""
SERVER_IP=""
LOCAL=0
BASE_URL=""
RANGES_DIR=""
ORIGIN_PORTS="80 443"
SKIP_DNS=0
SNIPPET="${CLOUDFLARE_NGINX_SNIPPET:-/etc/nginx/legion-cloudflare.conf}"
ACCESS_LOG="${NGINX_ACCESS_LOG:-/var/log/nginx/access.log}"
FAILS=0
WARNS=0

ok()   { printf '  \033[32mOK\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m  %s\n' "$*"; WARNS=$((WARNS + 1)); }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILS=$((FAILS + 1)); }
info() { printf '        %s\n' "$*"; }
section() { printf '\n%s\n' "$*"; }
die() { echo "check-cloudflare-setup: $*" >&2; exit 2; }

# --- IPv4 range arithmetic (pure bash) ---------------------------------------------------------------------------

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o; for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
ip4_to_int() { local IFS=.; local -a o; read -r -a o <<<"$1"; echo $(( (10#${o[0]} << 24) + (10#${o[1]} << 16) + (10#${o[2]} << 8) + 10#${o[3]} )); }
in_cidr4() { # ip cidr
  local ip="$1" net="${2%/*}" bits="${2#*/}" mask
  is_ipv4 "$ip" && is_ipv4 "$net" && [[ "$bits" =~ ^[0-9]{1,2}$ ]] && (( bits <= 32 )) || return 1
  mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  (( ($(ip4_to_int "$ip") & mask) == ($(ip4_to_int "$net") & mask) ))
}
RANGES=()
in_cloudflare() { local r; for r in "${RANGES[@]}"; do in_cidr4 "$1" "$r" && return 0; done; return 1; }

load_ranges() {
  local src=""
  if [[ -n "$RANGES_DIR" ]]; then
    src="$RANGES_DIR/ips-v4"; [[ -r "$src" ]] || die "$src is not readable"
    mapfile -t RANGES < <(tr -d '\r' < "$src" | grep -E '^[0-9.]+/[0-9]+$')
  elif [[ -r "$SNIPPET" ]]; then
    src="$SNIPPET"
    mapfile -t RANGES < <(sed -n 's/^set_real_ip_from \([0-9.]*\/[0-9]*\);$/\1/p' "$SNIPPET")
  else
    src="https://www.cloudflare.com/ips-v4"
    mapfile -t RANGES < <(curl -fsS -m 20 "$src" 2>/dev/null | tr -d '\r' | grep -E '^[0-9.]+/[0-9]+$')
  fi
  if (( ${#RANGES[@]} < 5 )); then
    warn "could not load Cloudflare's IPv4 ranges from $src — address checks are skipped"
    RANGES=()
  else
    info "Cloudflare IPv4 ranges: ${#RANGES[@]} (from $src)"
  fi
}

# Functions only (ops/tests/test-check-cloudflare.sh): `return` when sourced, `exit` otherwise.
# shellcheck disable=SC2317
if [[ "${CHECK_CLOUDFLARE_LIB_ONLY:-0}" == 1 ]]; then return 0 2>/dev/null || exit 0; fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)       DOMAIN="${2:?--domain needs a name}"; shift 2 ;;
    --server-ip)    SERVER_IP="${2:?--server-ip needs an address}"; shift 2 ;;
    --local)        LOCAL=1; shift ;;
    --base-url)     BASE_URL="${2:?--base-url needs a URL}"; shift 2 ;;
    --ranges-dir)   RANGES_DIR="${2:?--ranges-dir needs a directory}"; shift 2 ;;
    --origin-ports) ORIGIN_PORTS="${2:?--origin-ports needs ports}"; shift 2 ;;
    --skip-dns)     SKIP_DNS=1; shift ;;
    -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
    *)              die "unknown option: $1 (see --help)" ;;
  esac
done
[[ -n "$DOMAIN" ]] || die "--domain is required (see --help)"
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "--domain must be a host name, e.g. legion.example.uz"
command -v curl >/dev/null 2>&1 || die "curl is not installed"
BASE="${BASE_URL:-https://$DOMAIN}"
BASE="${BASE%/}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Legion behind Cloudflare: $DOMAIN"
load_ranges

# --- 1. DNS -------------------------------------------------------------------------------------------------------
section "1. Where the domain points"
if [[ $SKIP_DNS -eq 1 ]]; then
  info "skipped (--skip-dns)"
else
  mapfile -t ADDRS < <(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u)
  if (( ${#ADDRS[@]} == 0 )); then
    fail "$DOMAIN does not resolve (DNS record missing, or not propagated yet)"
  elif (( ${#RANGES[@]} == 0 )); then
    warn "$DOMAIN → ${ADDRS[*]} (cannot tell whether that is Cloudflare)"
  else
    outside=()
    for a in "${ADDRS[@]}"; do in_cloudflare "$a" || outside+=("$a"); done
    if (( ${#outside[@]} == 0 )); then
      ok "$DOMAIN → ${ADDRS[*]} — Cloudflare addresses (record is proxied, orange cloud)"
    else
      fail "$DOMAIN → ${outside[*]} is NOT Cloudflare: the DNS record is not proxied (grey cloud), so visitors reach the server directly"
      [[ -n "$SERVER_IP" ]] && printf '%s\n' "${outside[@]}" | grep -qx "$SERVER_IP" && info "that is your server's own address — anyone can now read it from DNS; after proxying, consider whether it must change"
    fi
  fi
fi

# --- 2. HTTPS through Cloudflare ----------------------------------------------------------------------------------
section "2. The site through Cloudflare"
code=$(curl -sS -m 20 -D "$WORK/h" -o "$WORK/b" -w '%{http_code}' "$BASE/api/health" 2>"$WORK/e") || code=000
if [[ "$code" == 000 ]]; then
  fail "$BASE/api/health: no answer ($(head -c 200 "$WORK/e"))"
  info "a certificate error here usually means Cloudflare SSL mode is not 'Full (strict)' or the server has no valid certificate"
else
  if [[ "$code" == 200 ]] && grep -q '"status"' "$WORK/b"; then ok "$BASE/api/health → 200, Legion answers"
  else fail "$BASE/api/health → HTTP $code (expected 200 from Legion): $(head -c 200 "$WORK/b")"; fi
  if grep -qi '^server: *cloudflare' "$WORK/h" && grep -qi '^cf-ray:' "$WORK/h"; then ok "the answer came through Cloudflare (server: cloudflare, cf-ray)"
  else fail "the answer did not come through Cloudflare (no 'server: cloudflare' / 'cf-ray' header) — is the record proxied?"; fi
fi
dash=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' "$BASE/login" 2>/dev/null) || dash=000
if [[ "$dash" == 200 ]]; then ok "the dashboard sign-in page loads ($BASE/login)"; else fail "$BASE/login → HTTP $dash"; fi
if [[ -z "$BASE_URL" ]]; then
  redir=$(curl -sS -m 20 -o /dev/null -w '%{http_code} %{redirect_url}' "http://$DOMAIN/login" 2>/dev/null) || redir="000"
  if [[ "$redir" =~ ^30[1278]\ https:// ]]; then ok "http:// is redirected to https://"; else warn "http://$DOMAIN/login → $redir (expected a redirect to https; Cloudflare: SSL/TLS → Edge Certificates → Always Use HTTPS)"; fi
fi

# --- 3. The Wazuh webhook through Cloudflare -----------------------------------------------------------------------
section "3. Can the Wazuh sensor still reach Legion?"
# An unsigned request, sent the way integrations/custom-legion.py sends one.
# Legion must answer (and refuse it): a JSON 4xx from Legion is the GOOD outcome.
# A challenge page or block from Cloudflare means real events would be held back.
wcode=$(curl -sS -m 20 -D "$WORK/wh" -o "$WORK/wb" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' -H 'User-Agent: Legion-Wazuh-Integration/2 (+custom-legion.py)' \
  --data '{"provider":"wazuh","event":{}}' "$BASE/api/security-events/webhook" 2>/dev/null) || wcode=000
if grep -qi '^cf-mitigated:' "$WORK/wh" 2>/dev/null || { [[ "$wcode" =~ ^(403|503)$ ]] && ! grep -qi '^content-type: *application/json' "$WORK/wh"; }; then
  fail "Cloudflare blocks the webhook (HTTP $wcode, challenge/block page): Wazuh events would be held in the sensor's spool"
  info "add a WAF custom rule: URI Path equals /api/security-events/webhook → Skip (bot protection, rate limiting) — DEPLOY-ONLINE.md §12.5"
elif [[ "$wcode" =~ ^4[0-9][0-9]$ ]] && grep -qi '^content-type: *application/json' "$WORK/wh"; then
  ok "the webhook reaches Legion through Cloudflare (Legion refused the unsigned test request with $wcode, as it should)"
else
  fail "unexpected answer from the webhook: HTTP $wcode $(head -c 200 "$WORK/wb" 2>/dev/null)"
fi

# --- 4. Origin lockdown ----------------------------------------------------------------------------------------------
section "4. Can the server be reached directly, bypassing Cloudflare?"
if [[ -z "$SERVER_IP" ]]; then
  info "skipped (add --server-ip YOUR-SERVER-IP, and run this from a computer that is not the server)"
else
  for port in $ORIGIN_PORTS; do
    if curl -sS -m 6 -o /dev/null "http://$SERVER_IP:$port/" 2>/dev/null || curl -sSk -m 6 -o /dev/null "https://$SERVER_IP:$port/" 2>/dev/null; then
      fail "$SERVER_IP:$port answers directly — an attacker can skip Cloudflare entirely (DEPLOY-ONLINE.md §12.4: ops/update-cloudflare-ips.sh --ufw --apply, then remove the open rule)"
    else
      ok "$SERVER_IP:$port does not answer directly"
    fi
  done
fi

# --- 5. On the server ------------------------------------------------------------------------------------------------
if [[ $LOCAL -eq 1 ]]; then
  section "5. On this server"
  if [[ -r "$SNIPPET" ]]; then
    age_days=$(( ($(date +%s) - $(stat -c %Y "$SNIPPET")) / 86400 ))
    n=$(grep -c '^set_real_ip_from ' "$SNIPPET")
    if (( age_days <= 14 )); then ok "$SNIPPET: $n Cloudflare ranges, updated $age_days day(s) ago"
    else warn "$SNIPPET is $age_days days old — is the update timer running?"; fi
  else
    fail "$SNIPPET is missing: sudo ops/update-cloudflare-ips.sh --reload"
  fi
  if command -v nginx >/dev/null 2>&1; then
    conf="$(nginx -T 2>/dev/null)"
    if grep -q 'real_ip_header CF-Connecting-IP' <<<"$conf"; then ok "nginx loads it (real_ip_header CF-Connecting-IP is active)"
    else fail "nginx does not load the Cloudflare snippet: uncomment 'include $SNIPPET;' in the Legion site and reload nginx"; fi
    if grep -Eq 'set_real_ip_from +(0\.0\.0\.0/0|::/0)' <<<"$conf"; then fail "nginx trusts EVERY address for the visitor address (set_real_ip_from 0.0.0.0/0 or ::/0): anyone can forge it"; fi
  else
    warn "nginx not found"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled --quiet legion-cloudflare-ips.timer 2>/dev/null && systemctl is-active --quiet legion-cloudflare-ips.timer 2>/dev/null; then ok "the weekly range-update timer is on"
    else warn "legion-cloudflare-ips.timer is not enabled — the range list will go stale (DEPLOY-ONLINE.md §12.2)"; fi
  fi
  if command -v ufw >/dev/null 2>&1; then
    st="$(ufw status 2>/dev/null)"
    if ! grep -q '^Status: active' <<<"$st"; then warn "ufw is not active"
    elif grep -Eq '^(80|443|80,443|80/tcp|443/tcp|Nginx (Full|HTTP|HTTPS))(\s+\(v6\))?\s+ALLOW\s+Anywhere' <<<"$st"; then
      warn "ufw still lets everyone reach the web ports (a rule ALLOW Anywhere for 80/443) — origin is not locked down (§12.4)"
    else ok "ufw does not open the web ports to everyone"; fi
  fi
  if [[ -r "$ACCESS_LOG" ]] && (( ${#RANGES[@]} > 0 )); then
    total=0; viaCf=0
    while read -r a _; do
      is_ipv4 "$a" || continue
      total=$((total + 1)); in_cloudflare "$a" && viaCf=$((viaCf + 1))
    done < <(tail -n 300 "$ACCESS_LOG")
    if (( total == 0 )); then info "no recent IPv4 requests in $ACCESS_LOG to judge"
    elif (( viaCf * 2 > total )); then fail "$viaCf of the last $total requests in $ACCESS_LOG are logged with a Cloudflare address — nginx is not restoring the visitor address, so every visitor shares one rate limit"
    else ok "the access log shows visitor addresses, not Cloudflare's ($viaCf of $total from Cloudflare ranges)"; fi
  fi
fi

printf '\n'
if (( FAILS > 0 )); then echo "Result: $FAILS problem(s), $WARNS warning(s). Fix the FAIL lines above (DEPLOY-ONLINE.md §12)."; exit 1; fi
echo "Result: no problems found ($WARNS warning(s))."
