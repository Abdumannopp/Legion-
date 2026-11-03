#!/usr/bin/env bash
#
# Makes Legion see the REAL visitor address behind Cloudflare, and (optionally)
# lets only Cloudflare reach the server's web ports.
#
# Why this matters. Behind a CDN, nginx sees the CDN's address for every
# visitor. Every per-address protection — the sign-in limit, the request
# limits, the audit log, the failed-webhook throttle — would then treat all
# visitors as ONE client: one attacker locks everybody out. The real address
# is in the CF-Connecting-IP header, but a header is only believable when it
# comes from Cloudflare itself. This script writes the nginx snippet that says
# exactly that, from Cloudflare's own published ranges (they change; a stale
# list quietly breaks it, so run this from a timer — deploy/legion-cloudflare-ips.timer).
#
#   sudo ops/update-cloudflare-ips.sh --reload       download, validate, write, test, reload nginx
#   ops/update-cloudflare-ips.sh --ufw               print the ufw rules (dry run)
#   sudo ops/update-cloudflare-ips.sh --ufw --apply  apply them
#
# Options:
#   --out FILE       where the nginx snippet goes (default /etc/nginx/legion-cloudflare.conf)
#   --from-dir DIR   read DIR/ips-v4 and DIR/ips-v6 instead of downloading (offline / tests)
#   --reload         after writing: nginx -t, then reload; on failure the previous file is restored
#   --ufw [--apply]  firewall: allow ports 80/443 only from the Cloudflare ranges
#
# The list is checked before anything is written: every line must be a CIDR,
# not absurdly wide (a poisoned list must never make nginx trust the world),
# and there must be a plausible number of them. On any problem the existing
# file is left alone and the script exits non-zero.
#
# Cloudflare's lists: https://www.cloudflare.com/ips/

set -euo pipefail

OUT="${CLOUDFLARE_NGINX_SNIPPET:-/etc/nginx/legion-cloudflare.conf}"
V4_URL="${CLOUDFLARE_IPS_V4_URL:-https://www.cloudflare.com/ips-v4}"
V6_URL="${CLOUDFLARE_IPS_V6_URL:-https://www.cloudflare.com/ips-v6}"
FROM_DIR=""
RELOAD=0
UFW=0
APPLY=0

die() { echo "update-cloudflare-ips: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)      OUT="${2:?--out needs a file}"; shift 2 ;;
    --from-dir) FROM_DIR="${2:?--from-dir needs a directory}"; shift 2 ;;
    --reload)   RELOAD=1; shift ;;
    --ufw)      UFW=1; shift ;;
    --apply)    APPLY=1; shift ;;
    -h|--help)  sed -n '2,32p' "$0"; exit 0 ;;
    *)          die "unknown option: $1 (see --help)" ;;
  esac
done
[[ $APPLY -eq 0 || $UFW -eq 1 ]] || die "--apply only goes with --ufw"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() { # url -> file
  local url="$1" dest="$2"
  command -v curl >/dev/null 2>&1 || die "curl is not installed"
  curl --fail --silent --show-error --location --max-time 30 --retry 2 -o "$dest" "$url" \
    || die "could not download $url — nothing was changed"
}

if [[ -n "$FROM_DIR" ]]; then
  [[ -r "$FROM_DIR/ips-v4" && -r "$FROM_DIR/ips-v6" ]] || die "$FROM_DIR must contain ips-v4 and ips-v6"
  cp "$FROM_DIR/ips-v4" "$WORK/v4"; cp "$FROM_DIR/ips-v6" "$WORK/v6"
  SOURCE="$FROM_DIR"
else
  fetch "$V4_URL" "$WORK/v4"; fetch "$V6_URL" "$WORK/v6"
  SOURCE="$V4_URL and $V6_URL"
fi

# Normalise: strip CR and blank lines.
for f in v4 v6; do tr -d '\r' < "$WORK/$f" | sed '/^[[:space:]]*$/d' > "$WORK/$f.clean"; done

valid_v4() { # a.b.c.d/p with p in 8..32 and octets <= 255
  local cidr="$1" prefix a b c d
  [[ "$cidr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,2})$ ]] || return 1
  a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}; c=${BASH_REMATCH[3]}; d=${BASH_REMATCH[4]}; prefix=${BASH_REMATCH[5]}
  (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 )) || return 1
  (( 10#$prefix >= 8 && 10#$prefix <= 32 ))   # /0../7 would trust a large part of the internet
}
valid_v6() { # hex groups with ':' and a prefix of 16..128
  local cidr="$1" prefix
  [[ "$cidr" =~ ^[0-9a-fA-F:]+/([0-9]{1,3})$ && "$cidr" == *:* ]] || return 1
  prefix=${BASH_REMATCH[1]}
  (( 10#$prefix >= 16 && 10#$prefix <= 128 ))
}

n4=0; n6=0
while IFS= read -r line; do valid_v4 "$line" || die "refusing the list: '$line' is not an acceptable IPv4 range — nothing was changed"; n4=$((n4 + 1)); done < "$WORK/v4.clean"
while IFS= read -r line; do valid_v6 "$line" || die "refusing the list: '$line' is not an acceptable IPv6 range — nothing was changed"; n6=$((n6 + 1)); done < "$WORK/v6.clean"
# Cloudflare publishes about 15 IPv4 and 7 IPv6 ranges. A list far shorter than that is a broken download, not news.
(( n4 >= 5 )) || die "only $n4 IPv4 ranges (expected at least 5) — nothing was changed"
(( n6 >= 3 )) || die "only $n6 IPv6 ranges (expected at least 3) — nothing was changed"

if [[ $UFW -eq 1 ]]; then
  run() { if [[ $APPLY -eq 1 ]]; then echo "+ $*"; "$@"; else echo "$*"; fi; }
  [[ $APPLY -eq 1 ]] && { command -v ufw >/dev/null 2>&1 || die "ufw is not installed"; }
  [[ $APPLY -eq 1 ]] || echo "# dry run — add --apply to run these. SSH and every other rule are left alone."
  while IFS= read -r cidr; do run ufw allow proto tcp from "$cidr" to any port 80,443; done < <(cat "$WORK/v4.clean" "$WORK/v6.clean")
  cat <<'EOF'
#
# The rules above ADD access for Cloudflare. To finish the lockdown, remove the
# rule that lets everyone reach the web ports (check `ufw status numbered` first;
# do it from a session that does not depend on those ports):
#   ufw delete allow 'Nginx Full'      # or whichever rule opens 80/443 to Anywhere
# Then, with the site open in a browser through Cloudflare, confirm that
#   curl -m 5 http://YOUR-SERVER-IP/   fails (times out), while https://YOUR-DOMAIN works.
EOF
  exit 0
fi

# --- the nginx snippet ---------------------------------------------------------------------------------------------
SNIPPET="$WORK/snippet.conf"
{
  echo "# Generated by ops/update-cloudflare-ips.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# from $SOURCE ($n4 IPv4 + $n6 IPv6 ranges). Do not edit by hand: it is rewritten weekly."
  echo "#"
  echo "# nginx believes CF-Connecting-IP ONLY when the TCP peer is one of these ranges;"
  echo "# from anyone else the header is ignored and the peer's own address is used."
  cat "$WORK/v4.clean" "$WORK/v6.clean" | while IFS= read -r cidr; do echo "set_real_ip_from $cidr;"; done
  echo "real_ip_header CF-Connecting-IP;"
} > "$SNIPPET"
chmod 644 "$SNIPPET"

mkdir -p "$(dirname "$OUT")"
BACKUP=""
if [[ -f "$OUT" ]]; then BACKUP="$WORK/previous.conf"; cp -p "$OUT" "$BACKUP"; fi

# Same directory + mv: the file is replaced atomically, never half-written.
STAGED="$(mktemp "$OUT.XXXXXX")"
cp "$SNIPPET" "$STAGED"; chmod 644 "$STAGED"; mv "$STAGED" "$OUT"
echo "wrote $OUT ($n4 IPv4 + $n6 IPv6 ranges)"

if [[ $RELOAD -eq 1 ]]; then
  command -v nginx >/dev/null 2>&1 || die "nginx is not installed"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    echo "nginx reloaded"
  else
    nginx -t || true
    if [[ -n "$BACKUP" ]]; then cp -p "$BACKUP" "$OUT"; echo "nginx -t failed: previous $OUT restored" >&2; else rm -f "$OUT"; echo "nginx -t failed: $OUT removed" >&2; fi
    exit 1
  fi
fi
