#!/usr/bin/env bash
# Tests for ops/check-cloudflare-setup.sh against a local stand-in for "Legion
# behind Cloudflare", whose answers can be switched between a correct setup and
# each misconfiguration the script is meant to catch.
#
#   bash ops/tests/test-check-cloudflare.sh
# The checks are strings evaluated by t(), so single quotes are deliberate.
# shellcheck disable=SC2016
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$HERE/check-cloudflare-setup.sh"
WORK="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
pass=0; failed=0
t() { if eval "$2"; then echo "  ✓ $1"; pass=$((pass + 1)); else echo "  ✗ $1"; failed=$((failed + 1)); fi; }

echo "▶ IPv4 range arithmetic"
# shellcheck source=/dev/null
CHECK_CLOUDFLARE_LIB_ONLY=1 source "$SCRIPT"
t "inside a /13" 'in_cidr4 104.16.0.1 104.16.0.0/13'
t "last address of a /13" 'in_cidr4 104.23.255.255 104.16.0.0/13'
t "just outside a /13" '! in_cidr4 104.24.0.0 104.16.0.0/13'
t "/32 exact" 'in_cidr4 127.0.0.1 127.0.0.1/32 && ! in_cidr4 127.0.0.2 127.0.0.1/32'
t "garbage is never inside" '! in_cidr4 999.1.1.1 0.0.0.0/0 && ! in_cidr4 1.2.3 1.0.0.0/8 && ! in_cidr4 1.2.3.4 1.0.0.0/40'

# Range fixtures: one that contains 127.0.0.0/8 (localhost "is Cloudflare"), one that does not.
mkdir -p "$WORK/cf" "$WORK/notcf"
printf '%s\n' 173.245.48.0/20 103.21.244.0/22 104.16.0.0/13 172.64.0.0/13 131.0.72.0/22 127.0.0.0/8 > "$WORK/cf/ips-v4"
printf '%s\n' 173.245.48.0/20 103.21.244.0/22 104.16.0.0/13 172.64.0.0/13 131.0.72.0/22 > "$WORK/notcf/ips-v4"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
PORT=$(free_port)
CLOSED=$(free_port)
# The stand-in: MODE file decides how it answers.
cat > "$WORK/stub.py" <<'PY'
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
mode_file = sys.argv[2]
class H(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype, extra=None):
        mode = open(mode_file).read().strip()
        self.send_response(code)
        if mode != "direct":
            self.send_header("Server", "cloudflare"); self.send_header("CF-RAY", "8a1b2c3d4e5f-WAW")
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self.send_header("Content-Type", ctype); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path == "/api/health": self.reply(200, b'{"status":"ok","database":"up"}', "application/json")
        else: self.reply(200, b"<html>sign in</html>", "text/html")
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if open(mode_file).read().strip() == "challenge":
            self.reply(403, b"<html>Just a moment...</html>", "text/html", {"cf-mitigated": "challenge"})
        else:
            self.reply(401, b'{"detail":"Invalid webhook signature"}', "application/json; charset=utf-8")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
echo good > "$WORK/mode"
python3 "$WORK/stub.py" "$PORT" "$WORK/mode" & PIDS+=($!)
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/api/health" && break; sleep 0.1; done

run() { bash "$SCRIPT" --domain localhost --base-url "http://127.0.0.1:$PORT" "$@" > "$WORK/out" 2>&1; echo $? > "$WORK/code"; }
code() { cat "$WORK/code"; }
says() { grep -q -- "$1" "$WORK/out"; }

echo "▶ a correct setup"
run --ranges-dir "$WORK/cf" --server-ip 127.0.0.1 --origin-ports "$CLOSED"
t "exits 0" '[[ $(code) == 0 ]]'
t "DNS points at Cloudflare" 'says "Cloudflare addresses"'
t "the answer came through Cloudflare" 'says "came through Cloudflare"'
t "the webhook reaches Legion (refused unsigned, as it should)" 'says "the webhook reaches Legion"'
t "the origin port is closed" "says \"127.0.0.1:$CLOSED does not answer directly\""
[[ $(code) == 0 ]] || cat "$WORK/out"

echo "▶ each misconfiguration is caught"
run --ranges-dir "$WORK/notcf" --server-ip 127.0.0.1 --origin-ports "$CLOSED"
t "grey-cloud DNS (domain points at a non-Cloudflare address) → FAIL" '[[ $(code) == 1 ]] && says "is NOT Cloudflare"'

echo challenge > "$WORK/mode"
run --ranges-dir "$WORK/cf" --skip-dns
t "Cloudflare challenges the webhook → FAIL with the fix" '[[ $(code) == 1 ]] && says "Cloudflare blocks the webhook" && says "Skip"'

echo direct > "$WORK/mode"
run --ranges-dir "$WORK/cf" --skip-dns
t "answers without Cloudflare headers (not proxied) → FAIL" '[[ $(code) == 1 ]] && says "did not come through Cloudflare"'

echo good > "$WORK/mode"
run --ranges-dir "$WORK/cf" --skip-dns --server-ip 127.0.0.1 --origin-ports "$PORT"
t "origin reachable directly → FAIL" "[[ \$(code) == 1 ]] && says \"127.0.0.1:$PORT answers directly\""

bash "$SCRIPT" --domain localhost --base-url "http://127.0.0.1:$CLOSED" --skip-dns --ranges-dir "$WORK/cf" > "$WORK/out" 2>&1; echo $? > "$WORK/code"
t "site down → FAIL" '[[ $(code) == 1 ]] && says "no answer"'

echo "▶ on-server checks (access log)"
printf '%s - - [02/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n' 104.16.1.1 104.16.2.2 172.64.3.3 198.51.100.7 > "$WORK/access-cf.log"
printf '%s - - [02/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n' 198.51.100.7 203.0.113.9 192.0.2.44 104.16.1.1 > "$WORK/access-real.log"
printf 'set_real_ip_from 104.16.0.0/13;\nreal_ip_header CF-Connecting-IP;\n' > "$WORK/snippet.conf"
NGINX_ACCESS_LOG="$WORK/access-cf.log" CLOUDFLARE_NGINX_SNIPPET="$WORK/snippet.conf" run --ranges-dir "$WORK/cf" --skip-dns --local
t "access log full of Cloudflare addresses (real IP not restored) → FAIL" 'says "nginx is not restoring the visitor address"'
NGINX_ACCESS_LOG="$WORK/access-real.log" CLOUDFLARE_NGINX_SNIPPET="$WORK/snippet.conf" run --ranges-dir "$WORK/cf" --skip-dns --local
t "access log with visitor addresses → OK" 'says "the access log shows visitor addresses"'
t "a fresh range snippet is recognised" 'says "1 Cloudflare ranges, updated 0 day"'

echo "▶ argument handling"
bash "$SCRIPT" > "$WORK/out" 2>&1; echo $? > "$WORK/code"
t "no --domain → usage error (2)" '[[ $(code) == 2 ]]'
bash "$SCRIPT" --domain 'bad domain;rm' > "$WORK/out" 2>&1; echo $? > "$WORK/code"
t "a malformed domain is refused (2)" '[[ $(code) == 2 ]]'

echo
echo "$pass passed, $failed failed"
[[ $failed -eq 0 ]]
