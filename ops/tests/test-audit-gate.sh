#!/usr/bin/env bash
# The checks are strings evaluated by t(), so single quotes are deliberate.
# shellcheck disable=SC2016
# Tests for .github/scripts/audit-gate.mjs: it must fail on an advisory nobody
# accepted, pass on one that is accepted and unexpired, and fail again when the
# acceptance expires.
#
#   bash ops/tests/test-audit-gate.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$HERE/.github/scripts/audit-gate.mjs"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pass=0; failed=0
t() { if eval "$2"; then echo "  ✓ $1"; pass=$((pass + 1)); else echo "  ✗ $1"; failed=$((failed + 1)); fi; }

adv() { # name severity ghsa
  printf '{"source":1,"name":"%s","title":"bad thing in %s","url":"https://github.com/advisories/%s","severity":"%s","range":"*"}' "$1" "$1" "$3" "$2"
}
cat > "$WORK/exceptions.json" <<JSON
{ "exceptions": [ { "advisory": "GHSA-aaaa-aaaa-aaaa", "package": "braces", "reason": "build time only", "expires": "2027-01-31" } ] }
JSON
# braces (accepted) and a dependent that only names it as a string
cat > "$WORK/accepted.json" <<JSON
{ "vulnerabilities": {
  "braces": { "severity": "high", "via": [ $(adv braces high GHSA-aaaa-aaaa-aaaa) ] },
  "micromatch": { "severity": "high", "via": [ "braces" ] } } }
JSON
cat > "$WORK/new-critical.json" <<JSON
{ "vulnerabilities": {
  "braces": { "severity": "high", "via": [ $(adv braces high GHSA-aaaa-aaaa-aaaa) ] },
  "proxy-addr": { "severity": "critical", "via": [ $(adv proxy-addr critical GHSA-bbbb-bbbb-bbbb) ] } } }
JSON
cat > "$WORK/moderate-only.json" <<JSON
{ "vulnerabilities": { "postcss": { "severity": "moderate", "via": [ $(adv postcss moderate GHSA-cccc-cccc-cccc) ] } } }
JSON
echo '{ "vulnerabilities": {} }' > "$WORK/clean.json"
echo '{ "error": { "summary": "registry unreachable" } }' > "$WORK/error.json"

run() { node "$GATE" --exceptions "$WORK/exceptions.json" "$@" > "$WORK/out" 2>&1; echo $? > "$WORK/code"; }
code() { cat "$WORK/code"; }
says() { grep -q -- "$1" "$WORK/out"; }

run --input "$WORK/accepted.json" --today 2026-10-06
t "an accepted, unexpired advisory passes; a string-only dependent is not counted separately" '[[ $(code) == 0 ]] && says "1 high/critical advisory, 0 not accepted"'
run --input "$WORK/new-critical.json" --today 2026-10-06
t "a new critical advisory fails the gate and names the package" '[[ $(code) == 1 ]] && says "proxy-addr" && says "CRITICAL"'
run --input "$WORK/accepted.json" --today 2027-02-01
t "an expired acceptance fails again" '[[ $(code) == 1 ]] && says "EXPIRED on 2027-01-31"'
run --input "$WORK/moderate-only.json" --today 2026-10-06
t "moderate advisories do not fail it" '[[ $(code) == 0 ]]'
t "a stale exception (advisory gone) is reported, not silent" 'says "no longer matches any advisory"'
run --input "$WORK/clean.json" --today 2026-10-06
t "a clean report passes" '[[ $(code) == 0 ]] && says "0 not accepted"'
run --input "$WORK/error.json" --today 2026-10-06
t "an npm audit error is not mistaken for 'no vulnerabilities'" '[[ $(code) == 2 ]]'
echo '{ "exceptions": [ { "advisory": "GHSA-x", "package": "p" } ] }' > "$WORK/bad.json"
node "$GATE" --exceptions "$WORK/bad.json" --input "$WORK/clean.json" > "$WORK/out" 2>&1; echo $? > "$WORK/code"
t "an exception without a reason and expiry is refused" '[[ $(code) == 2 ]]'
cat > "$WORK/real.json" <<JSON
{ "vulnerabilities": { "braces": { "severity": "high", "via": [ $(adv braces high GHSA-vfj7-8cjw-p6xm) ] } } }
JSON
node "$GATE" --input "$WORK/real.json" --today 2026-10-06 > "$WORK/out" 2>&1; echo $? > "$WORK/code"
t "the real exceptions file is valid and accepts the one known advisory (braces)" '[[ $(code) == 0 ]]'

echo; echo "$pass passed, $failed failed"
[[ $failed -eq 0 ]]
