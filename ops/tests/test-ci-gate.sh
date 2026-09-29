#!/usr/bin/env bash
# Proves the CI security gate cannot be switched off quietly, and that the
# release gate fails whenever a job it waits for did not succeed.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1

pass=0; fail=0
ok()   { echo "  ✓ $1"; pass=$((pass + 1)); }
bad()  { echo "  ✗ $1"; fail=$((fail + 1)); }
expect() { # expect <0|1> <description> <command...>
  local want=$1 desc=$2; shift 2
  if "$@" >/dev/null 2>&1; then got=0; else got=1; fi
  if [ "$got" = "$want" ]; then ok "$desc"; else bad "$desc (exit $got, wanted $want)"; fi
}

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
wf=.github/workflows/ci.yml

echo "check-ci-gate.mjs"
expect 0 "the committed workflow passes" node .github/scripts/check-ci-gate.mjs "$wf"

sed 's/^\(      - name: Attack assessment\)$/\1\n        continue-on-error: true/' "$wf" > "$tmp/coe.yml"
expect 1 "continue-on-error on a step is refused" node .github/scripts/check-ci-gate.mjs "$tmp/coe.yml"

sed 's/needs: \[deploy-scripts, dependencies, agent-identity, app, security-assessment\]/needs: [deploy-scripts, dependencies, agent-identity, app]/' "$wf" > "$tmp/unhooked.yml"
expect 1 "release gate not waiting for the security job is refused" node .github/scripts/check-ci-gate.mjs "$tmp/unhooked.yml"

sed 's/^    needs: \[release-gate\]$/    needs: [app]/' "$wf" > "$tmp/release.yml"
expect 1 "release not depending on the gate is refused" node .github/scripts/check-ci-gate.mjs "$tmp/release.yml"

sed 's/ --require-clean//' "$wf" > "$tmp/lax.yml"
expect 1 "dropping provenance checks from validation is refused" node .github/scripts/check-ci-gate.mjs "$tmp/lax.yml"

echo "release-gate.mjs"
all='{"deploy-scripts":{"result":"success"},"dependencies":{"result":"success"},"agent-identity":{"result":"success"},"app":{"result":"success"},"security-assessment":{"result":"success"}}'
expect 0 "all jobs succeeded → release allowed" env NEEDS="$all" node .github/scripts/release-gate.mjs
expect 1 "security job failed → release blocked" env NEEDS="${all/\"security-assessment\":{\"result\":\"success\"}/\"security-assessment\":{\"result\":\"failure\"}}" node .github/scripts/release-gate.mjs
expect 1 "security job skipped → release blocked" env NEEDS="${all/\"security-assessment\":{\"result\":\"success\"}/\"security-assessment\":{\"result\":\"skipped\"}}" node .github/scripts/release-gate.mjs
expect 1 "security job cancelled → release blocked" env NEEDS="${all/\"security-assessment\":{\"result\":\"success\"}/\"security-assessment\":{\"result\":\"cancelled\"}}" node .github/scripts/release-gate.mjs
expect 1 "no results at all → release blocked" env NEEDS='{}' node .github/scripts/release-gate.mjs

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
