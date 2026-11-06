// Checks that the CI workflow still enforces the security gate.
//
// Someone "fixing a red build" by adding continue-on-error, or by removing the
// security job from what a release waits for, would silently turn the gate
// off. This script fails CI if that happens.
//
//   node .github/scripts/check-ci-gate.mjs [path/to/ci.yml]
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const file = process.argv[2] ?? ".github/workflows/ci.yml";
const text = readFileSync(file, "utf8");
const problems = [];

// 1. No step or job may be allowed to fail quietly.
text.split("\n").forEach((line, i) => {
  if (/^\s*continue-on-error\s*:/.test(line) && !/:\s*false\s*(#.*)?$/.test(line)) {
    problems.push(`line ${i + 1}: continue-on-error is not allowed in this workflow`);
  }
});

// 2. Minimal structural read of the jobs block (2-space YAML as used here):
//    which jobs exist and what each one `needs`.
const jobs = {};
let inJobs = false;
let current = null;
for (const line of text.split("\n")) {
  if (/^jobs:\s*$/.test(line)) { inJobs = true; continue; }
  if (inJobs && /^\S/.test(line)) inJobs = false;
  if (!inJobs) continue;
  const job = /^  ([A-Za-z0-9_-]+):\s*$/.exec(line);
  if (job) { current = job[1]; jobs[current] = { needs: [], ifs: [] }; continue; }
  if (!current) continue;
  const needsInline = /^    needs:\s*\[(.*)\]\s*$/.exec(line);
  if (needsInline) jobs[current].needs = needsInline[1].split(",").map((s) => s.trim()).filter(Boolean);
  const needsOne = /^    needs:\s*([A-Za-z0-9_-]+)\s*$/.exec(line);
  if (needsOne) jobs[current].needs = [needsOne[1]];
  const cond = /^    if:\s*(.+)$/.exec(line);
  if (cond) jobs[current].ifs.push(cond[1]);
}

const REQUIRED_FOR_RELEASE = ["deploy-scripts", "dependencies", "agent-identity", "app", "security-assessment", "pilot-stack", "image-scan", "docker"];
for (const j of [...REQUIRED_FOR_RELEASE, "release-gate", "release"]) {
  if (!jobs[j]) problems.push(`job "${j}" is missing`);
}
if (jobs["release-gate"]) {
  for (const j of REQUIRED_FOR_RELEASE) {
    if (!jobs["release-gate"].needs.includes(j)) problems.push(`release-gate does not wait for "${j}"`);
  }
  // The gate must evaluate even when something failed, and must itself fail then.
  if (!jobs["release-gate"].ifs.some((c) => c.includes("always()"))) problems.push("release-gate must run with if: always() so a failed dependency fails the gate");
}
if (jobs.release && !jobs.release.needs.includes("release-gate")) problems.push("release does not depend on release-gate");
if (!/provenance\.mjs validate[^\n]*--require-clean[^\n]*--expect-commit/.test(text)) {
  problems.push("the security job no longer validates the assessment run with --require-clean and --expect-commit");
}

// K-3: the pilot-stack job keeps scanning the shipped images and fails on a fixable CRITICAL.
if (!/grype[^\n]*--only-fixed --fail-on critical/.test(text) || !/sha256sum -c/.test(text)) {
  problems.push("the image vulnerability scan (grype --only-fixed --fail-on critical, checksum-verified) is missing");
}

// 3. The security suites keep every regression test for a fixed finding.
//    Dropping one from `test:security` (or deleting its file) quietly removes
//    the guard against that finding coming back.
const REQUIRED_SECURITY_TESTS = {
  server: [
    "first-admin", "webhook-auth", "webhook-constant-time", "tenant-isolation-sweep", "tenant-query-guard",
    "cross-tenant-attacks", "ai-output-is-data", "ai-hardening", "ai-safety", "config-safety", "secret-placeholders",
    "secrets-at-rest", "sessions", "session-token-hardening", "auth-hardening", "authorization-hardening", "mfa",
    "db-app-role", "agent-security", "saas-signup-billing", "payments", "text-safety", "turnstile",
    // audit 2026-09-29 fixes, re-audit 2026-11
    "migrations", "access-log", "audit-append-only", "mock-provider", "deploy-supervision", "retention",
    // plans: prices, limits and what a plan refuses
    "plans", "plan-limits",
    // data lifecycle: retention, export, legal hold, erasure with proof
    "data-lifecycle", "tenant-deletion",
  ].map((n) => `tests/${n}.test.ts`),
  "packages/agent-identity": [
    "untrusted-content", "injection-regression", "suspension-immediate", "killswitch", "prompt-guard", "firewall",
    "db-least-privilege", "tools-database-executor", "policy-responses", "principal", "a2a",
  ].map((n) => `test/${n}.test.ts`),
};
const root = process.env.CI_GATE_ROOT ?? ".";
for (const [dir, required] of Object.entries(REQUIRED_SECURITY_TESTS)) {
  let script = "";
  try { script = JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8")).scripts?.["test:security"] ?? ""; } catch { /* reported below */ }
  if (!script) { problems.push(`${dir}: no test:security script`); continue; }
  const listed = new Set(script.split(/\s+/));
  for (const f of required) {
    if (!listed.has(f)) problems.push(`${dir}: test:security no longer runs ${f}`);
    if (!existsSync(join(root, dir, f))) problems.push(`${dir}: ${f} is missing`);
  }
}
if (!/npm run test:security -w server/.test(text)) problems.push("the security job no longer runs the server security tests");
if (!/working-directory: packages\/agent-identity[\s\S]{0,120}npm run test:security/.test(text)) problems.push("the security job no longer runs the agent security tests");

for (const p of problems) console.error(`✗ ${p}`);
console.log(problems.length ? `CI gate check: FAILED (${problems.length})` : `CI gate check: OK (${Object.keys(jobs).length} jobs)`);
process.exit(problems.length ? 1 : 0);
