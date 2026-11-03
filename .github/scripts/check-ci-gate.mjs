// Checks that the CI workflow still enforces the security gate.
//
// Someone "fixing a red build" by adding continue-on-error, or by removing the
// security job from what a release waits for, would silently turn the gate
// off. This script fails CI if that happens.
//
//   node .github/scripts/check-ci-gate.mjs [path/to/ci.yml]
import { readFileSync } from "node:fs";

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

const REQUIRED_FOR_RELEASE = ["deploy-scripts", "dependencies", "agent-identity", "app", "security-assessment"];
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

for (const p of problems) console.error(`✗ ${p}`);
console.log(problems.length ? `CI gate check: FAILED (${problems.length})` : `CI gate check: OK (${Object.keys(jobs).length} jobs)`);
process.exit(problems.length ? 1 : 0);
