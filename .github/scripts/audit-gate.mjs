// Fails when the lockfile has a high or critical advisory that nobody has
// consciously accepted.
//
// `npm audit --audit-level=high` alone cannot express "this one has no fix and
// does not apply to us" — and a gate that can only be satisfied by ignoring it
// gets switched off. So accepted advisories live in .github/audit-exceptions.json,
// each with a reason and an EXPIRY DATE: when it passes, the build fails again
// until someone looks. An exception for an advisory that no longer appears is
// reported so the list does not rot.
//
//   node .github/scripts/audit-gate.mjs [--input audit.json] [--today YYYY-MM-DD] [--exceptions file]
//
// Without --input it runs `npm audit --package-lock-only --json` itself.
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const arg = (name, fallback) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : fallback; };
const today = arg("--today", new Date().toISOString().slice(0, 10));
const exceptionsFile = arg("--exceptions", ".github/audit-exceptions.json");
const inputFile = arg("--input");

let raw;
if (inputFile) raw = readFileSync(inputFile, "utf8");
else {
  const r = spawnSync("npm", ["audit", "--package-lock-only", "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  raw = r.stdout;
  if (!raw) { console.error(`npm audit produced no output: ${r.stderr}`); process.exit(2); }
}
let report;
try { report = JSON.parse(raw); } catch { console.error("npm audit output is not JSON"); process.exit(2); }
if (report.error) { console.error(`npm audit failed: ${report.error.summary ?? JSON.stringify(report.error)}`); process.exit(2); }

const exceptions = JSON.parse(readFileSync(exceptionsFile, "utf8")).exceptions ?? [];
for (const e of exceptions) {
  for (const k of ["advisory", "package", "reason", "expires"]) {
    if (!e[k]) { console.error(`${exceptionsFile}: every exception needs "${k}" (${JSON.stringify(e)})`); process.exit(2); }
  }
}
const byId = new Map(exceptions.map((e) => [e.advisory, e]));

// The advisories themselves are the objects in `via`; a string in `via` only
// says "depends on a vulnerable package" and is covered by the advisory it points to.
const found = new Map();
for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of v.via ?? []) {
    if (typeof via !== "object") continue;
    if (via.severity !== "high" && via.severity !== "critical") continue;
    const id = (via.url ?? "").split("/").pop() || via.source;
    if (!found.has(id)) found.set(id, { id, severity: via.severity, title: via.title, package: via.name ?? name, url: via.url });
  }
}

let failed = 0;
for (const a of found.values()) {
  const e = byId.get(a.id);
  if (!e) { failed++; console.log(`FAIL  ${a.severity.toUpperCase()}  ${a.package}: ${a.title}\n      ${a.url}\n      Update the dependency, or — only if it truly does not apply and has no fix — add it to ${exceptionsFile} with a reason and an expiry.`); continue; }
  if (e.expires < today) { failed++; console.log(`FAIL  exception for ${a.id} (${a.package}) EXPIRED on ${e.expires}: ${e.reason}\n      Re-check it: is there a fix now? If not, renew deliberately.`); continue; }
  console.log(`ok    ${a.severity}  ${a.package} ${a.id} — accepted until ${e.expires}: ${e.reason.slice(0, 110)}${e.reason.length > 110 ? "…" : ""}`);
}
for (const e of exceptions) if (!found.has(e.advisory)) console.log(`note  exception ${e.advisory} (${e.package}) no longer matches any advisory — remove it from ${exceptionsFile}`);
console.log(`\n${found.size} high/critical advisor${found.size === 1 ? "y" : "ies"}, ${failed} not accepted.`);
process.exit(failed ? 1 : 0);
