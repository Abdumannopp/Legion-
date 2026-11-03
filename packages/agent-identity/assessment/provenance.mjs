// Provenance and validation for security-assessment runs.
//
// A verdict like DEFENDED only means something if you know exactly which code
// produced it. Every run records the git commit read from the checkout itself
// (never from an environment variable or argument someone could set), whether
// the working tree had uncommitted changes, the package and lockfile state,
// the runtime, and when it started and finished. Every result row carries the
// run's id, and a run file that is incomplete or inconsistent fails validation.
//
// Plain JavaScript so CI can run the validator with `node` and no build step.

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ASSESSMENT_VERSION = "2";
export const SCHEMA_VERSION = 1;
export const RESULTS = ["DEFENDED", "PARTIAL", "NOT DEFENDED"];
export const SEVERITIES = ["Critical", "High", "Medium", "Low", "None"];
/** A NOT DEFENDED result at one of these severities fails the gate. */
export const BLOCKING_SEVERITIES = ["Critical", "High"];

const here = dirname(fileURLToPath(import.meta.url));
export const ASSESSMENT_DIR = here;
export const PACKAGE_DIR = resolve(here, "..");

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const git = (cwd, args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/** Hash of every assessment source file, so a changed scenario is a changed assessment. */
export function assessmentSourceSha256(dir = ASSESSMENT_DIR) {
  const h = createHash("sha256");
  for (const f of readdirSync(dir).filter((n) => /\.(ts|mjs)$/.test(n)).sort()) {
    h.update(f).update("\0").update(readFileSync(join(dir, f))).update("\0");
  }
  return h.digest("hex");
}

/** Every scenario id declared in the assessment sources — all must appear in a run. */
export function expectedScenarioIds(dir = ASSESSMENT_DIR) {
  const ids = new Set();
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".assess.ts"))) {
    for (const m of readFileSync(join(dir, f), "utf8").matchAll(/^\s*id:\s*"([A-Z]+-\d+)"/gm)) ids.add(m[1]);
  }
  return [...ids].sort();
}

/**
 * The scenarios a run must contain: the pinned list in required-scenarios.json
 * (so deleting a scenario file cannot quietly shrink the gate) plus anything
 * declared in the sources.
 */
export function requiredScenarioIds(dir = ASSESSMENT_DIR) {
  const pinned = JSON.parse(readFileSync(join(dir, "required-scenarios.json"), "utf8")).ids;
  return [...new Set([...pinned, ...expectedScenarioIds(dir)])].sort();
}

/** Scenarios in the sources that are not yet pinned — the manifest must be updated. */
export function unpinnedScenarioIds(dir = ASSESSMENT_DIR) {
  const pinned = new Set(JSON.parse(readFileSync(join(dir, "required-scenarios.json"), "utf8")).ids);
  return expectedScenarioIds(dir).filter((id) => !pinned.has(id));
}

/**
 * Reads provenance from the repository checkout. Throws if the directory is
 * not a git checkout: a result that cannot be tied to a commit is not a result.
 */
export function collectProvenance(packageDir = PACKAGE_DIR) {
  const repoRoot = git(packageDir, ["rev-parse", "--show-toplevel"]);
  const gitCommit = git(repoRoot, ["rev-parse", "--verify", "HEAD^{commit}"]);
  const dirtyFiles = git(repoRoot, ["status", "--porcelain", "--untracked-files=no"]).split("\n").filter(Boolean);
  const pkg = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
  return {
    schemaVersion: SCHEMA_VERSION,
    assessmentVersion: ASSESSMENT_VERSION,
    assessmentSourceSha256: assessmentSourceSha256(join(packageDir, "assessment")),
    gitCommit,
    gitDirty: dirtyFiles.length > 0,
    gitDirtyFiles: dirtyFiles.slice(0, 50),
    packageName: pkg.name,
    packageVersion: pkg.version,
    lockfileSha256: sha256(readFileSync(join(packageDir, "package-lock.json"))),
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
  };
}

export function newRunHeader(provenance, startedAt = new Date()) {
  return { type: "run", runId: randomUUID(), startedAt: startedAt.toISOString(), ...provenance };
}

const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ISO = (s) => typeof s === "string" && !Number.isNaN(Date.parse(s)) && s.endsWith("Z");

/**
 * Validates one run file (JSON lines: a run header, results, a completion row).
 *
 * opts.expectedIds   scenario ids that must all be present (default: from sources)
 * opts.requireClean  fail if the run came from uncommitted code (CI sets this)
 * opts.repoRoot      if given, the recorded commit must exist in this repository
 * opts.expectCommit  if given, the recorded commit must equal it (CI passes HEAD)
 */
export function validateRun(text, opts = {}) {
  const problems = [];
  const lines = String(text).split("\n").filter((l) => l.trim());
  let rows;
  try {
    rows = lines.map((l, i) => { try { return JSON.parse(l); } catch { throw new Error(`line ${i + 1} is not valid JSON`); } });
  } catch (e) {
    return { ok: false, problems: [e.message], summary: null };
  }

  const header = rows[0];
  if (!header || header.type !== "run") return { ok: false, problems: ["first line must be the run header (type: run)"], summary: null };

  const need = {
    runId: (v) => typeof v === "string" && v.length >= 8,
    startedAt: ISO,
    schemaVersion: (v) => v === SCHEMA_VERSION,
    assessmentVersion: (v) => typeof v === "string" && v.length > 0,
    assessmentSourceSha256: (v) => HEX64.test(v ?? ""),
    gitCommit: (v) => HEX40.test(v ?? ""),
    gitDirty: (v) => typeof v === "boolean",
    packageName: (v) => typeof v === "string" && v.length > 0,
    packageVersion: (v) => typeof v === "string" && v.length > 0,
    lockfileSha256: (v) => HEX64.test(v ?? ""),
    node: (v) => /^v\d+\.\d+\.\d+/.test(v ?? ""),
    platform: (v) => typeof v === "string" && v.length > 0,
  };
  for (const [k, ok] of Object.entries(need)) if (!ok(header[k])) problems.push(`run header: missing or invalid ${k}`);

  if (opts.requireClean && header.gitDirty !== false) problems.push("run was made from uncommitted changes (gitDirty) — its results are not tied to a commit");
  if (opts.expectCommit && header.gitCommit !== opts.expectCommit) problems.push(`run commit ${header.gitCommit} is not the commit being released (${opts.expectCommit})`);
  if (opts.repoRoot && HEX40.test(header.gitCommit ?? "")) {
    try { git(opts.repoRoot, ["cat-file", "-e", `${header.gitCommit}^{commit}`]); }
    catch { problems.push(`run commit ${header.gitCommit} does not exist in this repository`); }
  }

  const completion = rows.at(-1);
  const results = rows.slice(1, completion?.type === "run_complete" ? -1 : undefined);
  if (completion?.type !== "run_complete") problems.push("run is incomplete: no completion row (the run crashed or was cut short)");
  else {
    if (completion.runId !== header.runId) problems.push("completion row belongs to a different run");
    if (!ISO(completion.completedAt)) problems.push("completion row: missing or invalid completedAt");
    else if (Date.parse(completion.completedAt) < Date.parse(header.startedAt)) problems.push("completion is before start");
    if (completion.resultCount !== results.length) problems.push(`completion says ${completion.resultCount} results, file has ${results.length}`);
  }

  const seen = new Set();
  const counts = { DEFENDED: 0, PARTIAL: 0, "NOT DEFENDED": 0 };
  const blocking = [];
  results.forEach((r, i) => {
    const where = `result ${i + 1}${r?.id ? ` (${r.id})` : ""}`;
    if (r?.type !== "result") problems.push(`${where}: type must be "result"`);
    if (r?.runId !== header.runId) problems.push(`${where}: runId does not match this run`);
    for (const k of ["id", "category", "title", "actual", "recommendedFix"]) if (typeof r?.[k] !== "string" || !r[k]) problems.push(`${where}: missing ${k}`);
    if (!RESULTS.includes(r?.result)) problems.push(`${where}: invalid result ${JSON.stringify(r?.result)}`);
    if (!SEVERITIES.includes(r?.severity)) problems.push(`${where}: invalid severity ${JSON.stringify(r?.severity)}`);
    if (!ISO(r?.ranAt)) problems.push(`${where}: missing or invalid ranAt`);
    if (typeof r?.evidence !== "object" || r.evidence === null) problems.push(`${where}: missing evidence`);
    if (r?.id) {
      if (seen.has(r.id)) problems.push(`${where}: duplicate scenario id`);
      seen.add(r.id);
    }
    if (RESULTS.includes(r?.result)) counts[r.result]++;
    if (r?.result === "NOT DEFENDED" && BLOCKING_SEVERITIES.includes(r?.severity)) blocking.push(`${r.id} (${r.severity}): ${r.title}`);
  });

  const expected = opts.expectedIds ?? requiredScenarioIds();
  if (!opts.expectedIds) {
    const unpinned = unpinnedScenarioIds();
    if (unpinned.length) problems.push(`scenarios not listed in assessment/required-scenarios.json: ${unpinned.join(", ")}`);
  }
  const missing = expected.filter((id) => !seen.has(id));
  if (missing.length) problems.push(`required scenarios missing from the run: ${missing.join(", ")}`);
  for (const b of blocking) problems.push(`security gate: NOT DEFENDED at blocking severity — ${b}`);

  return {
    ok: problems.length === 0,
    problems,
    summary: { runId: header.runId, gitCommit: header.gitCommit, gitDirty: header.gitDirty, results: results.length, ...counts },
  };
}

// CLI: node assessment/provenance.mjs validate <file> [--require-clean] [--expect-commit <sha>]
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [cmd, file, ...rest] = process.argv.slice(2);
  if (cmd !== "validate" || !file) {
    console.error("usage: node assessment/provenance.mjs validate <run.jsonl> [--require-clean] [--expect-commit <sha>]");
    process.exit(2);
  }
  const ec = rest.indexOf("--expect-commit");
  let repoRoot;
  try { repoRoot = git(PACKAGE_DIR, ["rev-parse", "--show-toplevel"]); } catch { repoRoot = undefined; }
  let text;
  try { text = readFileSync(file, "utf8"); } catch (e) { console.error(`cannot read ${file}: ${e.message}`); process.exit(1); }
  const r = validateRun(text, { requireClean: rest.includes("--require-clean"), expectCommit: ec >= 0 ? rest[ec + 1] : undefined, repoRoot });
  if (r.summary) console.log(JSON.stringify(r.summary));
  for (const p of r.problems) console.error(`✗ ${p}`);
  console.log(r.ok ? "assessment run: VALID" : `assessment run: INVALID (${r.problems.length} problem(s))`);
  process.exit(r.ok ? 0 : 1);
}
