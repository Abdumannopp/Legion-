/**
 * Every security-assessment verdict must be traceable to the exact code that
 * produced it. These tests cover how that provenance is collected and how a
 * run file is validated (assessment/provenance.mjs).
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  BLOCKING_SEVERITIES, PACKAGE_DIR, collectProvenance, expectedScenarioIds, newRunHeader, requiredScenarioIds, unpinnedScenarioIds, validateRun,
} from "../assessment/provenance.mjs";

const head = () => execFileSync("git", ["rev-parse", "HEAD"], { cwd: PACKAGE_DIR, encoding: "utf8" }).trim();
const repoRoot = () => execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: PACKAGE_DIR, encoding: "utf8" }).trim();

describe("collecting provenance", () => {
  const saved = { ...process.env };
  afterEach(() => { process.env = { ...saved }; });

  it("reads the commit from the checkout and hashes the real lockfile", () => {
    const p = collectProvenance();
    expect(p.gitCommit).toBe(head());
    expect(p.gitCommit).toMatch(/^[0-9a-f]{40}$/);
    expect(p.lockfileSha256).toBe(createHash("sha256").update(readFileSync(join(PACKAGE_DIR, "package-lock.json"))).digest("hex"));
    expect(p.packageName).toBe("@legion/agent-identity");
    expect(p.node).toBe(process.version);
    expect(typeof p.gitDirty).toBe("boolean");
  });

  it("ignores commit values supplied through the environment", () => {
    process.env.GIT_COMMIT = "0".repeat(40);
    process.env.GITHUB_SHA = "1".repeat(40);
    expect(collectProvenance().gitCommit).toBe(head());
  });

  it("refuses to produce provenance outside a git checkout", () => {
    const dir = mkdtempSync(join(tmpdir(), "legion-noprov-"));
    copyFileSync(join(PACKAGE_DIR, "package.json"), join(dir, "package.json"));
    copyFileSync(join(PACKAGE_DIR, "package-lock.json"), join(dir, "package-lock.json"));
    expect(() => collectProvenance(dir)).toThrow();
  });

  it("the pinned manifest covers every scenario in the sources", () => {
    expect(unpinnedScenarioIds()).toEqual([]);
    expect(requiredScenarioIds()).toEqual(expectedScenarioIds());
  });

  it("finds every scenario declared in the assessment sources", () => {
    const ids = expectedScenarioIds();
    expect(ids.length).toBeGreaterThanOrEqual(50);
    expect(ids).toContain("IPI-1");
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// --- Validation ------------------------------------------------------------

const IDS = ["AAA-1", "AAA-2"];
function runFile(over: { header?: Record<string, unknown>; results?: Record<string, unknown>[]; completion?: Record<string, unknown> | null } = {}) {
  const header = { ...newRunHeader(collectProvenance()), gitDirty: false, ...over.header };
  const results = over.results ?? IDS.map((id) => ({
    type: "result", runId: header.runId, id, category: "c", title: `t ${id}`, attackPath: "a", expectedDefense: "e",
    result: "DEFENDED", actual: "held", severity: "None", recommendedFix: "—", evidence: {}, ranAt: new Date().toISOString(),
  }));
  const completion = over.completion === null ? [] : [{
    type: "run_complete", runId: header.runId, completedAt: new Date(Date.now() + 1000).toISOString(), resultCount: results.length, ...over.completion,
  }];
  return [header, ...results, ...completion].map((r) => JSON.stringify(r)).join("\n") + "\n";
}
const check = (text: string, opts: Parameters<typeof validateRun>[1] = {}) => validateRun(text, { expectedIds: IDS, ...opts });

describe("validating a run", () => {
  it("accepts a complete, consistent run", () => {
    const r = check(runFile());
    expect(r.problems).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.summary).toMatchObject({ results: 2, DEFENDED: 2 });
  });

  it.each(["runId", "startedAt", "gitCommit", "gitDirty", "packageVersion", "lockfileSha256", "node", "assessmentVersion", "assessmentSourceSha256"])(
    "rejects a run header without %s",
    (field) => {
      const r = check(runFile({ header: { [field]: undefined } }));
      expect(r.ok).toBe(false);
      expect(r.problems.join()).toContain(field);
    },
  );

  it("rejects a malformed commit id", () => {
    expect(check(runFile({ header: { gitCommit: "not-a-sha" } })).ok).toBe(false);
  });

  it("rejects an incomplete run (no completion row)", () => {
    const r = check(runFile({ completion: null }));
    expect(r.problems.join()).toMatch(/incomplete/);
  });

  it("rejects a result that belongs to a different run", () => {
    const text = runFile();
    const tampered = text.replace(/"type":"result","runId":"[^"]+"/, '"type":"result","runId":"someone-else-run"');
    expect(check(tampered).problems.join()).toMatch(/runId does not match/);
  });

  it("rejects a run missing a required scenario", () => {
    const r = check(runFile(), { expectedIds: [...IDS, "AAA-3"] });
    expect(r.problems.join()).toMatch(/missing from the run: AAA-3/);
  });

  it("rejects a completion count that does not match the file", () => {
    expect(check(runFile({ completion: { resultCount: 5 } })).ok).toBe(false);
  });

  it("rejects malformed JSON", () => {
    expect(check(runFile() + "{not json\n").ok).toBe(false);
  });

  it("rejects an invalid verdict value", () => {
    const text = runFile().replace('"result":"DEFENDED"', '"result":"PROBABLY FINE"');
    expect(check(text).problems.join()).toMatch(/invalid result/);
  });

  it("fails the gate on NOT DEFENDED at a blocking severity", () => {
    for (const severity of BLOCKING_SEVERITIES) {
      const text = runFile().replace('"result":"DEFENDED","actual":"held","severity":"None"', `"result":"NOT DEFENDED","actual":"got through","severity":"${severity}"`);
      expect(check(text).problems.join()).toMatch(/security gate/);
    }
  });

  it("reports but does not fail on PARTIAL or a Medium finding", () => {
    let text = runFile().replace('"result":"DEFENDED","actual":"held","severity":"None"', '"result":"NOT DEFENDED","actual":"x","severity":"Medium"');
    text = text.replace('"result":"DEFENDED","actual":"held","severity":"None"', '"result":"PARTIAL","actual":"y","severity":"Medium"');
    const r = check(text);
    expect(r.ok).toBe(true);
    expect(r.summary).toMatchObject({ PARTIAL: 1, "NOT DEFENDED": 1 });
  });

  it("with requireClean, rejects results from uncommitted code", () => {
    expect(check(runFile({ header: { gitDirty: true } }), { requireClean: true }).problems.join()).toMatch(/uncommitted/);
  });

  it("with expectCommit, rejects a run made from a different commit", () => {
    expect(check(runFile(), { expectCommit: "f".repeat(40) }).problems.join()).toMatch(/not the commit being released/);
  });

  it("with repoRoot, rejects a commit that does not exist in the repository", () => {
    const r = check(runFile({ header: { gitCommit: "e".repeat(40) } }), { repoRoot: repoRoot() });
    expect(r.problems.join()).toMatch(/does not exist/);
  });
});
