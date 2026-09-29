/**
 * Runs once per assessment run, around all scenario files. Opens the run file
 * with a provenance header, hands the run id to every scenario, and on the way
 * out writes the completion row. A run without that row fails validation.
 */
import { appendFileSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { TestProject } from "vitest/node";
import { ASSESSMENT_DIR, collectProvenance, newRunHeader } from "./provenance.mjs";

declare module "vitest" {
  export interface ProvidedContext {
    assessmentRun: { runId: string; file: string };
  }
}

export default function setup(project: TestProject) {
  const header = newRunHeader(collectProvenance());
  const dir = join(ASSESSMENT_DIR, "results");
  mkdirSync(dir, { recursive: true });
  const stamp = header.startedAt.replace(/[:.]/g, "-");
  const file = join(dir, `run-${stamp}-${header.gitCommit.slice(0, 12)}.jsonl`);
  writeFileSync(file, JSON.stringify(header) + "\n");
  project.provide("assessmentRun", { runId: header.runId, file });

  return () => {
    const resultCount = readFileSync(file, "utf8").split("\n").filter((l) => l.includes('"type":"result"')).length;
    appendFileSync(file, JSON.stringify({ type: "run_complete", runId: header.runId, completedAt: new Date().toISOString(), resultCount }) + "\n");
    copyFileSync(file, join(dir, "latest.jsonl"));
    console.log(`\nassessment run ${header.runId} @ ${header.gitCommit}${header.gitDirty ? " (UNCOMMITTED CHANGES)" : ""}: ${file}`);
  };
}
