import { appendFileSync } from "node:fs";
import { inject, it } from "vitest";

export type Result = "DEFENDED" | "PARTIAL" | "NOT DEFENDED";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "None";

export interface Meta {
  id: string;
  category: string;
  title: string;
  attackPath: string;
  expectedDefense: string;
}

export interface Verdict {
  result: Result;
  /** What actually happened, in one or two sentences. */
  actual: string;
  severity: Severity;
  recommendedFix: string;
}

export type ResultRow = Meta & Verdict & { type: "result"; runId: string; evidence: Record<string, unknown>; ranAt: string };

/** The run this process belongs to, opened by global-setup.ts with its provenance header. */
function currentRun(): { runId: string; file: string } {
  const run = inject("assessmentRun");
  if (!run?.runId || !run.file) {
    throw new Error("No assessment run is open. Run the assessment with: npx vitest run --config assessment/vitest.config.ts");
  }
  return run;
}

/**
 * One attack scenario. `fn` performs the attack against the running stack,
 * collects evidence with `ev(key, value)`, and returns what happened. It
 * never asserts the outcome — an undefended attack is a finding to report,
 * not a failed test. Only a broken harness (a thrown error) fails the run.
 * Each result is appended to the run file immediately (see global-setup.ts),
 * tagged with the run id, so a later crash doesn't lose earlier findings — and
 * a crashed run is recognisable because it has no completion row.
 */
export function scenario(meta: Meta, fn: (ev: (k: string, v: unknown) => void) => Promise<Verdict>) {
  it(`${meta.id} ${meta.title}`, async () => {
    const evidence: Record<string, unknown> = {};
    const run = currentRun();
    const verdict = await fn((k, v) => { evidence[k] = v; });
    const row: ResultRow = { type: "result", runId: run.runId, ...meta, ...verdict, evidence, ranAt: new Date().toISOString() };
    appendFileSync(run.file, JSON.stringify(row) + "\n");
  });
}

export const defended = (actual: string, fix = "—"): Verdict => ({ result: "DEFENDED", actual, severity: "None", recommendedFix: fix });
export const notDefended = (actual: string, severity: Severity, recommendedFix: string): Verdict => ({ result: "NOT DEFENDED", actual, severity, recommendedFix });
export const partial = (actual: string, severity: Severity, recommendedFix: string): Verdict => ({ result: "PARTIAL", actual, severity, recommendedFix });
