import { appendFileSync, existsSync, writeFileSync } from "node:fs";
import { afterAll, it } from "vitest";

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

export type ResultRow = Meta & Verdict & { evidence: Record<string, unknown>; ranAt: string };

const FILE = new URL("./results.jsonl", import.meta.url).pathname;

/**
 * One attack scenario. `fn` performs the attack against the running stack,
 * collects evidence with `ev(key, value)`, and returns what happened. It
 * never asserts the outcome — an undefended attack is a finding to report,
 * not a failed test. Only a broken harness (a thrown error) fails the run.
 * Each result is appended to results.jsonl immediately, so a later crash
 * doesn't lose earlier findings.
 */
export function scenario(meta: Meta, fn: (ev: (k: string, v: unknown) => void) => Promise<Verdict>) {
  it(`${meta.id} ${meta.title}`, async () => {
    const evidence: Record<string, unknown> = {};
    const verdict = await fn((k, v) => { evidence[k] = v; });
    const row: ResultRow = { ...meta, ...verdict, evidence, ranAt: new Date().toISOString() };
    appendFileSync(FILE, JSON.stringify(row) + "\n");
  });
}

/** Call once, in a top-level file, to start results.jsonl fresh for this run. */
export function resetResultsFile() {
  writeFileSync(FILE, "");
}

export const defended = (actual: string, fix = "—"): Verdict => ({ result: "DEFENDED", actual, severity: "None", recommendedFix: fix });
export const notDefended = (actual: string, severity: Severity, recommendedFix: string): Verdict => ({ result: "NOT DEFENDED", actual, severity, recommendedFix });
export const partial = (actual: string, severity: Severity, recommendedFix: string): Verdict => ({ result: "PARTIAL", actual, severity, recommendedFix });
