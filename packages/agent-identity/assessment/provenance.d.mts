// Types for provenance.mjs (kept as plain JS so CI can run it without a build).
export declare const ASSESSMENT_VERSION: string;
export declare const SCHEMA_VERSION: number;
export declare const RESULTS: readonly string[];
export declare const SEVERITIES: readonly string[];
export declare const BLOCKING_SEVERITIES: readonly string[];
export declare const ASSESSMENT_DIR: string;
export declare const PACKAGE_DIR: string;

export interface Provenance {
  schemaVersion: number;
  assessmentVersion: string;
  assessmentSourceSha256: string;
  gitCommit: string;
  gitDirty: boolean;
  gitDirtyFiles: string[];
  packageName: string;
  packageVersion: string;
  lockfileSha256: string;
  node: string;
  platform: string;
}
export interface RunHeader extends Provenance {
  type: "run";
  runId: string;
  startedAt: string;
}
export interface ValidationResult {
  ok: boolean;
  problems: string[];
  summary: null | { runId: string; gitCommit: string; gitDirty: boolean; results: number; DEFENDED: number; PARTIAL: number; "NOT DEFENDED": number };
}

export declare function assessmentSourceSha256(dir?: string): string;
export declare function expectedScenarioIds(dir?: string): string[];
export declare function requiredScenarioIds(dir?: string): string[];
export declare function unpinnedScenarioIds(dir?: string): string[];
export declare function collectProvenance(packageDir?: string): Provenance;
export declare function newRunHeader(provenance: Provenance, startedAt?: Date): RunHeader;
export declare function validateRun(
  text: string,
  opts?: { expectedIds?: string[]; requireClean?: boolean; repoRoot?: string; expectCommit?: string },
): ValidationResult;
