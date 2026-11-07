import type { Severity } from "../types.js";
const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
export const severityAtLeast = (s: Severity, min: string): boolean => RANK[s] >= (RANK[min as Severity] ?? RANK.high);
