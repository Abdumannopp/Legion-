/**
 * Helpers shared by the adapters that read free-form events (generic JSON,
 * CEF/syslog). Everything here is defensive: input is attacker-influenced, so
 * every value is bounded, typed and stripped before it becomes a Finding.
 */
import { createHash } from "node:crypto";
import { clip, isIp } from "../ai-safety.js";
import type { Severity } from "../types.js";

export const MAX_EVENTS_PER_REQUEST = 200;

/** Control characters (except tab/newline) and bidi/zero-width tricks are removed. */
export function cleanText(v: unknown, max: number): string {
  if (v === null || v === undefined) return "";
  const s = typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : "";
  // eslint-disable-next-line no-control-regex
  return clip(s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060-\u2064]/g, ""), max).trim();
}

export const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

export function pickIp(...candidates: unknown[]): string | null {
  for (const c of candidates) if (typeof c === "string" && isIp(c.trim())) return c.trim();
  return null;
}

/** An event time the source gave, or null when absent, unparseable, before 2000 or in the future. */
export function parseTime(raw: unknown): string | null {
  let t: number;
  if (typeof raw === "number" && Number.isFinite(raw)) t = raw > 1e12 ? raw : raw * 1000; // epoch ms or s
  else if (typeof raw === "string" && raw.length <= 64) {
    const trimmed = raw.trim();
    t = /^\d{10,13}$/.test(trimmed) ? (trimmed.length > 10 ? Number(trimmed) : Number(trimmed) * 1000) : Date.parse(trimmed.replace(/([+-]\d{2})(\d{2})$/, "$1:$2"));
  } else return null;
  if (!Number.isFinite(t) || t < Date.UTC(2000, 0, 1) || t > Date.now() + 5 * 60_000) return null;
  return new Date(t).toISOString();
}

const WORDS: Record<string, Severity> = {
  critical: "critical", fatal: "critical", emergency: "critical", emerg: "critical", alert: "critical", severe: "critical",
  high: "high", error: "high", err: "high", major: "high", crit: "critical",
  medium: "medium", moderate: "medium", warning: "medium", warn: "medium", med: "medium",
  low: "low", minor: "low", info: "low", informational: "low", notice: "low", debug: "low", none: "low",
};

/**
 * A severity from a word ("High") or a number. `scale` says what a number means:
 * "ten" 0–10 (CEF), "hundred" 0–100 (Elastic risk_score, Microsoft), "five" 1–5. Unknown → medium,
 * never silently low: a missing severity must not hide an event.
 */
export function severityOf(raw: unknown, scale: "ten" | "hundred" | "five" = "ten"): Severity {
  if (typeof raw === "string") {
    const w = WORDS[raw.trim().toLowerCase()];
    if (w) return w;
    if (/^\d+(\.\d+)?$/.test(raw.trim())) return severityOf(Number(raw), scale);
    return "medium";
  }
  if (typeof raw !== "number" || !Number.isFinite(raw)) return "medium";
  const n = scale === "hundred" ? raw / 10 : scale === "five" ? raw * 2 : raw;
  return n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : "low";
}

export function mitreIn(...texts: unknown[]): string[] {
  const out = new Set<string>();
  for (const t of texts) {
    const s = Array.isArray(t) ? t.map(String).join(" ") : typeof t === "string" ? t : "";
    for (const m of s.matchAll(/\bT\d{4}(?:\.\d{3})?\b/g)) { out.add(m[0]); if (out.size >= 20) return [...out]; }
  }
  return [...out];
}

/**
 * The "since" time a poll resumes from: the cursor's ISO time if it is one (and not in the future), otherwise
 * `fallbackHours` ago. Adapters put this value into vendor query languages (FQL, OData, SPL…), so only a strict
 * ISO-8601 UTC timestamp is accepted — never free text.
 */
export function cursorSince(cursor: unknown, fallbackHours = 24): string {
  const c = (cursor as { since?: unknown } | null)?.since;
  if (typeof c === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(c) && Date.parse(c) <= Date.now() + 300_000) return c;
  return new Date(Date.now() - fallbackHours * 3600_000).toISOString();
}
