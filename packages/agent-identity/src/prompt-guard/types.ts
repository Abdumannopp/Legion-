/**
 * Where a piece of content came from. Everything here is untrusted by
 * default: it was written by someone other than Legion and the person or
 * agent Legion is working for.
 */
export const CONTENT_SOURCES = [
  "email",
  "webpage",
  "security_alert",
  "pdf",
  "document",
  "ticket",
  "github_issue",
  "api_response",
  "user_generated",
  "agent_message",
  "model_output",
  "other",
] as const;
export type ContentSource = (typeof CONTENT_SOURCES)[number];

/** Sources where links, images and HTML are normal. */
export const RICH_SOURCES: ReadonlySet<ContentSource> = new Set(["email", "webpage", "document", "github_issue", "pdf"]);

/**
 * What shape the content is supposed to have. A hostname that contains
 * sentences is suspicious whatever those sentences say.
 */
export type FieldHint = "free_text" | "short_text" | "identifier";

export type FindingCategory =
  | "instruction_override"
  | "persona_hijack"
  | "authority_claim"
  | "ai_addressing"
  | "covert_action"
  | "prompt_leak"
  | "action_directive"
  | "role_markers"
  | "wrapper_escape"
  | "invisible_unicode"
  | "homoglyph"
  | "obfuscation"
  | "encoded_payload"
  | "hidden_markup"
  | "exfiltration_markup"
  | "reader_addressing"
  | "shape_mismatch";

export interface Finding {
  category: FindingCategory;
  /** Stable rule id, e.g. "override.previous_instructions". */
  id: string;
  points: number;
  detail: string;
  /** Short, redacted excerpt of what matched, for investigation. */
  excerpt?: string;
}

export type Verdict = "clean" | "suspicious" | "malicious";

export interface Classification {
  verdict: Verdict;
  /** 0–100. Sum over categories of the strongest finding in each, capped. */
  riskScore: number;
  findings: Finding[];
  /** The text to hand a model: invisible channels removed. */
  sanitized: string;
  /** Characters removed by sanitisation. */
  removedChars: number;
}

export const THRESHOLDS = { suspicious: 25, malicious: 60 } as const;

export function verdictOf(score: number): Verdict {
  return score >= THRESHOLDS.malicious ? "malicious" : score >= THRESHOLDS.suspicious ? "suspicious" : "clean";
}

export const VERDICT_ORDER: readonly Verdict[] = ["clean", "suspicious", "malicious"];
export function worstVerdict(verdicts: Verdict[]): Verdict {
  return verdicts.reduce<Verdict>((a, v) => (VERDICT_ORDER.indexOf(v) > VERDICT_ORDER.indexOf(a) ? v : a), "clean");
}

/** What the firewall needs to know about external content that reached a principal. */
export interface ContentRiskSummary {
  /** Malicious content not yet reviewed by a person (no time limit: an attacker could just wait). */
  unacknowledgedMalicious: number;
  /** Suspicious content in the recent window, not yet reviewed. */
  unacknowledgedSuspicious: number;
  maxScore: number;
  lastEventAt: string | null;
}
