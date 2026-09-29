/**
 * Safety primitives for everything that talks to a language model.
 *
 * Pure functions, no I/O, no imports from the rest of Legion except the
 * configured secrets (so they can be recognised by value). Kept apart from
 * ai.ts so each rule can be tested — and attacked — on its own.
 *
 * The threat model, in one paragraph: alert text is written by whoever can
 * make a log line, so it may be a prompt injection, a secret that must not
 * leave the building, or an oversized blob. The model's answer is derived from
 * that text, so it is untrusted too: it may repeat an injected link, leak the
 * prompt, or be hostile markup. The model itself has no tools and no way to
 * change anything — these functions make sure it also cannot smuggle data out
 * or mislead the person reading it.
 */
import { isIP, isIPv4, isIPv6 } from "node:net";
import { config } from "./config.js";

// --- untrusted INPUT ---------------------------------------------------------

/** Zero-width, bidirectional-override and Unicode "tag" characters: they let
 *  text be read by a model but not by the analyst looking at the alert. */
export const INVISIBLE = /[​-‏‪-‮⁠-⁤⁦-⁩﻿\u{E0000}-\u{E007F}]/gu;
export const CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

export function sanitizeUntrusted(text: string): string {
  return String(text ?? "")
    .normalize("NFKC")
    .replace(INVISIBLE, "")
    .replace(CONTROL, "")
    .replace(/<\|/g, "‹|")
    .replace(/\|>/g, "|›")
    .replace(/<<<|>>>/g, "");
}

/** Cuts to at most `max` characters without splitting a surrogate pair. */
export function clip(text: string, max: number): string {
  const s = String(text ?? "");
  if (s.length <= max) return s;
  let end = max;
  const c = s.charCodeAt(end - 1);
  if (c >= 0xd800 && c <= 0xdbff) end -= 1;
  return s.slice(0, end);
}

// --- identifiers: never free text --------------------------------------------

const HOSTNAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$/;
const MITRE_RE = /^T\d{4}(?:\.\d{3})?$/;
const ID_RE = /^[A-Za-z0-9._:-]{1,100}$/;

export const isIp = (v: unknown): v is string => typeof v === "string" && v.length <= 45 && isIP(v) !== 0;

export type IdentifierKind = "ip" | "host" | "mitre" | "id";

/**
 * Structured fields — an IP, a hostname, a technique, an id — are the easiest
 * place to hide an instruction, because they look like data and nobody expects
 * prose there. So they are validated against what they may legitimately be.
 * Returns the value if it conforms, otherwise null; the caller shows the model
 * a fixed placeholder instead. (The dashboard still shows the analyst the real
 * value — this only governs what the model reads.)
 */
export function safeIdentifier(value: unknown, kind: IdentifierKind): string | null {
  if (typeof value !== "string" || value === "") return null;
  switch (kind) {
    case "ip": return isIp(value) ? value : null;
    case "host": return value.length <= 255 && HOSTNAME_RE.test(value) ? value : null;
    case "id": return ID_RE.test(value) ? value : null;
    case "mitre": {
      const parts = value.split(/[,\s]+/).filter(Boolean);
      return parts.length > 0 && parts.length <= 20 && parts.every((p) => MITRE_RE.test(p)) ? parts.join(", ") : null;
    }
  }
}

/** What the model is shown for a structured field. */
export function identifierForModel(value: unknown, kind: IdentifierKind, empty = "unknown"): string {
  if (value === null || value === undefined || value === "") return empty;
  return safeIdentifier(value, kind) ?? "(non-standard value omitted)";
}

// --- secrets -----------------------------------------------------------------

interface Rule { id: string; re: RegExp; replace?: (...m: string[]) => string }

/**
 * Formats that are secrets on sight. Deliberately not "any long random-looking
 * string": file hashes and other IOCs are exactly what an analyst needs the
 * model to see, and redacting them would blind it.
 */
const RULES: Rule[] = [
  { id: "private_key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  { id: "url_credentials", re: /(\b[a-z][a-z0-9+.-]*:)?\/\/[^/\s:@]+:[^/\s@]+@/gi, replace: (m, scheme) => `${scheme ?? ""}//[REDACTED:url_credentials]@` },
  { id: "auth_header", re: /\b(?:Bearer|Basic|Token|Digest)\s+[A-Za-z0-9._~+/=-]{6,}/gi },
  { id: "legion_credential", re: /\b(?:lga|lgs)_[0-9a-f]{32}_[A-Za-z0-9_-]{43}\b/g },
  { id: "legion_token", re: /\b(?:lgt|lst)_[A-Za-z0-9_-]{20,}\b/g },
  { id: "webhook_credential", re: /\bwh[ks]_[A-Za-z0-9_-]{20,}\b/g },
  { id: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "github_token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { id: "slack_token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { id: "llm_api_key", re: /\b(?:sk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,})\b/g },
  { id: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "stripe_key", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { id: "sendgrid_key", re: /\bSG\.[\w-]{16,}\.[\w-]{30,}\b/g },
  { id: "npm_token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  // password=..., "api_key": "...", token: ...  — the value is what goes.
  {
    id: "credential_field",
    re: /\b(pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth(?:orization)?|credentials?|session[_-]?(?:id|token)|cookie)\b(["']?\s*[=:]\s*["']?)([^\s"'&;,]+)/gi,
    replace: (_m, key, sep) => `${key}${sep}[REDACTED:credential_field]`,
  },
  // "the password is hunter2", "token was abc123" — how people and some log
  // formats actually write it.
  {
    id: "credential_phrase",
    re: /\b(pass(?:word|wd|phrase)|secret|token|api[ _-]?key)\s+(?:is|was|=|:)\s+([^\s"',;]+)/gi,
    replace: (_m, key) => `${key} [REDACTED:credential_phrase]`,
  },
  // command lines: --password hunter2, --token=abc, --api-key abc
  {
    id: "credential_flag",
    re: /(--(?:password|passwd|pass|token|secret|api-?key|access-?key|client-?secret))(?:=|\s+)(\S+)/gi,
    replace: (_m, flag) => `${flag} [REDACTED:credential_flag]`,
  },
];

/** Every secret this server itself holds, so a copy in alert text or in a
 *  model answer is recognised by value, whatever it is wrapped in. */
function configuredSecrets(): string[] {
  const dbPassword = (() => {
    try { return config.databaseUrl ? decodeURIComponent(new URL(config.databaseUrl).password) : ""; } catch { return ""; }
  })();
  return [
    config.jwtSecret, config.smtpPassword, config.openrouterApiKey, config.groqApiKey, config.webhookSecret,
    config.webhookEncryptionKey, config.paddleApiKey, config.paddleWebhookSecret, config.healthMetricsToken, dbPassword,
  ].filter((s): s is string => typeof s === "string" && s.length >= 8);
}

export interface Redaction { text: string; count: number }

/** Replaces secrets with a marker naming the kind — never the value. */
export function redactSecrets(input: string, extra: string[] = []): Redaction {
  let text = String(input ?? "");
  let count = 0;
  // Exact values first, longest first, so a secret that contains another
  // configured value is removed whole.
  for (const secret of [...configuredSecrets(), ...extra.filter((s) => s.length >= 8)].sort((a, b) => b.length - a.length)) {
    if (text.includes(secret)) {
      const parts = text.split(secret);
      count += parts.length - 1;
      text = parts.join("[REDACTED:configured_secret]");
    }
  }
  for (const rule of RULES) {
    text = text.replace(rule.re, (...m: unknown[]) => {
      count++;
      return rule.replace ? rule.replace(...(m as string[])) : `[REDACTED:${rule.id}]`;
    });
  }
  return { text, count };
}

// --- untrusted OUTPUT --------------------------------------------------------

export type OutputFlag = "html_removed" | "image_removed" | "link_defanged" | "url_defanged" | "secret_redacted" | "truncated" | "hidden_characters";

export type OutputResult =
  | { ok: true; text: string; flags: OutputFlag[] }
  | { ok: false; reason: "not_a_string" | "empty" | "prompt_leak" };

function defang(url: string): string {
  return url.replace(/^http/i, "hxxp").replace(/^ftp/i, "fxp").replace(/\./g, "[.]");
}

/**
 * The model's answer is data derived from attacker-influenced text, so it is
 * treated as such before anyone sees it or it is stored:
 *
 *  - not a string (an object, an array of parts, a number) → rejected;
 *  - hidden characters and control codes removed;
 *  - HTML removed; markdown images removed (an image URL is a way to make a
 *    browser or a chat client send data to a stranger without a click);
 *  - links and URLs defanged (hxxps://evil[.]example) — the SOC convention for
 *    showing an indicator that must not be clickable or auto-loaded;
 *  - anything that looks like a credential redacted, in case one slipped in;
 *  - an answer that quotes the request's own fence or system prompt is rejected
 *    as a prompt leak (`forbid` carries the per-request boundary);
 *  - length capped.
 */
export function sanitizeModelOutput(raw: unknown, opts: { maxChars: number; forbid?: string[] }): OutputResult {
  if (typeof raw !== "string") return { ok: false, reason: "not_a_string" };
  const flags = new Set<OutputFlag>();
  let text = raw;

  const visible = text.replace(INVISIBLE, "").replace(CONTROL, "");
  if (visible !== text) flags.add("hidden_characters");
  text = visible;

  for (const marker of [...(opts.forbid ?? []), "UNTRUSTED DATA"]) {
    if (marker && text.includes(marker)) return { ok: false, reason: "prompt_leak" };
  }

  const before = text;
  text = text.replace(/<!--[\s\S]*?-->/g, "").replace(/<\/?[A-Za-z][^>]*>/g, "");
  if (text !== before) flags.add("html_removed");

  text = text.replace(/!\[[^\]]*\]\([^)]*\)/g, () => { flags.add("image_removed"); return "[image removed]"; });
  text = text.replace(/!\[[^\]]*\]\[[^\]]*\]/g, () => { flags.add("image_removed"); return "[image removed]"; });
  text = text.replace(/\[([^\]]+)\]\(\s*([^)\s]*)[^)]*\)/g, (_m, label: string, url: string) => {
    flags.add("link_defanged");
    return /^(?:https?|ftp):/i.test(url) ? `${label} (${defang(url)})` : `${label} (link removed)`;
  });
  text = text.replace(/\b(?:https?|ftp):\/\/[^\s<>"'`)\]]+/gi, (url) => { flags.add("url_defanged"); return defang(url); });
  text = text.replace(/\b(?:javascript|vbscript|data):[^\s)]*/gi, "[link removed]");

  const redacted = redactSecrets(text);
  if (redacted.count > 0) flags.add("secret_redacted");
  text = redacted.text;

  text = text.replace(/[ \t]+\n/g, "\n").replace(/\n{4,}/g, "\n\n\n").trim();
  if (text.length > opts.maxChars) {
    text = `${clip(text, Math.max(0, opts.maxChars - 1)).trimEnd()}…`;
    flags.add("truncated");
  }
  if (!text) return { ok: false, reason: "empty" };
  return { ok: true, text, flags: [...flags] };
}

// --- pseudonymisation (strict data mode) -------------------------------------

/**
 * Reversible placeholders for the identifiers a provider has no need to see:
 * IP addresses, e-mail addresses and the hostnames of the assets involved.
 * The model reasons about IP_1 and HOST_2; the analyst reads the real values,
 * because the placeholders are swapped back in the answer.
 *
 * One instance per request. The mapping lives only in memory for the duration
 * of that request: it is not stored and never sent.
 */
export class Pseudonymizer {
  private readonly forward = new Map<string, string>();
  private readonly back = new Map<string, string>();
  private readonly counters = { IP: 0, EMAIL: 0, HOST: 0 };
  private readonly hostPatterns: RegExp[];

  constructor(hostnames: string[] = []) {
    const uniq = [...new Set(hostnames.filter((h) => h.length >= 2))].sort((a, b) => b.length - a.length);
    // The whole name including any domain suffix (web-01.corp.local) is one
    // token, so masking a short hostname never leaves its domain behind.
    this.hostPatterns = uniq.map((h) => new RegExp(`(?<![A-Za-z0-9._-])${h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:\\.[A-Za-z0-9-]+)*(?![A-Za-z0-9_-])`, "gi"));
  }

  private token(kind: "IP" | "EMAIL" | "HOST", value: string): string {
    const key = `${kind}:${value.toLowerCase()}`;
    const existing = this.forward.get(key);
    if (existing) return existing;
    const t = `${kind}_${++this.counters[kind]}`;
    this.forward.set(key, t);
    this.back.set(t, value);
    return t;
  }

  mask(text: string): string {
    let out = String(text ?? "");
    out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g, (m) => this.token("EMAIL", m));
    out = out.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (m) => (isIPv4(m) ? this.token("IP", m) : m));
    // Candidates are runs of hex digits and colons; isIPv6 decides, so compressed
    // forms (2001:db8::5, ::1) are caught and clock times (10:22:33) are not.
    out = out.replace(/(?<![A-Za-z0-9:])[0-9A-Fa-f:]{2,45}(?![A-Za-z0-9:])/g, (m) => (m.split(":").length > 2 && isIPv6(m) ? this.token("IP", m) : m));
    for (const re of this.hostPatterns) out = out.replace(re, (m) => this.token("HOST", m));
    return out;
  }

  /** Only tokens this instance issued are swapped back; anything else the
   *  model writes that merely looks like one is left alone. */
  unmask(text: string): string {
    return String(text ?? "").replace(/\b(?:IP|EMAIL|HOST)_\d+\b/g, (t) => this.back.get(t) ?? t);
  }

  get size(): number { return this.back.size; }
}
