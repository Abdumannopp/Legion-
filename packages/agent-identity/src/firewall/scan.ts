import { createHash } from "node:crypto";
import { canonical } from "../chain.js";

/*
 * Deterministic content checks on anything leaving Legion through an agent:
 * egress bodies, tool and MCP arguments, agent-to-agent messages.
 * High-confidence secret formats only — a match blocks outright.
 */
const SECRET_PATTERNS: { id: string; re: RegExp }[] = [
  { id: "legion_credential", re: /\b(?:lga|lgs)_[0-9a-f]{32}_[A-Za-z0-9_-]{43}\b/ },
  { id: "legion_access_token", re: /\blgt_[A-Za-z0-9_-]{43}\b/ },
  { id: "private_key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/ },
  { id: "aws_access_key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: "github_token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { id: "slack_token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/ },
  { id: "llm_api_key", re: /\b(?:sk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_-]{32,}|gsk_[A-Za-z0-9]{40,})\b/ },
  { id: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/ },
];

function flatten(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 20) return out;
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) value.forEach((v) => flatten(v, out, depth + 1));
  else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      out.push(k);
      flatten(v, out, depth + 1);
    }
  } else if (value !== undefined && value !== null) out.push(String(value));
  return out;
}

export function findSecrets(value: unknown): string[] {
  const text = flatten(value).join("\n");
  return SECRET_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.id);
}

/**
 * Replaces each secret found in a string with a marker naming its kind,
 * keeping the rest of the text (unlike redact(), which drops the whole
 * value). Used where text must stay readable: skill results and reports.
 */
export function maskSecrets(text: string): string {
  // A private key is the whole block, not just its header line.
  let out = text.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[REDACTED:private_key]");
  for (const p of SECRET_PATTERNS) out = out.replace(new RegExp(p.re.source, "g"), `[REDACTED:${p.id}]`);
  return out;
}

const URL_RE = /\bhttps?:\/\/[^\s"'<>]+/gi;
export function findUrls(value: unknown): string[] {
  return [...new Set(flatten(value).flatMap((s) => s.match(URL_RE) ?? []))].slice(0, 50);
}

export function byteSize(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value ?? null), "utf8");
}

/**
 * What the decision log keeps about arguments: their shape and a digest,
 * never full values. Strings are cut to 64 characters and any string that
 * matches a secret pattern is replaced entirely.
 */
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 4) return "[…]";
  if (typeof value === "string") {
    if (findSecrets(value).length) return "[REDACTED]";
    return value.length > 64 ? `${value.slice(0, 64)}…(${value.length})` : value;
  }
  if (Array.isArray(value)) return value.slice(0, 10).map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).slice(0, 30).map(([k, v]) => [k, redact(v, depth + 1)]));
  }
  return value;
}

export function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value ?? null)).digest("hex");
}

/**
 * Canonical fingerprint of an MCP tool definition (name, description, input
 * schema). Pin it in the policy; if the server later changes what the tool
 * says or accepts ("rug pull", tool poisoning), the hash no longer matches.
 */
export function hashToolDefinition(def: { name: string; description?: string; inputSchema?: unknown }): string {
  return digest({ name: def.name, description: def.description ?? "", inputSchema: def.inputSchema ?? null });
}
