import { createHash } from "node:crypto";

/** JSON with object keys sorted at every level: equal values give equal text. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[k];
      if (v !== undefined) out[k] = sortKeys(v);
    }
    return out;
  }
  return value;
}

export const sha256Hex = (text: string): string => createHash("sha256").update(text).digest("hex");

/** Digest of a value's canonical form: identical inputs always digest identically. */
export const digestOf = (value: unknown): string => sha256Hex(canonicalJson(value));
