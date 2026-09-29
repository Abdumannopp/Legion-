/**
 * Parses LEGION_ENCRYPTION_KEYS. No imports, so config.ts can validate the
 * keyring at boot without a circular dependency on secret-box.ts.
 *
 *   LEGION_ENCRYPTION_KEYS="k2026b:<key>,k2026a:<key>"
 *   LEGION_ENCRYPTION_KEY_ID="k2026b"      (optional; default: the first)
 *
 * <key> is 32 random bytes as 64 hex characters or as base64/base64url
 * (`openssl rand -hex 32`). The id is written into every ciphertext, so an old
 * key can be kept for decryption after a new one becomes active.
 *
 * Error messages name the entry by position and id only — never the key.
 */
export interface ParsedKeyring {
  keys: Map<string, Buffer>;
  active: string;
}

export const KEY_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

function decodeKey(value: string): Buffer | null {
  if (/^[0-9a-fA-F]{64}$/.test(value)) return Buffer.from(value, "hex");
  if (/^[A-Za-z0-9+/_-]{43}={0,1}$/.test(value)) {
    const b = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
    return b.length === 32 ? b : null;
  }
  return null;
}

export function parseKeyring(spec: string, activeId = ""): { ok: true; keyring: ParsedKeyring } | { ok: false; error: string } {
  const entries = spec.split(",").map((s) => s.trim()).filter(Boolean);
  if (entries.length === 0) return { ok: false, error: "LEGION_ENCRYPTION_KEYS is empty" };
  const keys = new Map<string, Buffer>();
  for (const [i, entry] of entries.entries()) {
    const colon = entry.indexOf(":");
    const id = colon > 0 ? entry.slice(0, colon) : "";
    if (!KEY_ID_RE.test(id)) return { ok: false, error: `LEGION_ENCRYPTION_KEYS entry ${i + 1}: expected "<id>:<key>" with an id of 1-32 letters, digits, - or _` };
    if (keys.has(id)) return { ok: false, error: `LEGION_ENCRYPTION_KEYS: key id "${id}" appears twice` };
    const key = decodeKey(entry.slice(colon + 1));
    if (!key) return { ok: false, error: `LEGION_ENCRYPTION_KEYS: key "${id}" must be 32 random bytes as 64 hex characters or base64 (openssl rand -hex 32)` };
    if (key.every((b) => b === key[0])) return { ok: false, error: `LEGION_ENCRYPTION_KEYS: key "${id}" is not random` };
    keys.set(id, key);
  }
  const active = activeId.trim() || entries[0]!.slice(0, entries[0]!.indexOf(":"));
  if (!keys.has(active)) return { ok: false, error: `LEGION_ENCRYPTION_KEY_ID "${active}" is not one of the ids in LEGION_ENCRYPTION_KEYS` };
  return { ok: true, keyring: { keys, active } };
}
