/**
 * Authenticated encryption for secrets Legion must be able to read back —
 * TOTP seeds (the server recomputes codes) and webhook signing secrets (the
 * server recomputes signatures). Anything that only needs to be COMPARED
 * (passwords, reset/invite/verify tokens, refresh tokens, API credentials) is
 * hashed instead and never comes through here.
 *
 *   sealed = "lsb1.<keyId>.<iv>.<tag>.<ciphertext>"     (base64url parts)
 *
 *  - AES-256-GCM, a fresh 96-bit IV per seal;
 *  - the key is a per-PURPOSE subkey (HKDF-SHA256) of the keyring entry, so one
 *    key never encrypts two kinds of secret under the same key;
 *  - the purpose and the owning record (e.g. the user id) are bound in as
 *    associated data: a ciphertext copied to another user's row, or used as
 *    another kind of secret, does not decrypt;
 *  - the key id is in the ciphertext, so keys can be rotated: add a new key as
 *    active, keep the old one until secrets-migration.ts has re-encrypted
 *    everything, then remove it;
 *  - `open` never throws and never echoes its input: wrong key, unknown key,
 *    tampering, truncation and garbage all return null, and the caller fails
 *    closed.
 *
 * The keyring comes from LEGION_ENCRYPTION_KEYS (keyring-parse.ts) — a key used
 * for nothing else, kept out of the database and its backups. Development and
 * test runs without one fall back to a key derived from JWT_SECRET (id "dev");
 * config.ts refuses to start any other deployment without a real keyring.
 * The "dev" key stays available for DECRYPTION even once a real keyring is
 * configured, so an install that started without one is migrated rather than
 * locked out (secrets-migration.ts re-encrypts under the real key at boot).
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { config } from "./config.js";
import { parseKeyring } from "./keyring-parse.js";

export type SecretPurpose = "mfa-totp" | "webhook-secret";

const FORMAT = "lsb1";
const DEV_KEY_ID = "dev";

interface Keyring {
  keys: Map<string, Buffer>;
  active: string;
  source: "configured" | "dev";
}

let cached: { spec: string; activeId: string; jwt: string; ring: Keyring } | null = null;

function devKey(): Buffer {
  return Buffer.from(hkdfSync("sha256", config.jwtSecret, "legion-dev-encryption-key", "legion secret box dev key v1", 32));
}

/** The current keyring. Re-read when the configuration changes (tests do that). */
export function keyring(): Keyring {
  const spec = config.encryptionKeys;
  const activeId = config.encryptionKeyActive;
  if (cached && cached.spec === spec && cached.activeId === activeId && cached.jwt === config.jwtSecret) return cached.ring;

  let ring: Keyring;
  if (spec.trim()) {
    const parsed = parseKeyring(spec, activeId);
    if (!parsed.ok) throw new Error(parsed.error); // config.ts already refused to boot on this
    const keys = new Map(parsed.keyring.keys);
    if (!keys.has(DEV_KEY_ID)) keys.set(DEV_KEY_ID, devKey()); // decrypt-only legacy key
    ring = { keys, active: parsed.keyring.active, source: "configured" };
  } else {
    ring = { keys: new Map([[DEV_KEY_ID, devKey()]]), active: DEV_KEY_ID, source: "dev" };
  }
  cached = { spec, activeId, jwt: config.jwtSecret, ring };
  return ring;
}

function subkey(master: Buffer, purpose: SecretPurpose): Buffer {
  return Buffer.from(hkdfSync("sha256", master, "legion-secret-box-v1", `purpose:${purpose}`, 32));
}

const aad = (purpose: SecretPurpose, context: string) => Buffer.from(`legion:${purpose}:${context}`, "utf8");

export function seal(plaintext: string, purpose: SecretPurpose, context: string): string {
  const ring = keyring();
  const master = ring.keys.get(ring.active)!;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", subkey(master, purpose), iv);
  cipher.setAAD(aad(purpose, context));
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return [FORMAT, ring.active, iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), body.toString("base64url")].join(".");
}

const B64URL = /^[A-Za-z0-9_-]+$/;

export function open(sealed: unknown, purpose: SecretPurpose, context: string): string | null {
  try {
    if (typeof sealed !== "string" || sealed.length > 4096) return null;
    const parts = sealed.split(".");
    if (parts.length !== 5 || parts[0] !== FORMAT) return null;
    const [, keyId, ivB64, tagB64, bodyB64] = parts as [string, string, string, string, string];
    if (!B64URL.test(ivB64) || !B64URL.test(tagB64) || (bodyB64 !== "" && !B64URL.test(bodyB64))) return null;
    const master = keyring().keys.get(keyId);
    if (!master) return null;
    const iv = Buffer.from(ivB64, "base64url");
    const tag = Buffer.from(tagB64, "base64url");
    if (iv.length !== 12 || tag.length !== 16) return null;
    const decipher = createDecipheriv("aes-256-gcm", subkey(master, purpose), iv, { authTagLength: 16 });
    decipher.setAAD(aad(purpose, context));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(bodyB64, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

/** The key id a sealed value was written with, or null if it is not one. */
export function keyIdOf(sealed: unknown): string | null {
  if (typeof sealed !== "string" || !sealed.startsWith(`${FORMAT}.`)) return null;
  return sealed.split(".")[1] ?? null;
}

export const isSealed = (v: unknown): v is string => keyIdOf(v) !== null;

/** Written with a key other than the active one: due for re-encryption. */
export function needsRotation(sealed: unknown): boolean {
  const id = keyIdOf(sealed);
  return id !== null && id !== keyring().active;
}

/** What an operator may know about the keyring: ids, never key material. */
export function keyringStatus(): { active: string; ids: string[]; source: "configured" | "dev" } {
  const ring = keyring();
  return { active: ring.active, ids: [...ring.keys.keys()], source: ring.source };
}
