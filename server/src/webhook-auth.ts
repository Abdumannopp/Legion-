/**
 * Authentication primitives for sensor webhooks (Wazuh and anything speaking
 * the same shape). Pure functions only; the database side — looking up the
 * credential, remembering nonces — is in webhook-credentials.ts.
 *
 * History, so the reasons stay visible:
 *
 *   1. A fixed header, HMAC(secret, tenant_id). Never changed, covered none of
 *      the message: seeing one request was enough to forge alerts forever.
 *   2. A per-tenant KEY derived from one server-wide secret, used to sign
 *      "<timestamp>.<body>". Better — but the tenant was still named by an
 *      unauthenticated `x-tenant-id` header, every tenant's key was one
 *      global secret away, there was no way to rotate or revoke one tenant
 *      without changing all of them, and a replay inside the time window was
 *      accepted (only absorbed later by alert-id dedup).
 *   3. This. Each credential is its own 256 random bits, chosen by nobody and
 *      derived from nothing.
 *
 * A request carries
 *
 *   x-legion-key-id     public identifier of the credential; selects the row,
 *                       and through it the tenant
 *   x-legion-timestamp  Unix seconds
 *   x-legion-nonce      random, single use per credential
 *   x-legion-signature  "v2=" + hex(HMAC-SHA256(secret,
 *                                   "v2.<timestamp>.<nonce>." + raw body bytes))
 *
 * The signature covers the exact bytes that were sent, the time and the
 * nonce, so none of the three can be changed without invalidating it. The
 * server-side rules that make it safe:
 *
 *   - the tenant is whatever the credential belongs to, never a header;
 *   - a stale or future timestamp is refused before any database work;
 *   - the signature is compared in constant time, and an unknown key costs the
 *     same HMAC as a known one so response time does not reveal which key ids
 *     exist;
 *   - the nonce is recorded only AFTER the signature checks out, so someone
 *     without a secret cannot fill the nonce table.
 */
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";
import { isSealed, open, seal } from "./secret-box.js";

export const SIGNATURE_VERSION = "v2";

export const KEY_ID_PREFIX = "whk_";
export const SECRET_PREFIX = "whs_";

const KEY_ID_RE = /^whk_[A-Za-z0-9_-]{22}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const TIMESTAMP_RE = /^\d{9,12}$/;
const SIGNATURE_RE = /^v2=([0-9a-f]{64})$/;

export const isKeyId = (value: unknown): value is string => typeof value === "string" && KEY_ID_RE.test(value);

// --- credentials -------------------------------------------------------------

/** A new credential: a public id and 256 random bits. Nothing is derived. */
export function generateCredential(): { keyId: string; secret: string } {
  return {
    keyId: KEY_ID_PREFIX + randomBytes(16).toString("base64url"),
    secret: SECRET_PREFIX + randomBytes(32).toString("base64url"),
  };
}

/** The value an operator pastes into ossec.conf's <api_key>. */
export const formatApiKey = (keyId: string, secret: string): string => `${keyId}:${secret}`;

// --- encryption at rest ------------------------------------------------------
// On the shared, versioned keyring (secret-box.ts), bound to the credential's
// key id: a ciphertext copied onto another credential's row does not decrypt.

/** The first format, "v1.<iv>.<tag>.<ct>", under a key derived from
 *  WEBHOOK_ENCRYPTION_KEY or JWT_SECRET. Read-only: kept so credentials created
 *  before the keyring still work until secrets-migration.ts re-encrypts them. */
function legacyKey(): Buffer {
  const ikm = config.webhookEncryptionKey || config.jwtSecret;
  return Buffer.from(hkdfSync("sha256", ikm, "legion-webhook-kek-salt", "legion webhook secret encryption v1", 32));
}

function legacyDecrypt(stored: string, keyId: string): string | null {
  try {
    const [version, iv, tag, body] = stored.split(".");
    if (version !== "v1" || !iv || !tag || !body) return null;
    const decipher = createDecipheriv("aes-256-gcm", legacyKey(), Buffer.from(iv, "base64url"));
    decipher.setAAD(Buffer.from(keyId));
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([decipher.update(Buffer.from(body, "base64url")), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

/** For tests of the upgrade path only: writes the old format. */
export function legacyEncryptForTests(secret: string, keyId: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", legacyKey(), iv);
  cipher.setAAD(Buffer.from(keyId));
  const body = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), body.toString("base64url")].join(".");
}

export function encryptSecret(secret: string, keyId: string): string {
  return seal(secret, "webhook-secret", keyId);
}

/** Returns null — never throws, never echoes the input — if it cannot be
 *  decrypted (wrong key, tampered, wrong row). The caller fails closed. */
export function decryptSecret(stored: string, keyId: string): string | null {
  return isSealed(stored) ? open(stored, "webhook-secret", keyId) : legacyDecrypt(stored, keyId);
}

// --- signing -----------------------------------------------------------------

/** Raw HMAC-SHA256 digest over "v2.<timestamp>.<nonce>." + the body bytes. */
export function computeSignature(secret: string, timestamp: string, nonce: string, rawBody: Buffer | string): Buffer {
  const mac = createHmac("sha256", secret);
  mac.update(`${SIGNATURE_VERSION}.${timestamp}.${nonce}.`);
  mac.update(rawBody);
  return mac.digest();
}

/** The x-legion-signature header value. Mirrors integrations/custom-legion.py. */
export function signWebhook(secret: string, timestamp: string, nonce: string, rawBody: Buffer | string): string {
  return `${SIGNATURE_VERSION}=${computeSignature(secret, timestamp, nonce, rawBody).toString("hex")}`;
}

/** Constant-time comparison of two digests. Lengths are public (both are 32
 *  bytes for anything well-formed), so an early length check leaks nothing. */
export function digestsEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

// --- request parsing ---------------------------------------------------------

export interface WebhookHeaders {
  keyId: string;
  timestamp: string;
  nonce: string;
  signature: Buffer;
}

export type RejectionReason = "legacy" | "missing" | "malformed" | "no-body" | "stale" | "invalid" | "replay";

export type ParseResult =
  | { ok: true; headers: WebhookHeaders }
  | { ok: false; reason: Exclude<RejectionReason, "invalid" | "replay"> };

/**
 * Checks shape and freshness only — no secrets, no database. Everything the
 * sender controls is validated against a strict pattern here, which is also
 * what keeps attacker-chosen text out of the logs.
 */
export function parseWebhookHeaders(input: {
  header: (name: string) => string | undefined;
  rawBody: Buffer | undefined;
  nowSeconds?: number;
  maxSkewSeconds?: number;
}): ParseResult {
  const keyId = input.header("x-legion-key-id");
  const timestamp = input.header("x-legion-timestamp");
  const nonce = input.header("x-legion-nonce");
  const signature = input.header("x-legion-signature");

  if (!keyId) {
    // The two earlier schemes identified the tenant instead of a credential.
    // Say so plainly — an operator reading the Wazuh log needs to know the
    // integration script is out of date — but never accept them.
    const oldScheme = input.header("x-tenant-id") || input.header("x-security-event-secret") || signature?.startsWith("v1=");
    return { ok: false, reason: oldScheme ? "legacy" : "missing" };
  }
  if (!timestamp || !nonce || !signature) return { ok: false, reason: "missing" };

  const sig = SIGNATURE_RE.exec(signature);
  if (!isKeyId(keyId) || !TIMESTAMP_RE.test(timestamp) || !NONCE_RE.test(nonce) || !sig) {
    return { ok: false, reason: "malformed" };
  }
  // Only JSON bodies keep their raw bytes; anything else has nothing to verify
  // against and is refused rather than trusted.
  if (!input.rawBody) return { ok: false, reason: "no-body" };

  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const skew = input.maxSkewSeconds ?? config.webhookMaxSkewSeconds;
  if (Math.abs(now - Number(timestamp)) > skew) return { ok: false, reason: "stale" };

  return { ok: true, headers: { keyId, timestamp, nonce, signature: Buffer.from(sig[1]!, "hex") } };
}

/** Human-readable reasons, returned to the sender so an operator reading the
 *  Wazuh integration log can tell what to fix. Deliberately coarse for
 *  anything that concerns the credential itself: an unknown, revoked, expired
 *  or wrongly-signed request all read the same. */
export const WEBHOOK_REJECTION_DETAIL: Record<RejectionReason, string> = {
  legacy:
    "This integration script is out of date: it identifies the organisation instead of using a per-organisation credential. " +
    "Create a webhook credential (Legion administrator) and install the current integrations/custom-legion.py on the Wazuh manager.",
  missing: "Missing x-legion-key-id, x-legion-timestamp, x-legion-nonce or x-legion-signature header",
  malformed: "Malformed webhook authentication headers",
  "no-body": "Webhook body must be JSON (Content-Type: application/json)",
  stale: "Timestamp is malformed or too far from this server's clock",
  invalid: "Invalid webhook credentials",
  replay: "This request was already received",
};
