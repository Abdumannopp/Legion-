import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { MachineKind } from "./types.js";

/*
 * Two kinds of secret, deliberately distinct:
 *
 * Credential   lga_<credential id>_<secret>   (AI agent)
 *              lgs_<credential id>_<secret>   (service account)
 *   Long-lived. Accepted ONLY by the token endpoint. The id part lets the
 *   server find the row; the secret part is compared by hash.
 *
 * Access token lgt_<secret>
 *   Short-lived (minutes). What every other request carries. Looked up by its
 *   hash, which is the primary key.
 *
 * Both secrets are 256 random bits, so a fast hash (SHA-256) is the right
 * storage: nothing to brute-force, and verification runs on every request.
 * Neither value is ever stored or logged in the clear.
 *
 * The prefixes also let secret scanners (GitHub, gitleaks) recognise a leaked
 * Legion key.
 */

const CREDENTIAL_PREFIX: Record<MachineKind, string> = { ai_agent: "lga", service_account: "lgs" };
const CREDENTIAL_RE = /^(lga|lgs)_([0-9a-f]{32})_([A-Za-z0-9_-]{43})$/;
const ACCESS_TOKEN_RE = /^lgt_([A-Za-z0-9_-]{43})$/;

export function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function randomSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function newCredential(kind: MachineKind, credentialId: string): { secret: string; hash: Buffer } {
  const secret = randomSecret();
  return {
    secret: `${CREDENTIAL_PREFIX[kind]}_${credentialId.replaceAll("-", "")}_${secret}`,
    hash: sha256(secret),
  };
}

export interface ParsedCredential {
  kind: MachineKind;
  credentialId: string;
  secretHash: Buffer;
}

export function parseCredential(value: string): ParsedCredential | null {
  const m = CREDENTIAL_RE.exec(value);
  if (!m) return null;
  const hex = m[2]!;
  return {
    kind: m[1] === "lga" ? "ai_agent" : "service_account",
    credentialId: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    secretHash: sha256(m[3]!),
  };
}

export function newAccessToken(): { token: string; hash: Buffer } {
  const secret = randomSecret();
  return { token: `lgt_${secret}`, hash: sha256(secret) };
}

export function parseAccessToken(value: string): Buffer | null {
  const m = ACCESS_TOKEN_RE.exec(value);
  return m ? sha256(m[1]!) : null;
}

/** Does this bearer value look like any Legion machine secret, valid or not? */
export function looksLikeMachineSecret(value: string): "credential" | "access_token" | null {
  if (/^(lga|lgs)_/.test(value)) return "credential";
  if (value.startsWith("lgt_")) return "access_token";
  return null;
}
