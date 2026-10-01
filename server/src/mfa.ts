/**
 * Two-factor authentication (TOTP, RFC 6238).
 *
 * Legion tells customers to "enforce MFA" when it sees a credential alert.
 * Shipping a security product that cannot do it itself is not defensible, and
 * it is the first item on every vendor security questionnaire.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { comparePassword, hashPassword } from "./passwords.js";
import * as OTPAuth from "otpauth";
import { config } from "./config.js";
import { query, queryAll, queryOne, transaction } from "./db/pool.js";
import { keyIdOf, needsRotation, open, seal } from "./secret-box.js";
import type { User } from "./types.js";

const PERIOD = 30;
const DIGITS = 6;
/** Accept the neighbouring steps so a slightly wrong device clock still works.
 *  1 = ±30s. Larger windows widen the guessing surface for no real gain. */
const WINDOW = 1;
const RECOVERY_CODE_COUNT = 10;

function totp(secret: string, email: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: config.mfaIssuer,
    label: email,
    algorithm: "SHA1", // What every authenticator app implements.
    digits: DIGITS,
    period: PERIOD,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

export function generateSecret(): string {
  // 20 bytes = 160 bits, the RFC 4226 recommendation.
  return new OTPAuth.Secret({ size: 20 }).base32;
}

// --- the seed at rest -----------------------------------------------------------

const PURPOSE = "mfa-totp" as const;
/** Base32 alphabet only: a decrypted value that is not one is not a seed. */
const BASE32 = /^[A-Z2-7]+=*$/;

export const sealSecret = (userId: string, secret: string): string => seal(secret, PURPOSE, userId);

export type SeedResult =
  | { ok: true; secret: string }
  /** No seed at all: MFA was never set up (or was disabled). */
  | { ok: false; reason: "none" }
  /** A seed exists but cannot be read — wrong/removed key, or tampering.
   *  NEVER treat this as "no MFA": the caller must refuse, not skip the check. */
  | { ok: false; reason: "unreadable"; keyId: string | null };

/**
 * The user's TOTP seed, decrypted. Also tidies up on the way:
 *  - a legacy PLAINTEXT seed (from before encryption at rest, or written by an
 *    older instance during a rolling upgrade) is returned and encrypted in place;
 *  - a seed under a no-longer-active key is re-encrypted under the active one.
 * Both writes are compare-and-swap on the old value, so a concurrent enrolment
 * or disable is never overwritten, and neither is required for the answer.
 */
export async function secretFor(user: Pick<User, "id" | "mfa_secret_enc" | "mfa_secret_legacy">): Promise<SeedResult> {
  // A plaintext seed can only have been written by code that predates
  // encryption (new code never writes it), so if both exist it is the newer.
  if (user.mfa_secret_legacy) {
    const secret = user.mfa_secret_legacy;
    await query(
      "UPDATE users SET mfa_secret_enc = $2, mfa_secret = NULL WHERE id = $1 AND mfa_secret = $3",
      [user.id, sealSecret(user.id, secret), secret]
    ).catch(() => { /* converted at the next boot instead */ });
    return { ok: true, secret };
  }
  if (!user.mfa_secret_enc) return { ok: false, reason: "none" };

  const secret = open(user.mfa_secret_enc, PURPOSE, user.id);
  if (secret === null || !BASE32.test(secret)) {
    // Identify the key, never the value: this is what an operator needs.
    console.error(`Legion: the two-factor secret of user ${user.id} cannot be decrypted (key "${keyIdOf(user.mfa_secret_enc) ?? "unknown"}"). Check LEGION_ENCRYPTION_KEYS; MFA stays enabled and sign-in is refused.`);
    return { ok: false, reason: "unreadable", keyId: keyIdOf(user.mfa_secret_enc) };
  }
  if (needsRotation(user.mfa_secret_enc)) {
    await query(
      "UPDATE users SET mfa_secret_enc = $2 WHERE id = $1 AND mfa_secret_enc = $3",
      [user.id, sealSecret(user.id, secret), user.mfa_secret_enc]
    ).catch(() => { /* re-encrypted at the next boot instead */ });
  }
  return { ok: true, secret };
}

/** Starts (or restarts) enrolment with a fresh seed, stored sealed. Returns the
 *  seed so it can be shown to the user ONCE, to scan. Refuses — returns null —
 *  if MFA is already on: re-running setup must never replace a working seed. */
export async function beginEnrolment(userId: string): Promise<string | null> {
  const secret = generateSecret();
  const row = await queryOne(
    "UPDATE users SET mfa_secret_enc = $2, mfa_secret = NULL WHERE id = $1 AND mfa_enabled = false RETURNING id",
    [userId, sealSecret(userId, secret)]
  );
  return row ? secret : null;
}

/** The otpauth:// URI an authenticator app consumes, usually via QR code. */
export function provisioningUri(secret: string, email: string): string {
  return totp(secret, email).toString();
}

/**
 * Verifies a code and consumes its counter so it cannot be replayed.
 *
 * Returns false both for a wrong code and for a correct code that has already
 * been used — a code observed in transit is otherwise valid for the rest of
 * its step.
 */
export async function verifyCode(
  userId: string,
  secret: string,
  email: string,
  token: string
): Promise<boolean> {
  const cleaned = token.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(cleaned)) return false;

  // delta is the offset in steps from now: 0 = current, -1 = previous.
  const delta = totp(secret, email).validate({ token: cleaned, window: WINDOW });
  if (delta === null) return false;

  const counter = Math.floor(Date.now() / 1000 / PERIOD) + delta;

  // The insert is the check: a duplicate counter means this code was already
  // spent. Doing it in one statement leaves no window for two concurrent
  // requests to both accept the same code.
  const result = await query(
    `INSERT INTO mfa_used_counters (user_id, counter) VALUES ($1, $2)
     ON CONFLICT (user_id, counter) DO NOTHING`,
    [userId, counter]
  );
  if (result.rowCount === 0) return false;

  // Old counters can never be replayed anyway — the code no longer validates.
  await query(
    "DELETE FROM mfa_used_counters WHERE user_id = $1 AND created_at < now() - interval '10 minutes'",
    [userId]
  ).catch(() => { /* housekeeping only */ });

  return true;
}

/** Human-friendly recovery codes: unambiguous alphabet, grouped for reading. */
function newRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/0/1
  const bytes = randomBytes(10);
  let out = "";
  for (let i = 0; i < 10; i++) {
    out += alphabet.charAt(bytes[i]! % alphabet.length);
    if (i === 4) out += "-";
  }
  return out;
}

/**
 * Replaces every recovery code with a fresh set and returns the plaintext.
 *
 * This is the only moment the codes exist in readable form — only hashes are
 * stored, exactly as for passwords, so a database leak does not hand over a
 * way past MFA.
 */
export async function regenerateRecoveryCodes(userId: string): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, newRecoveryCode);
  // Cost 10 rather than 12: a login may verify against all ten hashes in turn,
  // and these are 50-bit random strings, not user-chosen passwords.
  // One after another: ten at once would take a whole hashing queue slot each.
  const hashes: string[] = [];
  for (const code of codes) hashes.push(await hashPassword(code, 10));

  await transaction(async (client) => {
    await client.query("DELETE FROM mfa_recovery_codes WHERE user_id = $1", [userId]);
    for (const hash of hashes) {
      await client.query(
        "INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)",
        [randomUUID(), userId, hash]
      );
    }
  });

  return codes;
}

/** Spends a recovery code. Each one works exactly once. */
export async function consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
  const cleaned = code.trim().toUpperCase();
  if (!cleaned) return false;

  const rows = await queryAll<{ id: string; code_hash: string }>(
    "SELECT id, code_hash FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    [userId]
  );

  for (const row of rows) {
    if (!(await comparePassword(cleaned, row.code_hash))) continue;
    // Conditional update: if a concurrent request just spent this code, the
    // WHERE clause matches nothing and this attempt correctly fails.
    const claimed = await queryOne(
      "UPDATE mfa_recovery_codes SET used_at = now() WHERE id = $1 AND used_at IS NULL RETURNING id",
      [row.id]
    );
    return claimed !== null;
  }
  return false;
}

export async function countRecoveryCodes(userId: string): Promise<number> {
  const row = await queryOne<{ count: number }>(
    "SELECT count(*)::bigint AS count FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
    [userId]
  );
  return Number(row?.count ?? 0);
}

export async function disableMfa(userId: string): Promise<void> {
  await transaction(async (client) => {
    await client.query(
      "UPDATE users SET mfa_enabled = false, mfa_secret = NULL, mfa_secret_enc = NULL, mfa_enrolled_at = NULL WHERE id = $1",
      [userId]
    );
    await client.query("DELETE FROM mfa_recovery_codes WHERE user_id = $1", [userId]);
    await client.query("DELETE FROM mfa_used_counters WHERE user_id = $1", [userId]);
  });
}
