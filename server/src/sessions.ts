/**
 * Refresh-token sessions.
 *
 * Legion's access token used to last an hour with no way to renew it, so a SOC
 * analyst watching the dashboard through a shift was signed out every hour.
 * Simply extending the lifetime would have been worse: a stateless JWT cannot
 * be revoked, so a long one is a long-lived key that survives password changes
 * and deactivation until it expires.
 *
 * Instead: a short access token (minutes) plus a long refresh token that is
 * stored, rotated on every use, and revocable.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { config } from "./config.js";
import { query, queryOne, transaction } from "./db/pool.js";

export interface RefreshRecord {
  id: string;
  user_id: string;
  family_id: string;
  expires_at: string;
  rotated_at: string | null;
  revoked_at: string | null;
}

/**
 * SHA-256, not bcrypt.
 *
 * The token is 256 bits of randomness from a CSPRNG, so there is nothing to
 * brute-force and no need for a slow hash — and refresh runs on every page
 * load, where bcrypt's cost would be felt. Bcrypt is for passwords, which are
 * low-entropy and human-chosen.
 */
function hash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function newToken(): string {
  return randomBytes(32).toString("base64url");
}

const expiryDate = (): Date => new Date(Date.now() + config.refreshTokenDays * 86_400_000);

/** Starts a new session family — one per login. */
export async function issue(
  userId: string,
  meta: { userAgent?: string | null; ip?: string | null } = {}
): Promise<string> {
  const token = newToken();
  await query(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, user_agent, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      randomUUID(), userId, hash(token), randomUUID(), expiryDate(),
      meta.userAgent?.slice(0, 300) || null, meta.ip || null,
    ]
  );
  return token;
}

export type RotateResult =
  | { ok: true; token: string; userId: string }
  | { ok: false; reason: "unknown" | "expired" | "revoked" | "reused" };

/**
 * Exchanges a refresh token for a fresh one.
 *
 * Rotation means each token works exactly once. If a token that has already
 * been rotated is presented again, two parties hold it — the legitimate client
 * and a thief — and there is no way to tell which is which, so the entire
 * family is revoked and both must log in again. That converts silent, ongoing
 * account access into one visible logout.
 */
export async function rotate(
  presented: string,
  meta: { userAgent?: string | null; ip?: string | null } = {}
): Promise<RotateResult> {
  const presentedHash = hash(presented);

  return transaction(async (client) => {
    // FOR UPDATE: two tabs refreshing at once would otherwise both read the
    // un-rotated row and both succeed, and the loser's new token would be
    // orphaned.
    const found = await client.query<RefreshRecord>(
      "SELECT * FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE",
      [presentedHash]
    );
    const record = found.rows[0];
    if (!record) return { ok: false, reason: "unknown" as const };

    if (record.revoked_at) return { ok: false, reason: "revoked" as const };

    if (record.rotated_at) {
      // Replay of a spent token: assume compromise and kill the family.
      await client.query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL",
        [record.family_id]
      );
      return { ok: false, reason: "reused" as const };
    }

    if (new Date(record.expires_at) <= new Date()) {
      return { ok: false, reason: "expired" as const };
    }

    await client.query("UPDATE refresh_tokens SET rotated_at = now() WHERE id = $1", [record.id]);

    const token = newToken();
    await client.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, user_agent, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        randomUUID(), record.user_id, hash(token), record.family_id, expiryDate(),
        meta.userAgent?.slice(0, 300) || null, meta.ip || null,
      ]
    );

    return { ok: true, token, userId: record.user_id };
  });
}

/** Revokes one token and everything else from the same login. */
export async function revoke(presented: string): Promise<void> {
  await query(
    `UPDATE refresh_tokens SET revoked_at = now()
     WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
       AND revoked_at IS NULL`,
    [hash(presented)]
  );
}

/** Revokes every session a user has. Used when a password changes, a role
 *  changes, or an account is deactivated. */
export async function revokeAllForUser(userId: string): Promise<void> {
  await query(
    "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    [userId]
  );
}

export async function activeSessionCount(userId: string): Promise<number> {
  const row = await queryOne<{ count: number }>(
    `SELECT count(*)::bigint AS count FROM refresh_tokens
     WHERE user_id = $1 AND revoked_at IS NULL AND rotated_at IS NULL AND expires_at > now()`,
    [userId]
  );
  return Number(row?.count ?? 0);
}

/**
 * Deletes rows that can no longer authenticate anything.
 *
 * Without this the table grows by one row per refresh, forever — every active
 * user adds a row every few minutes.
 */
export async function pruneExpired(): Promise<number> {
  const result = await query(
    `DELETE FROM refresh_tokens
     WHERE expires_at < now() - interval '7 days'
        OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')
        OR (rotated_at IS NOT NULL AND rotated_at < now() - interval '7 days')`
  );
  return result.rowCount ?? 0;
}
