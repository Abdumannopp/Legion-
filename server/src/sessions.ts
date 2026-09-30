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
  created_at: string;
  rotated_at: string | null;
  revoked_at: string | null;
  /** When the login that started this family happened. NULL on rows from
   *  before the absolute lifetime existed: the row's own created_at stands in. */
  family_started_at: string | null;
  /** Set when this (already rotated) token was accepted once more inside the
   *  reuse grace window. A second such reuse is treated as theft. */
  grace_used_at: string | null;
  user_agent: string | null;
  /** The workspace this session belongs to; null on sessions from before workspaces (home). */
  tenant_id?: string | null;
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

/**
 * Idle expiry (REFRESH_TOKEN_DAYS from the last use) capped by the absolute
 * lifetime (SESSION_ABSOLUTE_DAYS from the login). Before the cap, every
 * rotation pushed the end 30 days further out, so a session that kept being
 * used never ended at all.
 */
const expiryDate = (familyStarted: Date = new Date()): Date => new Date(Math.min(
  Date.now() + config.refreshTokenDays * 86_400_000,
  familyStarted.getTime() + config.sessionAbsoluteDays * 86_400_000,
));

/** Starts a new session family — one per login (or workspace switch).
 *  A session belongs to one workspace: refreshing it never moves it. */
export async function issue(
  userId: string,
  meta: { userAgent?: string | null; ip?: string | null } = {},
  tenantId: string | null = null,
): Promise<string> {
  const token = newToken();
  await query(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, user_agent, ip_address, family_started_at, tenant_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8)`,
    [
      randomUUID(), userId, hash(token), randomUUID(), expiryDate(),
      meta.userAgent?.slice(0, 300) || null, meta.ip || null, tenantId,
    ]
  );
  return token;
}

export type RotateResult =
  | { ok: true; token: string; userId: string; /** null: a session from before workspaces (the home workspace). */ tenantId: string | null }
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

    const familyStarted = new Date(record.family_started_at ?? record.created_at);
    const pastAbsolute = Date.now() >= familyStarted.getTime() + config.sessionAbsoluteDays * 86_400_000;

    if (record.rotated_at) {
      // Two tabs of the same browser refreshing at the same moment present the
      // same token twice: the second one is not theft. It is let through ONCE,
      // only within REFRESH_REUSE_GRACE_SECONDS of the rotation, and only for
      // the browser (user agent) the token was issued to. Everything
      // else — a later replay, a second reuse, another client — is treated as
      // what it most likely is, and the whole family is revoked.
      const rotatedAgo = (Date.now() - new Date(record.rotated_at).getTime()) / 1000;
      const sameBrowser = (meta.userAgent?.slice(0, 300) || null) === record.user_agent;
      const withinGrace = config.refreshReuseGraceSeconds > 0 && rotatedAgo <= config.refreshReuseGraceSeconds;
      if (!withinGrace || !sameBrowser || record.grace_used_at || pastAbsolute) {
        await client.query(
          "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL",
          [record.family_id]
        );
        return { ok: false, reason: "reused" as const };
      }
      await client.query("UPDATE refresh_tokens SET grace_used_at = now() WHERE id = $1", [record.id]);
    } else {
      if (new Date(record.expires_at) <= new Date() || pastAbsolute) {
        return { ok: false, reason: "expired" as const };
      }
      await client.query("UPDATE refresh_tokens SET rotated_at = now() WHERE id = $1", [record.id]);
    }

    const token = newToken();
    await client.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, user_agent, ip_address, family_started_at, tenant_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        randomUUID(), record.user_id, hash(token), record.family_id, expiryDate(familyStarted),
        meta.userAgent?.slice(0, 300) || null, meta.ip || null, familyStarted, record.tenant_id ?? null,
      ]
    );

    return { ok: true, token, userId: record.user_id, tenantId: record.tenant_id ?? null };
  });
}

/** Ends a person's sessions in ONE workspace (their membership there changed
 *  or ended); sessions in their other workspaces are untouched. Legacy
 *  sessions (tenant_id NULL) belong to the home workspace. */
export async function revokeForUserInWorkspace(userId: string, tenantId: string): Promise<void> {
  await query(
    `UPDATE refresh_tokens r SET revoked_at = now()
      WHERE r.user_id = $1 AND r.revoked_at IS NULL
        AND (r.tenant_id = $2 OR (r.tenant_id IS NULL AND EXISTS (SELECT 1 FROM users u WHERE u.id = $1 AND u.tenant_id = $2)))`,
    [userId, tenantId],
  );
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
