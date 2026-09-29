/**
 * Account-level protections around sign-in: constant-cost password checks,
 * owner notifications for security-relevant changes, and new-device detection.
 */
import { createHash, randomBytes } from "node:crypto";
import bcrypt from "bcryptjs";
import type { Request } from "express";
import { query, queryOne } from "./db/pool.js";
import { requestLocale } from "./i18n.js";
import { securityNoticeEmail, sendMail, type SecurityNoticeKind } from "./mailer.js";
import type { User } from "./types.js";

// --- constant-cost password comparison -----------------------------------------

/**
 * A REAL bcrypt hash (cost 12, like every stored password) of a random value
 * nobody knows. The previous placeholder was 64 characters long; bcrypt hashes
 * are 60, so bcryptjs rejected it in ~1 ms while a real comparison takes
 * ~300 ms — which told anyone whether an email had an account.
 */
export const DUMMY_PASSWORD_HASH = bcrypt.hashSync(randomBytes(24).toString("base64url"), 12);

const BCRYPT_HASH = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

/** The hash to compare a login attempt against: the user's own when it is a
 *  well-formed bcrypt hash, otherwise the dummy — so an unknown address, an
 *  invited account (empty hash) and a real one all cost the same. */
export function hashForComparison(user: Pick<User, "password_hash"> | null | undefined): { hash: string; real: boolean } {
  const h = user?.password_hash ?? "";
  return BCRYPT_HASH.test(h) ? { hash: h, real: true } : { hash: DUMMY_PASSWORD_HASH, real: false };
}

// --- owner notifications ------------------------------------------------------------

const when = () => new Date().toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");

/**
 * Emails the account owner about a change to their own account. Never blocks
 * or fails the request that triggered it (the change has already happened) and
 * never logs the recipient's address.
 */
export function notifyAccountOwner(user: Pick<User, "email">, kind: SecurityNoticeKind, req: Request, detail?: string): void {
  void sendMail({ to: user.email, ...securityNoticeEmail(kind, { when: when(), detail, locale: requestLocale(req) }) })
    .then((r) => { if (!r.sent && r.reason !== "not_configured") console.warn(`Legion: security notice (${kind}) not delivered`); })
    .catch(() => { /* sendMail already reports; a notice must never break the request */ });
}

// --- new-device detection -------------------------------------------------------------

/** A browser identity that survives browser updates: version numbers removed. */
export function deviceFingerprint(userAgent: string | undefined): string {
  const family = (userAgent ?? "").toLowerCase().replace(/\d+([._]\d+)*/g, "#").replace(/\s+/g, " ").trim().slice(0, 512);
  return createHash("sha256").update(family || "(no user agent)").digest("hex");
}

/** The client's network, coarsened (/24 for IPv4, /48 for IPv6), for the notice text. */
export function networkOf(ip: string | undefined | null): string | null {
  if (!ip) return null;
  const v4 = /^(?:::ffff:)?(\d+)\.(\d+)\.(\d+)\.\d+$/.exec(ip);
  if (v4) return `${v4[1]}.${v4[2]}.${v4[3]}.0/24`;
  if (ip.includes(":")) return `${ip.split(":").slice(0, 3).join(":")}::/48`;
  return null;
}

/** Records this sign-in's device. Returns true when the user has signed in
 *  before but never from this device — the case worth telling them about. */
export async function rememberLoginDevice(userId: string, req: Request): Promise<boolean> {
  const fp = deviceFingerprint(req.header("user-agent"));
  const network = networkOf(req.ip);
  const known = await queryOne<{ n: number }>("SELECT count(*)::int AS n FROM user_known_devices WHERE user_id = $1", [userId]);
  const inserted = await query(
    `INSERT INTO user_known_devices (user_id, device_hash, last_network) VALUES ($1, $2, $3)
     ON CONFLICT (user_id, device_hash) DO UPDATE SET last_seen = now(), last_network = EXCLUDED.last_network
     RETURNING (xmax = 0) AS created`,
    [userId, fp, network],
  );
  const created = Boolean(inserted.rows[0]?.created);
  return created && Number(known?.n ?? 0) > 0;
}

/** Failed password attempts against this account in the last `minutes`. */
export async function recentLoginFailures(user: Pick<User, "id" | "tenant_id">, minutes = 15): Promise<number> {
  const row = await queryOne<{ n: number }>(
    `SELECT count(*)::int AS n FROM audit_log
      WHERE tenant_id = $1 AND action = 'auth.login_failed' AND user_id = $2 AND created_at > now() - make_interval(mins => $3)`,
    [user.tenant_id, user.id, minutes],
  );
  return Number(row?.n ?? 0);
}
