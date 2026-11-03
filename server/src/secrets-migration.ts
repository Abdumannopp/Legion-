/**
 * Brings every stored secret that must be readable to the current standard:
 * encrypted (secret-box.ts) under the ACTIVE key.
 *
 *   - TOTP seeds still in plaintext          → encrypted
 *   - TOTP seeds under an older key          → re-encrypted
 *   - webhook secrets in the old "v1." format → re-encrypted on the keyring
 *   - webhook secrets under an older key      → re-encrypted
 *
 * Runs at every boot (cheap when there is nothing to do) and on demand
 * (`npm run secrets -w server -- reencrypt`).
 *
 * Nothing is ever destroyed. Each row is converted by:
 *   1. decrypting (or reading) the current value;
 *   2. sealing it under the active key;
 *   3. decrypting what was just sealed and comparing — a round trip that must
 *      give back the same seed before anything is written;
 *   4. writing with compare-and-swap on the OLD value, so a user who enrols,
 *      re-enrols or disables at the same moment is never overwritten.
 * A value that cannot be read (its key is missing) is left exactly as it is,
 * and counted: MFA for that user stays ON and sign-in is refused until the key
 * is restored — never silently switched off.
 *
 * Logs counts and key ids. Never a secret, never a user's seed.
 */
import type pg from "pg";
import { pool } from "./db/pool.js";
import { keyIdOf, keyring, open, seal } from "./secret-box.js";
import { decryptSecret, encryptSecret } from "./webhook-auth.js";

type Queryable = Pick<pg.Pool, "query"> | Pick<pg.PoolClient, "query">;

export interface MigrationCounts { converted: number; rotated: number; unreadable: number; skipped: number }
export interface MigrationReport { mfa: MigrationCounts; webhook: MigrationCounts; activeKey: string }

const zero = (): MigrationCounts => ({ converted: 0, rotated: 0, unreadable: 0, skipped: 0 });
const BASE32 = /^[A-Z2-7]+=*$/;

export async function migrateSecretsAtRest(db: Queryable = pool): Promise<MigrationReport> {
  const active = keyring().active;
  const report: MigrationReport = { mfa: zero(), webhook: zero(), activeKey: active };

  // --- TOTP seeds ---
  const users = await db.query<{ id: string; mfa_secret: string | null; mfa_secret_enc: string | null }>(
    `SELECT id, mfa_secret, mfa_secret_enc FROM users
      WHERE mfa_secret IS NOT NULL
         OR (mfa_secret_enc IS NOT NULL AND mfa_secret_enc NOT LIKE $1)`,
    [`lsb1.${active}.%`]
  );
  for (const u of users.rows) {
    const plaintext = u.mfa_secret !== null;
    const secret = plaintext ? u.mfa_secret! : open(u.mfa_secret_enc, "mfa-totp", u.id);
    if (secret === null) { report.mfa.unreadable++; continue; }
    if (!BASE32.test(secret)) { report.mfa.skipped++; continue; } // not a seed: leave it for a human
    const sealed = seal(secret, "mfa-totp", u.id);
    if (open(sealed, "mfa-totp", u.id) !== secret) { report.mfa.skipped++; continue; }
    const res = plaintext
      ? await db.query("UPDATE users SET mfa_secret_enc = $2, mfa_secret = NULL WHERE id = $1 AND mfa_secret = $3", [u.id, sealed, u.mfa_secret])
      : await db.query("UPDATE users SET mfa_secret_enc = $2 WHERE id = $1 AND mfa_secret IS NULL AND mfa_secret_enc = $3", [u.id, sealed, u.mfa_secret_enc]);
    if ((res.rowCount ?? 0) === 1) report.mfa[plaintext ? "converted" : "rotated"]++;
    else report.mfa.skipped++; // changed underneath us: the new value is already current
  }

  // --- webhook signing secrets ---
  const creds = await db.query<{ key_id: string; secret_enc: string }>(
    "SELECT key_id, secret_enc FROM webhook_credentials WHERE secret_enc NOT LIKE $1",
    [`lsb1.${active}.%`]
  );
  for (const c of creds.rows) {
    const legacy = keyIdOf(c.secret_enc) === null;
    const secret = decryptSecret(c.secret_enc, c.key_id);
    if (secret === null) { report.webhook.unreadable++; continue; }
    const sealed = encryptSecret(secret, c.key_id);
    if (decryptSecret(sealed, c.key_id) !== secret) { report.webhook.skipped++; continue; }
    const res = await db.query("UPDATE webhook_credentials SET secret_enc = $2 WHERE key_id = $1 AND secret_enc = $3", [c.key_id, sealed, c.secret_enc]);
    if ((res.rowCount ?? 0) === 1) report.webhook[legacy ? "converted" : "rotated"]++;
    else report.webhook.skipped++;
  }
  return report;
}

/** Which key ids are still in use, for deciding when an old key can go. Ids and counts only. */
export async function secretsStatus(db: Queryable = pool) {
  const q = async (sql: string) => (await db.query<{ k: string | null; n: string }>(sql)).rows.map((r) => ({ key: r.k ?? "(none)", count: Number(r.n) }));
  return {
    keyring: { active: keyring().active, ids: [...keyring().keys.keys()] },
    mfa_plaintext: Number((await db.query<{ n: string }>("SELECT count(*) AS n FROM users WHERE mfa_secret IS NOT NULL")).rows[0]!.n),
    mfa_by_key: await q("SELECT split_part(mfa_secret_enc, '.', 2) AS k, count(*) AS n FROM users WHERE mfa_secret_enc IS NOT NULL GROUP BY 1 ORDER BY 1"),
    webhook_by_key: await q("SELECT CASE WHEN secret_enc LIKE 'lsb1.%' THEN split_part(secret_enc, '.', 2) ELSE 'legacy-v1' END AS k, count(*) AS n FROM webhook_credentials GROUP BY 1 ORDER BY 1"),
    plaintext_tokens: Number((await db.query<{ n: string }>("SELECT count(*) AS n FROM users WHERE reset_token IS NOT NULL OR invite_token IS NOT NULL")).rows[0]!.n),
  };
}

export function describeReport(r: MigrationReport): string {
  const part = (name: string, c: MigrationCounts) =>
    `${name}: ${c.converted} encrypted, ${c.rotated} re-encrypted${c.unreadable ? `, ${c.unreadable} UNREADABLE (key missing — left untouched)` : ""}${c.skipped ? `, ${c.skipped} skipped` : ""}`;
  return `Legion: secrets at rest (active key "${r.activeKey}") — ${part("two-factor", r.mfa)}; ${part("webhook", r.webhook)}.`;
}
