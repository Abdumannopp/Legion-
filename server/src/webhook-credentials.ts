/**
 * Per-tenant webhook credentials: verifying a request against them, and
 * creating, rotating and revoking them. The cryptography is in
 * webhook-auth.ts; this file is the part that touches the database.
 *
 * Nothing here is cached. Revocation and expiry are read from Postgres on
 * every request, so a revoked credential stops working on every instance at
 * once — including one that is mid-request when the administrator clicks.
 */
import { randomBytes } from "node:crypto";
import type { PoolClient } from "pg";
import { config } from "./config.js";
import { query, queryAll, transaction } from "./db/pool.js";
import {
  computeSignature, decryptSecret, digestsEqual, encryptSecret, formatApiKey, generateCredential, parseWebhookHeaders,
  type RejectionReason,
} from "./webhook-auth.js";

/** Most usable credentials one organisation may hold: enough for a rotation
 *  and a spare sensor, small enough that a leaked admin session cannot mint
 *  an unbounded supply. */
export const MAX_ACTIVE_CREDENTIALS = 5;

/** Fixed key for the "no such credential" path, so an unknown key id costs the
 *  same HMAC as a known one. Not a secret; it never validates anything. */
const DUMMY_SECRET = "whs_" + "0".repeat(43);
const DUMMY_DIGEST_INPUT = Buffer.alloc(0);

export type WebhookAuthResult =
  | { ok: true; tenantId: string; keyId: string }
  | {
      ok: false;
      /** Selects the (coarse) answer given to the sender. */
      reason: RejectionReason;
      /** What actually went wrong, for the server log only. */
      cause: string;
      /** Present only when the header was well-formed, so it is safe to log. */
      keyId?: string;
    };

interface CredentialRow {
  key_id: string;
  tenant_id: string;
  secret_enc: string;
  usable: boolean;
}

/**
 * Authenticates one webhook request. The tenant in the result is the tenant
 * the credential belongs to; `claimedTenantId` (the old x-tenant-id header) is
 * accepted only to be cross-checked, and can only ever cause a rejection.
 */
export async function authenticateWebhook(input: {
  header: (name: string) => string | undefined;
  rawBody: Buffer | undefined;
  claimedTenantId?: string;
  nowSeconds?: number;
}): Promise<WebhookAuthResult> {
  const parsed = parseWebhookHeaders({ header: input.header, rawBody: input.rawBody, nowSeconds: input.nowSeconds });
  if (!parsed.ok) return { ok: false, reason: parsed.reason, cause: parsed.reason };
  const { keyId, timestamp, nonce, signature } = parsed.headers;

  const rows = await queryAll<CredentialRow>(
    `SELECT key_id, tenant_id, secret_enc,
            (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())) AS usable
       FROM webhook_credentials WHERE key_id = $1`,
    [keyId]
  );
  const row = rows[0];

  // Always do one HMAC over the real body, whether or not the credential
  // exists or works, and always compare it.
  const secret = row ? decryptSecret(row.secret_enc, row.key_id) : null;
  const expected = computeSignature(secret ?? DUMMY_SECRET, timestamp, nonce, input.rawBody ?? DUMMY_DIGEST_INPUT);
  const signatureOk = digestsEqual(expected, signature);

  if (!row) return { ok: false, reason: "invalid", cause: "unknown-key", keyId };
  if (secret === null) {
    // The stored secret cannot be decrypted: the encryption key changed (or
    // the row was tampered with). Fail closed and say so in the log.
    return { ok: false, reason: "invalid", cause: "secret-unreadable (check WEBHOOK_ENCRYPTION_KEY / JWT_SECRET)", keyId };
  }
  if (!signatureOk) return { ok: false, reason: "invalid", cause: "bad-signature", keyId };
  if (!row.usable) return { ok: false, reason: "invalid", cause: "revoked-or-expired", keyId };
  if (input.claimedTenantId && input.claimedTenantId.toLowerCase() !== row.tenant_id.toLowerCase()) {
    return { ok: false, reason: "invalid", cause: "tenant-mismatch", keyId };
  }

  // Only now — the sender has proved it holds the secret — remember the nonce.
  if (!(await consumeNonce(row.key_id, nonce, Number(timestamp)))) {
    return { ok: false, reason: "replay", cause: "replay", keyId };
  }
  void touchLastUsed(row.key_id);
  return { ok: true, tenantId: row.tenant_id, keyId: row.key_id };
}

/**
 * Atomic "seen it? if not, remember it". The row outlives the request's
 * freshness window: it is needed until timestamp + skew, the last moment the
 * same request could still pass the time check.
 */
async function consumeNonce(keyId: string, nonce: string, timestampSeconds: number): Promise<boolean> {
  const res = await query(
    `INSERT INTO webhook_nonces (key_id, nonce, expires_at)
     VALUES ($1, $2, to_timestamp($3::double precision) + make_interval(secs => $4))
     ON CONFLICT (key_id, nonce) DO NOTHING`,
    [keyId, nonce, timestampSeconds, config.webhookMaxSkewSeconds + 5]
  );
  pruneNoncesSometimes();
  return (res.rowCount ?? 0) === 1;
}

let lastPrune = 0;
function pruneNoncesSometimes(): void {
  if (Date.now() - lastPrune < 60_000) return;
  lastPrune = Date.now();
  void pruneExpiredNonces().catch(() => {
    // Housekeeping only; the next request tries again.
  });
}

export async function pruneExpiredNonces(): Promise<number> {
  const res = await query("DELETE FROM webhook_nonces WHERE expires_at < now()");
  return res.rowCount ?? 0;
}

/** At most once a minute per credential, so ingestion is not a write per alert. */
async function touchLastUsed(keyId: string): Promise<void> {
  try {
    await query(
      `UPDATE webhook_credentials SET last_used_at = now()
        WHERE key_id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`,
      [keyId]
    );
  } catch {
    // Informational; never fail an accepted alert over it.
  }
}

// --- management --------------------------------------------------------------

export interface CredentialView {
  id: string;
  label: string;
  status: "active" | "rotating" | "expired" | "revoked";
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  rotated_from: string | null;
}

/** A newly issued credential. The secret exists in this object once and is
 *  not recoverable afterwards. */
export interface IssuedCredential extends CredentialView {
  secret: string;
  /** What goes into ossec.conf's <api_key>. */
  api_key: string;
}

export class CredentialError extends Error {
  constructor(readonly code: "not_found" | "limit" | "not_usable" | "already_rotating", message: string) {
    super(message);
  }
}

const VIEW_COLUMNS = `key_id AS id, label, created_at, expires_at, revoked_at, last_used_at, rotated_from,
  CASE WHEN revoked_at IS NOT NULL THEN 'revoked'
       WHEN expires_at IS NOT NULL AND expires_at <= now() THEN 'expired'
       WHEN expires_at IS NOT NULL THEN 'rotating'
       ELSE 'active' END AS status`;

export async function listCredentials(tenantId: string): Promise<CredentialView[]> {
  return queryAll<CredentialView>(
    `SELECT ${VIEW_COLUMNS} FROM webhook_credentials WHERE tenant_id = $1 ORDER BY created_at DESC`,
    [tenantId]
  );
}

/** Whether the organisation has at least one credential that works right now. */
export async function hasUsableCredential(tenantId: string): Promise<boolean> {
  const rows = await queryAll(
    `SELECT 1 FROM webhook_credentials
      WHERE tenant_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) LIMIT 1`,
    [tenantId]
  );
  return rows.length > 0;
}

async function insertCredential(
  client: PoolClient, tenantId: string,
  opts: { label: string; createdBy: string | null; rotatedFrom?: string | null }
): Promise<IssuedCredential> {
  const { keyId, secret } = generateCredential();
  const res = await client.query(
    `INSERT INTO webhook_credentials (key_id, tenant_id, secret_enc, label, created_by, rotated_from)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING ${VIEW_COLUMNS}`,
    [keyId, tenantId, encryptSecret(secret, keyId), opts.label.slice(0, 100), opts.createdBy, opts.rotatedFrom ?? null]
  );
  return { ...(res.rows[0] as CredentialView), secret, api_key: formatApiKey(keyId, secret) };
}

/** Serialises credential changes for one organisation, so two concurrent
 *  requests cannot both slip under the limit or both rotate the same key. */
async function lockTenant(client: PoolClient, tenantId: string): Promise<void> {
  const res = await client.query("SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE", [tenantId]);
  if (res.rowCount === 0) throw new CredentialError("not_found", "Unknown tenant");
}

export async function createCredential(
  tenantId: string, opts: { label?: string; createdBy?: string | null } = {}
): Promise<IssuedCredential> {
  return transaction(async (client) => {
    await lockTenant(client, tenantId);
    const active = await client.query(
      `SELECT count(*)::int AS n FROM webhook_credentials
        WHERE tenant_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
      [tenantId]
    );
    if ((active.rows[0]?.n as number) >= MAX_ACTIVE_CREDENTIALS) {
      throw new CredentialError("limit", `Too many active webhook credentials (maximum ${MAX_ACTIVE_CREDENTIALS})`);
    }
    return insertCredential(client, tenantId, { label: opts.label ?? "", createdBy: opts.createdBy ?? null });
  });
}

/**
 * Issues a replacement and lets the old credential run on for `overlapHours`
 * so the sender can be reconfigured without dropping alerts. Both work during
 * the overlap; afterwards only the new one does. 0 ends the old one now.
 * An early end at any time is `revokeCredential`.
 */
export async function rotateCredential(
  tenantId: string, keyId: string,
  opts: { overlapHours?: number; createdBy?: string | null } = {}
): Promise<{ issued: IssuedCredential; previous: { id: string; expires_at: string } }> {
  const overlapHours = opts.overlapHours ?? config.webhookRotationOverlapHours;
  return transaction(async (client) => {
    await lockTenant(client, tenantId);
    const found = await client.query(
      `SELECT label, expires_at,
              (revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())) AS usable
         FROM webhook_credentials WHERE key_id = $1 AND tenant_id = $2 FOR UPDATE`,
      [keyId, tenantId]
    );
    const old = found.rows[0] as { label: string; expires_at: string | null; usable: boolean } | undefined;
    if (!old) throw new CredentialError("not_found", "Webhook credential not found");
    if (!old.usable) throw new CredentialError("not_usable", "This webhook credential is revoked or expired");
    if (old.expires_at) throw new CredentialError("already_rotating", "This webhook credential is already being rotated");

    const issued = await insertCredential(client, tenantId, { label: old.label, createdBy: opts.createdBy ?? null, rotatedFrom: keyId });
    const ended = await client.query(
      "UPDATE webhook_credentials SET expires_at = now() + make_interval(secs => $2) WHERE key_id = $1 RETURNING expires_at",
      [keyId, Math.round(overlapHours * 3600)]
    );
    return { issued, previous: { id: keyId, expires_at: ended.rows[0].expires_at as string } };
  });
}

/** Ends a credential immediately. Idempotent; scoped to the organisation. */
export async function revokeCredential(tenantId: string, keyId: string): Promise<void> {
  const res = await query(
    `UPDATE webhook_credentials SET revoked_at = COALESCE(revoked_at, now())
      WHERE key_id = $1 AND tenant_id = $2`,
    [keyId, tenantId]
  );
  if ((res.rowCount ?? 0) === 0) throw new CredentialError("not_found", "Webhook credential not found");
}

/** Incident response: every credential of the organisation, at once. */
export async function revokeAllCredentials(tenantId: string): Promise<number> {
  const res = await query(
    "UPDATE webhook_credentials SET revoked_at = now() WHERE tenant_id = $1 AND revoked_at IS NULL",
    [tenantId]
  );
  return res.rowCount ?? 0;
}

/** For callers that need a fresh nonce (tests, the CLI's self-check). */
export const newNonce = (): string => randomBytes(16).toString("base64url");
