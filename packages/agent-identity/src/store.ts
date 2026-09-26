import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { Permission } from "./permissions.js";
import { newAccessToken, newCredential } from "./secrets.js";
import type { IdentityStatus, MachineKind, RiskLevel } from "./types.js";

/** An identity as the API returns it. Secrets are never part of it. */
export interface Identity {
  id: string;
  kind: MachineKind;
  name: string;
  description: string;
  tenantId: string;
  ownerUserId: string;
  status: IdentityStatus;
  statusReason: string | null;
  permissions: Permission[];
  riskLevel: RiskLevel;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastActivityAt: string | null;
}

export interface CredentialInfo {
  id: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string | null;
  revokedAt: string | null;
  lastUsedAt: string | null;
}

const iso = (v: Date | null) => (v ? new Date(v).toISOString() : null);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function toIdentity(r: any): Identity {
  return {
    id: r.id,
    kind: r.kind,
    name: r.name,
    description: r.description,
    tenantId: r.tenant_id,
    ownerUserId: r.owner_user_id,
    status: r.status,
    statusReason: r.status_reason,
    permissions: r.permissions,
    riskLevel: r.risk_level,
    createdAt: iso(r.created_at)!,
    createdBy: r.created_by,
    updatedAt: iso(r.updated_at)!,
    expiresAt: iso(r.expires_at),
    revokedAt: iso(r.revoked_at),
    lastActivityAt: iso(r.last_activity_at),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toCredential(r: any): CredentialInfo {
  return {
    id: r.id,
    createdAt: iso(r.created_at)!,
    createdBy: r.created_by,
    expiresAt: iso(r.expires_at),
    revokedAt: iso(r.revoked_at),
    lastUsedAt: iso(r.last_used_at),
  };
}

export const MAX_ACTIVE_CREDENTIALS = 2;

export class IdentityStore {
  constructor(private readonly pool: Pool) {}

  async tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const out = await fn(client);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async create(c: PoolClient, input: {
    tenantId: string;
    kind: MachineKind;
    name: string;
    description: string;
    ownerUserId: string;
    permissions: Permission[];
    riskLevel: RiskLevel;
    expiresAt: string | null;
    createdBy: string;
  }): Promise<{ identity: Identity; credential: CredentialInfo; secret: string }> {
    const res = await c.query(
        `INSERT INTO machine_identities
           (tenant_id, kind, name, description, owner_user_id, permissions, risk_level, expires_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [input.tenantId, input.kind, input.name, input.description, input.ownerUserId,
          input.permissions, input.riskLevel, input.expiresAt, input.createdBy],
      );
    const identity = toIdentity(res.rows[0]);
    const { credential, secret } = await this.insertCredential(c, identity, input.createdBy, null);
    return { identity, credential, secret };
  }

  private async insertCredential(c: PoolClient, identity: Identity, createdBy: string, expiresAt: string | null) {
    const id = randomUUID();
    const { secret, hash } = newCredential(identity.kind, id);
    const res = await c.query(
      `INSERT INTO machine_credentials (id, identity_id, tenant_id, secret_hash, created_by, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [id, identity.id, identity.tenantId, hash, createdBy, expiresAt],
    );
    return { credential: toCredential(res.rows[0]), secret };
  }

  async get(tenantId: string, kind: MachineKind, id: string): Promise<Identity | null> {
    const res = await this.pool.query(
      "SELECT * FROM machine_identities WHERE tenant_id = $1 AND kind = $2 AND id = $3",
      [tenantId, kind, id],
    );
    return res.rows[0] ? toIdentity(res.rows[0]) : null;
  }

  async list(tenantId: string, kind: MachineKind): Promise<Identity[]> {
    const res = await this.pool.query(
      "SELECT * FROM machine_identities WHERE tenant_id = $1 AND kind = $2 ORDER BY created_at DESC",
      [tenantId, kind],
    );
    return res.rows.map(toIdentity);
  }

  /** Locks the row for the rest of the transaction. */
  async getForUpdate(c: PoolClient, tenantId: string, kind: MachineKind, id: string): Promise<Identity | null> {
    const res = await c.query(
      "SELECT * FROM machine_identities WHERE tenant_id = $1 AND kind = $2 AND id = $3 FOR UPDATE",
      [tenantId, kind, id],
    );
    return res.rows[0] ? toIdentity(res.rows[0]) : null;
  }

  async update(
    c: PoolClient,
    id: string,
    patch: Partial<Pick<Identity, "name" | "description" | "ownerUserId" | "permissions" | "riskLevel" | "expiresAt">>,
  ): Promise<Identity> {
    const res = await c.query(
      `UPDATE machine_identities SET
         name          = COALESCE($2, name),
         description   = COALESCE($3, description),
         owner_user_id = COALESCE($4, owner_user_id),
         permissions   = COALESCE($5, permissions),
         risk_level    = COALESCE($6, risk_level),
         expires_at    = CASE WHEN $7::boolean THEN $8::timestamptz ELSE expires_at END,
         updated_at    = now()
       WHERE id = $1 RETURNING *`,
      [id, patch.name ?? null, patch.description ?? null, patch.ownerUserId ?? null,
        patch.permissions ?? null, patch.riskLevel ?? null, patch.expiresAt !== undefined, patch.expiresAt ?? null],
    );
    return toIdentity(res.rows[0]);
  }

  /**
   * Suspension and revocation also kill every outstanding access token, so a
   * later resume cannot bring an old, possibly leaked token back to life.
   * Revocation additionally kills every credential and is final.
   */
  async setStatus(c: PoolClient, id: string, status: IdentityStatus, reason: string | null): Promise<Identity> {
    const res = await c.query(
      `UPDATE machine_identities SET status = $2, status_reason = $3, updated_at = now(),
         revoked_at = CASE WHEN $2 = 'revoked' THEN now() ELSE NULL END
       WHERE id = $1 RETURNING *`,
      [id, status, reason],
    );
    if (status !== "active") {
      await c.query("UPDATE machine_tokens SET revoked_at = now() WHERE identity_id = $1 AND revoked_at IS NULL", [id]);
    }
    if (status === "revoked") {
      await c.query("UPDATE machine_credentials SET revoked_at = now() WHERE identity_id = $1 AND revoked_at IS NULL", [id]);
    }
    return toIdentity(res.rows[0]);
  }

  async listCredentials(identityId: string): Promise<CredentialInfo[]> {
    const res = await this.pool.query(
      "SELECT * FROM machine_credentials WHERE identity_id = $1 ORDER BY created_at DESC",
      [identityId],
    );
    return res.rows.map(toCredential);
  }

  /** Returns null when the identity already has MAX_ACTIVE_CREDENTIALS usable credentials. */
  async addCredential(c: PoolClient, identity: Identity, createdBy: string, expiresAt: string | null) {
    const active = await c.query(
      `SELECT count(*)::int AS n FROM machine_credentials
        WHERE identity_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
      [identity.id],
    );
    if (active.rows[0].n >= MAX_ACTIVE_CREDENTIALS) return null;
    return this.insertCredential(c, identity, createdBy, expiresAt);
  }

  async revokeCredential(c: PoolClient, identityId: string, credentialId: string): Promise<boolean> {
    const res = await c.query(
      "UPDATE machine_credentials SET revoked_at = now() WHERE id = $1 AND identity_id = $2 AND revoked_at IS NULL",
      [credentialId, identityId],
    );
    await c.query("UPDATE machine_tokens SET revoked_at = now() WHERE credential_id = $1 AND revoked_at IS NULL", [credentialId]);
    return (res.rowCount ?? 0) > 0;
  }

  /** Credential row + its identity, for the token endpoint. No tenant filter: the id is the lookup key. */
  async findCredential(credentialId: string) {
    const res = await this.pool.query(
      `SELECT c.id AS credential_id, c.secret_hash, c.expires_at AS credential_expires_at,
              c.revoked_at AS credential_revoked_at, i.*
         FROM machine_credentials c JOIN machine_identities i ON i.id = c.identity_id
        WHERE c.id = $1`,
      [credentialId],
    );
    const r = res.rows[0];
    if (!r) return null;
    return {
      credentialId: r.credential_id as string,
      secretHash: r.secret_hash as Buffer,
      credentialExpiresAt: r.credential_expires_at as Date | null,
      credentialRevokedAt: r.credential_revoked_at as Date | null,
      identity: toIdentity(r),
    };
  }

  async issueToken(identity: Identity, credentialId: string, ttlSeconds: number) {
    const { token, hash } = newAccessToken();
    const res = await this.pool.query(
      `INSERT INTO machine_tokens (token_hash, identity_id, credential_id, tenant_id, expires_at)
       VALUES ($1,$2,$3,$4, now() + make_interval(secs => $5)) RETURNING token_id, expires_at`,
      [hash, identity.id, credentialId, identity.tenantId, ttlSeconds],
    );
    await this.pool.query("UPDATE machine_credentials SET last_used_at = now() WHERE id = $1", [credentialId]);
    return { token, tokenId: res.rows[0].token_id as string, expiresAt: iso(res.rows[0].expires_at)! };
  }

  async findToken(hash: Buffer) {
    const res = await this.pool.query(
      `SELECT t.token_id, t.credential_id, t.expires_at AS token_expires_at, t.revoked_at AS token_revoked_at,
              c.revoked_at AS credential_revoked_at, c.expires_at AS credential_expires_at, i.*
         FROM machine_tokens t
         JOIN machine_credentials c ON c.id = t.credential_id
         JOIN machine_identities i ON i.id = t.identity_id
        WHERE t.token_hash = $1`,
      [hash],
    );
    const r = res.rows[0];
    if (!r) return null;
    return {
      tokenId: r.token_id as string,
      credentialId: r.credential_id as string,
      tokenExpiresAt: r.token_expires_at as Date,
      tokenRevokedAt: r.token_revoked_at as Date | null,
      credentialRevokedAt: r.credential_revoked_at as Date | null,
      credentialExpiresAt: r.credential_expires_at as Date | null,
      identity: toIdentity(r),
    };
  }

  async revokeToken(tokenId: string): Promise<void> {
    await this.pool.query("UPDATE machine_tokens SET revoked_at = now() WHERE token_id = $1 AND revoked_at IS NULL", [tokenId]);
  }

  /** At most one write per identity per minute, whatever the request rate. */
  async touchActivity(identityId: string, ip: string | undefined): Promise<void> {
    await this.pool.query(
      `UPDATE machine_identities SET last_activity_at = now(), last_activity_ip = $2
        WHERE id = $1 AND (last_activity_at IS NULL OR last_activity_at < now() - interval '60 seconds')`,
      [identityId, ip ?? null],
    );
  }

  /** Housekeeping: expired tokens older than a day carry no audit value (issuance is audited). */
  async purgeExpiredTokens(): Promise<number> {
    const res = await this.pool.query("DELETE FROM machine_tokens WHERE expires_at < now() - interval '1 day'");
    return res.rowCount ?? 0;
  }
}
