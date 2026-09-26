import type { Pool, PoolClient } from "pg";
import type { Permission } from "../permissions.js";

export interface Delegation {
  id: string;
  tenantId: string;
  agentId: string;
  userId: string;
  permissions: Permission[];
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokedBy: string | null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const toDelegation = (r: any): Delegation => ({
  id: r.id,
  tenantId: r.tenant_id,
  agentId: r.identity_id,
  userId: r.user_id,
  permissions: r.permissions,
  createdAt: new Date(r.created_at).toISOString(),
  expiresAt: new Date(r.expires_at).toISOString(),
  revokedAt: r.revoked_at ? new Date(r.revoked_at).toISOString() : null,
  revokedBy: r.revoked_by,
});

export const MAX_DELEGATION_DAYS = 7;

export class DelegationStore {
  constructor(private readonly pool: Pool) {}

  async create(c: PoolClient, d: { tenantId: string; agentId: string; userId: string; permissions: Permission[]; expiresAt: string }) {
    const res = await c.query(
      `INSERT INTO agent_delegations (tenant_id, identity_id, user_id, permissions, expires_at)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [d.tenantId, d.agentId, d.userId, d.permissions, d.expiresAt],
    );
    return toDelegation(res.rows[0]);
  }

  /** Unexpired, unrevoked grants from this person to this agent. */
  async active(tenantId: string, agentId: string, userId: string): Promise<Delegation[]> {
    const res = await this.pool.query(
      `SELECT * FROM agent_delegations
        WHERE tenant_id = $1 AND identity_id = $2 AND user_id = $3 AND revoked_at IS NULL AND expires_at > now()
        ORDER BY created_at DESC`,
      [tenantId, agentId, userId],
    );
    return res.rows.map(toDelegation);
  }

  async list(tenantId: string, f: { agentId?: string; userId?: string }): Promise<Delegation[]> {
    const res = await this.pool.query(
      `SELECT * FROM agent_delegations WHERE tenant_id = $1
         AND ($2::uuid IS NULL OR identity_id = $2) AND ($3::text IS NULL OR user_id = $3)
       ORDER BY created_at DESC LIMIT 500`,
      [tenantId, f.agentId ?? null, f.userId ?? null],
    );
    return res.rows.map(toDelegation);
  }

  async get(c: PoolClient, tenantId: string, id: string): Promise<Delegation | null> {
    const res = await c.query("SELECT * FROM agent_delegations WHERE tenant_id = $1 AND id = $2 FOR UPDATE", [tenantId, id]);
    return res.rows[0] ? toDelegation(res.rows[0]) : null;
  }

  async revoke(c: PoolClient, id: string, by: string): Promise<void> {
    await c.query("UPDATE agent_delegations SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL", [id, by]);
  }
}
