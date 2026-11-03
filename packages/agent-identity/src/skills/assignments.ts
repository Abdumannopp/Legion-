import type { Pool } from "pg";

export interface SkillAssignment {
  id: string;
  tenantId: string;
  identityId: string;
  skill: string;
  assignedBy: string;
  assignedAt: string;
}

const row = (r: any): SkillAssignment => ({
  id: r.id,
  tenantId: r.tenant_id,
  identityId: r.identity_id,
  skill: r.skill,
  assignedBy: r.assigned_by,
  assignedAt: new Date(r.assigned_at).toISOString(),
});

/**
 * Explicit skill assignment. Nothing is assigned by default; an agent sees
 * and runs only the skills a person assigned to it, in its own tenant.
 * Every query is tenant-scoped.
 */
export class SkillAssignments {
  constructor(private readonly pool: Pool) {}

  async isAssigned(tenantId: string, identityId: string, skill: string): Promise<boolean> {
    const r = await this.pool.query(
      "SELECT 1 FROM agent_skill_assignments WHERE tenant_id = $1 AND identity_id = $2 AND skill = $3 AND revoked_at IS NULL",
      [tenantId, identityId, skill],
    );
    return (r.rowCount ?? 0) > 0;
  }

  async listFor(tenantId: string, identityId: string): Promise<SkillAssignment[]> {
    const r = await this.pool.query(
      "SELECT * FROM agent_skill_assignments WHERE tenant_id = $1 AND identity_id = $2 AND revoked_at IS NULL ORDER BY skill",
      [tenantId, identityId],
    );
    return r.rows.map(row);
  }

  async listTenant(tenantId: string): Promise<SkillAssignment[]> {
    const r = await this.pool.query(
      "SELECT * FROM agent_skill_assignments WHERE tenant_id = $1 AND revoked_at IS NULL ORDER BY identity_id, skill LIMIT 5000",
      [tenantId],
    );
    return r.rows.map(row);
  }

  /** Assigns (idempotently). The caller has checked the identity is in `tenantId`. */
  async assign(tenantId: string, identityId: string, skill: string, by: string): Promise<{ assignment: SkillAssignment; created: boolean }> {
    const ins = await this.pool.query(
      `INSERT INTO agent_skill_assignments (tenant_id, identity_id, skill, assigned_by) VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id, identity_id, skill) WHERE revoked_at IS NULL DO NOTHING RETURNING *`,
      [tenantId, identityId, skill, by],
    );
    if (ins.rows[0]) return { assignment: row(ins.rows[0]), created: true };
    const cur = await this.pool.query(
      "SELECT * FROM agent_skill_assignments WHERE tenant_id = $1 AND identity_id = $2 AND skill = $3 AND revoked_at IS NULL",
      [tenantId, identityId, skill],
    );
    return { assignment: row(cur.rows[0]), created: false };
  }

  async revoke(tenantId: string, identityId: string, skill: string, by: string): Promise<boolean> {
    const r = await this.pool.query(
      `UPDATE agent_skill_assignments SET revoked_at = now(), revoked_by = $4
        WHERE tenant_id = $1 AND identity_id = $2 AND skill = $3 AND revoked_at IS NULL`,
      [tenantId, identityId, skill, by],
    );
    return (r.rowCount ?? 0) > 0;
  }

  /** The identity, if it exists in this tenant. */
  async identity(tenantId: string, identityId: string): Promise<{ id: string; kind: string; status: string; permissions: string[] } | null> {
    if (!/^[0-9a-f-]{36}$/i.test(identityId)) return null;
    const r = await this.pool.query(
      "SELECT id::text, kind, status, permissions FROM machine_identities WHERE id = $1 AND tenant_id = $2",
      [identityId, tenantId],
    );
    return r.rows[0] ?? null;
  }
}
