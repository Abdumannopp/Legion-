import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { digest, redact } from "./scan.js";
import type { ActionRequest, FirewallContext } from "./types.js";

/**
 * Human approval for CONFIRM decisions.
 *
 * An approval is bound to one agent, one tenant and one exact action (the
 * digest of the request and the authority it runs under), expires, and is
 * consumed by the one evaluation that uses it. It satisfies CONFIRM rules
 * only: the action is evaluated again in full when the agent retries, so a
 * suspension, a revoked permission or new injected content in between still
 * stops it. Only people decide; machines have no route to this store.
 */
export type ApprovalStatus = "pending" | "approved" | "denied" | "consumed" | "expired" | "cancelled";

export interface ApprovalRow {
  id: string;
  tenantId: string;
  identityId: string;
  decisionId: string;
  surface: string;
  action: string;
  permission: string | null;
  resourceType: string | null;
  resourceId: string | null;
  actionDigest: string;
  preview: unknown;
  riskScore: number;
  ruleIds: string[];
  status: ApprovalStatus;
  requestedAt: string;
  expiresAt: string;
  decidedBy: string | null;
  decidedAt: string | null;
  decisionReason: string | null;
  consumedAt: string | null;
  consumedDecisionId: string | null;
}

/**
 * The digest an approval is bound to: the action as the agent asked for it
 * (not Legion's analysis of it, which a policy change could alter), plus the
 * authority it runs under — a person it acts for, or a relayed request.
 */
export function approvalDigest(ctx: FirewallContext, req: ActionRequest): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { analysisHits, analysisFactors, ...stable } = req as ActionRequest & { analysisHits?: unknown; analysisFactors?: unknown };
  return digest({ req: stable, onBehalfOf: ctx.onBehalfOf ?? null, viaMessage: ctx.viaMessage?.id ?? null });
}

export type ConsumeResult =
  | { ok: true; row: ApprovalRow }
  | { ok: false; reason: "pending"; row: ApprovalRow }
  | { ok: false; reason: "denied" | "invalid" };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class ApprovalStore {
  constructor(private readonly pool: Pool) {}

  /**
   * An open request for this agent and exact action, or a new one. Reusing
   * the open request means an agent that retries does not flood people
   * with copies of the same question.
   */
  async request(
    ctx: FirewallContext,
    req: ActionRequest,
    d: { decisionId: string; riskScore: number; ruleIds: string[] },
    opts: { ttlSeconds: number; maxPending: number },
  ): Promise<{ row: ApprovalRow; created: boolean } | { tooMany: true }> {
    const p = ctx.principal;
    const actionDigest = approvalDigest(ctx, req);
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      // One writer per agent, so the pending cap and the reuse check hold under concurrency.
      await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`agent_action_approvals:${p.id}`]);
      await c.query(
        `UPDATE agent_action_approvals SET status = 'expired'
          WHERE tenant_id = $1 AND identity_id = $2 AND status IN ('pending', 'approved') AND expires_at <= now()`,
        [p.tenantId, p.id],
      );
      const open = await c.query(
        `SELECT * FROM agent_action_approvals
          WHERE tenant_id = $1 AND identity_id = $2 AND action_digest = $3 AND status = 'pending' AND expires_at > now()
          ORDER BY requested_at DESC LIMIT 1`,
        [p.tenantId, p.id, actionDigest],
      );
      if (open.rows[0]) {
        await c.query("COMMIT");
        return { row: toRow(open.rows[0]), created: false };
      }
      const pending = await c.query(
        "SELECT count(*)::int AS n FROM agent_action_approvals WHERE tenant_id = $1 AND identity_id = $2 AND status = 'pending'",
        [p.tenantId, p.id],
      );
      if (pending.rows[0].n >= opts.maxPending) {
        await c.query("COMMIT");
        return { tooMany: true };
      }
      const res = await c.query(
        `INSERT INTO agent_action_approvals
           (id, tenant_id, identity_id, decision_id, surface, action, permission, resource_type, resource_id, action_digest, preview,
            risk_score, rule_ids, status, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending', now() + make_interval(secs => $14))
         RETURNING *`,
        [randomUUID(), p.tenantId, p.id, d.decisionId, req.surface, req.action.slice(0, 200), req.permission, req.resource?.type ?? null,
          req.resource?.id?.slice(0, 200) ?? null, actionDigest, JSON.stringify(redact(req)), d.riskScore, d.ruleIds, opts.ttlSeconds],
      );
      await c.query("COMMIT");
      return { row: toRow(res.rows[0]), created: true };
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }

  /**
   * Uses an approval, atomically: only an approved, unexpired, unused
   * approval for this tenant, this agent and this exact action. Anything
   * else — someone else's approval, a changed argument, a second use — is
   * refused and does not burn the approval.
   */
  async consume(ctx: FirewallContext, req: ActionRequest, approvalId: string, decisionId: string): Promise<ConsumeResult> {
    const p = ctx.principal;
    if (!UUID_RE.test(approvalId)) return { ok: false, reason: "invalid" };
    const actionDigest = approvalDigest(ctx, req);
    const res = await this.pool.query(
      `UPDATE agent_action_approvals SET status = 'consumed', consumed_at = now(), consumed_decision_id = $5
        WHERE id = $1 AND tenant_id = $2 AND identity_id = $3 AND action_digest = $4 AND status = 'approved' AND expires_at > now()
        RETURNING *`,
      [approvalId, p.tenantId, p.id, actionDigest, decisionId],
    );
    if (res.rows[0]) return { ok: true, row: toRow(res.rows[0]) };
    const known = (await this.pool.query(
      "SELECT * FROM agent_action_approvals WHERE id = $1 AND tenant_id = $2 AND identity_id = $3",
      [approvalId, p.tenantId, p.id],
    )).rows[0];
    if (known && known.action_digest === actionDigest && known.expires_at > new Date()) {
      if (known.status === "pending") return { ok: false, reason: "pending", row: toRow(known) };
      if (known.status === "denied") return { ok: false, reason: "denied" };
    }
    return { ok: false, reason: "invalid" };
  }

  /** Marks a request cancelled (its decision could not be recorded). */
  async cancel(tenantId: string, id: string): Promise<void> {
    await this.pool.query("UPDATE agent_action_approvals SET status = 'cancelled' WHERE id = $1 AND tenant_id = $2 AND status = 'pending'", [id, tenantId]);
  }

  async get(tenantId: string, id: string): Promise<ApprovalRow | null> {
    if (!UUID_RE.test(id)) return null;
    const r = await this.pool.query("SELECT * FROM agent_action_approvals WHERE id = $1 AND tenant_id = $2", [id, tenantId]);
    return r.rows[0] ? toRow(r.rows[0]) : null;
  }

  /** A person's answer. Only a pending, unexpired request can be decided, and only once. */
  async decide(tenantId: string, id: string, answer: "approved" | "denied", by: string, reason: string | null, client?: PoolClient): Promise<ApprovalRow | null> {
    if (!UUID_RE.test(id)) return null;
    const r = await (client ?? this.pool).query(
      `UPDATE agent_action_approvals SET status = $3, decided_by = $4, decided_at = now(), decision_reason = $5
        WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND expires_at > now()
        RETURNING *`,
      [id, tenantId, answer, by, reason],
    );
    return r.rows[0] ? toRow(r.rows[0]) : null;
  }

  async list(tenantId: string, f: { status?: ApprovalStatus; identityId?: string; limit?: number } = {}): Promise<ApprovalRow[]> {
    await this.pool.query(
      "UPDATE agent_action_approvals SET status = 'expired' WHERE tenant_id = $1 AND status IN ('pending', 'approved') AND expires_at <= now()",
      [tenantId],
    );
    const where = ["tenant_id = $1"];
    const args: unknown[] = [tenantId];
    if (f.status) { args.push(f.status); where.push(`status = $${args.length}`); }
    if (f.identityId && UUID_RE.test(f.identityId)) { args.push(f.identityId); where.push(`identity_id = $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
    const r = await this.pool.query(
      `SELECT * FROM agent_action_approvals WHERE ${where.join(" AND ")} ORDER BY requested_at DESC LIMIT $${args.length}`, args);
    return r.rows.map(toRow);
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRow(r: any): ApprovalRow {
  const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);
  return {
    id: r.id, tenantId: r.tenant_id, identityId: r.identity_id, decisionId: r.decision_id, surface: r.surface, action: r.action,
    permission: r.permission, resourceType: r.resource_type, resourceId: r.resource_id, actionDigest: r.action_digest,
    preview: r.preview, riskScore: r.risk_score, ruleIds: r.rule_ids ?? [], status: r.status,
    requestedAt: iso(r.requested_at)!, expiresAt: iso(r.expires_at)!, decidedBy: r.decided_by, decidedAt: iso(r.decided_at),
    decisionReason: r.decision_reason, consumedAt: iso(r.consumed_at), consumedDecisionId: r.consumed_decision_id,
  };
}
