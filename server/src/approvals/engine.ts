/**
 * Approval Engine v0: a person (two, for critical actions) says yes or no to
 * one exactly-described action.
 *
 *  - Only the action engine creates approval requests (createApproval takes a
 *    transaction client; no route exposes it). An agent or a model cannot
 *    "ask itself" for approval.
 *  - The approver confirms the action's digest: approving one thing never
 *    authorises a different one.
 *  - The person who asked cannot approve their own request.
 *  - Critical (R4): two different people, each with a fresh second-factor code.
 *  - Every request expires; an approval is used at most once (CONSUMED),
 *    atomically, by the action engine.
 *  - Decisions are serialised per request (row lock): no double counting,
 *    no decision after the request was settled.
 */
import { randomUUID } from "node:crypto";
import type pg from "pg";
import { queryAll, queryOne, transaction } from "../db/pool.js";
import type { ActorRef, RiskClass } from "../policy/types.js";

export const APPROVAL_TTL_MINUTES = { R1: 24 * 60, R2: 24 * 60, R3: 4 * 60, R4: 60 } as const satisfies Record<Exclude<RiskClass, "R0">, number>;

export type ApprovalStatus = "pending" | "approved" | "rejected" | "expired" | "consumed" | "cancelled";

export interface Approval {
  id: string;
  tenant_id: string;
  subject_type: "action_request";
  subject_id: string;
  action_id: string;
  risk_class: Exclude<RiskClass, "R0">;
  action_digest: string;
  summary: string;
  requested_by: ActorRef;
  requester_user_id: string | null;
  required_approvals: number;
  require_mfa: boolean;
  approvals: number;
  status: ApprovalStatus;
  expires_at: string;
  decided_at: string | null;
  consumed_at: string | null;
  created_at: string;
}

const COLUMNS = `tenant_id, id, subject_type, subject_id, action_id, risk_class, action_digest, summary, requested_by, requester_user_id,
  required_approvals, require_mfa, approvals, status, expires_at, decided_at, consumed_at, created_at`;

type Row = Omit<Approval, "expires_at" | "decided_at" | "consumed_at" | "created_at"> & { expires_at: Date; decided_at: Date | null; consumed_at: Date | null; created_at: Date };
const toApproval = (r: Row): Approval => ({
  ...r, expires_at: r.expires_at.toISOString(), decided_at: r.decided_at?.toISOString() ?? null,
  consumed_at: r.consumed_at?.toISOString() ?? null, created_at: r.created_at.toISOString(),
});

export class ApprovalError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

export interface NewApproval {
  subject_id: string;
  action_id: string;
  risk_class: Exclude<RiskClass, "R0">;
  action_digest: string;
  summary: string;
  requested_by: ActorRef;
}

/** Called by the action engine only, inside its own transaction. */
export async function createApproval(client: pg.PoolClient, tenantId: string, a: NewApproval): Promise<Approval> {
  const critical = a.risk_class === "R4";
  const r = await client.query<Row>(
    `INSERT INTO approval_requests (tenant_id, id, subject_type, subject_id, action_id, risk_class, action_digest, summary, requested_by,
       requester_user_id, required_approvals, require_mfa, expires_at)
     VALUES ($1, $2, 'action_request', $3, $4, $5, $6, $7, $8, $9, $10, $11, now() + make_interval(mins => $12))
     RETURNING ${COLUMNS}`,
    [tenantId, randomUUID(), a.subject_id, a.action_id, a.risk_class, a.action_digest, a.summary.slice(0, 500), JSON.stringify(a.requested_by),
      a.requested_by.kind === "human" ? a.requested_by.user_id : null, critical ? 2 : 1, critical, APPROVAL_TTL_MINUTES[a.risk_class]],
  );
  return toApproval(r.rows[0]!);
}

/** Pending requests past their deadline become expired (this workspace only). */
async function expireDue(client: pg.PoolClient | null, tenantId: string): Promise<void> {
  const sql = "UPDATE approval_requests SET status = 'expired', decided_at = now() WHERE tenant_id = $1 AND status = 'pending' AND expires_at <= now()";
  if (client) await client.query(sql, [tenantId]); else await queryOne(sql, [tenantId]);
}

export async function getApproval(tenantId: string, id: string): Promise<(Approval & { decisions: Array<{ user_id: string; decision: string; reason: string | null; mfa_verified: boolean; decided_at: string }> }) | null> {
  if (!UUID.test(id)) return null;
  await expireDue(null, tenantId);
  const row = await queryOne<Row>(`SELECT ${COLUMNS} FROM approval_requests WHERE tenant_id = $1 AND id = $2`, [tenantId, id]);
  if (!row) return null;
  const decisions = await queryAll<{ user_id: string; decision: string; reason: string | null; mfa_verified: boolean; decided_at: Date }>(
    "SELECT user_id, decision, reason, mfa_verified, decided_at FROM approval_decisions WHERE tenant_id = $1 AND approval_id = $2 ORDER BY decided_at",
    [tenantId, id],
  );
  return { ...toApproval(row), decisions: decisions.map((d) => ({ ...d, decided_at: d.decided_at.toISOString() })) };
}

export async function listApprovals(tenantId: string, opts: { status?: ApprovalStatus; limit: number }): Promise<Approval[]> {
  await expireDue(null, tenantId);
  const rows = await queryAll<Row>(
    `SELECT ${COLUMNS} FROM approval_requests WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2)
      ORDER BY created_at DESC, id LIMIT $3`,
    [tenantId, opts.status ?? null, opts.limit],
  );
  return rows.map(toApproval);
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface DecisionInput {
  userId: string;
  decision: "approve" | "reject";
  reason?: string;
  /** The digest the approver saw. Must equal the request's. */
  actionDigest: string;
  /** True only when the route verified a fresh second-factor code for this decision. */
  mfaVerified: boolean;
}

/**
 * Records one person's decision. Returns the request after the decision and
 * whether it is now settled.
 */
export async function decide(tenantId: string, id: string, d: DecisionInput): Promise<{ approval: Approval; settled: "approved" | "rejected" | null }> {
  if (!UUID.test(id)) throw new ApprovalError(404, "not_found", "No such approval request");
  return transaction(async (client) => {
    await expireDue(client, tenantId);
    const row = (await client.query<Row>(`SELECT ${COLUMNS} FROM approval_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [tenantId, id])).rows[0];
    if (!row) throw new ApprovalError(404, "not_found", "No such approval request");
    const a = toApproval(row);
    if (a.status === "expired") throw new ApprovalError(410, "expired", "This approval request has expired");
    if (a.status !== "pending") throw new ApprovalError(409, "already_settled", `This approval request is already ${a.status}`);
    if (d.actionDigest !== a.action_digest) throw new ApprovalError(409, "digest_mismatch", "The action changed since you looked at it; reload before deciding");
    if (a.requester_user_id && a.requester_user_id === d.userId) throw new ApprovalError(403, "self_approval", "You cannot decide on a request you made yourself");
    if (a.require_mfa && !d.mfaVerified) throw new ApprovalError(403, "mfa_required", "This critical action needs a current two-factor code");
    const inserted = await client.query(
      `INSERT INTO approval_decisions (tenant_id, approval_id, user_id, decision, reason, mfa_verified)
       VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
      [tenantId, id, d.userId, d.decision, d.reason?.slice(0, 500) ?? null, d.mfaVerified],
    );
    if (!inserted.rowCount) throw new ApprovalError(409, "already_decided", "You already decided on this request");

    let settled: "approved" | "rejected" | null = null;
    let updated: Row;
    if (d.decision === "reject") {
      settled = "rejected";
      updated = (await client.query<Row>(
        `UPDATE approval_requests SET status = 'rejected', decided_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING ${COLUMNS}`, [tenantId, id],
      )).rows[0]!;
    } else {
      updated = (await client.query<Row>(
        `UPDATE approval_requests SET approvals = approvals + 1,
                status = CASE WHEN approvals + 1 >= required_approvals THEN 'approved' ELSE status END,
                decided_at = CASE WHEN approvals + 1 >= required_approvals THEN now() ELSE decided_at END
          WHERE tenant_id = $1 AND id = $2 RETURNING ${COLUMNS}`, [tenantId, id],
      )).rows[0]!;
      if (updated.status === "approved") settled = "approved";
    }
    return { approval: toApproval(updated), settled };
  });
}

/**
 * Uses an approval: once, only while approved and unexpired, and only for the
 * exact action it was given for. Returns false otherwise. Runs in the caller's
 * transaction so the use and the action's state change commit together.
 */
export async function consumeApproval(client: pg.PoolClient, tenantId: string, id: string, actionDigest: string): Promise<boolean> {
  const r = await client.query(
    `UPDATE approval_requests SET status = 'consumed', consumed_at = now()
      WHERE tenant_id = $1 AND id = $2 AND status = 'approved' AND action_digest = $3 AND expires_at > now()`,
    [tenantId, id, actionDigest],
  );
  return r.rowCount === 1;
}

/** Withdraws a request that is still pending (its action was cancelled). */
export async function cancelApproval(client: pg.PoolClient, tenantId: string, id: string): Promise<boolean> {
  const r = await client.query(
    "UPDATE approval_requests SET status = 'cancelled', decided_at = now() WHERE tenant_id = $1 AND id = $2 AND status IN ('pending', 'approved')",
    [tenantId, id],
  );
  return r.rowCount === 1;
}
