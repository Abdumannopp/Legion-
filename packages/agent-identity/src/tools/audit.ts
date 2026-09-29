import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { chainHash, GENESIS, lockChain } from "../chain.js";
import type { FirewallContext, FirewallDecision } from "../firewall/types.js";
import { digest, redact } from "../firewall/scan.js";
import type { ToolAnalysis } from "./types.js";

export type ToolAuditPhase = "decision" | "outcome" | "ticket_verified" | "ticket_rejected";

export interface ToolAuditRow {
  seq: string;
  eventId: string;
  phase: ToolAuditPhase;
  occurredAt: string;
  tenantId: string;
  principalType: string;
  principalId: string;
  principalName: string;
  ownerUserId: string | null;
  delegatedUser: string | null;
  toolKind: string;
  operation: string;
  target: string;
  destination: string;
  permission: string | null;
  decision: string;
  riskScore: number;
  highRisk: boolean;
  ruleIds: string[];
  ruleHits: unknown;
  firewallDecisionId: string;
  callDigest: string;
  callPreview: unknown;
  outcome: string | null;
  outcomeDetail: string | null;
  outputVerdict: string | null;
  requestId: string | null;
}

const COLUMNS: [Exclude<keyof ToolAuditRow, "seq">, string][] = [
  ["eventId", "event_id"], ["phase", "phase"], ["occurredAt", "occurred_at"], ["tenantId", "tenant_id"],
  ["principalType", "principal_type"], ["principalId", "principal_id"], ["principalName", "principal_name"],
  ["ownerUserId", "owner_user_id"], ["delegatedUser", "delegated_user"], ["toolKind", "tool_kind"], ["operation", "operation"],
  ["target", "target"], ["destination", "destination"], ["permission", "permission"], ["decision", "decision"],
  ["riskScore", "risk_score"], ["highRisk", "high_risk"], ["ruleIds", "rule_ids"], ["ruleHits", "rule_hits"],
  ["firewallDecisionId", "firewall_decision_id"], ["callDigest", "call_digest"], ["callPreview", "call_preview"],
  ["outcome", "outcome"], ["outcomeDetail", "outcome_detail"], ["outputVerdict", "output_verdict"], ["requestId", "request_id"],
];
const JSON_FIELDS = new Set<Exclude<keyof ToolAuditRow, "seq">>(["ruleHits", "callPreview"]);

/** The investigation record for tool calls that were blocked or risky. */
export class ToolAuditLog {
  constructor(private readonly pool: Pool) {}

  static build(
    phase: ToolAuditPhase,
    ctx: FirewallContext,
    call: unknown,
    a: ToolAnalysis,
    d: FirewallDecision,
    extra: { outcome?: string; outcomeDetail?: string; outputVerdict?: string } = {},
  ): Omit<ToolAuditRow, "seq"> {
    const p = ctx.principal;
    return {
      eventId: randomUUID(),
      phase,
      occurredAt: new Date().toISOString(),
      tenantId: p.tenantId,
      principalType: p.type,
      principalId: p.id,
      principalName: p.displayName.slice(0, 200),
      ownerUserId: p.ownerUserId,
      delegatedUser: d.delegation?.userId ?? ctx.onBehalfOf ?? null,
      toolKind: a.toolKind,
      operation: a.operation.slice(0, 200),
      target: a.target.slice(0, 1000),
      destination: a.destination.slice(0, 1000),
      permission: a.permission,
      decision: d.decision,
      riskScore: d.riskScore,
      highRisk: a.highRisk,
      ruleIds: d.hits.map((h) => h.id),
      ruleHits: d.hits,
      firewallDecisionId: d.decisionId,
      callDigest: digest(call),
      callPreview: redact(call),
      outcome: extra.outcome ?? null,
      outcomeDetail: extra.outcomeDetail?.slice(0, 500) ?? null,
      outputVerdict: extra.outputVerdict ?? null,
      requestId: ctx.requestId ?? null,
    };
  }

  async record(row: Omit<ToolAuditRow, "seq">): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const prev = await lockChain(client, "tool_call_audit", row.tenantId);
      const values = COLUMNS.map(([k]) => (JSON_FIELDS.has(k) ? JSON.stringify(row[k]) : row[k]));
      await client.query(
        `INSERT INTO tool_call_audit (chain_key, ${COLUMNS.map(([, c]) => c).join(", ")}, prev_hash, hash)
         VALUES ($1, ${COLUMNS.map((_, i) => `$${i + 2}`).join(", ")}, $${COLUMNS.length + 2}, $${COLUMNS.length + 3})`,
        [row.tenantId, ...values, prev, chainHash(prev, row)],
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async list(tenantId: string, f: { decision?: string; principalId?: string; toolKind?: string; phase?: string; before?: string; limit?: number } = {}) {
    const where = ["tenant_id = $1"];
    const args: unknown[] = [tenantId];
    const add = (col: string, v: unknown) => { args.push(v); where.push(`${col} = $${args.length}`); };
    if (f.decision) add("decision", f.decision);
    if (f.principalId) add("principal_id", f.principalId);
    if (f.toolKind) add("tool_kind", f.toolKind);
    if (f.phase) add("phase", f.phase);
    if (f.before) { args.push(f.before); where.push(`seq < $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
    const res = await this.pool.query(
      `SELECT * FROM tool_call_audit WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${args.length}`, args);
    return res.rows.map(toRow);
  }

  async verifyChain(tenantId: string): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.pool.query("SELECT * FROM tool_call_audit WHERE chain_key = $1 ORDER BY seq", [tenantId]);
    let prev = GENESIS;
    let n = 0;
    for (const r of res.rows) {
      n++;
      const { seq, ...fields } = toRow(r);
      if (r.prev_hash !== prev || r.hash !== chainHash(prev, fields)) return { ok: false, brokenAtSeq: seq, rows: n };
      prev = r.hash;
    }
    return { ok: true, rows: n };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRow(r: any): ToolAuditRow {
  const out = { seq: String(r.seq) } as ToolAuditRow;
  for (const [k, c] of COLUMNS) (out as unknown as Record<string, unknown>)[k] = r[c];
  out.occurredAt = new Date(r.occurred_at).toISOString();
  return out;
}
