import type { Pool } from "pg";
import { chainHash, GENESIS, lockChain } from "../chain.js";
import type { FirewallContext, FirewallDecision, ActionRequest } from "./types.js";
import { digest, redact } from "./scan.js";

export interface DecisionRow {
  seq: string;
  decisionId: string;
  occurredAt: string;
  tenantId: string;
  principalType: string;
  principalId: string;
  principalName: string;
  ownerUserId: string;
  credentialId: string | null;
  tokenId: string | null;
  delegatedUser: string | null;
  delegationId: string | null;
  agentChain: string[];
  viaMessageId: string | null;
  surface: string;
  action: string;
  permission: string | null;
  resourceType: string | null;
  resourceId: string | null;
  sensitivity: string;
  destination: string | null;
  decision: string;
  wouldBlock: boolean;
  mode: string;
  riskScore: number;
  riskFactors: unknown;
  ruleHits: unknown;
  advisor: unknown;
  policyVersion: number;
  inputDigest: string;
  inputPreview: unknown;
  requestId: string | null;
  ip: string | null;
}

const COLUMNS: [Exclude<keyof DecisionRow, "seq">, string][] = [
  ["decisionId", "decision_id"], ["occurredAt", "occurred_at"], ["tenantId", "tenant_id"],
  ["principalType", "principal_type"], ["principalId", "principal_id"], ["principalName", "principal_name"],
  ["ownerUserId", "owner_user_id"], ["credentialId", "credential_id"], ["tokenId", "token_id"],
  ["delegatedUser", "delegated_user"], ["delegationId", "delegation_id"], ["agentChain", "agent_chain"],
  ["viaMessageId", "via_message_id"], ["surface", "surface"], ["action", "action"], ["permission", "permission"],
  ["resourceType", "resource_type"], ["resourceId", "resource_id"], ["sensitivity", "sensitivity"],
  ["destination", "destination"], ["decision", "decision"], ["wouldBlock", "would_block"], ["mode", "mode"],
  ["riskScore", "risk_score"], ["riskFactors", "risk_factors"], ["ruleHits", "rule_hits"], ["advisor", "advisor"],
  ["policyVersion", "policy_version"], ["inputDigest", "input_digest"], ["inputPreview", "input_preview"],
  ["requestId", "request_id"], ["ip", "ip"],
];
const JSON_FIELDS = new Set<Exclude<keyof DecisionRow, "seq">>(["riskFactors", "ruleHits", "advisor", "inputPreview"]);

/** The investigation record: every field needed to reconstruct why an agent was allowed or stopped. */
export class DecisionLog {
  constructor(private readonly pool: Pool) {}

  static build(ctx: FirewallContext, req: ActionRequest, d: FirewallDecision, permission: string | null): Omit<DecisionRow, "seq"> {
    const p = ctx.principal;
    return {
      decisionId: d.decisionId,
      occurredAt: new Date().toISOString(),
      tenantId: p.tenantId,
      principalType: p.type,
      principalId: p.id,
      principalName: p.displayName.slice(0, 200),
      ownerUserId: p.ownerUserId,
      credentialId: p.credentialId || null,
      tokenId: p.tokenId || null,
      delegatedUser: d.delegation?.userId ?? ctx.onBehalfOf ?? null,
      delegationId: d.delegation?.grantId ?? null,
      agentChain: ctx.chain ?? [],
      viaMessageId: ctx.viaMessage?.id ?? null,
      surface: req.surface,
      action: req.action.slice(0, 200),
      permission,
      resourceType: req.resource?.type ?? null,
      resourceId: req.resource?.id ?? null,
      sensitivity: d.sensitivity,
      destination: d.destination?.slice(0, 1000) ?? null,
      decision: d.decision,
      wouldBlock: d.wouldBlock,
      mode: d.mode,
      riskScore: d.riskScore,
      riskFactors: d.riskFactors,
      ruleHits: d.hits,
      advisor: d.advisor,
      policyVersion: d.policyVersion,
      inputDigest: digest(req),
      inputPreview: redact(req),
      requestId: ctx.requestId ?? null,
      ip: ctx.ip ?? null,
    };
  }

  async record(row: Omit<DecisionRow, "seq">): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const prev = await lockChain(client, "firewall_decisions", row.tenantId);
      const values = COLUMNS.map(([k]) => (JSON_FIELDS.has(k) ? JSON.stringify(row[k]) : row[k]));
      await client.query(
        `INSERT INTO firewall_decisions (chain_key, ${COLUMNS.map(([, c]) => c).join(", ")}, prev_hash, hash)
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

  async list(tenantId: string, f: { decision?: string; principalId?: string; surface?: string; before?: string; limit?: number } = {}) {
    const where = ["tenant_id = $1"];
    const args: unknown[] = [tenantId];
    const add = (col: string, v: unknown) => { args.push(v); where.push(`${col} = $${args.length}`); };
    if (f.decision) add("decision", f.decision);
    if (f.principalId) add("principal_id", f.principalId);
    if (f.surface) add("surface", f.surface);
    if (f.before) { args.push(f.before); where.push(`seq < $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
    const res = await this.pool.query(
      `SELECT * FROM firewall_decisions WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${args.length}`, args);
    return res.rows.map(toRow);
  }

  async verifyChain(tenantId: string): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.pool.query("SELECT * FROM firewall_decisions WHERE chain_key = $1 ORDER BY seq", [tenantId]);
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
function toRow(r: any): DecisionRow {
  const out = { seq: String(r.seq) } as DecisionRow;
  for (const [k, c] of COLUMNS) (out as unknown as Record<string, unknown>)[k] = r[c];
  out.occurredAt = new Date(r.occurred_at).toISOString();
  return out;
}
