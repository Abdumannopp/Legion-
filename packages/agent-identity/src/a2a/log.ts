import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { chainHash, GENESIS, lockChain } from "../chain.js";
import type { Authority } from "../firewall/types.js";

export type InteractionKind =
  | "request_sent"
  | "request_blocked"
  | "request_read"
  | "acted"
  | "act_blocked"
  | "hidden_delegation_blocked";

/**
 * One step of an agent-to-agent interaction. Every row names the five
 * things an investigator needs: source agent, destination agent, tenant,
 * requested action, and the delegated authority it ran under — plus the
 * chain of agents before it and the firewall decision that allowed or
 * refused it.
 */
export interface InteractionRow {
  seq: string;
  eventId: string;
  occurredAt: string;
  tenantId: string;
  kind: InteractionKind;
  /** The root request's id. null for a request refused before it existed. */
  interactionId: string | null;
  messageId: string | null;
  parentMessageId: string | null;
  hop: number;
  sourceAgent: string;
  destinationAgent: string;
  /** Who did this step (the sender for requests, the recipient for reads and actions). */
  actorId: string;
  /** The requested permission for requests; the action taken for actions. */
  action: string;
  requestedPermission: string | null;
  resource: string | null;
  authority: Authority | { kind: "unresolved" };
  agentChain: string[];
  decision: string;
  decisionId: string | null;
  ruleIds: string[];
}

const COLUMNS: [Exclude<keyof InteractionRow, "seq">, string][] = [
  ["eventId", "event_id"], ["occurredAt", "occurred_at"], ["tenantId", "tenant_id"], ["kind", "kind"],
  ["interactionId", "interaction_id"], ["messageId", "message_id"], ["parentMessageId", "parent_message_id"], ["hop", "hop"],
  ["sourceAgent", "source_agent"], ["destinationAgent", "destination_agent"], ["actorId", "actor_id"], ["action", "action"],
  ["requestedPermission", "requested_permission"], ["resource", "resource"], ["authority", "authority"],
  ["agentChain", "agent_chain"], ["decision", "decision"], ["decisionId", "decision_id"], ["ruleIds", "rule_ids"],
];

/** Append-only, hash-chained record of agent-to-agent interactions (per tenant). */
export class InteractionLog {
  constructor(private readonly pool: Pool) {}

  async record(e: Omit<InteractionRow, "seq" | "eventId" | "occurredAt">, inTx?: PoolClient): Promise<InteractionRow> {
    const row: Omit<InteractionRow, "seq"> = { eventId: randomUUID(), occurredAt: new Date().toISOString(), ...e };
    const write = async (c: PoolClient) => {
      const prev = await lockChain(c, "agent_interactions", row.tenantId);
      await c.query(
        `INSERT INTO agent_interactions (chain_key, ${COLUMNS.map(([, col]) => col).join(", ")}, prev_hash, hash)
         VALUES ($1, ${COLUMNS.map((_, i) => `$${i + 2}`).join(", ")}, $${COLUMNS.length + 2}, $${COLUMNS.length + 3})`,
        [row.tenantId, ...COLUMNS.map(([k]) => (k === "authority" ? JSON.stringify(row[k]) : row[k])), prev, chainHash(prev, row)],
      );
    };
    if (inTx) await write(inTx);
    else {
      const c = await this.pool.connect();
      try {
        await c.query("BEGIN");
        await write(c);
        await c.query("COMMIT");
      } catch (err) {
        await c.query("ROLLBACK").catch(() => {});
        throw err;
      } finally {
        c.release();
      }
    }
    return { seq: "", ...row };
  }

  async list(tenantId: string, f: { interactionId?: string; agentId?: string; kind?: InteractionKind; before?: string; limit?: number } = {}): Promise<InteractionRow[]> {
    const args: unknown[] = [tenantId];
    const where = ["tenant_id = $1"];
    if (f.interactionId) { args.push(f.interactionId); where.push(`interaction_id = $${args.length}`); }
    if (f.agentId) { args.push(f.agentId); where.push(`(source_agent = $${args.length} OR destination_agent = $${args.length} OR $${args.length} = ANY(agent_chain))`); }
    if (f.kind) { args.push(f.kind); where.push(`kind = $${args.length}`); }
    if (f.before) { args.push(f.before); where.push(`seq < $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 1000));
    const order = f.interactionId ? "ASC" : "DESC";
    const res = await this.pool.query(`SELECT * FROM agent_interactions WHERE ${where.join(" AND ")} ORDER BY seq ${order} LIMIT $${args.length}`, args);
    return res.rows.map(toRow);
  }

  async verifyChain(tenantId: string): Promise<{ ok: true; rows: number; head: string } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.pool.query("SELECT * FROM agent_interactions WHERE chain_key = $1 ORDER BY seq", [tenantId]);
    let prev = GENESIS;
    let n = 0;
    for (const r of res.rows) {
      n++;
      const { seq, ...fields } = toRow(r);
      if (r.prev_hash !== prev || r.hash !== chainHash(prev, fields)) return { ok: false, brokenAtSeq: seq, rows: n };
      prev = r.hash;
    }
    return { ok: true, rows: n, head: prev };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRow(r: any): InteractionRow {
  const out = { seq: String(r.seq) } as InteractionRow;
  for (const [k, c] of COLUMNS) (out as unknown as Record<string, unknown>)[k] = r[c];
  out.occurredAt = new Date(r.occurred_at).toISOString();
  return out;
}
