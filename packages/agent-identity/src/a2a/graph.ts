import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import { canonical, chainHash, GENESIS, lockChain } from "../chain.js";
import type { PolicyStore } from "../firewall/policy.js";
import type { Permission } from "../permissions.js";
import type { InteractionLog, InteractionRow } from "./log.js";

/** Refusals that mean an agent tried to exceed its authority — not a missing allowlist entry. */
export const VIOLATION_RULES = new Set([
  "a2a.laundering", "a2a.cross_tenant", "a2a.hidden_tool_request", "a2a.hidden_tool_text", "a2a.hidden_tool_delegation",
  "a2a.authority_mismatch", "a2a.redelegation_not_allowed", "a2a.resource_scope", "a2a.message_scope",
  "a2a.injection_payload", "a2a.secret_in_payload", "a2a.cycle", "a2a.depth", "a2a.interaction_budget", "a2a.fan_out",
  "a2a.self", "delegation.not_granted", "delegation.exceeds_user", "delegation.invalid",
]);

export type EdgeTrust =
  /** Allowed by policy and used without violations. */
  | "trusted"
  /** Allowed by policy, not used in the window. */
  | "declared_unused"
  /** Allowed by policy, but can no longer work (an agent stopped, or the recipient lacks the permission). */
  | "broken"
  /** Used or attempted without a policy entry. */
  | "undeclared"
  /** An agent tried to exceed its authority over this edge. */
  | "violating"
  /** A person's delegation grant to an agent. */
  | "delegated";

export interface GraphNode {
  id: string;
  type: "ai_agent" | "human" | "unknown_agent";
  name: string;
  status?: string;
  riskLevel?: string;
  behaviorLevel?: string;
  ownerUserId?: string;
  permissions?: Permission[];
  /** Agents this one can reach through allowed edges, within the policy's depth. */
  reach?: string[];
  /** Permissions it can cause other agents to exercise (never more than it holds). */
  canRequest?: Permission[];
  stats?: { sent: number; received: number; blockedAsSource: number; violationsAsSource: number };
}

export interface GraphEdge {
  from: string;
  to: string;
  type: "delegates" | "requests";
  trust: EdgeTrust;
  grant?: { grantId: string; permissions: Permission[]; redelegable: boolean; expiresAt: string };
  declared?: { permissions: Permission[] | "any" } | null;
  observed?: {
    sent: number; blocked: number; read: number; acted: number; actBlocked: number; hiddenDelegationBlocked: number;
    permissions: Record<string, number>; firstSeen: string | null; lastSeen: string | null;
  };
  violations?: Record<string, number>;
}

export interface GraphFinding {
  severity: "high" | "medium" | "info";
  kind: string;
  message: string;
  from?: string;
  to?: string;
}

export interface TrustGraph {
  tenantId: string;
  generatedAt: string;
  windowDays: number;
  policyVersion: number;
  maxDepth: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: GraphFinding[];
  /** What the observed half of the graph was derived from, and whether that record is intact. */
  evidence: {
    interactionLog: { ok: boolean; rows: number; head?: string; brokenAtSeq?: string };
  };
  /** sha256 of the canonical JSON of everything above. */
  graphHash: string;
}

/** One request in an interaction, with the requests forwarded from it. */
export interface TraceNode {
  messageId: string; from: string; to: string; permission: string; hop: number; resource: string | null; authority: unknown;
  createdAt: string | null; readAt: string | null; withdrawnAt: string | null; expiresAt: string | null; forwarded: TraceNode[];
}

export const hashGraph = (g: Omit<TrustGraph, "graphHash">): string =>
  createHash("sha256").update(canonical(g)).digest("hex");

const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);

/**
 * The Agent Trust Graph: who may ask whom for what (policy), on whose
 * authority (people's grants), and what actually happened (the interaction
 * log) — with every edge classified and every attempt to exceed authority
 * surfaced. The observed half is derived only from the hash-chained
 * interaction log, whose integrity is checked on every build; snapshots
 * are stored in their own chain so what the graph showed can be proven
 * later.
 */
export class TrustGraphService {
  constructor(private readonly o: { pool: Pool; policies: PolicyStore; interactions: InteractionLog }) {}

  async build(tenantId: string, windowDays = 30): Promise<TrustGraph> {
    const days = Math.min(Math.max(Math.floor(windowDays), 1), 365);
    const { policy, version } = await this.o.policies.get(tenantId);
    const [agentsRes, behaviorRes, grantsRes, observedRes, violationsRes, integrity, violatorsRes] = await Promise.all([
      this.o.pool.query(
        "SELECT id::text, name, status, risk_level, owner_user_id, permissions FROM machine_identities WHERE tenant_id = $1 AND kind = 'ai_agent' ORDER BY id",
        [tenantId],
      ),
      this.o.pool.query("SELECT identity_id, level FROM agent_behavior_state WHERE tenant_id = $1", [tenantId]),
      this.o.pool.query(
        `SELECT id::text, identity_id::text, user_id, permissions, redelegable, expires_at FROM agent_delegations
          WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY id`,
        [tenantId],
      ),
      this.o.pool.query(
        `SELECT source_agent, destination_agent, kind, requested_permission, count(*)::int AS n, min(occurred_at) AS first, max(occurred_at) AS last
           FROM agent_interactions WHERE tenant_id = $1 AND occurred_at > now() - make_interval(days => $2)
          GROUP BY 1, 2, 3, 4`,
        [tenantId, days],
      ),
      this.o.pool.query(
        `SELECT source_agent, destination_agent, r AS rule, count(*)::int AS n
           FROM agent_interactions, unnest(rule_ids) AS r
          WHERE tenant_id = $1 AND occurred_at > now() - make_interval(days => $2)
            AND kind IN ('request_blocked', 'act_blocked', 'hidden_delegation_blocked')
          GROUP BY 1, 2, 3`,
        [tenantId, days],
      ),
      this.o.interactions.verifyChain(tenantId),
      this.o.pool.query(
        `SELECT source_agent, count(*)::int AS n FROM agent_interactions
          WHERE tenant_id = $1 AND occurred_at > now() - make_interval(days => $2)
            AND kind IN ('request_blocked', 'act_blocked', 'hidden_delegation_blocked') AND rule_ids && $3::text[]
          GROUP BY 1`,
        [tenantId, days, [...VIOLATION_RULES]],
      ),
    ]);

    const behavior = new Map(behaviorRes.rows.map((r) => [r.identity_id as string, r.level as string]));
    const nodes = new Map<string, GraphNode>();
    for (const a of agentsRes.rows) {
      nodes.set(a.id, {
        id: a.id, type: "ai_agent", name: a.name, status: a.status, riskLevel: a.risk_level, behaviorLevel: behavior.get(a.id) ?? "NORMAL",
        ownerUserId: a.owner_user_id, permissions: [...a.permissions].sort(),
        stats: { sent: 0, received: 0, blockedAsSource: 0, violationsAsSource: 0 },
      });
    }
    const node = (id: string): GraphNode => {
      let n = nodes.get(id);
      if (!n) {
        // Not an agent of this organisation: a typo, a deleted agent, or another tenant's.
        n = { id, type: "unknown_agent", name: "(not an agent of this organisation)" };
        nodes.set(id, n);
      }
      return n;
    };
    const active = (id: string) => nodes.get(id)?.status === "active";

    const edges = new Map<string, GraphEdge>();
    const edge = (from: string, to: string): GraphEdge => {
      const k = `${from}>${to}`;
      let e = edges.get(k);
      if (!e) {
        e = { from, to, type: "requests", trust: "undeclared", declared: null };
        edges.set(k, e);
      }
      return e;
    };

    // Declared: the policy's allowlist.
    for (const a of policy.agentMessages.allow) {
      const e = edge(a.from, a.to);
      const prev = e.declared?.permissions;
      const next = a.permissions ? [...a.permissions] : "any";
      e.declared = { permissions: prev === "any" || next === "any" ? "any" : [...new Set([...(prev ?? []), ...next])].sort() as Permission[] };
      node(a.from); node(a.to);
    }

    // Observed: the interaction log.
    for (const r of observedRes.rows) {
      const e = edge(r.source_agent, r.destination_agent);
      node(r.source_agent); node(r.destination_agent);
      e.observed ??= { sent: 0, blocked: 0, read: 0, acted: 0, actBlocked: 0, hiddenDelegationBlocked: 0, permissions: {}, firstSeen: null, lastSeen: null };
      const o = e.observed;
      const field = ({ request_sent: "sent", request_blocked: "blocked", request_read: "read", acted: "acted", act_blocked: "actBlocked", hidden_delegation_blocked: "hiddenDelegationBlocked" } as const)[r.kind as InteractionRow["kind"]];
      o[field] += r.n;
      if (r.kind === "request_sent" && r.requested_permission) o.permissions[r.requested_permission] = (o.permissions[r.requested_permission] ?? 0) + r.n;
      const first = iso(r.first)!;
      const last = iso(r.last)!;
      if (!o.firstSeen || first < o.firstSeen) o.firstSeen = first;
      if (!o.lastSeen || last > o.lastSeen) o.lastSeen = last;
      const src = nodes.get(r.source_agent);
      const dst = nodes.get(r.destination_agent);
      if (src?.stats && r.kind === "request_sent") src.stats.sent += r.n;
      if (dst?.stats && r.kind === "request_sent") dst.stats.received += r.n;
      if (src?.stats && r.kind === "request_blocked") src.stats.blockedAsSource += r.n;
    }
    for (const r of violationsRes.rows) {
      if (!VIOLATION_RULES.has(r.rule)) continue;
      const e = edge(r.source_agent, r.destination_agent);
      e.violations ??= {};
      e.violations[r.rule] = (e.violations[r.rule] ?? 0) + r.n;
    }
    // Counted per refused step: one attempt can break several rules.
    for (const r of violatorsRes.rows) {
      const src = nodes.get(r.source_agent);
      if (src?.stats) src.stats.violationsAsSource = r.n;
    }

    // Classify each request edge.
    const findings: GraphFinding[] = [];
    const name = (id: string) => nodes.get(id)?.name ?? id;
    for (const e of edges.values()) {
      const to = nodes.get(e.to);
      if (e.violations && Object.keys(e.violations).length) {
        e.trust = "violating";
        const list = Object.entries(e.violations).map(([k, n]) => `${k} ×${n}`).join(", ");
        const cross = e.violations["a2a.cross_tenant"];
        findings.push({
          severity: "high", kind: cross ? "cross_tenant_attempt" : "authority_violation", from: e.from, to: e.to,
          message: `${name(e.from)} → ${name(e.to)}: attempts to exceed authority were refused (${list}).`,
        });
      } else if (e.declared) {
        const lacks = to?.permissions && e.declared.permissions !== "any"
          ? e.declared.permissions.filter((p) => !to.permissions!.includes(p)) : [];
        if (!active(e.from) || !active(e.to) || lacks.length) {
          e.trust = "broken";
          findings.push({
            severity: "info", kind: "dead_allowlist_entry", from: e.from, to: e.to,
            message: `Policy allows ${name(e.from)} → ${name(e.to)}, but ${lacks.length ? `the recipient lacks ${lacks.join(", ")}` : "an agent on it can no longer act"}. Remove the entry.`,
          });
        } else {
          e.trust = e.observed?.sent ? "trusted" : "declared_unused";
        }
      } else {
        e.trust = "undeclared";
        findings.push({
          severity: e.observed?.sent ? "medium" : "info", kind: "undeclared_edge", from: e.from, to: e.to,
          message: `${name(e.from)} → ${name(e.to)} is not in the policy${e.observed?.sent ? ` but ${e.observed.sent} request(s) went through (monitor mode)` : `; ${e.observed?.blocked ?? 0} attempt(s) refused`}.`,
        });
      }
      if (e.observed?.hiddenDelegationBlocked) {
        findings.push({
          severity: "high", kind: "hidden_delegation", from: e.from, to: e.to,
          message: `${name(e.to)} tried to use a tool on a request from ${name(e.from)} without citing it (${e.observed.hiddenDelegationBlocked}×).`,
        });
      }
    }

    // People's authority: grants, and which of them may travel.
    const out: GraphEdge[] = [...edges.values()];
    for (const g of grantsRes.rows) {
      if (!nodes.has(`user:${g.user_id}`)) nodes.set(`user:${g.user_id}`, { id: `user:${g.user_id}`, type: "human", name: g.user_id });
      node(g.identity_id);
      out.push({
        from: `user:${g.user_id}`, to: g.identity_id, type: "delegates", trust: "delegated",
        grant: { grantId: g.id, permissions: [...g.permissions].sort(), redelegable: g.redelegable, expiresAt: iso(g.expires_at)! },
      });
      if (g.redelegable) {
        findings.push({
          severity: "info", kind: "redelegable_grant", from: `user:${g.user_id}`, to: g.identity_id,
          message: `${g.user_id} lets ${name(g.identity_id)} pass their authority (${g.permissions.join(", ")}) to other agents.`,
        });
      }
    }

    // Reach through allowed, working edges, within the depth limit — and
    // what an agent can get others to do (bounded by what it holds itself).
    const allowedOut = new Map<string, GraphEdge[]>();
    for (const e of edges.values()) {
      if (e.declared && e.trust !== "broken") allowedOut.set(e.from, [...(allowedOut.get(e.from) ?? []), e]);
    }
    for (const n of nodes.values()) {
      if (n.type !== "ai_agent") continue;
      const reach = new Set<string>();
      let frontier = [n.id];
      for (let depth = 0; depth < policy.agentMessages.maxDepth && frontier.length; depth++) {
        const next: string[] = [];
        for (const id of frontier) {
          for (const e of allowedOut.get(id) ?? []) {
            if (e.to !== n.id && !reach.has(e.to)) { reach.add(e.to); next.push(e.to); }
          }
        }
        frontier = next;
      }
      n.reach = [...reach].sort();
      const downstream = new Set(n.reach.flatMap((id) => nodes.get(id)?.permissions ?? []));
      n.canRequest = (n.permissions ?? []).filter((p) => downstream.has(p));
      if (n.status === "active" && (n.behaviorLevel === "HIGH_RISK" || n.behaviorLevel === "CRITICAL") && n.reach.length) {
        findings.push({
          severity: "medium", kind: "risky_agent_with_reach", from: n.id,
          message: `${n.name} is ${n.behaviorLevel} and can still reach ${n.reach.length} agent(s).`,
        });
      }
    }

    if (!integrity.ok) {
      findings.unshift({ severity: "high", kind: "evidence_tampered", message: `The interaction log's hash chain is broken at row ${integrity.brokenAtSeq}; the observed graph cannot be trusted.` });
    }

    const order = { high: 0, medium: 1, info: 2 };
    findings.sort((a, b) => order[a.severity] - order[b.severity] || a.kind.localeCompare(b.kind));
    const body: Omit<TrustGraph, "graphHash"> = {
      tenantId,
      generatedAt: new Date().toISOString(),
      windowDays: days,
      policyVersion: version,
      maxDepth: policy.agentMessages.maxDepth,
      nodes: [...nodes.values()].sort((a, b) => a.id.localeCompare(b.id)),
      edges: out.sort((a, b) => a.type.localeCompare(b.type) || a.from.localeCompare(b.from) || a.to.localeCompare(b.to)),
      findings,
      evidence: { interactionLog: integrity.ok ? { ok: true, rows: integrity.rows, head: integrity.head } : { ok: false, rows: integrity.rows, brokenAtSeq: integrity.brokenAtSeq } },
    };
    return { ...body, graphHash: hashGraph(body) };
  }

  // ---- Snapshots ------------------------------------------------------------

  async snapshot(tenantId: string, takenBy: string, note: string | null, windowDays?: number) {
    const graph = await this.build(tenantId, windowDays);
    const row = { snapshotId: randomUUID(), occurredAt: new Date().toISOString(), tenantId, takenBy, note, graphHash: graph.graphHash };
    const c = await this.o.pool.connect();
    try {
      await c.query("BEGIN");
      const prev = await lockChain(c, "agent_trust_graph_snapshots", tenantId);
      await c.query(
        `INSERT INTO agent_trust_graph_snapshots (chain_key, snapshot_id, occurred_at, tenant_id, taken_by, note, graph_hash, graph, prev_hash, hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [tenantId, row.snapshotId, row.occurredAt, tenantId, takenBy, note, graph.graphHash, JSON.stringify(graph), prev, chainHash(prev, row)],
      );
      await c.query("COMMIT");
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
    return { ...row, graph };
  }

  async listSnapshots(tenantId: string, limit = 50) {
    const res = await this.o.pool.query(
      `SELECT seq, snapshot_id, occurred_at, taken_by, note, graph_hash FROM agent_trust_graph_snapshots
        WHERE tenant_id = $1 ORDER BY seq DESC LIMIT $2`,
      [tenantId, Math.min(Math.max(limit, 1), 500)],
    );
    return res.rows.map((r) => ({ seq: String(r.seq), snapshotId: r.snapshot_id, occurredAt: iso(r.occurred_at), takenBy: r.taken_by, note: r.note, graphHash: r.graph_hash }));
  }

  /** A stored snapshot, with its content re-hashed: `intact` is false if the stored graph no longer matches its hash. */
  async getSnapshot(tenantId: string, snapshotId: string) {
    const r = (await this.o.pool.query(
      "SELECT * FROM agent_trust_graph_snapshots WHERE tenant_id = $1 AND snapshot_id = $2",
      [tenantId, snapshotId],
    )).rows[0];
    if (!r) return null;
    const { graphHash, ...body } = r.graph as TrustGraph;
    return {
      snapshotId: r.snapshot_id, occurredAt: iso(r.occurred_at), takenBy: r.taken_by, note: r.note, graphHash: r.graph_hash,
      intact: graphHash === r.graph_hash && hashGraph(body) === r.graph_hash, graph: r.graph as TrustGraph,
    };
  }

  async verifySnapshots(tenantId: string): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.o.pool.query("SELECT * FROM agent_trust_graph_snapshots WHERE chain_key = $1 ORDER BY seq", [tenantId]);
    let prev = GENESIS;
    let n = 0;
    for (const r of res.rows) {
      n++;
      const row = { snapshotId: r.snapshot_id, occurredAt: iso(r.occurred_at), tenantId: r.tenant_id, takenBy: r.taken_by, note: r.note, graphHash: r.graph_hash };
      const { graphHash, ...body } = r.graph as TrustGraph;
      const contentOk = graphHash === r.graph_hash && hashGraph(body) === r.graph_hash;
      if (r.prev_hash !== prev || r.hash !== chainHash(prev, row) || !contentOk) return { ok: false, brokenAtSeq: String(r.seq), rows: n };
      prev = r.hash;
    }
    return { ok: true, rows: n };
  }

  // ---- Investigation ----------------------------------------------------------

  /** Everything about one interaction: every step, every request, every firewall decision taken on it. */
  async trace(tenantId: string, interactionId: string) {
    const events = await this.o.interactions.list(tenantId, { interactionId, limit: 1000 });
    const messages = (await this.o.pool.query(
      `SELECT id, from_identity, to_identity, requested_permission, parent_message_id, hop, authority, resource_type, resource_id, chain,
              decision_id, created_at, expires_at, read_at, withdrawn_at
         FROM agent_messages WHERE tenant_id = $1 AND interaction_id = $2 ORDER BY created_at, id`,
      [tenantId, interactionId],
    )).rows;
    if (!events.length && !messages.length) return null;
    const messageIds = messages.map((m) => m.id);
    const decisionIds = events.map((e) => e.decisionId).filter((x): x is string => !!x);
    const decisions = (await this.o.pool.query(
      `SELECT decision_id, occurred_at, principal_id, principal_name, surface, action, permission, resource_type, resource_id, destination,
              decision, risk_score, rule_hits, via_message_id, delegated_user, agent_chain
         FROM firewall_decisions WHERE tenant_id = $1 AND (via_message_id = ANY($2::text[]) OR decision_id = ANY($3::uuid[]))
        ORDER BY seq`,
      [tenantId, messageIds, decisionIds],
    )).rows.map((d) => ({
      decisionId: d.decision_id, occurredAt: iso(d.occurred_at), principalId: d.principal_id, principalName: d.principal_name,
      surface: d.surface, action: d.action, permission: d.permission, resource: d.resource_type ? `${d.resource_type}:${d.resource_id ?? ""}` : null,
      destination: d.destination, decision: d.decision, riskScore: d.risk_score,
      rules: (d.rule_hits as { id: string }[]).map((h) => h.id), viaMessageId: d.via_message_id, delegatedUser: d.delegated_user, agentChain: d.agent_chain,
    }));
    const byId = new Map<string, TraceNode>();
    for (const m of messages) {
      byId.set(m.id, {
        messageId: m.id, from: m.from_identity, to: m.to_identity, permission: m.requested_permission, hop: m.hop,
        resource: m.resource_type ? `${m.resource_type}:${m.resource_id ?? ""}` : null, authority: m.authority,
        createdAt: iso(m.created_at), readAt: iso(m.read_at), withdrawnAt: iso(m.withdrawn_at), expiresAt: iso(m.expires_at), forwarded: [],
      });
    }
    const roots: TraceNode[] = [];
    for (const m of messages) {
      const n = byId.get(m.id)!;
      const parent = m.parent_message_id ? byId.get(m.parent_message_id) : undefined;
      if (parent) parent.forwarded.push(n); else roots.push(n);
    }
    const participants = [...new Set([...messages.flatMap((m) => [m.from_identity, m.to_identity]), ...events.flatMap((e) => [e.sourceAgent, e.destinationAgent])])];
    const names = new Map((await this.o.pool.query(
      "SELECT id::text, name, status FROM machine_identities WHERE tenant_id = $1 AND id::text = ANY($2::text[])",
      [tenantId, participants],
    )).rows.map((r) => [r.id as string, { name: r.name as string, status: r.status as string }]));
    return {
      interactionId,
      origin: roots[0] ? { agentId: roots[0].from, authority: roots[0].authority, startedAt: roots[0].createdAt } : null,
      summary: {
        requests: messages.length,
        maxHop: Math.max(0, ...messages.map((m) => m.hop as number)),
        refused: events.filter((e) => e.kind === "request_blocked" || e.kind === "act_blocked" || e.kind === "hidden_delegation_blocked").length,
        actions: events.filter((e) => e.kind === "acted").length,
      },
      participants: participants.map((id) => ({ id, ...(names.get(id) ?? { name: "(not an agent of this organisation)", status: null }) })),
      tree: roots,
      events,
      decisions,
    };
  }

  /** Interactions an agent took part in, newest first. */
  async interactions(tenantId: string, agentId?: string, limit = 50) {
    const res = await this.o.pool.query(
      `SELECT interaction_id, min(occurred_at) AS started, max(occurred_at) AS last, count(*)::int AS events,
              count(*) FILTER (WHERE kind IN ('request_blocked', 'act_blocked', 'hidden_delegation_blocked'))::int AS refused,
              max(hop)::int AS max_hop, array_agg(DISTINCT source_agent) AS sources, array_agg(DISTINCT destination_agent) AS destinations
         FROM agent_interactions
        WHERE tenant_id = $1 AND interaction_id IS NOT NULL
          AND ($2::text IS NULL OR source_agent = $2 OR destination_agent = $2 OR $2 = ANY(agent_chain))
        GROUP BY interaction_id ORDER BY max(seq) DESC LIMIT $3`,
      [tenantId, agentId ?? null, Math.min(Math.max(limit, 1), 500)],
    );
    return res.rows.map((r) => ({
      interactionId: r.interaction_id, startedAt: iso(r.started), lastAt: iso(r.last), events: r.events, refused: r.refused,
      maxHop: r.max_hop, agents: [...new Set([...r.sources, ...r.destinations])].sort(),
    }));
  }
}
