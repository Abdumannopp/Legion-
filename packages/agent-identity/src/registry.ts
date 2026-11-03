import type { Pool } from "pg";
import type { BehaviorLevel } from "./behavior/types.js";
import { baselineRisk, effectivePermissions, riskAtLeast, type Permission } from "./permissions.js";
import { identityBlockReason } from "./principal.js";
import type { IdentityStore } from "./store.js";
import type { HostAdapter, MachineKind, RiskLevel } from "./types.js";

/**
 * The agent registry: one row per machine identity with everything an
 * operator needs to answer "what is this agent, what can it do, what has it
 * touched, and should I worry" — computed from the records Legion already
 * keeps (identities, grants, skills, the decision log, behaviour, approvals),
 * never from anything an agent reports about itself.
 */
export interface RegistryEntry {
  id: string;
  kind: MachineKind;
  name: string;
  description: string;
  owner: { userId: string; active: boolean };
  /** Lifecycle: active, suspended, revoked, expired — and whether it can act right now. */
  status: string;
  statusReason: string | null;
  canActNow: boolean;
  blockedBecause: string | null;
  createdAt: string;
  expiresAt: string | null;
  permissions: { granted: Permission[]; effective: Permission[] };
  /** What it may use: tool families from its permissions, and assigned skills. */
  tools: { families: string[]; skills: string[]; used: { action: string; calls: number; lastAt: string }[] };
  /** Where it reached in the window: external destinations, MCP servers, other agents. */
  connectedSystems: { destinations: string[]; mcpServers: string[]; agents: string[] };
  risk: {
    level: RiskLevel;
    /** The minimum its permissions imply. */
    baseline: RiskLevel;
    behavior: { level: BehaviorLevel; score: number; assessedAt: string } | null;
    refusalsInWindow: number;
    containmentsInWindow: number;
    pendingApprovals: number;
    /** A short summary for sorting: the worst of the above. */
    overall: "low" | "medium" | "high" | "critical";
  };
  activity: { lastActivityAt: string | null; decisionsInWindow: number; activeCredentials: number; activeDelegations: number };
}

export async function buildRegistry(
  o: { pool: Pool; store: IdentityStore; host: HostAdapter },
  tenantId: string,
  kind: MachineKind,
  windowDays = 30,
): Promise<RegistryEntry[]> {
  const identities = await o.store.list(tenantId, kind);
  if (!identities.length) return [];
  const ids = identities.map((i) => i.id);
  const q = <T>(sql: string, args: unknown[]) => o.pool.query(sql, args).then((r) => r.rows as T[]);

  const [usage, reach, stats, skills, behavior, approvals, creds, delegations] = await Promise.all([
    q<{ principal_id: string; action: string; calls: number; last_at: Date }>(
      `SELECT principal_id, action, count(*)::int AS calls, max(occurred_at) AS last_at FROM firewall_decisions
        WHERE tenant_id = $1 AND principal_id = ANY($2) AND occurred_at > now() - make_interval(days => $3)
          AND surface IN ('tool_call', 'tool', 'mcp_tool')
        GROUP BY principal_id, action ORDER BY calls DESC`, [tenantId, ids, windowDays]),
    q<{ principal_id: string; surface: string; destination: string }>(
      `SELECT DISTINCT principal_id, surface, destination FROM firewall_decisions
        WHERE tenant_id = $1 AND principal_id = ANY($2) AND occurred_at > now() - make_interval(days => $3)
          AND destination IS NOT NULL AND destination NOT LIKE 'api:%' AND decision IN ('ALLOW', 'WARN')
        LIMIT 5000`, [tenantId, ids, windowDays]),
    q<{ principal_id: string; total: number; refused: number; contained: number; last_at: Date }>(
      `SELECT principal_id, count(*)::int AS total,
              count(*) FILTER (WHERE decision NOT IN ('ALLOW', 'WARN'))::int AS refused,
              count(*) FILTER (WHERE decision IN ('QUARANTINE', 'KILL'))::int AS contained,
              max(occurred_at) AS last_at
         FROM firewall_decisions WHERE tenant_id = $1 AND principal_id = ANY($2) AND occurred_at > now() - make_interval(days => $3)
        GROUP BY principal_id`, [tenantId, ids, windowDays]),
    q<{ identity_id: string; skill: string }>(
      "SELECT identity_id::text, skill FROM agent_skill_assignments WHERE tenant_id = $1 AND identity_id::text = ANY($2) AND revoked_at IS NULL", [tenantId, ids]),
    q<{ identity_id: string; level: BehaviorLevel; score: number; assessed_at: Date }>(
      "SELECT identity_id::text, level, score, assessed_at FROM agent_behavior_state WHERE tenant_id = $1 AND identity_id::text = ANY($2)", [tenantId, ids]),
    q<{ identity_id: string; n: number }>(
      `SELECT identity_id::text, count(*)::int AS n FROM agent_action_approvals
        WHERE tenant_id = $1 AND status = 'pending' AND expires_at > now() GROUP BY identity_id`, [tenantId]),
    q<{ identity_id: string; n: number }>(
      `SELECT identity_id::text, count(*)::int AS n FROM machine_credentials
        WHERE identity_id::text = ANY($1) AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) GROUP BY identity_id`, [ids]),
    q<{ identity_id: string; n: number }>(
      `SELECT identity_id::text, count(*)::int AS n FROM agent_delegations
        WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now() GROUP BY identity_id`, [tenantId]),
  ]);
  const by = <T extends Record<string, unknown>>(rows: T[], key: keyof T) => {
    const m = new Map<string, T[]>();
    for (const r of rows) m.set(String(r[key]), [...(m.get(String(r[key])) ?? []), r]);
    return m;
  };
  const usageBy = by(usage, "principal_id");
  const reachBy = by(reach, "principal_id");
  const statsBy = new Map(stats.map((s) => [s.principal_id, s]));
  const skillsBy = by(skills, "identity_id");
  const behaviorBy = new Map(behavior.map((b) => [b.identity_id, b]));
  const count = (rows: { identity_id: string; n: number }[]) => new Map(rows.map((r) => [r.identity_id, r.n]));
  const approvalsBy = count(approvals);
  const credsBy = count(creds);
  const delegationsBy = count(delegations);
  const iso = (d: Date | string | null | undefined) => (d ? new Date(d).toISOString() : null);

  const out: RegistryEntry[] = [];
  for (const i of identities) {
    const block = await identityBlockReason(i, o.host);
    const effective = block.reason === null ? effectivePermissions(i.permissions, block.ownerRole) : [];
    const owner = await o.host.getUser(tenantId, i.ownerUserId);
    const s = statsBy.get(i.id);
    const b = behaviorBy.get(i.id);
    const destinations = new Set<string>();
    const mcpServers = new Set<string>();
    const agents = new Set<string>();
    for (const r of reachBy.get(i.id) ?? []) {
      if (r.destination.startsWith("agent:")) agents.add(r.destination.slice(6));
      else if (r.destination.startsWith("mcp:")) mcpServers.add(r.destination.slice(4).split("/")[0]!);
      else destinations.add(r.destination);
    }
    const pending = approvalsBy.get(i.id) ?? 0;
    const baseline = baselineRisk(i.permissions);
    const overall: RegistryEntry["risk"]["overall"] =
      i.riskLevel === "critical" || b?.level === "CRITICAL" || (s?.contained ?? 0) > 0 ? "critical"
        : riskAtLeast(i.riskLevel, "high") || b?.level === "HIGH_RISK" ? "high"
          : riskAtLeast(i.riskLevel, "medium") || b?.level === "SUSPICIOUS" || (s?.refused ?? 0) > 0 || pending > 0 ? "medium" : "low";
    const lastDecision = iso(s?.last_at);
    const lastActivityAt = [i.lastActivityAt, lastDecision].filter((x): x is string => !!x).sort().at(-1) ?? null;
    out.push({
      id: i.id, kind: i.kind, name: i.name, description: i.description,
      owner: { userId: i.ownerUserId, active: owner?.status === "active" },
      status: i.expiresAt && new Date(i.expiresAt).getTime() <= Date.now() && i.status === "active" ? "expired" : i.status,
      statusReason: i.statusReason,
      canActNow: block.reason === null,
      blockedBecause: block.reason,
      createdAt: i.createdAt, expiresAt: i.expiresAt,
      permissions: { granted: i.permissions, effective },
      tools: {
        families: [...new Set(effective.filter((p) => p.startsWith("tool.")).map((p) => p.slice(5).split(":")[0]!))].sort(),
        skills: (skillsBy.get(i.id) ?? []).map((r) => r.skill).sort(),
        used: (usageBy.get(i.id) ?? []).slice(0, 50).map((u) => ({ action: u.action, calls: u.calls, lastAt: iso(u.last_at)! })),
      },
      connectedSystems: { destinations: [...destinations].sort().slice(0, 200), mcpServers: [...mcpServers].sort(), agents: [...agents].sort() },
      risk: {
        level: i.riskLevel, baseline,
        behavior: b ? { level: b.level, score: b.score, assessedAt: iso(b.assessed_at)! } : null,
        refusalsInWindow: s?.refused ?? 0, containmentsInWindow: s?.contained ?? 0, pendingApprovals: pending, overall,
      },
      activity: {
        lastActivityAt, decisionsInWindow: s?.total ?? 0,
        activeCredentials: credsBy.get(i.id) ?? 0, activeDelegations: delegationsBy.get(i.id) ?? 0,
      },
    });
  }
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return out.sort((a, b) => order[a.risk.overall] - order[b.risk.overall] || a.name.localeCompare(b.name));
}
