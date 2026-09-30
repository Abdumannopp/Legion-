/**
 * "Am I protected?" — one answer, computed from the workspace's own records.
 *
 * The dashboard's first screen answers four questions without assuming the
 * reader knows what Wazuh, a webhook or a firewall rule is:
 *   - what is protected   (connected sources, the machines they watch, AI agents under control)
 *   - what threats exist  (open alerts by severity — open ones only)
 *   - what Legion blocked (AI agent actions refused, contained, or waiting for a person)
 *   - what is left to set up (the getting-started checklist)
 * Every number comes from a query; nothing is estimated or invented.
 */
import { DEFAULT_POLICY, PERMISSION_TIERS, policySchema, type Permission } from "@legion/agent-identity";
import { config } from "./config.js";
import { queryAll, queryOne } from "./db/pool.js";

export type ProtectionStatus = "not_connected" | "waiting_for_data" | "attention" | "protected";
export type SourceHealth = "receiving" | "waiting" | "silent" | "error" | "paused";

export interface Overview {
  status: ProtectionStatus;
  /** Why the status is what it is — codes the dashboard explains in the reader's language. */
  reasons: string[];
  protected: {
    sources: { kind: string; name: string; health: SourceHealth; last_event_at: string | null }[];
    assets: number;
    assets_online: number;
    agents: { total: number; active: number; stopped: number };
  };
  threats: {
    open: { critical: number; high: number; medium: number; low: number };
    open_total: number;
    new_last_24h: number;
    top: { id: string; title: string; severity: string; created_at: string }[];
  };
  blocked: {
    window_days: number;
    refused: number;
    contained: number;
    approvals_pending: number;
    recent: { decision_id: string; at: string; agent_id: string; agent_name: string | null; action: string; decision: string; rules: string[]; reason: string | null }[];
  };
  onboarding: { steps: { id: OnboardingStep; done: boolean; optional: boolean }[]; complete: boolean };
}

export type OnboardingStep = "connect" | "first_event" | "notifications" | "team" | "agent";

const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);

export async function overview(tenantId: string): Promise<Overview> {
  const silenceMinutes = config.sensorSilenceMinutes || 120;
  const [creds, conns, assets, agents, alerts, top, decisions, recent, pending, tenant, members, realEvent] = await Promise.all([
    queryAll<{ label: string; last_used_at: Date | null; recent: boolean }>(
      `SELECT label, last_used_at, last_used_at > now() - make_interval(mins => $2) AS recent FROM webhook_credentials
        WHERE tenant_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) ORDER BY created_at`,
      [tenantId, silenceMinutes]),
    queryAll<{ kind: string; name: string; status: string; last_success_at: Date | null }>(
      "SELECT kind, name, status, last_success_at FROM integration_connections WHERE tenant_id = $1 AND status <> 'disabled' ORDER BY created_at",
      [tenantId]),
    queryOne<{ total: number; online: number }>(
      "SELECT count(*)::int AS total, count(*) FILTER (WHERE online)::int AS online FROM assets WHERE tenant_id = $1", [tenantId]),
    queryOne<{ total: number; active: number }>(
      "SELECT count(*)::int AS total, count(*) FILTER (WHERE status = 'active')::int AS active FROM machine_identities WHERE tenant_id = $1::text AND kind = 'ai_agent' AND status <> 'revoked'",
      [tenantId]),
    queryOne<Record<string, number>>(
      `SELECT count(*) FILTER (WHERE status <> 'resolved' AND severity = 'critical')::int AS critical,
              count(*) FILTER (WHERE status <> 'resolved' AND severity = 'high')::int AS high,
              count(*) FILTER (WHERE status <> 'resolved' AND severity = 'medium')::int AS medium,
              count(*) FILTER (WHERE status <> 'resolved' AND severity = 'low')::int AS low,
              count(*) FILTER (WHERE created_at > now() - interval '24 hours')::int AS last_24h
         FROM alerts WHERE tenant_id = $1`, [tenantId]),
    queryAll<{ id: string; title: string; severity: string; created_at: Date }>(
      `SELECT id, title, severity, created_at FROM alerts WHERE tenant_id = $1 AND status <> 'resolved'
        ORDER BY array_position(ARRAY['critical','high','medium','low'], severity), created_at DESC LIMIT 3`, [tenantId]),
    queryOne<{ refused: number; contained: number }>(
      `SELECT count(*) FILTER (WHERE decision IN ('BLOCK', 'QUARANTINE', 'KILL'))::int AS refused,
              count(*) FILTER (WHERE decision IN ('QUARANTINE', 'KILL'))::int AS contained
         FROM firewall_decisions WHERE tenant_id = $1::text AND occurred_at > now() - interval '7 days'`, [tenantId]),
    queryAll<{ decision_id: string; occurred_at: Date; principal_id: string; name: string | null; action: string; decision: string; rule_hits: { id: string; effect: string; reason: string }[] }>(
      `SELECT d.decision_id, d.occurred_at, d.principal_id, i.name, d.action, d.decision, d.rule_hits
         FROM firewall_decisions d LEFT JOIN machine_identities i ON i.id::text = d.principal_id AND i.tenant_id = d.tenant_id
        WHERE d.tenant_id = $1::text AND d.decision NOT IN ('ALLOW', 'WARN') AND d.occurred_at > now() - interval '7 days'
        ORDER BY d.seq DESC LIMIT 5`, [tenantId]),
    queryOne<{ n: number }>(
      "SELECT count(*)::int AS n FROM agent_action_approvals WHERE tenant_id = $1::text AND status = 'pending' AND expires_at > now()", [tenantId]),
    queryOne<{ notification_email: string | null }>("SELECT notification_email FROM tenants WHERE id = $1", [tenantId]),
    queryOne<{ n: number }>("SELECT count(*)::int AS n FROM workspace_memberships WHERE tenant_id = $1 AND status IN ('active', 'invited')", [tenantId]),
    // A real event: one a sensor or integration delivered (not a test or a sample).
    queryOne<{ ok: boolean }>(
      "SELECT EXISTS (SELECT 1 FROM alerts WHERE tenant_id = $1 AND source NOT IN ('legion-test', 'mock', 'legion-monitor', 'legion-agent-security')) AS ok", [tenantId]),
  ]);

  const sources: Overview["protected"]["sources"] = [
    ...creds.map((c) => ({
      kind: "wazuh", name: c.label || "Wazuh",
      health: (!c.last_used_at ? "waiting" : c.recent ? "receiving" : "silent") as SourceHealth,
      last_event_at: iso(c.last_used_at),
    })),
    ...conns.map((c) => ({
      kind: c.kind, name: c.name,
      health: (c.status === "paused" ? "paused" : c.status === "error" ? "error" : c.last_success_at ? "receiving" : "waiting") as SourceHealth,
      last_event_at: iso(c.last_success_at),
    })),
  ];
  const open = { critical: alerts?.critical ?? 0, high: alerts?.high ?? 0, medium: alerts?.medium ?? 0, low: alerts?.low ?? 0 };
  const openTotal = open.critical + open.high + open.medium + open.low;
  const approvalsPending = pending?.n ?? 0;
  const contained = decisions?.contained ?? 0;
  const firstEvent = Boolean(realEvent?.ok) || sources.some((s) => s.last_event_at);

  // AI agents are protected by Legion whether or not a sensor is connected,
  // so what they need from a person is reported in every state.
  const agentReasons = [...(approvalsPending ? ["approvals_pending"] : []), ...(contained ? ["agent_contained"] : [])];
  const reasons: string[] = [];
  let status: ProtectionStatus;
  if (!sources.length) {
    status = "not_connected";
    reasons.push("no_sources", ...agentReasons);
  } else if (!firstEvent) {
    status = "waiting_for_data";
    reasons.push("no_events_yet", ...agentReasons);
  } else {
    if (open.critical) reasons.push("open_critical");
    if (open.high) reasons.push("open_high");
    if (sources.some((s) => s.health === "silent" || s.health === "error")) reasons.push("source_silent");
    reasons.push(...agentReasons);
    status = reasons.length ? "attention" : "protected";
  }

  const steps: Overview["onboarding"]["steps"] = [
    { id: "connect", done: sources.length > 0, optional: false },
    { id: "first_event", done: firstEvent, optional: false },
    { id: "notifications", done: Boolean(tenant?.notification_email), optional: false },
    { id: "team", done: (members?.n ?? 0) > 1, optional: true },
    { id: "agent", done: (agents?.total ?? 0) > 0, optional: true },
  ];

  return {
    status, reasons,
    protected: {
      sources,
      assets: assets?.total ?? 0,
      assets_online: assets?.online ?? 0,
      agents: { total: agents?.total ?? 0, active: agents?.active ?? 0, stopped: (agents?.total ?? 0) - (agents?.active ?? 0) },
    },
    threats: {
      open, open_total: openTotal, new_last_24h: alerts?.last_24h ?? 0,
      top: top.map((a) => ({ id: a.id, title: a.title, severity: a.severity, created_at: iso(a.created_at)! })),
    },
    blocked: {
      window_days: 7,
      refused: decisions?.refused ?? 0,
      contained,
      approvals_pending: approvalsPending,
      recent: recent.map((d) => {
        const refusing = (d.rule_hits ?? []).filter((h) => h.effect !== "WARN");
        return {
          decision_id: d.decision_id, at: iso(d.occurred_at)!, agent_id: d.principal_id, agent_name: d.name, action: d.action,
          decision: d.decision, rules: refusing.map((h) => h.id), reason: refusing[0]?.reason ?? null,
        };
      }),
    },
    onboarding: { steps, complete: steps.filter((s) => !s.optional).every((s) => s.done) },
  };
}

/**
 * What an AI agent can be allowed to do, how risky each is, and which ones
 * this workspace makes it ask a person for first — for the permission picker.
 */
export async function agentPermissionCatalogue(tenantId: string) {
  const row = await queryOne<{ policy: unknown }>("SELECT policy FROM firewall_policies WHERE tenant_id = $1::text ORDER BY version DESC LIMIT 1", [tenantId]);
  const parsed = row ? policySchema.safeParse(row.policy) : null;
  const policy = parsed?.success ? parsed.data : DEFAULT_POLICY;
  const asksFirst = new Set<string>(policy.responses.confirm.permissions);
  return {
    permissions: (Object.entries(PERMISSION_TIERS) as [Permission, number][]).map(([id, tier]) => ({ id, tier, asks_first: asksFirst.has(id) })),
    // Things no agent can ever be given, whoever asks (tier 3).
    never: ["manage_people", "change_settings", "export_data", "billing", "contain_hosts"],
  };
}
