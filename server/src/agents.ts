/**
 * AI agents in Legion: the @legion/agent-identity module, wired to this
 * server.
 *
 * What it adds: registered identities for AI agents and service accounts,
 * the agent firewall in front of every agent action, the prompt-injection
 * guard, the tool gateway, behaviour monitoring, the kill switch,
 * agent-to-agent controls and the security skills — plus the agent API
 * below, which exposes the same alert and asset functions the dashboard
 * uses, each behind a permission check.
 *
 * What it does not change: human sign-in. People keep the existing cookie
 * session; the module only asks `resolveSessionUser` who is signed in.
 */
import { Router, type Application, type Request } from "express";
import { z } from "zod";
import {
  createAgentIdentity,
  type HostAdapter,
  type MachinePrincipal,
  type SecurityEvent,
  type SkillDataSource,
  type SkillModel,
} from "@legion/agent-identity";
import { chatSafe } from "./ai.js";
import { aiPolicy, consumeAiQuota } from "./ai-policy.js";
import { Pseudonymizer } from "./ai-safety.js";
import { pool } from "./db/pool.js";
import { mailEnabled, sendMail } from "./mailer.js";
import * as store from "./store.js";
import type { AccessState, Alert, Severity, User } from "./types.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MITRE = /^T\d{4}(?:\.\d{3})?$/;
const VULN_TITLE = /(CVE-\d{4}-\d{4,7}) affects ([^\s,;]+)/i;

export interface AgentLayerDeps {
  /** The signed-in person, decided exactly as the dashboard's own auth decides it. */
  resolveSessionUser(req: Request): Promise<User | null>;
  accessState(tenantId: string): Promise<AccessState>;
  /** Realtime fan-out after an agent changes an alert. */
  onAlertUpdated(alert: Alert): void;
}

/** A Legion alert in the shape the security skills read. */
export function toSecurityEvent(a: Alert): SecurityEvent {
  return {
    id: a.id,
    tenantId: a.tenant_id,
    title: a.title.slice(0, 2_000),
    summary: (a.summary ?? "").slice(0, 20_000),
    severity: a.severity,
    status: a.status,
    createdAt: new Date(a.created_at).toISOString(),
    source: (a.source || "unknown").slice(0, 100),
    sourceIp: a.source_ip,
    asset: a.target,
    user: null,
    mitreTechniques: (a.mitre_technique ?? "").split(/[,\s]+/).filter((t) => MITRE.test(t)).slice(0, 20),
    ruleGroups: [],
  };
}

/**
 * The skills' view of this installation's data. Every method receives the
 * tenant from the authenticated agent and queries only that tenant.
 * Threat intelligence is not configured: Legion has no provider, so that
 * skill answers "unknown" and says so.
 */
export function skillData(): SkillDataSource {
  return {
    async listSecurityEvents(tenantId, q) {
      if (!UUID.test(tenantId)) return [];
      return (await store.listAlertsForSkills(tenantId, q)).map(toSecurityEvent);
    },
    async listAssets(tenantId, q) {
      if (!UUID.test(tenantId)) return [];
      const names = q.names ? new Set(q.names) : null;
      return (await store.listAssets(tenantId))
        .filter((a) => !names || names.has(a.name))
        .slice(0, q.limit)
        .map((a) => ({
          name: a.name, tenantId: a.tenant_id, ip: a.ip_address, os: a.os, risk: a.risk, online: a.online,
          exposure: "unknown" as const, lastSeen: new Date(a.last_seen).toISOString(),
        }));
    },
    // Findings come only from Wazuh's vulnerability detector ("CVE-… affects
    // <package>"). An alert that merely mentions a CVE is not a finding.
    async listVulnerabilities(tenantId, q) {
      if (!UUID.test(tenantId)) return [];
      const out = [];
      for (const a of await store.listVulnerabilityAlerts(tenantId, q.limit)) {
        const m = VULN_TITLE.exec(a.title);
        if (!m) continue;
        const cve = m[1]!.toUpperCase();
        const finding = {
          id: `${a.id}:${cve}`, tenantId: a.tenant_id, asset: a.target ?? "(unknown asset)", component: m[2]!.slice(0, 300),
          cve, severity: a.severity as Severity, detectedAt: new Date(a.created_at).toISOString(),
          source: a.source === "wazuh" ? "wazuh-vulnerability-detector" : a.source, evidence: a.title.slice(0, 2_000),
        };
        if (q.cve && finding.cve !== q.cve) continue;
        if (q.asset && finding.asset !== q.asset) continue;
        if (q.component && !finding.component.toLowerCase().includes(q.component.toLowerCase())) continue;
        out.push(finding);
      }
      return out;
    },
  };
}

/**
 * The configured AI provider, for optional skill narratives. A failure is an
 * error (the skill then answers without a narrative), never an empty answer.
 * The organisation's own AI policy applies here exactly as it does to the
 * dashboard's Oracle and Copilot: an organisation that switched AI off has
 * none of its data sent for a skill either, and its data mode is honoured.
 * The skill's abort signal is passed through, so its deadline really stops the call.
 */
export const skillModel: SkillModel = async (messages, { signal, tenantId }) => {
  const policy = await aiPolicy(tenantId);
  if (!policy.allowed) throw new Error(`AI analysis is unavailable for this organisation (${policy.reason})`);
  if (!consumeAiQuota(tenantId).ok) throw new Error("AI request limit reached");
  const r = await chatSafe(messages, { maxTokens: 700, signal, pseudonymizer: policy.dataMode === "strict" ? new Pseudonymizer() : undefined });
  if (!r.ok) throw new Error(`the AI provider did not answer (${r.reason})`);
  return r.text;
};

export function createAgentLayer(deps: AgentLayerDeps, opts: { withModel: boolean }) {
  const host: HostAdapter = {
    async authenticateHuman(req) {
      const u = await deps.resolveSessionUser(req);
      return u ? { userId: u.id, tenantId: u.tenant_id, role: u.role, displayName: u.email } : null;
    },
    async getUser(tenantId, userId) {
      if (!UUID.test(userId) || !UUID.test(tenantId)) return null;
      const u = await store.findUserInTenant(tenantId, userId);
      return u ? { id: u.id, tenantId: u.tenant_id, role: u.role, status: u.status, displayName: u.email } : null;
    },
  };

  const identity = createAgentIdentity({
    pool,
    host,
    exemptPaths: ["/health", "/security-events/webhook", "/billing/webhook"],
    skillData: skillData(),
    skillModel: opts.withModel ? skillModel : undefined,
    // Without SMTP, suspension notices stay visible (undeliverable) at
    // GET /kill-switch/notifications instead of being marked sent.
    notifyAdmins: mailEnabled()
      ? async (notice) => {
        const admins = (await store.listUsers(notice.tenantId)).filter((u) => u.role === "admin" && u.status === "active");
        if (!admins.length) throw new Error("no active administrator to notify");
        for (const a of admins) {
          const r = await sendMail({ to: a.email, subject: notice.subject, text: JSON.stringify(notice, null, 2) });
          if (!r.sent) throw new Error(`notice not delivered (${r.reason})`);
        }
      }
      : undefined,
    log: (msg, err) => console.warn(`[agents] ${msg}`, err instanceof Error ? err.message : err ?? ""),
  });

  return { identity, mount: (app: Application) => mount(app, identity, deps) };
}

type Identity = ReturnType<typeof createAgentIdentity>;

function mount(app: Application, identity: Identity, deps: AgentLayerDeps): void {
  app.use("/agent/v1", identity.agentApi);
  app.use("/agent/v1", agentRoutes(identity, deps));
  app.use("/agents", identity.agents);
  app.use("/service-accounts", identity.serviceAccounts);
  app.use("/audit/principal-events", identity.auditApi);
  app.use("/firewall", identity.firewallApi);
  app.use("/prompt-guard", identity.promptGuardApi);
  app.use("/tools", identity.toolsApi);
  app.use("/behavior", identity.behaviorApi);
  app.use("/kill-switch", identity.killSwitchApi);
  app.use("/a2a", identity.a2aApi);
  app.use("/skills", identity.skillsApi);
}

/** What an agent sees of an alert. The text fields are external content. */
function agentAlert(a: Alert) {
  return {
    id: a.id, title: a.title, severity: a.severity, status: a.status, summary: a.summary, confidence: a.confidence,
    source_ip: a.source_ip, target: a.target, mitre_technique: a.mitre_technique, source: a.source, created_at: a.created_at,
  };
}

/**
 * The agent API over Legion's own data: the same store functions the
 * dashboard uses, each behind the firewall (permission, tenant, suspension,
 * risk, prompt-injection hold) and the principal audit trail.
 */
function agentRoutes(identity: Identity, deps: AgentLayerDeps): Router {
  const r = Router();
  const g = identity.guards;
  const me = (req: Request) => req.principal as MachinePrincipal;

  // Alert text is written by whoever can make a log line. Before an agent
  // reads it, it is classified and recorded against the agent — which is
  // what puts it under the untrusted-content hold, so the text cannot turn
  // into the agent's next state-changing action. No record, no read.
  async function recordRead(req: Request, source: "security_alert" | "api_response", id: string, text: string, fieldHint?: "identifier") {
    await identity.contentGuard.ingest({ tenantId: me(req).tenantId, principal: me(req), requestId: req.requestId }, source, text, { sourceId: id, fieldHint });
  }

  async function allowed(req: Request, res: import("express").Response, write: boolean): Promise<boolean> {
    const state = await deps.accessState(me(req).tenantId);
    if (state === "ok" || (state === "readonly" && !write)) return true;
    res.status(402).json({ error: { code: "subscription_inactive", message: "This workspace does not have an active Legion subscription.", access_state: state } });
    return false;
  }

  const listQuery = z.strictObject({
    severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    status: z.enum(["open", "investigating", "resolved"]).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
  });

  r.get("/alerts/stats", g.requirePermission("stats:read", { resource: () => ({ type: "alert_stats" }) }), async (req, res) => {
    if (!(await allowed(req, res, false))) return;
    res.json(await store.alertStats(me(req).tenantId));
  });

  r.get("/alerts", g.requirePermission("alerts:read", { resource: () => ({ type: "alert" }) }), async (req, res) => {
    const q = listQuery.safeParse(req.query);
    if (!q.success) return res.status(400).json({ error: { code: "invalid_request", message: q.error.issues[0]?.message ?? "invalid" } });
    if (!(await allowed(req, res, false))) return;
    const alerts = await store.listAlerts(me(req).tenantId, { severity: q.data.severity, status: q.data.status, limit: q.data.limit });
    try {
      if (alerts.length) await recordRead(req, "security_alert", `alerts:${alerts.length}`, alerts.map((a) => `[${a.id}] ${a.title}\n${a.summary}`).join("\n\n").slice(0, 100_000));
    } catch {
      return res.status(503).json({ error: { code: "content_unrecorded", message: "Alert content could not be recorded, so it was not returned." } });
    }
    res.json({ trust: "untrusted_external_content", alerts: alerts.map(agentAlert) });
  });

  r.get("/alerts/:id", g.requirePermission("alerts:read", { resource: (req) => ({ type: "alert", id: String(req.params.id) }) }), async (req, res) => {
    if (!(await allowed(req, res, false))) return;
    const alert = await store.getAlert(me(req).tenantId, String(req.params.id).slice(0, 200));
    if (!alert) return res.status(404).json({ error: { code: "not_found", message: "Alert not found." } });
    try {
      await recordRead(req, "security_alert", `alert:${alert.id}`, `${alert.title}\n${alert.summary}`);
    } catch {
      return res.status(503).json({ error: { code: "content_unrecorded", message: "Alert content could not be recorded, so it was not returned." } });
    }
    res.json({ trust: "untrusted_external_content", alert: agentAlert(alert) });
  });

  const statusBody = z.strictObject({ status: z.enum(["open", "investigating", "resolved"]) });
  r.patch("/alerts/:id/status", g.requirePermission("alerts:update_status", { resource: (req) => ({ type: "alert", id: String(req.params.id) }) }), async (req, res) => {
    const body = statusBody.safeParse(req.body ?? {});
    if (!body.success) return res.status(400).json({ error: { code: "invalid_request", message: body.error.issues[0]?.message ?? "invalid" } });
    if (!(await allowed(req, res, true))) return;
    const p = me(req);
    const alert = await store.updateAlertStatus(p.tenantId, String(req.params.id).slice(0, 200), body.data.status);
    if (!alert) return res.status(404).json({ error: { code: "not_found", message: "Alert not found." } });
    // Legion's own audit log, next to the people's changes: who (the agent) and on whose behalf (its owner).
    await store.audit({
      tenant_id: p.tenantId, user_id: null, user_email: null, action: "alert.status_updated", resource_type: "alert",
      resource_id: alert.id, detail: `${body.data.status} (by ${p.type} ${p.displayName} ${p.id}, owner ${p.ownerUserId})`, ip_address: req.ip || null,
    });
    deps.onAlertUpdated(alert);
    res.json({ alert: agentAlert(alert) });
  });

  r.get("/assets", g.requirePermission("assets:read", { resource: () => ({ type: "asset" }) }), async (req, res) => {
    if (!(await allowed(req, res, false))) return;
    const assets = await store.listAssets(me(req).tenantId);
    try {
      if (assets.length) await recordRead(req, "api_response", `assets:${assets.length}`, assets.map((a) => a.name).join("\n").slice(0, 100_000));
    } catch {
      return res.status(503).json({ error: { code: "content_unrecorded", message: "Asset data could not be recorded, so it was not returned." } });
    }
    res.json({ assets: assets.map((a) => ({ name: a.name, os: a.os, ip_address: a.ip_address, risk: a.risk, online: a.online, last_seen: a.last_seen })) });
  });

  return r;
}
