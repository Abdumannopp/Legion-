import { Router, type Request } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import { ALL_PERMISSIONS, exceedsRole, isPermission, roleAllows, type Permission } from "../permissions.js";
import type { ApprovalStatus, ApprovalStore } from "./approvals.js";
import { clientIp, sendError } from "../principal.js";
import type { IdentityStore } from "../store.js";
import type { HostAdapter, HumanPrincipal, MachinePrincipal } from "../types.js";
import { MAX_DELEGATION_DAYS, type DelegationStore } from "./delegations.js";
import type { AgentFirewall } from "./engine.js";
import { DECISIONS, refusalCode, refusingHits } from "./types.js";
import type { DecisionLog } from "./log.js";
import { policySchema, type PolicyStore } from "./policy.js";
import { hashToolDefinition } from "./scan.js";
import { scanToolDefinition } from "./tool-poisoning.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const permission = z.enum(ALL_PERMISSIONS as unknown as [Permission, ...Permission[]]);

type Deps = {
  store: IdentityStore;
  audit: AuditLog;
  host: HostAdapter;
  guards: ReturnType<typeof createGuards>;
  firewall: AgentFirewall;
  policies: PolicyStore;
  decisions: DecisionLog;
  delegations: DelegationStore;
  approvals: ApprovalStore;
};

const me = (req: Request) => req.principal as HumanPrincipal;
const ctxOf = (req: Request) => ({ principal: me(req), requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent") });

/** People: policy, decision log, delegations. Mounted at /firewall. */
export function firewallAdminRouter(d: Deps): Router {
  const router = Router();
  const admin = d.guards.requireHuman(["admin"]);
  const staff = d.guards.requireHuman(["admin", "analyst"]);
  const anyone = d.guards.requireHuman(["admin", "analyst", "viewer"]);

  router.get("/policy", staff, async (req, res) => {
    res.json(await d.policies.get(me(req).tenantId));
  });

  router.put("/policy", admin, async (req, res) => {
    const parsed = policySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      const i = parsed.error.issues[0];
      return sendError(res, 400, "invalid_policy", `${i?.path.join(".") || "policy"}: ${i?.message}`);
    }
    const tenantId = me(req).tenantId;
    const before = await d.policies.get(tenantId);
    const saved = await d.store.tx(async (c) => {
      const v = await d.policies.put(c, tenantId, parsed.data, me(req).id);
      await d.audit.record({
        ...ctxOf(req),
        action: "firewall.policy_updated",
        outcome: "success",
        resourceType: "firewall_policy",
        resourceId: String(v.version),
        details: { fromVersion: before.version, toVersion: v.version, mode: v.policy.mode },
      }, c);
      return v;
    });
    res.json(saved);
  });

  router.get("/decisions", staff, async (req, res) => {
    const q = req.query;
    const s = (v: unknown) => (typeof v === "string" ? v : undefined);
    const decision = s(q.decision);
    res.json({
      decisions: await d.decisions.list(me(req).tenantId, {
        decision: decision && (DECISIONS as readonly string[]).includes(decision) ? decision : undefined,
        principalId: s(q.principalId),
        surface: s(q.surface),
        before: s(q.before) && /^\d+$/.test(s(q.before)!) ? s(q.before) : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/decisions/verify", admin, async (req, res) => {
    res.json(await d.decisions.verifyChain(me(req).tenantId));
  });

  // A person lets an agent act for them. Only for themselves, only within
  // their own role and the agent's grants, for at most a week.
  const delegationBody = z.strictObject({
    agentId: z.string().regex(UUID),
    permissions: z.array(permission).min(1).max(20),
    expiresAt: z.iso.datetime({ offset: true }),
    /** Let the agent pass this authority to other agents (within the same permissions). Default false. */
    redelegable: z.boolean().default(false),
  });
  router.post("/delegations", anyone, async (req, res) => {
    const parsed = delegationBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const b = parsed.data;
    const user = me(req);
    const expires = new Date(b.expiresAt).getTime();
    if (expires <= Date.now() || expires > Date.now() + MAX_DELEGATION_DAYS * 86_400_000) {
      return sendError(res, 400, "invalid_expiry", `Delegations must expire within ${MAX_DELEGATION_DAYS} days.`);
    }
    const agent = await d.store.get(user.tenantId, "ai_agent", b.agentId);
    if (!agent || agent.status !== "active") return sendError(res, 404, "not_found", "No such active agent.");
    const permissions = [...new Set(b.permissions)];
    const overRole = exceedsRole(user.role, permissions);
    if (overRole.length) return sendError(res, 400, "exceeds_your_role", `You cannot delegate what you do not have: ${overRole.join(", ")}.`);
    const overAgent = permissions.filter((p) => !agent.permissions.includes(p));
    if (overAgent.length) return sendError(res, 400, "exceeds_agent", `The agent does not hold: ${overAgent.join(", ")}.`);
    const grant = await d.store.tx(async (c) => {
      const g = await d.delegations.create(c, { tenantId: user.tenantId, agentId: agent.id, userId: user.id, permissions, expiresAt: b.expiresAt, redelegable: b.redelegable });
      await d.audit.record({
        ...ctxOf(req), action: "delegation.created", outcome: "success", resourceType: "ai_agent", resourceId: agent.id,
        details: { delegationId: g.id, permissions, expiresAt: g.expiresAt, redelegable: g.redelegable },
      }, c);
      return g;
    });
    res.status(201).json({ delegation: grant });
  });

  router.get("/delegations", anyone, async (req, res) => {
    const user = me(req);
    const agentId = typeof req.query.agentId === "string" && UUID.test(req.query.agentId) ? req.query.agentId : undefined;
    // People see their own grants; admins and analysts see the tenant's.
    const userId = user.role === "viewer" ? user.id : undefined;
    res.json({ delegations: await d.delegations.list(user.tenantId, { agentId, userId }) });
  });

  router.delete("/delegations/:id", anyone, async (req, res) => {
    const user = me(req);
    const id = String(req.params.id);
    if (!UUID.test(id)) return sendError(res, 404, "not_found", "No such delegation.");
    const outcome = await d.store.tx(async (c) => {
      const g = await d.delegations.get(c, user.tenantId, id);
      if (!g) return "missing";
      if (g.userId !== user.id && user.role !== "admin") return "forbidden";
      await d.delegations.revoke(c, id, user.id);
      await d.audit.record({ ...ctxOf(req), action: "delegation.revoked", outcome: "success", resourceType: "ai_agent", resourceId: g.agentId, details: { delegationId: id } }, c);
      return "ok";
    });
    if (outcome === "missing") return sendError(res, 404, "not_found", "No such delegation.");
    if (outcome === "forbidden") return sendError(res, 403, "forbidden", "Only the person who delegated, or an administrator, can revoke it.");
    res.status(204).end();
  });

  // ---- Approvals (CONFIRM decisions) ----------------------------------------
  // Only people answer. An approval is for one exact action by one agent; it
  // is used once, when the agent retries, and every other rule is checked
  // again then.
  const APPROVAL_STATUSES: ApprovalStatus[] = ["pending", "approved", "denied", "consumed", "expired", "cancelled"];
  router.get("/approvals", staff, async (req, res) => {
    const status = typeof req.query.status === "string" && (APPROVAL_STATUSES as string[]).includes(req.query.status)
      ? req.query.status as ApprovalStatus : undefined;
    const identityId = typeof req.query.agentId === "string" ? req.query.agentId : undefined;
    res.json({ approvals: await d.approvals.list(me(req).tenantId, { status, identityId, limit: Number(req.query.limit) || 100 }) });
  });

  router.get("/approvals/:id", staff, async (req, res) => {
    const a = await d.approvals.get(me(req).tenantId, String(req.params.id));
    if (!a) return sendError(res, 404, "not_found", "No such approval request.");
    res.json({ approval: a });
  });

  const answerBody = z.strictObject({ reason: z.string().trim().max(500).optional() });
  const answer = (verdict: "approved" | "denied") => async (req: Request, res: import("express").Response) => {
    const parsed = answerBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const user = me(req);
    const a = await d.approvals.get(user.tenantId, String(req.params.id));
    if (!a) return sendError(res, 404, "not_found", "No such approval request.");
    const agent = (await d.store.get(user.tenantId, "ai_agent", a.identityId)) ?? (await d.store.get(user.tenantId, "service_account", a.identityId));
    if (!agent) return sendError(res, 404, "not_found", "No such approval request.");
    // Who may answer: an administrator, or the person answerable for the agent.
    if (user.role !== "admin" && agent.ownerUserId !== user.id) {
      return sendError(res, 403, "forbidden", "Only an administrator or the agent's owner can answer this request.");
    }
    // Nobody can approve what they could not do themselves.
    if (verdict === "approved" && a.permission && (!isPermission(a.permission) || !roleAllows(user.role, a.permission))) {
      return sendError(res, 403, "exceeds_your_role", `Your role does not allow ${a.permission}.`);
    }
    const decided = await d.store.tx(async (c) => {
      const row = await d.approvals.decide(user.tenantId, a.id, verdict, user.id, parsed.data.reason ?? null, c);
      if (!row) return null;
      await d.audit.record({
        ...ctxOf(req), action: verdict === "approved" ? "firewall.approval_granted" : "firewall.approval_denied", outcome: "success",
        resourceType: agent.kind, resourceId: agent.id, reason: parsed.data.reason,
        details: { approvalId: a.id, decisionId: a.decisionId, action: a.action, permission: a.permission, actionDigest: a.actionDigest },
      }, c);
      return row;
    });
    if (!decided) return sendError(res, 409, "not_pending", `This request is ${a.status === "pending" ? "expired" : a.status}; it can no longer be answered.`);
    res.json({ approval: decided });
  };
  router.post("/approvals/:id/approve", staff, answer("approved"));
  router.post("/approvals/:id/deny", staff, answer("denied"));

  // ---- MCP tool definitions ---------------------------------------------------
  // Before approving an MCP server's tools, see what the model would read:
  // descriptions (and parameter descriptions) are scanned for instructions
  // aimed at the model, and each tool's hash is what the policy pins.
  const mcpBody = z.strictObject({
    server: z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/),
    tools: z.array(z.strictObject({ name: z.string().min(1).max(100), description: z.string().max(20_000).optional(), inputSchema: z.unknown().optional() })).min(1).max(200),
  });
  router.post("/mcp/inspect", staff, async (req, res) => {
    const parsed = mcpBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const { policy } = await d.policies.get(me(req).tenantId);
    const pinned = policy.mcp.servers[parsed.data.server]?.tools ?? {};
    res.json({
      server: parsed.data.server,
      tools: parsed.data.tools.map((tool) => {
        const c = scanToolDefinition(tool);
        const sha256 = hashToolDefinition(tool);
        return {
          name: tool.name, sha256, verdict: c.verdict, riskScore: c.score, findings: c.findings,
          pinned: pinned[tool.name] ? (pinned[tool.name]!.sha256 === sha256 ? "matches" : "changed") : "not_approved",
        };
      }),
    });
  });

  return router;
}

/** Machines: agent-to-agent messages, relayed and checked by Legion. Mounted inside the agent API. */
export function agentMessageRouter(d: Deps): Router {
  const router = Router();
  const body = z.strictObject({
    toAgentId: z.string().max(64),
    requestedPermission: permission,
    /** Optional: the one resource the recipient may act on under this request. */
    resource: z.strictObject({ type: z.string().regex(/^[a-z][a-z0-9_:-]{0,63}$/), id: z.string().min(1).max(200) }).optional(),
    /** Optional: the tenant the sender believes the recipient is in. Anything but its own is refused. */
    tenantId: z.string().max(200).optional(),
    payload: z.unknown().optional(),
  });

  router.post("/messages", d.guards.requireMachine(["ai_agent"]), async (req, res) => {
    const parsed = body.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const { ctx, extraHits } = await d.firewall.contextFromRequest(req);
    const { decision, messageId, request } = await d.firewall.sendMessage(ctx, parsed.data as Parameters<AgentFirewall["sendMessage"]>[1], extraHits);
    req.firewallDecision = decision;
    res.setHeader("x-legion-firewall", decision.decision.toLowerCase());
    res.setHeader("x-legion-decision-id", decision.decisionId);
    if (!messageId) {
      return res.status(403).json({
        error: {
          code: refusalCode(decision.decision),
          message: refusingHits(decision)[0]?.reason ?? "Blocked.",
          decisionId: decision.decisionId,
          decision: decision.decision,
          rules: refusingHits(decision).map((h) => h.id),
          approval: decision.approval ?? null,
        },
      });
    }
    res.status(201).json({ messageId, decision: decision.decision, decisionId: decision.decisionId, request });
  });

  router.get("/messages", d.guards.requireMachine(["ai_agent"]), d.guards.traced("agents:read_inbox"), async (req, res) => {
    res.json({ messages: await d.firewall.inbox(req.principal as MachinePrincipal) });
  });

  // An agent may see where its own requests for approval stand — nothing
  // else, and it has no way to answer one.
  router.get("/approvals/:id", d.guards.requireMachine(["ai_agent", "service_account"]), d.guards.traced("approvals:read_own"), async (req, res) => {
    const p = req.principal as MachinePrincipal;
    const a = await d.approvals.get(p.tenantId, String(req.params.id));
    if (!a || a.identityId !== p.id) return sendError(res, 404, "not_found", "No such approval request.");
    res.json({ approval: { id: a.id, status: a.status, action: a.action, expiresAt: a.expiresAt, decidedAt: a.decidedAt } });
  });

  return router;
}
