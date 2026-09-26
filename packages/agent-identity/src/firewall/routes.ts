import { Router, type Request } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import { ALL_PERMISSIONS, exceedsRole, type Permission } from "../permissions.js";
import { clientIp, sendError } from "../principal.js";
import type { IdentityStore } from "../store.js";
import type { HostAdapter, HumanPrincipal, MachinePrincipal } from "../types.js";
import { MAX_DELEGATION_DAYS, type DelegationStore } from "./delegations.js";
import type { AgentFirewall } from "./engine.js";
import type { DecisionLog } from "./log.js";
import { policySchema, type PolicyStore } from "./policy.js";

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
        decision: decision && ["ALLOW", "WARN", "BLOCK"].includes(decision) ? decision : undefined,
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
      const g = await d.delegations.create(c, { tenantId: user.tenantId, agentId: agent.id, userId: user.id, permissions, expiresAt: b.expiresAt });
      await d.audit.record({
        ...ctxOf(req), action: "delegation.created", outcome: "success", resourceType: "ai_agent", resourceId: agent.id,
        details: { delegationId: g.id, permissions, expiresAt: g.expiresAt },
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

  return router;
}

/** Machines: agent-to-agent messages, relayed and checked by Legion. Mounted inside the agent API. */
export function agentMessageRouter(d: Deps): Router {
  const router = Router();
  const body = z.strictObject({
    toAgentId: z.string().max(64),
    requestedPermission: permission,
    payload: z.unknown().optional(),
  });

  router.post("/messages", d.guards.requireMachine(["ai_agent"]), async (req, res) => {
    const parsed = body.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const { ctx, extraHits } = await d.firewall.contextFromRequest(req);
    const { decision, messageId } = await d.firewall.sendMessage(ctx, parsed.data as { toAgentId: string; requestedPermission: Permission; payload: unknown }, extraHits);
    req.firewallDecision = decision;
    res.setHeader("x-legion-firewall", decision.decision.toLowerCase());
    res.setHeader("x-legion-decision-id", decision.decisionId);
    if (!messageId) {
      return res.status(403).json({
        error: {
          code: "firewall_blocked",
          message: decision.hits.find((h) => h.effect === "BLOCK")?.reason ?? "Blocked.",
          decisionId: decision.decisionId,
          rules: decision.hits.filter((h) => h.effect === "BLOCK").map((h) => h.id),
        },
      });
    }
    res.status(201).json({ messageId, decision: decision.decision, decisionId: decision.decisionId });
  });

  router.get("/messages", d.guards.requireMachine(["ai_agent"]), d.guards.traced("agents:read_inbox"), async (req, res) => {
    res.json({ messages: await d.firewall.inbox(req.principal as MachinePrincipal) });
  });

  return router;
}
