import { Router, type Request } from "express";
import { z } from "zod";
import type { createGuards } from "../authorize.js";
import type { AgentFirewall } from "../firewall/engine.js";
import { sendError } from "../principal.js";
import type { HumanPrincipal, MachinePrincipal } from "../types.js";
import type { ToolGateway } from "./gateway.js";
import { TOOL_KINDS } from "./types.js";

type Deps = { guards: ReturnType<typeof createGuards>; firewall: AgentFirewall; tools: ToolGateway };

/** Machines: ask before every tool call; tool servers verify the ticket. Mounted inside the agent API. */
export function toolAgentRouter(d: Deps): Router {
  const router = Router();

  // An agent asks Legion before running a tool. Allowed calls get a
  // single-use ticket bound to the exact arguments.
  router.post("/tools/authorize", d.guards.requireMachine(["ai_agent", "service_account"]), async (req, res) => {
    const { ctx, extraHits } = await d.firewall.contextFromRequest(req);
    const auth = await d.tools.authorize(ctx, req.body?.call, extraHits);
    const dec = auth.decision;
    req.firewallDecision = dec;
    res.setHeader("x-legion-firewall", dec.decision.toLowerCase());
    res.setHeader("x-legion-decision-id", dec.decisionId);
    const body = {
      decision: dec.decision,
      decisionId: dec.decisionId,
      wouldBlock: dec.wouldBlock,
      riskScore: dec.riskScore,
      tool: auth.analysis.toolKind,
      operation: auth.analysis.operation,
      target: auth.analysis.target,
      destination: auth.analysis.destination,
      permission: auth.analysis.permission,
      highRisk: auth.analysis.highRisk,
      audited: auth.audited,
      rules: dec.hits.map((h) => ({ id: h.id, effect: h.effect, reason: h.reason })),
      ticket: auth.ticket?.value ?? null,
      ticketExpiresAt: auth.ticket?.expiresAt ?? null,
    };
    if (dec.decision === "BLOCK") {
      return res.status(403).json({ error: { code: "tool_blocked", message: dec.hits.find((h) => h.effect === "BLOCK")?.reason ?? "Blocked.", decisionId: dec.decisionId, rules: body.rules.filter((r) => r.effect === "BLOCK").map((r) => r.id) }, ...body });
    }
    res.json(body);
  });

  // A tool server (service account) confirms Legion approved this exact call.
  const verifyBody = z.strictObject({ ticket: z.string().max(200), call: z.unknown() });
  router.post("/tools/verify", d.guards.requireMachine(["service_account"]), d.guards.traced("tools:verify_ticket"), async (req, res) => {
    const parsed = verifyBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const r = await d.tools.verifyTicket(req.principal as MachinePrincipal, parsed.data.ticket, parsed.data.call);
    if (!r.ok) return res.status(403).json({ valid: false, reason: r.reason });
    res.json({ valid: true, decisionId: r.decisionId, agentId: r.agentId });
  });

  return router;
}

/** People: the tool audit log. Mounted at /tools. */
export function toolAdminRouter(d: Deps): Router {
  const router = Router();
  const staff = d.guards.requireHuman(["admin", "analyst"]);
  const admin = d.guards.requireHuman(["admin"]);
  const me = (req: Request) => req.principal as HumanPrincipal;

  router.get("/audit", staff, async (req, res) => {
    const q = req.query;
    const s = (v: unknown) => (typeof v === "string" ? v : undefined);
    const decision = s(q.decision);
    const toolKind = s(q.tool);
    const phase = s(q.phase);
    res.json({
      events: await d.tools.audit.list(me(req).tenantId, {
        decision: decision && ["ALLOW", "WARN", "BLOCK"].includes(decision) ? decision : undefined,
        principalId: s(q.principalId),
        toolKind: toolKind && ([...TOOL_KINDS, "unknown"] as string[]).includes(toolKind) ? toolKind : undefined,
        phase: phase && ["decision", "outcome", "ticket_verified", "ticket_rejected"].includes(phase) ? phase : undefined,
        before: s(q.before) && /^\d+$/.test(s(q.before)!) ? s(q.before) : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/audit/verify", admin, async (req, res) => {
    res.json(await d.tools.audit.verifyChain(me(req).tenantId));
  });

  return router;
}
