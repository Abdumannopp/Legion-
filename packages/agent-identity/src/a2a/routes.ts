import { Router, type Request } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import { clientIp, sendError } from "../principal.js";
import type { HumanPrincipal } from "../types.js";
import type { TrustGraphService } from "./graph.js";
import type { InteractionLog } from "./log.js";

type Deps = { guards: ReturnType<typeof createGuards>; trustGraph: TrustGraphService; interactions: InteractionLog; audit: AuditLog };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const me = (req: Request) => req.principal as HumanPrincipal;
const days = (req: Request) => Number(req.query.days) || 30;

/** People: the Agent Trust Graph and interaction chains. Mounted at /a2a. */
export function a2aAdminRouter(d: Deps): Router {
  const router = Router();
  const staff = d.guards.requireHuman(["admin", "analyst"]);
  const admin = d.guards.requireHuman(["admin"]);

  /** Who may ask whom for what, on whose authority, and what actually happened. */
  router.get("/graph", staff, async (req, res) => {
    res.json(await d.trustGraph.build(me(req).tenantId, days(req)));
  });

  const snapshotBody = z.strictObject({ note: z.string().trim().max(500).optional(), days: z.number().int().min(1).max(365).optional() });
  /** Freeze the graph as it is now, hash-chained, for audits and incident records. */
  router.post("/graph/snapshots", admin, async (req, res) => {
    const parsed = snapshotBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const user = me(req);
    const s = await d.trustGraph.snapshot(user.tenantId, user.id, parsed.data.note ?? null, parsed.data.days);
    await d.audit.record({
      principal: user, action: "a2a.graph_snapshot", outcome: "success", resourceType: "agent_trust_graph", resourceId: s.snapshotId,
      requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent"), details: { graphHash: s.graphHash },
    });
    res.status(201).json({ snapshotId: s.snapshotId, occurredAt: s.occurredAt, graphHash: s.graphHash });
  });

  router.get("/graph/snapshots", staff, async (req, res) => {
    res.json({ snapshots: await d.trustGraph.listSnapshots(me(req).tenantId) });
  });

  router.get("/graph/snapshots/verify", admin, async (req, res) => {
    res.json(await d.trustGraph.verifySnapshots(me(req).tenantId));
  });

  router.get("/graph/snapshots/:id", staff, async (req, res) => {
    const id = String(req.params.id);
    const s = UUID.test(id) ? await d.trustGraph.getSnapshot(me(req).tenantId, id) : null;
    if (!s) return sendError(res, 404, "not_found", "No such snapshot.");
    res.json(s);
  });

  /** Interactions, newest first; ?agentId= for one agent's. */
  router.get("/interactions", staff, async (req, res) => {
    const agentId = typeof req.query.agentId === "string" && UUID.test(req.query.agentId) ? req.query.agentId : undefined;
    res.json({ interactions: await d.trustGraph.interactions(me(req).tenantId, agentId, Number(req.query.limit) || 50) });
  });

  /** The complete chain of one interaction, for investigation. */
  router.get("/interactions/:id", staff, async (req, res) => {
    const id = String(req.params.id);
    const t = UUID.test(id) ? await d.trustGraph.trace(me(req).tenantId, id) : null;
    if (!t) return sendError(res, 404, "not_found", "No such interaction.");
    res.json(t);
  });

  /** Every step, including refusals with no interaction yet (e.g. a cross-tenant attempt). */
  router.get("/events", staff, async (req, res) => {
    const q = req.query;
    const kinds = new Set(["request_sent", "request_blocked", "request_read", "acted", "act_blocked", "hidden_delegation_blocked"]);
    res.json({
      events: await d.interactions.list(me(req).tenantId, {
        agentId: typeof q.agentId === "string" && UUID.test(q.agentId) ? q.agentId : undefined,
        kind: typeof q.kind === "string" && kinds.has(q.kind) ? (q.kind as never) : undefined,
        before: typeof q.before === "string" && /^\d+$/.test(q.before) ? q.before : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/events/verify", admin, async (req, res) => {
    res.json(await d.interactions.verifyChain(me(req).tenantId));
  });

  return router;
}
