import { Router, type Request } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import { clientIp, sendError } from "../principal.js";
import type { IdentityStore } from "../store.js";
import type { HumanPrincipal } from "../types.js";
import type { BehaviorMonitor } from "./monitor.js";

type Deps = { guards: ReturnType<typeof createGuards>; behavior: BehaviorMonitor; store: IdentityStore; audit: AuditLog };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const me = (req: Request) => req.principal as HumanPrincipal;

/** People: behaviour of the tenant's agents. Mounted at /behavior. */
export function behaviorAdminRouter(d: Deps): Router {
  const router = Router();
  const staff = d.guards.requireHuman(["admin", "analyst"]);
  const admin = d.guards.requireHuman(["admin"]);

  async function identity(req: Request) {
    const id = String(req.params.id ?? "");
    if (!UUID.test(id)) return null;
    return (await d.store.get(me(req).tenantId, "ai_agent", id)) ?? (await d.store.get(me(req).tenantId, "service_account", id));
  }

  /** Every monitored agent, worst first. */
  router.get("/agents", staff, async (req, res) => {
    res.json({ agents: await d.behavior.listStates(me(req).tenantId) });
  });

  /** A fresh assessment and the baseline it was compared with. */
  router.get("/agents/:id", staff, async (req, res) => {
    const i = await identity(req);
    if (!i) return sendError(res, 404, "not_found", "No such agent.");
    const { assessment, profile } = await d.behavior.refresh(i.tenantId, i.id, i.name);
    res.json({
      identity: { id: i.id, name: i.name, kind: i.kind, status: i.status },
      assessment,
      profile: {
        established: profile.established,
        events: profile.events,
        since: profile.since,
        until: profile.until,
        hourly: profile.hourly,
        blockRate: profile.blockRate,
        sensitiveRate: profile.sensitiveRate,
        messagesPerHour: profile.messagesPerHour,
        topActions: Object.entries(profile.actions).sort((a, b) => b[1] - a[1]).slice(0, 20),
        externalDestinations: Object.keys(profile.externalDestinations).slice(0, 50),
        peers: Object.keys(profile.peers),
      },
    });
  });

  router.get("/events", staff, async (req, res) => {
    const q = req.query;
    res.json({
      events: await d.behavior.events(me(req).tenantId, {
        identityId: typeof q.identityId === "string" && UUID.test(q.identityId) ? q.identityId : undefined,
        before: typeof q.before === "string" && /^\d+$/.test(q.before) ? q.before : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/events/verify", admin, async (req, res) => {
    res.json(await d.behavior.verifyChain(me(req).tenantId));
  });

  /** Reassess every active agent now (hosts also run this on a timer). */
  router.post("/sweep", admin, async (req, res) => {
    res.json({ agents: await d.behavior.sweep(me(req).tenantId) });
  });

  const ackBody = z.strictObject({
    reason: z.string().trim().min(10, "explain what you reviewed (at least 10 characters)").max(500),
    /** true: the reviewed activity is this agent's role — learn it. false: it was wrong — keep it out of the baseline. */
    learn: z.boolean(),
  });
  router.post("/agents/:id/acknowledge", admin, async (req, res) => {
    const parsed = ackBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const i = await identity(req);
    if (!i) return sendError(res, 404, "not_found", "No such agent.");
    const user = me(req);
    await d.store.tx(async (c) => {
      await d.behavior.acknowledge(c, i.tenantId, i.id, i.name, user.id, parsed.data.reason, parsed.data.learn);
      await d.audit.record({
        principal: user, action: "behavior.acknowledged", outcome: "success", resourceType: i.kind, resourceId: i.id,
        reason: parsed.data.reason, requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent"),
        details: { learn: parsed.data.learn },
      }, c);
    });
    res.json({ identityId: i.id, level: "NORMAL", learned: parsed.data.learn });
  });

  return router;
}
