import { Router, type Request } from "express";
import { z } from "zod";
import type { createGuards } from "../authorize.js";
import { clientIp, sendError } from "../principal.js";
import type { HumanPrincipal } from "../types.js";
import type { KillSwitch } from "./service.js";

type Deps = { guards: ReturnType<typeof createGuards>; killSwitch: KillSwitch };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const me = (req: Request) => req.principal as HumanPrincipal;

const body = z.strictObject({
  reason: z.string().trim().min(10, "say why (at least 10 characters) — it goes into the security event and the notice").max(500),
  /** "suspected": stop it, keep its credentials so it can be resumed. "confirmed": also revoke credentials and delegations. */
  compromise: z.enum(["suspected", "confirmed"]),
});
const allBody = body.extend({
  /** Must be true: a guard against stopping every agent by accident. */
  confirmAll: z.literal(true, { error: "set confirmAll: true to stop every AI agent in the organisation" }),
});

/** Administrators: the emergency stop. Mounted at /kill-switch. */
export function killSwitchRouter(d: Deps): Router {
  const router = Router();
  const admin = d.guards.requireHuman(["admin"]);
  const staff = d.guards.requireHuman(["admin", "analyst"]);

  const origin = (req: Request) => ({ requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent") });

  /** Stop one agent (or service account) now. */
  router.post("/agents/:id", admin, async (req, res) => {
    const parsed = body.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const id = String(req.params.id ?? "");
    if (!UUID.test(id)) return sendError(res, 404, "not_found", "No such identity.");
    const result = await d.killSwitch.activate({
      tenantId: me(req).tenantId, identityIds: [id], reason: parsed.data.reason, compromise: parsed.data.compromise,
      actor: me(req), kind: "agent_killed", ...origin(req),
    });
    if (result.notFound.length) return sendError(res, 404, "not_found", "No such identity.");
    res.json(result);
  });

  /** Stop every active AI agent in the organisation. */
  router.post("/all", admin, async (req, res) => {
    const parsed = allBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const result = await d.killSwitch.activate({
      tenantId: me(req).tenantId, identityIds: "all_agents", reason: parsed.data.reason, compromise: parsed.data.compromise,
      actor: me(req), kind: "agent_killed", ...origin(req),
    });
    res.json(result);
  });

  router.get("/events", staff, async (req, res) => {
    const q = req.query;
    res.json({
      events: await d.killSwitch.events(me(req).tenantId, {
        identityId: typeof q.identityId === "string" && UUID.test(q.identityId) ? q.identityId : undefined,
        before: typeof q.before === "string" && /^\d+$/.test(q.before) ? q.before : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/events/verify", admin, async (req, res) => {
    res.json(await d.killSwitch.verifyChain(me(req).tenantId));
  });

  router.get("/notifications", admin, async (req, res) => {
    res.json({ notifications: await d.killSwitch.notifications(me(req).tenantId, Number(req.query.limit) || 100) });
  });

  /** Retry notices that failed (hosts should also call killSwitch.deliverPending() every minute). */
  router.post("/notifications/retry", admin, async (req, res) => {
    res.json(await d.killSwitch.deliverPending(me(req).tenantId));
  });

  return router;
}
