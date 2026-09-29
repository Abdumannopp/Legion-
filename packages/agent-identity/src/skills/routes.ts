import { Router, type Request, type Response } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import type { AgentFirewall } from "../firewall/engine.js";
import { clientIp, sendError } from "../principal.js";
import type { HumanPrincipal, MachinePrincipal } from "../types.js";
import type { SkillAssignments } from "./assignments.js";
import { SKILL_NAME } from "./registry.js";
import type { SkillRuntime } from "./runtime.js";
import { SkillError } from "./types.js";

type Deps = {
  guards: ReturnType<typeof createGuards>;
  firewall: AgentFirewall;
  skills: SkillRuntime;
  skillAssignments: SkillAssignments;
  audit: AuditLog;
  log: (msg: string, err?: unknown) => void;
};

function skillError(res: Response, err: unknown, log: Deps["log"]) {
  if (err instanceof SkillError) {
    return res.status(err.status).json({
      error: {
        code: err.code, message: err.message,
        ...(err.details.rules ? { rules: err.details.rules } : {}),
        ...(err.details.decisionIds ? { decisionIds: err.details.decisionIds } : {}),
        ...(err.details.missing ? { missing: err.details.missing } : {}),
      },
    });
  }
  log("skill request failed", err);
  return sendError(res, 500, "skill_failed", "The skill failed.");
}

/** Agents: discover and run their assigned skills. Mounted inside the agent API. */
export function skillAgentRouter(d: Deps): Router {
  const router = Router();
  const machine = d.guards.requireMachine(["ai_agent", "service_account"]);

  // Only what is assigned to this agent, and whether it can run it now.
  router.get("/skills", machine, async (req, res) => {
    const p = req.principal as MachinePrincipal;
    try {
      const assigned = await d.skillAssignments.listFor(p.tenantId, p.id);
      const skills = assigned.flatMap((a) => {
        const s = d.skills.registry.describe(a.skill);
        if (!s) return [];
        const missing = s.requiredPermissions.filter((perm) => !p.permissions.includes(perm as never));
        return [{ ...s, assignedAt: a.assignedAt, runnable: missing.length === 0, missingPermissions: missing }];
      });
      res.json({ skills });
    } catch (err) {
      d.log("skill discovery failed", err);
      sendError(res, 503, "skills_unavailable", "Skills could not be listed.");
    }
  });

  router.post("/skills/:name/invoke", machine, async (req, res) => {
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((k) => k !== "input")) {
      return sendError(res, 400, "invalid_request", "Send { \"input\": { … } }.");
    }
    try {
      const { ctx, extraHits } = await d.firewall.contextFromRequest(req);
      const result = await d.skills.invoke(ctx, String(req.params.name), body.input, {
        requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent"), extraHits,
      });
      res.setHeader("x-legion-skill-invocation", result.invocationId);
      res.json(result);
    } catch (err) {
      skillError(res, err, d.log);
    }
  });

  return router;
}

const assignBody = z.strictObject({ identityId: z.uuid(), skill: z.string().regex(SKILL_NAME) });

/** People: the skill catalogue and who may use what. Mounted at /skills. */
export function skillAdminRouter(d: Deps): Router {
  const router = Router();
  const staff = d.guards.requireHuman(["admin", "analyst"]);
  const admin = d.guards.requireHuman(["admin"]);
  const me = (req: Request) => req.principal as HumanPrincipal;

  router.get("/", staff, (_req, res) => {
    res.json({ skills: d.skills.registry.list() });
  });

  router.get("/assignments", staff, async (req, res) => {
    const identityId = typeof req.query.identityId === "string" ? req.query.identityId : undefined;
    const list = identityId
      ? await d.skillAssignments.listFor(me(req).tenantId, identityId).catch(() => null)
      : await d.skillAssignments.listTenant(me(req).tenantId).catch(() => null);
    if (!list) return sendError(res, 503, "skills_unavailable", "Assignments could not be read.");
    res.json({ assignments: list });
  });

  // Assigning a skill grants no permission. The response says which
  // permissions the agent still lacks; an administrator grants those
  // separately, through the normal identity management (and its checks).
  router.post("/assignments", admin, async (req, res) => {
    const parsed = assignBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const h = me(req);
    const skill = d.skills.registry.describe(parsed.data.skill);
    if (!skill) return sendError(res, 404, "unknown_skill", "No such skill.");
    const identity = await d.skillAssignments.identity(h.tenantId, parsed.data.identityId);
    if (!identity) return sendError(res, 404, "not_found", "No such agent in this organisation.");
    if (identity.status !== "active") return sendError(res, 409, "identity_not_active", `This identity is ${identity.status}.`);
    const event = { principal: h, action: "skill.assign", resourceType: "machine_identity", resourceId: identity.id, requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent") };
    try {
      await d.audit.record({ ...event, outcome: "attempt", details: { skill: skill.name, version: skill.version } });
    } catch (err) {
      d.log("audit unavailable; refusing skill assignment", err);
      return sendError(res, 503, "audit_unavailable", "The assignment was not made because it could not be recorded.");
    }
    const { assignment, created } = await d.skillAssignments.assign(h.tenantId, identity.id, skill.name, h.id);
    const missing = skill.requiredPermissions.filter((p) => !identity.permissions.includes(p));
    await d.audit.record({ ...event, outcome: "success", details: { skill: skill.name, created, missingPermissions: missing } })
      .catch((err) => d.log("audit write failed for a skill assignment", err));
    res.status(created ? 201 : 200).json({
      assignment,
      requiredPermissions: skill.requiredPermissions,
      missingPermissions: missing,
      note: missing.length
        ? `The agent cannot run this skill until it is granted ${missing.join(", ")}. Assigning a skill grants no permission.`
        : "The agent holds the permissions this skill needs.",
    });
  });

  router.delete("/assignments/:identityId/:skill", admin, async (req, res) => {
    const h = me(req);
    const skill = String(req.params.skill);
    if (!SKILL_NAME.test(skill)) return sendError(res, 400, "invalid_request", "Not a skill name.");
    const identity = await d.skillAssignments.identity(h.tenantId, String(req.params.identityId));
    if (!identity) return sendError(res, 404, "not_found", "No such agent in this organisation.");
    const revoked = await d.skillAssignments.revoke(h.tenantId, identity.id, skill, h.id);
    await d.audit.record({
      principal: h, action: "skill.unassign", outcome: revoked ? "success" : "failure", resourceType: "machine_identity", resourceId: identity.id,
      reason: revoked ? undefined : "not assigned", requestId: req.requestId, ip: clientIp(req), details: { skill },
    }).catch((err) => d.log("audit write failed for a skill unassignment", err));
    if (!revoked) return sendError(res, 404, "not_assigned", "That skill is not assigned to this agent.");
    res.json({ revoked: true });
  });

  return router;
}

