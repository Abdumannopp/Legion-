import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { AuditLog } from "./audit.js";
import type { AgentFirewall } from "./firewall/engine.js";
import { permits, refusalCode, refusingHits, type ActionRequest, type Sensitivity } from "./firewall/types.js";
import { roleAllows, type Permission } from "./permissions.js";
import { clientIp, sendError } from "./principal.js";
import { isMachine, type HumanRole, type MachineKind, type Principal } from "./types.js";

export interface ResourceRef {
  type: string;
  id?: string;
  /** Owning tenant, when known. The firewall blocks a machine whose tenant differs. */
  tenantId?: string;
}

export interface GuardOptions {
  /** Which record the action touches, for the audit trail and the firewall. */
  resource?: (req: Request) => ResourceRef | undefined;
  /** How sensitive the target is (the tenant policy can only raise it). Default "internal". */
  sensitivity?: Sensitivity;
}

export function createGuards(audit: AuditLog, log: (msg: string, err?: unknown) => void, firewall: AgentFirewall) {
  const base = (req: Request, p: Principal, action: string, resource?: ResourceRef) => ({
    principal: p,
    action,
    resourceType: resource?.type,
    resourceId: resource?.id,
    requestId: req.requestId,
    ip: clientIp(req),
    userAgent: req.get("user-agent"),
  });

  /**
   * Records the action BEFORE it runs, and its result after. If the first
   * record cannot be written the action does not run: an agent action that
   * leaves no trace is worse than one that fails.
   */
  /**
   * Every machine request passes the agent firewall here, before the audit
   * trace and before the handler. BLOCK stops it; WARN lets it through,
   * flagged in the response headers and the decision log.
   */
  async function firewallGate(req: Request, res: Response, p: Principal, action: string, permission: Permission | null, opts: GuardOptions, resource?: ResourceRef): Promise<boolean> {
    if (!isMachine(p)) return true;
    const { ctx, extraHits } = await firewall.contextFromRequest(req);
    // The call's content is part of what a person approves (CONFIRM): the
    // approval of "resolve alert 7" does not cover "delete asset 9".
    const request: ActionRequest = {
      surface: "api", action, permission, resource, sensitivity: opts.sensitivity,
      input: { method: req.method, path: req.baseUrl + req.path, query: req.query, body: req.body ?? null },
    };
    const d = await firewall.evaluate(ctx, request, extraHits);
    req.firewallDecision = d;
    res.setHeader("x-legion-firewall", d.decision.toLowerCase());
    res.setHeader("x-legion-decision-id", d.decisionId);
    if (permits(d)) return true;
    const rules = refusingHits(d).map((h) => h.id);
    await audit
      .record({
        ...base(req, p, action, resource), outcome: "denied", reason: `firewall: ${rules.join(", ")}`,
        details: { decisionId: d.decisionId, decision: d.decision, ...(d.approval ? { approvalId: d.approval.id } : {}) },
      })
      .catch((err) => log("audit write failed for a blocked action", err));
    res.status(403).json({
      error: {
        code: refusalCode(d.decision),
        message: refusingHits(d)[0]?.reason ?? "Blocked by the agent firewall.",
        decisionId: d.decisionId,
        decision: d.decision,
        rules,
        ...(d.approval ? { approval: d.approval } : {}),
        ...(d.response ? { containment: d.response } : {}),
      },
    });
    return false;
  }

  async function trace(req: Request, res: Response, next: NextFunction, p: Principal, action: string, resource?: ResourceRef) {
    const event = { ...base(req, p, action, resource), ...(req.firewallDecision ? { details: { decisionId: req.firewallDecision.decisionId } } : {}) };
    try {
      await audit.record({
        ...event,
        outcome: "attempt",
        details: { method: req.method, path: req.path, ...(req.firewallDecision ? { decisionId: req.firewallDecision.decisionId, firewall: req.firewallDecision.decision } : {}) },
      });
    } catch (err) {
      log(`audit unavailable; refusing ${action}`, err);
      return sendError(res, 503, "audit_unavailable", "The action was not performed because it could not be recorded.");
    }
    res.on("finish", () => {
      audit
        .record({
          ...event,
          outcome: res.statusCode < 400 ? "success" : "failure",
          details: { status: res.statusCode, ...(req.firewallDecision ? { decisionId: req.firewallDecision.decisionId } : {}) },
        })
        .catch((err) => log(`audit write failed for the result of ${action}`, err));
    });
    next();
  }

  /**
   * Humans and machine identities always count as authenticated. A named
   * external system (labelled by externalSystem(), e.g. a verified sensor
   * webhook) counts only where `allowNamedExternal` — it can be traced, but it
   * can never hold a permission. Anonymous callers never count.
   */
  function authenticated(req: Request, res: Response, allowNamedExternal = false): Principal | null {
    const p = req.principal;
    if (!p || (p.type === "external_system" && (!allowNamedExternal || p.id === "anonymous"))) {
      sendError(res, 401, "authentication_required", "Sign in, or authenticate as a registered machine identity.");
      return null;
    }
    return p;
  }

  /**
   * The single authorization check for routes that humans and machines can
   * both call. Humans are held to their role, machines to their granted
   * permissions (already narrowed to their owner's role).
   */
  function requirePermission(permission: Permission, opts: GuardOptions = {}): RequestHandler {
    return async (req, res, next) => {
      const p = authenticated(req, res);
      if (!p) return;
      const resource = opts.resource?.(req);
      // Machines: the firewall decides (identity, tenant, delegation,
      // permission, sensitivity, risk). People: their role, as before.
      if (isMachine(p)) {
        if (!(await firewallGate(req, res, p, permission, permission, opts, resource))) return;
        return trace(req, res, next, p, permission, resource);
      }
      const allowed = p.type === "human" && roleAllows(p.role, permission);
      if (!allowed) {
        await audit
          .record({ ...base(req, p, permission, resource), outcome: "denied", reason: "role" })
          .catch((err) => log("audit write failed for a denied action", err));
        return sendError(res, 403, "forbidden", `Missing permission: ${permission}`);
      }
      return trace(req, res, next, p, permission, resource);
    };
  }

  /** Audits an authenticated action that needs no specific permission (e.g. whoami). */
  function traced(action: string, opts: GuardOptions = {}): RequestHandler {
    return async (req, res, next) => {
      const p = authenticated(req, res, true);
      if (!p) return;
      const resource = opts.resource?.(req);
      if (!(await firewallGate(req, res, p, action, null, opts, resource))) return;
      return trace(req, res, next, p, action, resource);
    };
  }

  /** Only machine identities (of the given kinds). Humans are pointed to the human API. */
  function requireMachine(kinds?: MachineKind[]): RequestHandler {
    return (req, res, next) => {
      const p = req.principal;
      if (!isMachine(p) || (kinds && !kinds.includes(p.type))) {
        return sendError(res, 401, "machine_identity_required", "This endpoint is for registered AI agents and service accounts.");
      }
      next();
    };
  }

  /** Only signed-in people with one of these roles. Machines can never manage identities. */
  function requireHuman(roles: HumanRole[]): RequestHandler {
    return async (req, res, next) => {
      const p = req.principal;
      if (isMachine(p)) {
        await audit
          .record({ ...base(req, p, "identity.manage"), outcome: "denied", reason: "machines cannot manage identities" })
          .catch((err) => log("audit write failed", err));
        return sendError(res, 403, "human_required", "Only people can manage machine identities.");
      }
      if (!p || p.type !== "human") return sendError(res, 401, "authentication_required", "Sign in first.");
      if (!roles.includes(p.role)) return sendError(res, 403, "forbidden", "Your role does not allow this.");
      next();
    };
  }

  /** Labels a route's caller as a named external system (e.g. the Wazuh webhook) for the audit trail. */
  function externalSystem(name: string, tenantId?: (req: Request) => string | null): RequestHandler {
    return (req, _res, next) => {
      if (!req.principal || req.principal.type === "external_system") {
        req.principal = { type: "external_system", id: name, tenantId: tenantId?.(req) ?? null, displayName: name };
      }
      next();
    };
  }

  return { requirePermission, traced, requireMachine, requireHuman, externalSystem };
}
