import { Router, type Request, type Response } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import {
  baselineRisk,
  exceedsRole,
  isPermission,
  riskAtLeast,
  type Permission,
} from "../permissions.js";
import { sendError, clientIp } from "../principal.js";
import type { KillSwitch } from "../killswitch/service.js";
import type { Identity, IdentityStore } from "../store.js";
import type { HostAdapter, HumanPrincipal, MachineKind, RiskLevel } from "../types.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const riskEnum = z.enum(["low", "medium", "high", "critical"]);
const futureDate = z.iso.datetime({ offset: true }).refine((v) => new Date(v).getTime() > Date.now(), "must be in the future");

const createBody = z.strictObject({
  name: z.string().trim().min(1).max(100),
  description: z.string().max(1000).default(""),
  ownerUserId: z.string().min(1).max(200).optional(),
  permissions: z.array(z.string()).max(50).default([]),
  riskLevel: riskEnum.optional(),
  expiresAt: futureDate.nullable().optional(),
});

const patchBody = z.strictObject({
  name: z.string().trim().min(1).max(100).optional(),
  description: z.string().max(1000).optional(),
  ownerUserId: z.string().min(1).max(200).optional(),
  permissions: z.array(z.string()).max(50).optional(),
  riskLevel: riskEnum.optional(),
  expiresAt: futureDate.nullable().optional(),
});

const reasonBody = z.strictObject({ reason: z.string().trim().max(500).optional() });
const credentialBody = z.strictObject({ expiresAt: futureDate.nullable().optional() });

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const r = schema.safeParse(body ?? {});
  if (!r.success) {
    const first = r.error.issues[0];
    throw new HttpError(400, "invalid_request", `${first?.path.join(".") || "body"}: ${first?.message}`);
  }
  return r.data;
}

function validPermissions(list: string[]): Permission[] {
  const unknown = list.filter((p) => !isPermission(p));
  if (unknown.length) {
    throw new HttpError(400, "unknown_permission",
      `Not grantable to machine identities: ${unknown.join(", ")}. Administrative actions stay with people.`);
  }
  return [...new Set(list as Permission[])];
}

function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "23505";
}

/**
 * CRUD and lifecycle for one kind of machine identity. Mounted twice by the
 * module: /agents (ai_agent) and /service-accounts (service_account).
 * People only — requireHuman refuses every machine principal.
 */
export function managementRouter(
  kind: MachineKind,
  deps: { store: IdentityStore; audit: AuditLog; host: HostAdapter; guards: ReturnType<typeof createGuards>; killSwitch: KillSwitch },
): Router {
  const { store, audit, host, guards, killSwitch } = deps;
  const router = Router();
  const admin = guards.requireHuman(["admin"]);
  const staff = guards.requireHuman(["admin", "analyst"]);
  const anyone = guards.requireHuman(["admin", "analyst", "viewer"]);

  const me = (req: Request) => req.principal as HumanPrincipal;
  const ctx = (req: Request) => ({
    principal: me(req),
    resourceType: kind,
    requestId: req.requestId,
    ip: clientIp(req),
    userAgent: req.get("user-agent"),
  });

  /** The owner must be an active person in the same tenant whose role covers the permissions. */
  async function checkOwner(tenantId: string, ownerUserId: string, permissions: Permission[]) {
    const owner = await host.getUser(tenantId, ownerUserId);
    if (!owner || owner.status !== "active" || owner.tenantId !== tenantId) {
      throw new HttpError(400, "invalid_owner", "The owner must be an active user of this organisation.");
    }
    const over = exceedsRole(owner.role, permissions);
    if (over.length) {
      throw new HttpError(400, "exceeds_owner_role",
        `An identity cannot hold more than its owner. The owner's role (${owner.role}) does not include: ${over.join(", ")}.`);
    }
  }

  function resolveRisk(requested: RiskLevel | undefined, current: RiskLevel | undefined, permissions: Permission[]): RiskLevel {
    const floor = baselineRisk(permissions);
    if (requested) {
      if (!riskAtLeast(requested, floor)) {
        throw new HttpError(400, "risk_below_baseline",
          `These permissions imply at least "${floor}" risk; it can be raised, not lowered.`);
      }
      return requested;
    }
    return current && riskAtLeast(current, floor) ? current : floor;
  }

  const handle =
    (fn: (req: Request, res: Response) => Promise<void>) => async (req: Request, res: Response) => {
      try {
        await fn(req, res);
      } catch (err) {
        if (err instanceof HttpError) return sendError(res, err.status, err.code, err.message);
        if (isUniqueViolation(err)) return sendError(res, 409, "name_taken", "An active identity with this name already exists.");
        throw err;
      }
    };

  function idParam(req: Request): string {
    const id = String(req.params.id ?? "");
    if (!UUID.test(id)) throw new HttpError(404, "not_found", "No such identity.");
    return id;
  }

  async function lockedIdentity(c: Parameters<Parameters<IdentityStore["tx"]>[0]>[0], req: Request): Promise<Identity> {
    const found = await store.getForUpdate(c, me(req).tenantId, kind, idParam(req));
    if (!found) throw new HttpError(404, "not_found", "No such identity.");
    return found;
  }

  router.post("/", admin, handle(async (req, res) => {
    const body = parse(createBody, req.body);
    const caller = me(req);
    const permissions = validPermissions(body.permissions);
    const ownerUserId = body.ownerUserId ?? caller.id;
    await checkOwner(caller.tenantId, ownerUserId, permissions);
    const riskLevel = resolveRisk(body.riskLevel, undefined, permissions);

    const out = await store.tx(async (c) => {
      const created = await store.create(c, {
        tenantId: caller.tenantId,
        kind,
        name: body.name,
        description: body.description,
        ownerUserId,
        permissions,
        riskLevel,
        expiresAt: body.expiresAt ?? null,
        createdBy: caller.id,
      });
      await audit.record({
        ...ctx(req),
        action: "identity.created",
        outcome: "success",
        resourceId: created.identity.id,
        details: { name: created.identity.name, ownerUserId, permissions, riskLevel, credentialId: created.credential.id },
      }, c);
      return created;
    });

    res.status(201).json({
      identity: out.identity,
      credential: {
        ...out.credential,
        secret: out.secret,
        notice: "Store this secret now. Legion keeps only a hash and cannot show it again.",
      },
    });
  }));

  router.get("/", staff, handle(async (req, res) => {
    res.json({ identities: await store.list(me(req).tenantId, kind) });
  }));

  router.get("/:id", staff, handle(async (req, res) => {
    const identity = await store.get(me(req).tenantId, kind, idParam(req));
    if (!identity) throw new HttpError(404, "not_found", "No such identity.");
    res.json({ identity, credentials: await store.listCredentials(identity.id) });
  }));

  router.patch("/:id", admin, handle(async (req, res) => {
    const body = parse(patchBody, req.body);
    const updated = await store.tx(async (c) => {
      const current = await lockedIdentity(c, req);
      if (current.status === "revoked") throw new HttpError(409, "revoked", "A revoked identity cannot be changed.");

      const permissions = body.permissions ? validPermissions(body.permissions) : current.permissions;
      const ownerUserId = body.ownerUserId ?? current.ownerUserId;
      if (body.permissions || body.ownerUserId) await checkOwner(current.tenantId, ownerUserId, permissions);
      const riskLevel = resolveRisk(body.riskLevel, current.riskLevel, permissions);

      const next = await store.update(c, current.id, {
        name: body.name,
        description: body.description,
        ownerUserId: body.ownerUserId,
        permissions: body.permissions ? permissions : undefined,
        riskLevel,
        expiresAt: body.expiresAt,
      });
      const changes: Record<string, { from: unknown; to: unknown }> = {};
      for (const k of ["name", "description", "ownerUserId", "permissions", "riskLevel", "expiresAt"] as const) {
        if (JSON.stringify(current[k]) !== JSON.stringify(next[k])) changes[k] = { from: current[k], to: next[k] };
      }
      await audit.record({ ...ctx(req), action: "identity.updated", outcome: "success", resourceId: current.id, details: { changes } }, c);
      return next;
    });
    res.json({ identity: updated });
  }));

  // Suspension is the fast "stop this agent now" switch, so its owner may use
  // it too — not only administrators. Resuming stays with administrators.
  // Suspension and revocation go through the kill switch, so every way of
  // stopping an identity has the same effect: tokens, tool tickets and
  // pending agent requests withdrawn, running tool calls aborted, a
  // security event recorded and administrators notified.
  router.post("/:id/suspend", anyone, handle(async (req, res) => {
    const { reason } = parse(reasonBody, req.body);
    const caller = me(req);
    const current = await store.get(caller.tenantId, kind, idParam(req));
    if (!current) throw new HttpError(404, "not_found", "No such identity.");
    if (caller.role !== "admin" && current.ownerUserId !== caller.id) {
      throw new HttpError(403, "forbidden", "Only an administrator or the identity's owner can suspend it.");
    }
    if (current.status === "revoked") throw new HttpError(409, "revoked", "This identity is revoked.");
    await killSwitch.activate({
      tenantId: caller.tenantId, identityIds: [current.id], onlyKind: kind, reason: reason ?? null, compromise: "none",
      actor: caller, kind: "agent_suspended", requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent"),
    });
    res.json({ identity: await store.get(caller.tenantId, kind, current.id) });
  }));

  router.post("/:id/resume", admin, handle(async (req, res) => {
    const { reason } = parse(reasonBody, req.body);
    const updated = await store.tx(async (c) => {
      const current = await lockedIdentity(c, req);
      if (current.status !== "suspended") throw new HttpError(409, "invalid_transition", `Cannot resume an identity that is ${current.status}.`);
      const next = await store.setStatus(c, current.id, "active", null);
      await audit.record({ ...ctx(req), action: "identity.resumed", outcome: "success", resourceId: current.id, reason }, c);
      return next;
    });
    res.json({ identity: updated });
  }));

  router.post("/:id/revoke", admin, handle(async (req, res) => {
    const { reason } = parse(reasonBody, req.body);
    const caller = me(req);
    const current = await store.get(caller.tenantId, kind, idParam(req));
    if (!current) throw new HttpError(404, "not_found", "No such identity.");
    if (current.status === "revoked") throw new HttpError(409, "revoked", "Already revoked.");
    await killSwitch.activate({
      tenantId: caller.tenantId, identityIds: [current.id], onlyKind: kind, reason: reason ?? null, compromise: "none",
      actor: caller, kind: "agent_revoked", status: "revoked", requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent"),
    });
    res.json({ identity: await store.get(caller.tenantId, kind, current.id) });
  }));

  router.post("/:id/credentials", admin, handle(async (req, res) => {
    const body = parse(credentialBody, req.body);
    const out = await store.tx(async (c) => {
      const current = await lockedIdentity(c, req);
      if (current.status === "revoked") throw new HttpError(409, "revoked", "A revoked identity cannot get credentials.");
      const created = await store.addCredential(c, current, me(req).id, body.expiresAt ?? null);
      if (!created) {
        throw new HttpError(409, "too_many_credentials",
          "Two usable credentials already exist. Revoke one first — two is enough to rotate without downtime.");
      }
      await audit.record({
        ...ctx(req), action: "credential.created", outcome: "success", resourceId: current.id,
        details: { credentialId: created.credential.id },
      }, c);
      return created;
    });
    res.status(201).json({
      credential: { ...out.credential, secret: out.secret, notice: "Store this secret now. Legion keeps only a hash." },
    });
  }));

  router.delete("/:id/credentials/:credentialId", admin, handle(async (req, res) => {
    const credentialId = String(req.params.credentialId ?? "");
    if (!UUID.test(credentialId)) throw new HttpError(404, "not_found", "No such credential.");
    await store.tx(async (c) => {
      const current = await lockedIdentity(c, req);
      if (!(await store.revokeCredential(c, current.id, credentialId))) {
        throw new HttpError(404, "not_found", "No such active credential.");
      }
      await audit.record({
        ...ctx(req), action: "credential.revoked", outcome: "success", resourceId: current.id, details: { credentialId },
      }, c);
    });
    res.status(204).end();
  }));

  router.get("/:id/activity", staff, handle(async (req, res) => {
    const id = idParam(req);
    const identity = await store.get(me(req).tenantId, kind, id);
    if (!identity) throw new HttpError(404, "not_found", "No such identity.");
    const before = typeof req.query.before === "string" && /^\d+$/.test(req.query.before) ? req.query.before : undefined;
    const limit = Number(req.query.limit) || 100;
    res.json({ events: await audit.list(identity.tenantId, { involving: { id, resourceType: kind }, before, limit }) });
  }));

  return router;
}

/** Tenant-wide view of who did what, across all four principal types. Administrators only. */
export function auditRouter(deps: { audit: AuditLog; guards: ReturnType<typeof createGuards> }): Router {
  const router = Router();
  const admin = deps.guards.requireHuman(["admin"]);
  const types = new Set(["human", "ai_agent", "service_account", "external_system"]);

  router.get("/", admin, async (req, res) => {
    const p = req.principal as HumanPrincipal;
    const q = req.query;
    const principalType = typeof q.principalType === "string" && types.has(q.principalType) ? q.principalType : undefined;
    res.json({
      events: await deps.audit.list(p.tenantId, {
        principalType: principalType as never,
        principalId: typeof q.principalId === "string" ? q.principalId : undefined,
        before: typeof q.before === "string" && /^\d+$/.test(q.before) ? q.before : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/verify", admin, async (req, res) => {
    res.json(await deps.audit.verifyChain((req.principal as HumanPrincipal).tenantId));
  });

  return router;
}
