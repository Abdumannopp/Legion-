/**
 * HTTP routes of the SOC core (Task 10). Authentication, permission checks,
 * input parsing and auditing come from index.ts, so every route here follows
 * exactly the same rules as the rest of the API.
 */
import type { Express, NextFunction, Request, RequestHandler, Response } from "express";
import { z } from "zod";
import type { Permission } from "./permissions.js";
import type { User } from "./types.js";
import { catalogList, CATALOG_VERSION, ACTION_IDS } from "./policy/catalog.js";
import { DEFAULT_POLICY, parsePolicyDocument } from "./policy/document.js";
import { ENGINE_VERSION, evaluatePolicy } from "./policy/evaluate.js";
import { getActivePolicy, listDecisions, listPolicyVersions, PolicyConflict, PolicyInvalid, putPolicy, rollbackPolicy } from "./policy/store.js";
import { AGENTS, ORIGINS } from "./policy/types.js";
import { ApprovalError, decide, getApproval, listApprovals, type ApprovalStatus } from "./approvals/engine.js";

type AuthedRequest = Request & { user?: User };
type Middleware = (req: AuthedRequest, res: Response, next: NextFunction) => Promise<void>;

export interface SocRouteDeps {
  requirePermission: (p: Permission) => Middleware;
  parse: <T>(schema: z.ZodType<T>, value: unknown, res: Response) => T | null;
  log: (req: AuthedRequest, action: string, resourceType?: string | null, resourceId?: string | null, detail?: string | null) => Promise<void>;
  /** True only for a current, unused TOTP code of a user who has two-factor sign-in on. */
  verifyMfa: (user: User, code: string) => Promise<boolean>;
  /** Counts failed attempts per signed-in user (wrong codes): brute-force brake. */
  stepUp: RequestHandler;
}

const limitOf = (v: unknown, max = 200) => Math.min(max, Math.max(1, Math.floor(Number(v ?? 50)) || 50));

const APPROVAL_STATUSES = ["pending", "approved", "rejected", "expired", "consumed", "cancelled"] as const;

export function registerSocRoutes(app: Express, { requirePermission, parse, log, verifyMfa, stepUp }: SocRouteDeps): void {
  // --- Policy Engine v0 -------------------------------------------------------

  app.get("/policy", requirePermission("policy:read"), async (req: AuthedRequest, res) => {
    const active = await getActivePolicy(req.user!.tenant_id);
    res.json({
      enforcement: "shadow",
      active: active ?? null,
      default: DEFAULT_POLICY,
      catalog: catalogList(),
      catalog_version: CATALOG_VERSION,
      engine_version: ENGINE_VERSION,
    });
  });

  app.get("/policy/versions", requirePermission("policy:read"), async (req: AuthedRequest, res) => {
    res.json({ versions: await listPolicyVersions(req.user!.tenant_id) });
  });

  app.put("/policy", requirePermission("policy:manage"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({
      document: z.unknown(),
      expected_version: z.number().int().min(0),
      note: z.string().max(200).optional(),
    }), req.body, res); if (!body) return;
    try {
      const active = await putPolicy(req.user!.tenant_id, body.document, { expectedVersion: body.expected_version, userId: req.user!.id, note: body.note });
      await log(req, "policy.updated", "policy", String(active.version), `hash ${active.hash.slice(0, 16)}`);
      res.json({ active });
    } catch (error) {
      if (error instanceof PolicyConflict) return res.status(409).json({ detail: error.message, current_version: error.current });
      if (error instanceof PolicyInvalid) return res.status(422).json({ detail: error.message });
      throw error;
    }
  });

  app.post("/policy/rollback", requirePermission("policy:manage"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({ version: z.number().int().min(1), expected_version: z.number().int().min(0) }), req.body, res); if (!body) return;
    try {
      const active = await rollbackPolicy(req.user!.tenant_id, body.version, { expectedVersion: body.expected_version, userId: req.user!.id });
      if (!active) return res.status(404).json({ detail: "No such policy version" });
      await log(req, "policy.rolled_back", "policy", String(active.version), `to v${body.version}`);
      res.json({ active });
    } catch (error) {
      if (error instanceof PolicyConflict) return res.status(409).json({ detail: error.message, current_version: error.current });
      if (error instanceof PolicyInvalid) return res.status(422).json({ detail: error.message });
      throw error;
    }
  });

  /**
   * What the policy would decide — the active one, or a draft — for a
   * hypothetical request. Evaluates only: nothing is recorded or done.
   */
  app.post("/policy/simulate", requirePermission("policy:read"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({
      action_id: z.string().max(64),
      actor: z.discriminatedUnion("kind", [
        z.strictObject({ kind: z.literal("agent"), agent: z.enum(AGENTS) }),
        z.strictObject({ kind: z.literal("human") }),
        z.strictObject({ kind: z.literal("system") }),
      ]),
      origin: z.enum(ORIGINS),
      mode: z.enum(["shadow", "simulation", "live"]).default("simulation"),
      document: z.unknown().optional(),
    }), req.body, res); if (!body) return;
    let doc = null;
    if (body.document !== undefined) {
      const parsed = parsePolicyDocument(body.document);
      if (!parsed.ok) return res.status(422).json({ detail: parsed.error });
      doc = parsed.document;
    } else {
      doc = (await getActivePolicy(req.user!.tenant_id))?.document ?? null;
    }
    // A "human" actor is the caller themself, with their real role.
    const actor = body.actor.kind === "human"
      ? { kind: "human" as const, user_id: req.user!.id, role: req.user!.role }
      : body.actor.kind === "system" ? { kind: "system" as const, component: "simulation" } : body.actor;
    res.json({ outcome: evaluatePolicy({ action_id: body.action_id, actor, origin: body.origin, mode: body.mode }, doc), recorded: false });
  });

  app.get("/policy/decisions", requirePermission("policy:read"), async (req: AuthedRequest, res) => {
    const raw = req.query.action_id;
    if (raw !== undefined && (typeof raw !== "string" || !ACTION_IDS.includes(raw))) return res.status(422).json({ detail: "Unknown action" });
    const actionId = raw as string | undefined;
    res.json({ decisions: await listDecisions(req.user!.tenant_id, { limit: limitOf(req.query.limit), actionId }) });
  });

  // --- Approval Engine v0 -----------------------------------------------------
  // Requests are created only by the action engine. People list, read, decide.

  app.get("/approvals", requirePermission("approvals:read"), async (req: AuthedRequest, res) => {
    const raw = req.query.status;
    if (raw !== undefined && (typeof raw !== "string" || !(APPROVAL_STATUSES as readonly string[]).includes(raw))) return res.status(422).json({ detail: "Unknown status" });
    res.json({ approvals: await listApprovals(req.user!.tenant_id, { status: raw as ApprovalStatus | undefined, limit: limitOf(req.query.limit) }) });
  });

  app.get("/approvals/:id", requirePermission("approvals:read"), async (req: AuthedRequest, res) => {
    const a = await getApproval(req.user!.tenant_id, String(req.params.id));
    return a ? res.json(a) : res.status(404).json({ detail: "No such approval request" });
  });

  app.post("/approvals/:id/decision", stepUp, requirePermission("approvals:decide"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({
      decision: z.enum(["approve", "reject"]),
      action_digest: z.string().regex(/^[0-9a-f]{64}$/, "action_digest must be the 64-character digest shown with the request"),
      reason: z.string().max(500).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), "No control characters").optional(),
      mfa_code: z.string().regex(/^\d{6,8}$/).optional(),
    }), req.body, res); if (!body) return;
    const user = req.user!;
    // The second factor is checked here, for THIS decision; the engine only
    // learns whether it was verified.
    const mfaVerified = body.mfa_code !== undefined && user.mfa_enabled && (await verifyMfa(user, body.mfa_code));
    try {
      const out = await decide(user.tenant_id, String(req.params.id), {
        userId: user.id, decision: body.decision, reason: body.reason, actionDigest: body.action_digest, mfaVerified,
      });
      const verb = out.settled ?? (body.decision === "approve" ? "approval_counted" : "rejected");
      await log(req, `approval.${verb}`, "approval", out.approval.id, `${out.approval.action_id} ${out.approval.approvals}/${out.approval.required_approvals}`);
      res.json(out);
    } catch (error) {
      if (error instanceof ApprovalError) return res.status(error.status).json({ detail: error.message, code: error.code });
      throw error;
    }
  });
}
