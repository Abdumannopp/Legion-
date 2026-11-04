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
import {
  ActionError, actionEvents, approvalOf, cancelAction, getAction, isPaused, listActions, proposeAction, runQueued, setPaused, syncWithApproval,
  type ActionRequest, type ActionStatus,
} from "./actions/engine.js";
import { getRun, listRuns, runWorkflow, workflowDefinitions, WorkflowError } from "./orchestrator/engine.js";
import { listJobs, runtimeStatus } from "./runtime/queue.js";
import { actionConnectors, connectedFor, connectorsFor } from "./integrations/action-connectors.js";
import { addMemory, forget, listMemory, MAX_TTL_DAYS, MEMORY_KINDS, MemoryError, SUBJECT_TYPES, type SubjectType } from "./memory/store.js";
import { learningSummary } from "./memory/learning.js";

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

const ACTION_STATUSES = ["denied", "recorded", "awaiting_approval", "rejected", "expired", "cancelled", "queued", "running", "simulated", "failed"] as const;
const humanOf = (u: User) => ({ kind: "human" as const, user_id: u.id, role: u.role });

/** v0: a queued simulation runs right away (Background Runtime takes this over later). */
async function settle(tenantId: string, a: ActionRequest | null): Promise<ActionRequest | null> {
  return a?.status === "queued" ? runQueued(tenantId, a.id) : a;
}

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

  // --- Action Engine v0 -------------------------------------------------------
  // A person proposes through here; agents propose through the orchestrator.
  // Who acts and where the request came from are taken from the session.

  app.post("/actions", requirePermission("actions:propose"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({
      action_id: z.string().max(64),
      input: z.record(z.string(), z.unknown()),
      mode: z.enum(["shadow", "simulation"]),
      idempotency_key: z.string().regex(/^[A-Za-z0-9_.:-]{8,100}$/, "idempotency_key: 8–100 letters, digits, . _ : -"),
      reason: z.string().max(500).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), "No control characters").optional(),
    }), req.body, res); if (!body) return;
    const user = req.user!;
    try {
      const { action, replayed } = await proposeAction(user.tenant_id, { ...body, actor: humanOf(user), origin: "human" });
      if (!replayed) await log(req, "action.proposed", "action", action.id, `${action.action_id} → ${action.status} (${action.execution_mode})`);
      res.status(replayed ? 200 : 201).json({ action: replayed ? action : await settle(user.tenant_id, action), replayed });
    } catch (error) {
      if (error instanceof ActionError) return res.status(error.status).json({ detail: error.message, code: error.code });
      throw error;
    }
  });

  app.get("/actions", requirePermission("actions:read"), async (req: AuthedRequest, res) => {
    const raw = req.query.status;
    if (raw !== undefined && (typeof raw !== "string" || !(ACTION_STATUSES as readonly string[]).includes(raw))) return res.status(422).json({ detail: "Unknown status" });
    res.json({ actions: await listActions(req.user!.tenant_id, { status: raw as ActionStatus | undefined, limit: limitOf(req.query.limit) }), paused: await isPaused(req.user!.tenant_id) });
  });

  app.get("/actions/controls", requirePermission("actions:read"), async (req: AuthedRequest, res) => {
    res.json({ paused: await isPaused(req.user!.tenant_id) });
  });

  app.post("/actions/controls", requirePermission("actions:control"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({ paused: z.boolean(), reason: z.string().max(500).optional() }), req.body, res); if (!body) return;
    await setPaused(req.user!.tenant_id, body.paused, req.user!.id, body.reason);
    await log(req, body.paused ? "actions.paused" : "actions.resumed", "tenant", req.user!.tenant_id, body.reason ?? null);
    res.json({ paused: body.paused });
  });

  app.get("/actions/:id", requirePermission("actions:read"), async (req: AuthedRequest, res) => {
    const tenantId = req.user!.tenant_id;
    const found = await getAction(tenantId, String(req.params.id));
    if (!found) return res.status(404).json({ detail: "No such action" });
    const action = found.status === "awaiting_approval" ? (await syncWithApproval(tenantId, found.id, { kind: "system", component: "action_engine" }))! : found;
    res.json({ ...action, events: await actionEvents(tenantId, action.id), approval: await approvalOf(tenantId, action) });
  });

  app.post("/actions/:id/cancel", requirePermission("actions:propose"), async (req: AuthedRequest, res) => {
    try {
      const action = await cancelAction(req.user!.tenant_id, String(req.params.id), humanOf(req.user!));
      if (!action) return res.status(404).json({ detail: "No such action" });
      await log(req, "action.cancelled", "action", action.id, action.action_id);
      res.json({ action });
    } catch (error) {
      if (error instanceof ActionError) return res.status(error.status).json({ detail: error.message, code: error.code });
      throw error;
    }
  });

  // --- Agent Orchestrator v0 -------------------------------------------------
  // Code-defined workflows only. Each step acts as its own agent and proposes
  // through the action engine; the run's starter is recorded, not borrowed.

  app.get("/workflows", requirePermission("workflows:read"), (_req, res) => {
    res.json({ workflows: workflowDefinitions() });
  });

  app.get("/workflows/runs", requirePermission("workflows:read"), async (req: AuthedRequest, res) => {
    res.json({ runs: await listRuns(req.user!.tenant_id, limitOf(req.query.limit)) });
  });

  app.get("/workflows/runs/:id", requirePermission("workflows:read"), async (req: AuthedRequest, res) => {
    const run = await getRun(req.user!.tenant_id, String(req.params.id));
    return run ? res.json(run) : res.status(404).json({ detail: "No such workflow run" });
  });

  app.post("/workflows/:name/runs", requirePermission("workflows:run"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({
      alert_id: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_.:-]+$/, "Not an alert id"),
      mode: z.enum(["shadow", "simulation"]),
    }), req.body, res); if (!body) return;
    const name = String(req.params.name);
    if (!/^[a-z_]{1,40}$/.test(name)) return res.status(404).json({ detail: "No such workflow" });
    try {
      const { run, replayed } = await runWorkflow(req.user!.tenant_id, name, body.alert_id, body.mode, humanOf(req.user!));
      if (!replayed) await log(req, "workflow.run", "workflow_run", run.id, `${name} for ${body.alert_id} (${body.mode}): ${run.status}`);
      res.status(replayed ? 200 : 201).json({ run, replayed });
    } catch (error) {
      if (error instanceof WorkflowError) return res.status(error.status).json({ detail: error.message, code: error.code });
      throw error;
    }
  });

  // --- Universal Integration Layer (foundation) --------------------------------

  app.get("/integrations/capabilities", requirePermission("integrations:read"), async (req: AuthedRequest, res) => {
    const tenantId = req.user!.tenant_id;
    const actions = await Promise.all(catalogList().filter((a) => a.effect === "write").map(async (a) => ({
      action_id: a.id, class: a.class, mode: "simulation_only" as const,
      connectors: connectorsFor(a.id).map((c) => c.manifest.kind),
      connected: await connectedFor(tenantId, a.id),
    })));
    res.json({ connectors: actionConnectors(), actions, live_execution: false });
  });

  // --- Memory and Learning (foundation) ----------------------------------------
  // People write memory (source is always the session's person here); models cannot.

  app.get("/memory", requirePermission("memory:read"), async (req: AuthedRequest, res) => {
    const type = req.query.subject_type;
    if (type !== undefined && (typeof type !== "string" || !(SUBJECT_TYPES as readonly string[]).includes(type))) return res.status(422).json({ detail: "Unknown subject_type" });
    const key = typeof req.query.subject_key === "string" ? req.query.subject_key.slice(0, 200) : undefined;
    res.json({ memory: await listMemory(req.user!.tenant_id, { subject_type: type as SubjectType | undefined, subject_key: key, limit: limitOf(req.query.limit) }) });
  });

  app.post("/memory", requirePermission("memory:write"), async (req: AuthedRequest, res) => {
    const body = parse(z.strictObject({
      kind: z.enum(MEMORY_KINDS), subject_type: z.enum(SUBJECT_TYPES), subject_key: z.string().min(1).max(200),
      content: z.string().min(1).max(2000), ttl_days: z.number().int().min(1).max(MAX_TTL_DAYS).default(90),
    }), req.body, res); if (!body) return;
    try {
      const m = await addMemory(req.user!.tenant_id, { ...body, source: "human", created_by: req.user!.id });
      await log(req, "memory.added", "memory", m.id, `${m.kind} ${m.subject_type}`);
      res.status(201).json({ memory: m });
    } catch (error) {
      if (error instanceof MemoryError) return res.status(error.status).json({ detail: error.message });
      throw error;
    }
  });

  app.delete("/memory/:id", requirePermission("memory:write"), async (req: AuthedRequest, res) => {
    const r = await forget(req.user!.tenant_id, String(req.params.id), { user_id: req.user!.id, role: req.user!.role });
    if (r === "not_found") return res.status(404).json({ detail: "No such memory entry" });
    if (r === "forbidden") return res.status(403).json({ detail: "Only its author or an administrator can remove it" });
    await log(req, "memory.removed", "memory", String(req.params.id));
    res.json({ deleted: true });
  });

  app.get("/learning", requirePermission("memory:read"), async (req: AuthedRequest, res) => {
    res.json({ ...(await learningSummary(req.user!.tenant_id)), automatic_changes: false });
  });

  // --- Background Runtime -----------------------------------------------------

  app.get("/runtime/status", requirePermission("runtime:read"), async (req: AuthedRequest, res) => {
    const tenantId = req.user!.tenant_id;
    const status = typeof req.query.status === "string" && ["queued", "running", "done", "dead"].includes(req.query.status) ? req.query.status : undefined;
    res.json({ ...(await runtimeStatus(tenantId)), jobs: await listJobs(tenantId, { status, limit: limitOf(req.query.limit, 100) }) });
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
      // The action this approval is for moves on (consumed + queued + simulated, or rejected).
      const action = out.settled ? await settle(user.tenant_id, await syncWithApproval(user.tenant_id, out.approval.subject_id, humanOf(user))) : await getAction(user.tenant_id, out.approval.subject_id);
      res.json({ ...out, action });
    } catch (error) {
      if (error instanceof ApprovalError) return res.status(error.status).json({ detail: error.message, code: error.code });
      throw error;
    }
  });
}
