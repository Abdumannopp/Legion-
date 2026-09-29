import { Router, type Request } from "express";
import { z } from "zod";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import type { PolicyStore } from "../firewall/policy.js";
import { clientIp, sendError } from "../principal.js";
import type { IdentityStore } from "../store.js";
import type { HumanPrincipal, MachinePrincipal } from "../types.js";
import { PromptAssembly } from "./assembly.js";
import type { PromptInjectionGuard } from "./guard.js";
import { CONTENT_SOURCES, type ContentSource } from "./types.js";

type Deps = {
  audit: AuditLog;
  guards: ReturnType<typeof createGuards>;
  contentGuard: PromptInjectionGuard;
  policies: PolicyStore;
  store: IdentityStore;
};

const me = (req: Request) => req.principal as HumanPrincipal;

/** People: flagged-content events, per-agent status, and acknowledgement. Mounted at /prompt-guard. */
export function promptGuardAdminRouter(d: Deps): Router {
  const router = Router();
  const admin = d.guards.requireHuman(["admin"]);
  const staff = d.guards.requireHuman(["admin", "analyst"]);

  router.get("/events", staff, async (req, res) => {
    const q = req.query;
    const s = (v: unknown) => (typeof v === "string" ? v : undefined);
    const verdict = s(q.verdict);
    const source = s(q.source);
    res.json({
      events: await d.contentGuard.log.list(me(req).tenantId, {
        verdict: verdict && ["suspicious", "malicious"].includes(verdict) ? verdict : undefined,
        principalId: s(q.principalId),
        source: source && (CONTENT_SOURCES as readonly string[]).includes(source) ? source : undefined,
        before: s(q.before) && /^\d+$/.test(s(q.before)!) ? s(q.before) : undefined,
        limit: Number(q.limit) || 100,
      }),
    });
  });

  router.get("/events/verify", admin, async (req, res) => {
    res.json(await d.contentGuard.log.verifyChain(me(req).tenantId));
  });

  router.get("/status/:principalId", staff, async (req, res) => {
    const tenantId = me(req).tenantId;
    const { policy } = await d.policies.get(tenantId);
    const summary = await d.contentGuard.summary(tenantId, String(req.params.principalId), policy.promptInjection.suspiciousWindowSeconds);
    res.json({ principalId: req.params.principalId, quarantined: summary.unacknowledgedMalicious > 0, ...summary });
  });

  // Clearing a quarantine is the "stronger authorization": an administrator
  // looks at what reached the agent and says why it is safe to continue.
  const ackBody = z.strictObject({
    principalId: z.string().min(1).max(200),
    reason: z.string().trim().min(10, "explain what you reviewed (at least 10 characters)").max(500),
  });
  router.post("/acknowledge", admin, async (req, res) => {
    const parsed = ackBody.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const user = me(req);
    const result = await d.store.tx(async (c) => {
      const r = await d.contentGuard.acknowledge(c, user.tenantId, parsed.data.principalId, user.id, parsed.data.reason);
      await d.audit.record({
        principal: user,
        action: "content.risk_acknowledged",
        outcome: "success",
        resourceType: "principal",
        resourceId: parsed.data.principalId,
        reason: parsed.data.reason,
        requestId: req.requestId,
        ip: clientIp(req),
        userAgent: req.get("user-agent"),
        details: { throughSeq: r.throughSeq, cleared: r.cleared },
      }, c);
      return r;
    });
    res.json(result);
  });

  return router;
}

/** Machines: submit external content you read, get it classified and wrapped. Mounted inside the agent API. */
export function contentInspectRouter(d: Deps): Router {
  const router = Router();
  const body = z.strictObject({
    source: z.enum(CONTENT_SOURCES as unknown as [ContentSource, ...ContentSource[]]),
    content: z.string().max(200_000),
    sourceId: z.string().max(200).optional(),
    fieldHint: z.enum(["free_text", "short_text", "identifier"]).optional(),
  });

  router.post("/content/inspect", d.guards.requireMachine(), d.guards.traced("content:inspect"), async (req, res) => {
    const parsed = body.safeParse(req.body ?? {});
    if (!parsed.success) return sendError(res, 400, "invalid_request", parsed.error.issues[0]?.message ?? "invalid");
    const p = req.principal as MachinePrincipal;
    const { source, content, sourceId, fieldHint } = parsed.data;
    const { classification, eventId } = await d.contentGuard.ingest({ tenantId: p.tenantId, principal: p, requestId: req.requestId }, source, content, { sourceId, fieldHint });

    // The same wrapping Legion uses for its own prompts, for the agent to
    // place in its model's context as data.
    const wrapped = new PromptAssembly("agent.summarize_content");
    wrapped.addUntrustedContent(source, content, { sourceId, fieldHint });
    const envelope = wrapped.untrustedBlocks();

    res.json({
      eventId,
      verdict: classification.verdict,
      riskScore: classification.riskScore,
      findings: classification.findings.map((f) => ({ id: f.id, category: f.category, points: f.points, detail: f.detail })),
      sanitized: classification.sanitized,
      removedChars: classification.removedChars,
      envelope,
      consequence: classification.verdict === "malicious"
        ? "Recorded against this agent. Sensitive actions are blocked until an administrator reviews it."
        : classification.verdict === "suspicious"
          ? "Recorded against this agent. Its risk score is raised for a while."
          : "Recorded against this agent. Until a person reviews it, the agent may read but not take sensitive actions (untrusted-content hold).",
    });
  });

  return router;
}
