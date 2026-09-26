import { randomUUID } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { AuditLog } from "./audit.js";
import { effectivePermissions } from "./permissions.js";
import { looksLikeMachineSecret, parseAccessToken } from "./secrets.js";
import type { Identity, IdentityStore } from "./store.js";
import type { ExternalPrincipal, HostAdapter, HumanRole, MachinePrincipal, Principal } from "./types.js";

/**
 * User agents of AI crawlers and AI browsing agents that announce themselves.
 * Honest agents are redirected to a real identity instead of being served as
 * anonymous clients; dishonest ones are not stopped by this (they spoof a
 * browser) — that is the job of behavioural detection, not of this list.
 */
export const DEFAULT_AI_USER_AGENTS =
  /\b(GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai|PerplexityBot|Perplexity-User|MistralAI-User|cohere-ai|Bytespider|meta-externalagent|meta-externalfetcher|Google-CloudVertexBot|Amazonbot|DuckAssistBot)\b/i;

export interface PrincipalOptions {
  /** Where the agent API is mounted. Credentials are accepted only at `${agentBasePath}/token`. */
  agentBasePath: string;
  /** Paths that must answer everyone (health checks, sensor webhooks). */
  exemptPaths: string[];
  aiUserAgents: RegExp | null;
}

export const anonymous = (): ExternalPrincipal => ({
  type: "external_system",
  id: "anonymous",
  tenantId: null,
  displayName: "Unauthenticated client",
});

export function clientIp(req: Request): string | undefined {
  return req.ip ?? req.socket?.remoteAddress ?? undefined;
}

export function sendError(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ error: { code, message } });
}

/**
 * Failed authentication from unknown callers is audited, but a flood of
 * garbage tokens must not become a flood of audit writes. Per IP, the first
 * `limit` failures per minute are recorded. Failures that point at a real
 * identity are never sampled — an attack on a specific agent always shows.
 */
export class FailureSampler {
  private readonly windows = new Map<string, { start: number; count: number }>();
  constructor(private readonly limit = 20, private readonly windowMs = 60_000) {}
  allow(key: string): boolean {
    const now = Date.now();
    const w = this.windows.get(key);
    if (!w || now - w.start >= this.windowMs) {
      if (this.windows.size > 10_000) this.windows.clear();
      this.windows.set(key, { start: now, count: 1 });
      return true;
    }
    w.count++;
    return w.count <= this.limit;
  }
}

/**
 * Why an identity may not act right now, or null if it may. Shared by the
 * token endpoint and per-request authentication so the two cannot drift.
 */
export async function identityBlockReason(
  identity: Identity,
  host: HostAdapter,
): Promise<{ reason: string } | { reason: null; ownerRole: HumanRole }> {
  if (identity.status !== "active") return { reason: `identity_${identity.status}` };
  if (identity.expiresAt && new Date(identity.expiresAt).getTime() <= Date.now()) return { reason: "identity_expired" };
  if (identity.riskLevel === "critical") return { reason: "risk_hold" };
  // The owner lends the identity its authority. A disabled, deleted or
  // moved owner means nobody is accountable — refuse.
  const owner = await host.getUser(identity.tenantId, identity.ownerUserId);
  if (!owner || owner.status !== "active" || owner.tenantId !== identity.tenantId) return { reason: "owner_inactive" };
  return { reason: null, ownerRole: owner.role };
}

type TokenResult =
  | { ok: true; principal: MachinePrincipal }
  | { ok: false; reason: string; known?: MachinePrincipal };

export function createPrincipalResolver(deps: {
  store: IdentityStore;
  audit: AuditLog;
  host: HostAdapter;
  options: PrincipalOptions;
  sampler: FailureSampler;
  log: (msg: string, err?: unknown) => void;
}): RequestHandler {
  const { store, audit, host, options, sampler, log } = deps;
  const tokenPath = `${options.agentBasePath}/token`;

  const auditFailure = async (req: Request, principal: Principal, action: string, reason: string) => {
    if (principal.type === "external_system" && !sampler.allow(clientIp(req) ?? "unknown")) return;
    await audit
      .record({
        principal,
        action,
        outcome: "denied",
        reason,
        requestId: req.requestId,
        ip: clientIp(req),
        userAgent: req.get("user-agent"),
        details: { method: req.method, path: req.path },
      })
      .catch((err) => log("audit write failed for rejected request", err));
  };

  async function authenticateToken(bearer: string, req: Request): Promise<TokenResult> {
    const hash = parseAccessToken(bearer);
    if (!hash) return { ok: false, reason: "malformed_token" };
    const row = await store.findToken(hash);
    if (!row) return { ok: false, reason: "unknown_token" };

    const id = row.identity;
    const known: MachinePrincipal = {
      type: id.kind,
      id: id.id,
      tenantId: id.tenantId,
      displayName: id.name,
      ownerUserId: id.ownerUserId,
      permissions: [],
      riskLevel: id.riskLevel,
      credentialId: row.credentialId,
      tokenId: row.tokenId,
    };
    const now = Date.now();
    const past = (d: Date | string | null) => d !== null && new Date(d).getTime() <= now;

    if (row.tokenRevokedAt) return { ok: false, reason: "token_revoked", known };
    if (past(row.tokenExpiresAt)) return { ok: false, reason: "token_expired", known };
    if (row.credentialRevokedAt) return { ok: false, reason: "credential_revoked", known };
    if (past(row.credentialExpiresAt)) return { ok: false, reason: "credential_expired", known };
    const block = await identityBlockReason(id, host);
    if (block.reason !== null) return { ok: false, reason: block.reason, known };

    await store.touchActivity(id.id, clientIp(req));
    return { ok: true, principal: { ...known, permissions: effectivePermissions(id.permissions, block.ownerRole) } };
  }

  return async function resolvePrincipal(req: Request, res: Response, next: NextFunction) {
    req.requestId = randomUUID();
    res.setHeader("x-request-id", req.requestId);

    if (options.exemptPaths.includes(req.path)) {
      req.principal = anonymous();
      return next();
    }

    const bearer = /^Bearer\s+(\S+)\s*$/i.exec(req.get("authorization") ?? "")?.[1];
    const machineSecret = bearer ? looksLikeMachineSecret(bearer) : null;

    let human = null;
    try {
      human = await host.authenticateHuman(req);
    } catch (err) {
      log("host authenticateHuman threw; treating the request as not signed in", err);
    }

    if (machineSecret && human) {
      // A request is one principal. Letting an agent ride along on a human
      // session would blur whose authority was used and hide agent actions.
      await auditFailure(
        req,
        { type: "human", id: human.userId, tenantId: human.tenantId, role: human.role, displayName: human.displayName ?? human.userId },
        "principal.ambiguous",
        "request carried both a human session and a machine token",
      );
      return sendError(res, 400, "ambiguous_principal",
        "A request must be made either by a signed-in person or by a machine identity, not both.");
    }

    if (machineSecret === "credential") {
      if (req.path === tokenPath) {
        req.principal = anonymous(); // the token endpoint authenticates the credential itself
        return next();
      }
      await auditFailure(req, anonymous(), "auth.credential_misuse", "long-lived credential sent to a resource endpoint");
      return sendError(res, 401, "credential_not_accepted",
        `Exchange the credential for an access token at ${tokenPath}; credentials are not accepted here.`);
    }

    if (machineSecret === "access_token") {
      const result = await authenticateToken(bearer!, req);
      if (!result.ok) {
        await auditFailure(req, result.known ?? anonymous(), "auth.token", result.reason);
        return result.known
          ? sendError(res, 401, result.reason, "This access token cannot be used.")
          : sendError(res, 401, "invalid_token", "Invalid access token.");
      }
      req.principal = result.principal;
      return next();
    }

    if (human) {
      req.principal = {
        type: "human",
        id: human.userId,
        tenantId: human.tenantId,
        role: human.role,
        displayName: human.displayName ?? human.userId,
      };
      return next();
    }

    const ua = req.get("user-agent") ?? "";
    const declaredAgent =
      req.get("x-legion-agent") !== undefined ||
      req.get("signature-agent") !== undefined ||
      (options.aiUserAgents?.test(ua) ?? false);
    if (declaredAgent) {
      await auditFailure(req, anonymous(), "auth.agent_identity_required", "AI agent without a Legion identity");
      return sendError(res, 401, "agent_identity_required",
        "AI agents must authenticate with a registered Legion agent identity.");
    }

    req.principal = anonymous();
    return next();
  };
}
