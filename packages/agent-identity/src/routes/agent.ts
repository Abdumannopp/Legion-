import { Router, type Request } from "express";
import type { AuditLog } from "../audit.js";
import type { createGuards } from "../authorize.js";
import { effectivePermissions } from "../permissions.js";
import { anonymous, clientIp, identityBlockReason, sendError, type FailureSampler } from "../principal.js";
import { parseCredential, safeEqual } from "../secrets.js";
import type { IdentityStore } from "../store.js";
import type { HostAdapter, MachinePrincipal, RiskLevel } from "../types.js";

/** Higher-risk identities get shorter-lived tokens, so a leaked one is useful for less time. */
export const TOKEN_TTL_SECONDS: Record<Exclude<RiskLevel, "critical">, number> = {
  low: 900,
  medium: 900,
  high: 300,
};

/** The API machine identities call as themselves. Mounted at options.agentBasePath. */
export function agentRouter(deps: {
  store: IdentityStore;
  audit: AuditLog;
  host: HostAdapter;
  guards: ReturnType<typeof createGuards>;
  sampler: FailureSampler;
  log: (msg: string, err?: unknown) => void;
}): Router {
  const { store, audit, host, guards, sampler, log } = deps;
  const router = Router();

  const event = (req: Request) => ({ requestId: req.requestId, ip: clientIp(req), userAgent: req.get("user-agent") });

  // Credential → short-lived access token. The only place a long-lived
  // credential is ever accepted.
  router.post("/token", async (req, res) => {
    const bearer = /^Bearer\s+(\S+)\s*$/i.exec(req.get("authorization") ?? "")?.[1] ?? "";
    const parsed = parseCredential(bearer);
    const reject = async (principal: MachinePrincipal | null, reason: string) => {
      // Garbage credentials are sampled per IP; failures against a real
      // identity are always recorded.
      if (principal || sampler.allow(clientIp(req) ?? "unknown")) {
        await audit
          .record({ ...event(req), principal: principal ?? anonymous(), action: "auth.credential", outcome: "denied", reason })
          .catch((err) => log("audit write failed for a rejected credential", err));
      }
      // Specific reasons only once the secret itself was proven; a wrong
      // secret gets the same answer as a credential that does not exist.
      const code = principal && reason !== "bad_secret" ? reason : "invalid_credential";
      return sendError(res, 401, code, "Invalid credential.");
    };

    if (!parsed) return reject(null, "malformed_credential");
    const row = await store.findCredential(parsed.credentialId);
    if (!row) return reject(null, "unknown_credential");

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
      tokenId: "",
    };
    // A wrong secret for a real credential id is a targeted attempt on this
    // identity: always recorded against it, never sampled away.
    if (!safeEqual(parsed.secretHash, row.secretHash)) return reject(known, "bad_secret");
    if (parsed.kind !== id.kind) return reject(known, "credential_kind_mismatch");
    if (row.credentialRevokedAt) return reject(known, "credential_revoked");
    if (row.credentialExpiresAt && new Date(row.credentialExpiresAt).getTime() <= Date.now()) {
      return reject(known, "credential_expired");
    }
    const block = await identityBlockReason(id, host);
    if (block.reason !== null) return reject(known, block.reason);

    const ttl = TOKEN_TTL_SECONDS[id.riskLevel as Exclude<RiskLevel, "critical">];
    const issued = await store.issueToken(id, row.credentialId, ttl);
    await store.touchActivity(id.id, clientIp(req));
    const principal: MachinePrincipal = { ...known, tokenId: issued.tokenId, permissions: effectivePermissions(id.permissions, block.ownerRole) };
    await audit.record({
      ...event(req), principal, action: "token.issued", outcome: "success",
      resourceType: id.kind, resourceId: id.id, details: { tokenId: issued.tokenId, expiresAt: issued.expiresAt },
    });

    res.setHeader("cache-control", "no-store");
    res.json({
      access_token: issued.token,
      token_type: "Bearer",
      expires_in: ttl,
      expires_at: issued.expiresAt,
      principal: { type: id.kind, id: id.id, tenantId: id.tenantId, name: id.name },
    });
  });

  router.get("/me", guards.requireMachine(), guards.traced("identity.whoami"), async (req, res) => {
    const p = req.principal as MachinePrincipal;
    const identity = await store.get(p.tenantId, p.type, p.id);
    if (!identity) return sendError(res, 404, "not_found", "Identity no longer exists.");
    res.json({
      principalType: p.type,
      id: identity.id,
      name: identity.name,
      tenantId: identity.tenantId,
      ownerUserId: identity.ownerUserId,
      status: identity.status,
      grantedPermissions: identity.permissions,
      effectivePermissions: p.permissions,
      riskLevel: identity.riskLevel,
      createdAt: identity.createdAt,
      lastActivityAt: identity.lastActivityAt,
      expiresAt: identity.expiresAt,
      credentialId: p.credentialId,
      tokenId: p.tokenId,
    });
  });

  // Lets a well-behaved agent end its own session early.
  router.post("/token/revoke", guards.requireMachine(), guards.traced("token.revoke"), async (req, res) => {
    await store.revokeToken((req.principal as MachinePrincipal).tokenId);
    res.status(204).end();
  });

  return router;
}
