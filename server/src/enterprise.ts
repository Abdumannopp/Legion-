/**
 * Enterprise extension points — contracts, not implementations.
 *
 * Each of these plugs into a boundary that already exists, so adding it later
 * is additive: no change to how requests are authorized, how workspaces
 * isolate data, or how the audit trail is written.
 *
 *   SSO (OIDC / SAML)  → produces an ExternalIdentity; sign-in continues at
 *                        startSession() exactly like a password sign-in
 *                        (workspace landing, MFA policy, device notice).
 *   SCIM               → calls the workspace membership functions
 *                        (workspaces.ts): invite / change role / deactivate.
 *   Enterprise RBAC    → replaces roleAllows() in permissions.ts.
 *   Audit export       → GET /audit/export (implemented); SIEM streaming would
 *                        be an outbound integration (src/integrations).
 *   API keys           → machine identities (packages/agent-identity service
 *                        accounts): scoped permissions, short-lived tokens,
 *                        rotation, revocation, kill switch — already built.
 *   Webhooks (out)     → an outbound integration (NotifyAdapter), delivered
 *                        through the notification outbox (retries, dead letters).
 *   Service accounts   → as API keys.
 *
 * See GLOBAL-SAAS-ARCHITECTURE.md §6 for the sequencing.
 */
import type { Role } from "./types.js";

/** Who an identity provider says signed in. Never trusted for workspace or role by itself. */
export interface ExternalIdentity {
  /** OIDC `iss` or SAML IdP entity id. */
  issuer: string;
  /** OIDC `sub` / SAML NameID (persistent): the stable key, not the email. */
  subject: string;
  email: string;
  /** Only a verified email may be matched to an existing Legion account. */
  emailVerified: boolean;
  displayName?: string;
  /** Group claims, mapped to a workspace role by the workspace's SSO policy. */
  groups: string[];
}

/** One configured SSO connection of a workspace (OIDC or SAML). */
export interface IdentityProvider {
  kind: "oidc" | "saml";
  /** The workspace that owns the connection; its policy decides who may sign in through it. */
  workspaceId: string;
  /** Where to send the browser (with state/nonce bound to the session to stop login CSRF). */
  startLogin(opts: { redirectUri: string; state: string; nonce: string }): Promise<{ url: string }>;
  /** Validates the IdP's response (signature, audience, expiry, nonce) and returns who signed in. */
  completeLogin(opts: { params: Record<string, string>; state: string; nonce: string }): Promise<ExternalIdentity>;
}

/** A workspace's SSO policy: how an ExternalIdentity becomes (or does not become) a member. */
export interface SsoPolicy {
  /** Email domains this workspace has proven it owns (DNS TXT); only these may be auto-provisioned. */
  verifiedDomains: string[];
  /** Create memberships on first sign-in (just-in-time), or only admit people already invited. */
  provisioning: "invite_only" | "just_in_time";
  defaultRole: Role;
  /** IdP group → role; the highest match wins. */
  groupRoles: Record<string, Role>;
  /** Refuse password sign-in for members whose email is in a verified domain. */
  enforceSso: boolean;
}

/**
 * SCIM 2.0 (RFC 7644) provisioning for one workspace. Each call maps onto an
 * existing membership operation, under the same "a workspace keeps at least
 * one admin" lock and the same audit trail as the admin UI.
 */
export interface ScimProvisioner {
  /** POST /Users → invite (existing account: membership invitation; new: account + invitation). */
  createUser(workspaceId: string, user: { email: string; active: boolean; role: Role; externalId: string }): Promise<{ id: string }>;
  /** PATCH /Users/{id} active=false → deactivate the membership (the account is untouched outside its home). */
  setActive(workspaceId: string, userId: string, active: boolean): Promise<void>;
  /** Group membership changes → role changes. */
  setRole(workspaceId: string, userId: string, role: Role): Promise<void>;
  /** DELETE /Users/{id} → end the membership (audit rows keep resolving to the identity). */
  remove(workspaceId: string, userId: string): Promise<void>;
}
