import type { Request } from "express";
import type { Permission } from "./permissions.js";

/**
 * Who is behind a request. Every request is exactly one of these; nothing is
 * ever "just an API client".
 *
 * - human            a person signed in through Legion's existing login
 * - ai_agent         an autonomous or semi-autonomous AI system with its own
 *                    registered identity and an accountable human owner
 * - service_account  a non-AI machine identity (scripts, integrations)
 * - external_system  anything not authenticated as one of the above: sensor
 *                    webhooks, billing callbacks, anonymous traffic
 */
export type PrincipalType = "human" | "ai_agent" | "service_account" | "external_system";
export type MachineKind = "ai_agent" | "service_account";
export const MACHINE_KINDS: readonly MachineKind[] = ["ai_agent", "service_account"];

export type HumanRole = "admin" | "analyst" | "viewer";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type IdentityStatus = "active" | "suspended" | "revoked";

export interface HumanPrincipal {
  type: "human";
  id: string;
  tenantId: string;
  role: HumanRole;
  displayName: string;
}

export interface MachinePrincipal {
  type: MachineKind;
  id: string;
  tenantId: string;
  displayName: string;
  ownerUserId: string;
  /** Granted permissions intersected with the owner's current role ceiling. */
  permissions: Permission[];
  riskLevel: RiskLevel;
  credentialId: string;
  tokenId: string;
}

export interface ExternalPrincipal {
  type: "external_system";
  /** "anonymous", or the integration's name ("wazuh-webhook", …). */
  id: string;
  tenantId: string | null;
  displayName: string;
}

export type Principal = HumanPrincipal | MachinePrincipal | ExternalPrincipal;

export function isMachine(p: Principal | undefined): p is MachinePrincipal {
  return p?.type === "ai_agent" || p?.type === "service_account";
}

/** What the host's existing login returns for a signed-in person. */
export interface HumanSession {
  userId: string;
  tenantId: string;
  role: HumanRole;
  displayName?: string;
}

export interface HostUser {
  id: string;
  tenantId: string;
  role: HumanRole;
  /** Only "active" users may own identities or lend them permissions. */
  status: string;
  displayName?: string;
}

/**
 * The module's only contact with Legion's existing authentication. It calls
 * these; it never reads cookies, verifies human JWTs or touches the users
 * table itself, so human login behaviour cannot change underneath it.
 */
export interface HostAdapter {
  /** Wraps the existing cookie/JWT check. Return null when not signed in. */
  authenticateHuman(req: Request): Promise<HumanSession | null>;
  /** Current state of a user, used to check identity owners on every request. */
  getUser(tenantId: string, userId: string): Promise<HostUser | null>;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      principal?: Principal;
      requestId?: string;
    }
  }
}
