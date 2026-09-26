import type { HumanRole, RiskLevel } from "./types.js";

/**
 * Everything a machine identity can ever be granted, with its risk tier:
 *
 *   0  read inside Legion's reach
 *   1  annotate, or read through something that reaches outside Legion
 *      (a URL fetched by a browser or HTTP tool can itself carry data out)
 *   2  change state or act on the world — sending, pushing, running
 *
 * Tier 3 (users, roles, credentials, settings, exports, containment) is
 * deliberately absent: no agent or service account can hold it, whatever an
 * administrator tries to grant. Those actions stay with humans.
 */
export const PERMISSION_TIERS = {
  "alerts:read": 0,
  "assets:read": 0,
  "stats:read": 0,
  "alerts:comment": 1,
  "alerts:update_status": 2,
  "assets:update": 2,
  // Tool families (enforced by the tool gateway, src/tools/).
  "tool.browser:read": 1,
  "tool.browser:write": 2,
  "tool.http:read": 1,
  "tool.http:write": 2,
  "tool.database:read": 0,
  "tool.database:write": 2,
  "tool.files:read": 0,
  "tool.files:write": 2,
  "tool.shell:execute": 2,
  "tool.email:read": 0,
  "tool.email:write": 2,
  "tool.github:read": 0,
  "tool.github:write": 2,
  "tool.slack:read": 0,
  "tool.slack:write": 2,
  "tool.mcp:read": 1,
  "tool.mcp:write": 2,
  "tool.cloud:read": 1,
  "tool.cloud:write": 2,
} as const;

export type Permission = keyof typeof PERMISSION_TIERS;
export const ALL_PERMISSIONS = Object.keys(PERMISSION_TIERS) as Permission[];

export function isPermission(value: string): value is Permission {
  return Object.prototype.hasOwnProperty.call(PERMISSION_TIERS, value);
}

/** An identity can never hold more than its owner's role allows. */
const ROLE_CEILING: Record<HumanRole, ReadonlySet<Permission>> = {
  viewer: new Set(ALL_PERMISSIONS.filter((p) => PERMISSION_TIERS[p] === 0)),
  analyst: new Set(ALL_PERMISSIONS),
  admin: new Set(ALL_PERMISSIONS),
};

export function roleAllows(role: HumanRole, permission: Permission): boolean {
  return ROLE_CEILING[role]?.has(permission) ?? false;
}

export function exceedsRole(role: HumanRole, permissions: readonly Permission[]): Permission[] {
  return permissions.filter((p) => !roleAllows(role, p));
}

/** Granted ∩ owner's current ceiling. Demote the owner, and the agent shrinks too. */
export function effectivePermissions(granted: readonly string[], ownerRole: HumanRole): Permission[] {
  return granted.filter((p): p is Permission => isPermission(p) && roleAllows(ownerRole, p));
}

export const RISK_ORDER: readonly RiskLevel[] = ["low", "medium", "high", "critical"];

export function riskAtLeast(a: RiskLevel, b: RiskLevel): boolean {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b);
}

/**
 * The lowest risk level an identity with these permissions may carry.
 * Administrators can raise it (e.g. to "critical" to hold an agent pending
 * review) but never set it below what the permissions imply.
 */
export function baselineRisk(permissions: readonly Permission[]): RiskLevel {
  const top = Math.max(-1, ...permissions.map((p) => PERMISSION_TIERS[p]));
  return top >= 2 ? "high" : top === 1 ? "medium" : "low";
}
