/**
 * What each workspace role may do — the extension point for enterprise RBAC.
 *
 * Today a workspace has three fixed roles and every permission has a minimum
 * role. Routes ask for a PERMISSION (requirePermission in index.ts), not a
 * role, so custom roles later (an "incident commander" who may resolve
 * alerts but not manage users; roles mapped from an identity provider's
 * groups) replace `roleAllows` with a per-workspace lookup — without touching
 * a single route.
 *
 * Older routes still say requireRole(min); each maps onto this same ladder.
 */
import type { Role } from "./types.js";

export const PERMISSIONS = {
  "alerts:read": "viewer",
  "alerts:triage": "analyst",
  "assets:read": "viewer",
  "ai:use": "analyst",
  "integrations:read": "viewer",
  "integrations:manage": "admin",
  "members:manage": "admin",
  "workspace:manage": "admin",
  "billing:manage": "admin",
  "audit:read": "admin",
  "audit:export": "admin",
  "agents:manage": "admin",
} as const satisfies Record<string, Role>;

export type Permission = keyof typeof PERMISSIONS;

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

export function roleAllows(role: Role, permission: Permission): boolean {
  return RANK[role] >= RANK[PERMISSIONS[permission]];
}

/** The matrix, for the UI and for documentation. */
export function roleMatrix(): Record<Role, Permission[]> {
  const all = Object.keys(PERMISSIONS) as Permission[];
  return {
    viewer: all.filter((p) => roleAllows("viewer", p)),
    analyst: all.filter((p) => roleAllows("analyst", p)),
    admin: all.filter((p) => roleAllows("admin", p)),
  };
}
