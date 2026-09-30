/**
 * Workspaces: one person, several organisations.
 *
 * A workspace is a tenant row (every `tenant_id` in the schema already means
 * "workspace"). What a person may do in it comes from their membership
 * (workspace_memberships), resolved on every request: an access token names
 * the workspace it was issued for, and it is honoured only while that
 * membership is active. Switching workspace issues a new session for the
 * other one; nothing else in the API changes — handlers keep reading
 * req.user.tenant_id and req.user.role.
 *
 * The account (email, password, MFA, token version) is global. The home
 * workspace — the one that created the account — owns it: deactivating the
 * person there disables the account everywhere, as before workspaces existed.
 * Any other workspace can only change or end its own membership.
 *
 * This module is also the provisioning boundary a future SCIM endpoint calls
 * (see enterprise.ts): add, change and remove members.
 */
import { randomUUID } from "node:crypto";
import { config } from "./config.js";
import { query, queryAll, queryOne, transaction } from "./db/pool.js";
import * as store from "./store.js";
import type { Role, User } from "./types.js";

export interface WorkspaceSummary {
  id: string;
  name: string;
  role: Role;
  status: "active" | "invited";
  home: boolean;
  region: string;
}

/** The person as a member of this workspace (null: not a member). */
export async function memberView(userId: string, tenantId: string): Promise<User | null> {
  const row = await queryOne(`${store.MEMBER_SELECT} WHERE m.user_id = $1 AND m.tenant_id = $2`, [userId, tenantId]);
  return row ? store.toMember(row) : null;
}

/**
 * Where a sign-in lands: the chosen default workspace if the person is still
 * an active member there, otherwise the home workspace, otherwise the first
 * workspace they are active in. Null: they are active nowhere.
 */
export async function landingMember(user: User): Promise<User | null> {
  const home = user.home_tenant_id ?? user.tenant_id;
  for (const candidate of [user.default_workspace_id, home]) {
    if (!candidate) continue;
    const m = await memberView(user.id, candidate);
    if (m && m.status === "active") return m;
  }
  const row = await queryOne(
    `${store.MEMBER_SELECT} WHERE m.user_id = $1 AND m.status = 'active' AND u.status = 'active' ORDER BY m.created_at LIMIT 1`,
    [user.id],
  );
  return row ? store.toMember(row) : null;
}

export async function listForUser(userId: string): Promise<WorkspaceSummary[]> {
  const rows = await queryAll<{ id: string; name: string; role: Role; status: "active" | "invited"; home: boolean; region: string | null }>(
    `SELECT t.id, t.name, m.role, m.status, (u.tenant_id = t.id) AS home, t.region
       FROM workspace_memberships m
       JOIN tenants t ON t.id = m.tenant_id
       JOIN users u ON u.id = m.user_id
      WHERE m.user_id = $1 AND m.status IN ('active', 'invited')
        AND (m.status <> 'invited' OR m.invite_expires IS NULL OR m.invite_expires > now())
      ORDER BY lower(t.name), t.id`,
    [userId],
  );
  return rows.map((r) => ({ ...r, region: r.region ?? config.region }));
}

/** How many workspaces this person administers or belongs to (the creation cap). */
export async function countForUser(userId: string): Promise<number> {
  const r = await queryOne<{ n: number }>("SELECT count(*)::int AS n FROM workspace_memberships WHERE user_id = $1 AND status = 'active'", [userId]);
  return r?.n ?? 0;
}

/** A new workspace, with its creator as its first administrator. */
export async function create(owner: User, name: string, opts: { locale?: string; timezone?: string; currency?: string } = {}) {
  return transaction(async (client) => {
    const t = (await client.query(
      `INSERT INTO tenants (id, name, trial_ends_at, notification_locale, region, locale, timezone, currency)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, name`,
      [randomUUID(), name, store.trialEnd(), opts.locale ?? "en", config.region, opts.locale ?? "en", opts.timezone ?? "UTC", opts.currency ?? config.defaultCurrency],
    )).rows[0] as { id: string; name: string };
    await client.query(
      "INSERT INTO workspace_memberships (tenant_id, user_id, role, status, invited_by) VALUES ($1, $2, 'admin', 'active', $2)",
      [t.id, owner.id],
    );
    return t;
  });
}

/**
 * Invites someone who already has an account. Returns null when they are
 * already an active member. A deactivated member can be invited back; an
 * outstanding invitation is replaced (the previous link stops working).
 */
export async function inviteExisting(
  tenantId: string, userId: string, role: Role, invitedBy: string, tokenHash: string, expires: Date,
): Promise<{ created: boolean } | null> {
  const r = await queryOne<{ inserted: boolean }>(
    `INSERT INTO workspace_memberships (tenant_id, user_id, role, status, invited_by, invite_token_hash, invite_expires)
     VALUES ($1, $2, $3, 'invited', $4, $5, $6)
     ON CONFLICT (tenant_id, user_id) DO UPDATE
       SET role = EXCLUDED.role, status = 'invited', invited_by = EXCLUDED.invited_by,
           invite_token_hash = EXCLUDED.invite_token_hash, invite_expires = EXCLUDED.invite_expires, updated_at = now()
       WHERE workspace_memberships.status <> 'active'
         -- The home membership mirrors the account; it is never re-invited this way.
         AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = workspace_memberships.user_id AND u.tenant_id = workspace_memberships.tenant_id)
     RETURNING (xmax = 0) AS inserted`,
    [tenantId, userId, role, invitedBy, tokenHash, expires],
  );
  return r ? { created: r.inserted } : null;
}

/** A fresh link for an outstanding invitation of an existing account. */
export async function refreshInvite(tenantId: string, userId: string, tokenHash: string, expires: Date): Promise<boolean> {
  const r = await query(
    `UPDATE workspace_memberships SET invite_token_hash = $3, invite_expires = $4, updated_at = now()
      WHERE tenant_id = $1 AND user_id = $2 AND status = 'invited'
        AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = $2 AND u.tenant_id = $1)`,
    [tenantId, userId, tokenHash, expires],
  );
  return (r.rowCount ?? 0) > 0;
}

export interface MembershipInvite { tenantId: string; tenantName: string; userId: string; email: string; role: Role }

/** The outstanding invitation of an existing account behind this (hashed) token. */
export async function findInvite(tokenHash: string): Promise<MembershipInvite | null> {
  const r = await queryOne<{ tenant_id: string; name: string; user_id: string; email: string; role: Role }>(
    `SELECT m.tenant_id, t.name, m.user_id, u.email, m.role
       FROM workspace_memberships m JOIN tenants t ON t.id = m.tenant_id JOIN users u ON u.id = m.user_id
      WHERE m.invite_token_hash = $1 AND m.invite_expires > now() AND m.status = 'invited'`,
    [tokenHash],
  );
  return r ? { tenantId: r.tenant_id, tenantName: r.name, userId: r.user_id, email: r.email, role: r.role } : null;
}

/**
 * Accepts it — once, and only for the person it was sent to, who must be
 * signed in: an invitation is never a way to set an existing account's
 * password or to sign in as someone.
 */
export async function acceptInvite(tokenHash: string, userId: string): Promise<{ tenantId: string; role: Role } | null> {
  const r = await queryOne<{ tenant_id: string; role: Role }>(
    `UPDATE workspace_memberships SET status = 'active', invite_token_hash = NULL, invite_expires = NULL, updated_at = now()
      WHERE invite_token_hash = $1 AND invite_expires > now() AND status = 'invited' AND user_id = $2
      RETURNING tenant_id, role`,
    [tokenHash, userId],
  );
  return r ? { tenantId: r.tenant_id, role: r.role } : null;
}

/**
 * Leaves a workspace (not the home one: that is the account). The last
 * administrator cannot leave — the same rule as demotion, under the same lock.
 */
export async function leave(tenantId: string, userId: string): Promise<"ok" | "not_member" | "home" | "last_admin"> {
  return transaction(async (client) => {
    await client.query(
      "SELECT user_id FROM workspace_memberships WHERE tenant_id = $1 AND role = 'admin' AND status = 'active' ORDER BY user_id FOR UPDATE",
      [tenantId],
    );
    const m = (await client.query(
      `SELECT m.role, m.status, u.tenant_id AS home FROM workspace_memberships m JOIN users u ON u.id = m.user_id
        WHERE m.tenant_id = $1 AND m.user_id = $2 FOR UPDATE OF m`,
      [tenantId, userId],
    )).rows[0] as { role: Role; status: string; home: string } | undefined;
    if (!m) return "not_member" as const;
    if (m.home === tenantId) return "home" as const;
    if (m.role === "admin" && m.status === "active") {
      const others = (await client.query(
        `SELECT count(*)::int AS n FROM workspace_memberships m JOIN users u ON u.id = m.user_id
          WHERE m.tenant_id = $1 AND m.user_id <> $2 AND m.role = 'admin' AND m.status = 'active' AND u.status = 'active'`,
        [tenantId, userId],
      )).rows[0].n as number;
      if (others === 0) return "last_admin" as const;
    }
    await client.query("DELETE FROM workspace_memberships WHERE tenant_id = $1 AND user_id = $2", [tenantId, userId]);
    await client.query("UPDATE users SET default_workspace_id = NULL WHERE id = $1 AND default_workspace_id = $2", [userId, tenantId]);
    return "ok" as const;
  });
}

export async function setDefault(userId: string, tenantId: string | null): Promise<void> {
  await query("UPDATE users SET default_workspace_id = $2 WHERE id = $1", [userId, tenantId]);
}
