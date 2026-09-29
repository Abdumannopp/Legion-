/**
 * Data access for Legion.
 *
 * Postgres is the single source of truth — nothing is cached in process
 * memory. That is deliberate and is the whole reason for the migration: with
 * an in-memory copy, a second instance would serve stale data and writes from
 * one pod would be invisible to another, which defeats running more than one.
 */
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { config } from "./config.js";
import { query, queryAll, queryOne, transaction } from "./db/pool.js";
import { isLocale, type Locale } from "./i18n.js";
import type {
  Alert, AlertStatus, Asset, AuditLog, Role, Severity,
  Subscription, Tenant, User, UserStatus,
} from "./types.js";

export { migrate, isUniqueViolation, transaction, closePool } from "./db/pool.js";

const iso = (value: Date | string | null): string | null =>
  value === null ? null : value instanceof Date ? value.toISOString() : value;
const isoRequired = (value: Date | string): string => iso(value)!;

export function trialEnd(from: Date = new Date()): string {
  return new Date(from.getTime() + config.trialDays * 86_400_000).toISOString();
}

// --- Row mappers -------------------------------------------------------------
// Postgres hands back Date objects for timestamptz; the API contract is ISO
// strings, so the boundary is converted in exactly one place per table.

/* eslint-disable @typescript-eslint/no-explicit-any */
const toTenant = (r: any): Tenant => ({
  id: r.id, name: r.name, notification_email: r.notification_email,
  notification_email_pending: r.notification_email_pending ?? null,
  notification_locale: isLocale(r.notification_locale) ? r.notification_locale : "en",
  trial_ends_at: iso(r.trial_ends_at), created_at: isoRequired(r.created_at),
  ai_enabled: typeof r.ai_enabled === "boolean" ? r.ai_enabled : null,
  ai_data_mode: r.ai_data_mode === "strict" ? "strict" : "standard",
});

const toUser = (r: any): User => ({
  id: r.id, email: r.email, password_hash: r.password_hash, tenant_id: r.tenant_id,
  role: r.role as Role, status: r.status as UserStatus, token_version: r.token_version,
  reset_token_hash: r.reset_token_hash ?? null, reset_expires: iso(r.reset_expires),
  invite_token_hash: r.invite_token_hash ?? null, invite_expires: iso(r.invite_expires),
  invited_by: r.invited_by, created_at: isoRequired(r.created_at),
  mfa_enabled: Boolean(r.mfa_enabled),
  mfa_secret_enc: r.mfa_secret_enc ?? null, mfa_secret_legacy: r.mfa_secret ?? null,
  mfa_enrolled_at: iso(r.mfa_enrolled_at),
  email_verified_at: iso(r.email_verified_at),
});

const toAlert = (r: any): Alert => ({
  id: r.id, tenant_id: r.tenant_id, title: r.title, severity: r.severity as Severity,
  agent: r.agent, status: r.status as AlertStatus, summary: r.summary,
  confidence: Number(r.confidence), created_at: isoRequired(r.created_at),
  ai_explanation: r.ai_explanation, explained_at: iso(r.explained_at),
  ai_explanation_locale: isLocale(r.ai_explanation_locale) ? r.ai_explanation_locale : null,
  ai_explanation_source: r.ai_explanation_source === "ai" || r.ai_explanation_source === "local" ? r.ai_explanation_source : null,
  seq: Number(r.seq), created_seq: Number(r.created_seq),
  source_ip: r.source_ip, target: r.target, mitre_technique: r.mitre_technique,
  source: r.source,
});

const toAsset = (r: any): Asset => ({
  id: r.id, tenant_id: r.tenant_id, name: r.name, os: r.os, ip_address: r.ip_address,
  risk: r.risk as Severity, online: r.online, last_seen: isoRequired(r.last_seen),
});

const toAudit = (r: any): AuditLog => ({
  id: r.id, tenant_id: r.tenant_id, user_id: r.user_id, user_email: r.user_email,
  action: r.action, resource_type: r.resource_type, resource_id: r.resource_id,
  detail: r.detail, ip_address: r.ip_address, created_at: isoRequired(r.created_at),
});

const toSubscription = (r: any): Subscription => ({
  tenant_id: r.tenant_id, status: r.status, paddle_customer_id: r.paddle_customer_id,
  paddle_subscription_id: r.paddle_subscription_id, paddle_price_id: r.paddle_price_id,
  current_period_end: iso(r.current_period_end),
  cancel_at_period_end: r.cancel_at_period_end, last_event_at: iso(r.last_event_at),
});
/* eslint-enable @typescript-eslint/no-explicit-any */

// --- Tenants -----------------------------------------------------------------

export async function getTenant(id: string): Promise<Tenant | null> {
  const row = await queryOne("SELECT * FROM tenants WHERE id = $1", [id]);
  return row ? toTenant(row) : null;
}

/** An organisation's own AI choices. `enabled: null` returns it to "use the
 *  deployment default". Scoped to the tenant it is called for. */
export async function updateTenantAiSettings(
  tenantId: string, patch: { enabled?: boolean | null; data_mode?: "standard" | "strict" }
): Promise<Tenant | null> {
  const row = await queryOne(
    `UPDATE tenants SET
       ai_enabled   = CASE WHEN $2::boolean THEN $3::boolean ELSE ai_enabled END,
       ai_data_mode = COALESCE($4::text, ai_data_mode)
     WHERE id = $1 RETURNING *`,
    [tenantId, patch.enabled !== undefined, patch.enabled ?? null, patch.data_mode ?? null]
  );
  return row ? toTenant(row) : null;
}

/** True once any workspace exists. Drives first-run setup on a self-hosted
 *  install, where open registration would be an unlocked front door. */
export async function hasAnyTenant(): Promise<boolean> {
  const row = await queryOne("SELECT 1 FROM tenants LIMIT 1");
  return row !== null;
}

export async function tenantExists(id: string): Promise<boolean> {
  const row = await queryOne("SELECT 1 FROM tenants WHERE id = $1", [id]);
  return row !== null;
}

/** Records a requested address and its confirmation token; the active address is unchanged. */
export async function requestNotificationEmail(tenantId: string, email: string, tokenHash: string, expiresAt: Date): Promise<void> {
  await query(
    `UPDATE tenants SET notification_email_pending = $2, notification_email_token_hash = $3, notification_email_token_expires = $4 WHERE id = $1`,
    [tenantId, email, tokenHash, expiresAt.toISOString()]
  );
}

/** Drops a pending request (the administrator kept or cleared the address). */
export async function clearPendingNotificationEmail(tenantId: string): Promise<void> {
  await query(
    "UPDATE tenants SET notification_email_pending = NULL, notification_email_token_hash = NULL, notification_email_token_expires = NULL WHERE id = $1",
    [tenantId]
  );
}

/** The owner of the address confirmed: it becomes the active one. Single use, expiring. */
export async function confirmNotificationEmail(tokenHash: string): Promise<{ id: string; notification_email: string } | null> {
  return queryOne(
    `UPDATE tenants SET notification_email = notification_email_pending,
            notification_email_pending = NULL, notification_email_token_hash = NULL, notification_email_token_expires = NULL
      WHERE notification_email_token_hash = $1 AND notification_email_token_expires > now() AND notification_email_pending IS NOT NULL
      RETURNING id, notification_email`,
    [tokenHash]
  );
}

/** How many times this tenant did `action` in the last hour (shared across instances). */
export async function recentAuditCount(tenantId: string, action: string, minutes = 60): Promise<number> {
  const row = await queryOne<{ n: number }>(
    "SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = $2 AND created_at > now() - make_interval(mins => $3)",
    [tenantId, action, minutes]
  );
  return Number(row?.n ?? 0);
}

export async function setNotificationEmail(
  tenantId: string,
  email: string | null
): Promise<void> {
  await query("UPDATE tenants SET notification_email = $2 WHERE id = $1", [tenantId, email]);
}

export async function setNotificationLocale(tenantId: string, locale: Locale): Promise<void> {
  await query("UPDATE tenants SET notification_locale = $2 WHERE id = $1", [tenantId, locale]);
}

// --- Users -------------------------------------------------------------------

export async function findUserById(id: string): Promise<User | null> {
  const row = await queryOne("SELECT * FROM users WHERE id = $1", [id]);
  return row ? toUser(row) : null;
}

export async function findUserByEmail(email: string): Promise<User | null> {
  const row = await queryOne("SELECT * FROM users WHERE lower(email) = lower($1)", [email]);
  return row ? toUser(row) : null;
}

/**
 * One-time tokens (reset, invitation, e-mail verification) are looked up by
 * their SHA-256 hash. Matching a hash in SQL leaks nothing through timing: an
 * attacker cannot choose inputs whose hashes share a prefix with a stored one.
 *
 * "Consume" is ONE conditional UPDATE: the token must still be present,
 * unexpired and in the right state, and it is cleared in the same statement.
 * Two concurrent requests with the same token cannot both succeed — the second
 * finds nothing to update. (The previous code read the token, then updated the
 * row, and both requests could get through in between.)
 */
export async function findUserByInviteTokenHash(hash: string): Promise<User | null> {
  const row = await queryOne(
    "SELECT * FROM users WHERE invite_token_hash = $1 AND invite_expires > now() AND status = 'invited'",
    [hash]
  );
  return row ? toUser(row) : null;
}

/** Accepts an invitation: sets the password and activates, once. */
export async function consumeInviteToken(hash: string, passwordHash: string): Promise<User | null> {
  const row = await queryOne(
    `UPDATE users SET password_hash = $2, status = 'active', invite_token_hash = NULL, invite_expires = NULL
      WHERE invite_token_hash = $1 AND invite_expires > now() AND status = 'invited'
      RETURNING *`,
    [hash, passwordHash]
  );
  return row ? toUser(row) : null;
}

/** Resets a password, once. Also ends every existing access token (token_version)
 *  and proves the address (the link was e-mailed to it). */
export async function consumeResetToken(hash: string, passwordHash: string): Promise<User | null> {
  const row = await queryOne(
    `UPDATE users SET password_hash = $2, reset_token_hash = NULL, reset_expires = NULL,
            token_version = token_version + 1, email_verified_at = COALESCE(email_verified_at, now())
      WHERE reset_token_hash = $1 AND reset_expires > now() AND status = 'active'
      RETURNING *`,
    [hash, passwordHash]
  );
  return row ? toUser(row) : null;
}

/** Confirms an e-mail address, once. */
export async function consumeVerifyToken(hash: string): Promise<User | null> {
  const row = await queryOne(
    `UPDATE users SET email_verified_at = now(), verify_token_hash = NULL, verify_expires = NULL
      WHERE verify_token_hash = $1 AND verify_expires > now() AND email_verified_at IS NULL
      RETURNING *`,
    [hash]
  );
  return row ? toUser(row) : null;
}

/** The unverified account holding this (hashed) verification token, if still valid. */
export async function findUserByVerifyTokenHash(hash: string): Promise<User | null> {
  const row = await queryOne(
    "SELECT * FROM users WHERE verify_token_hash = $1 AND verify_expires > now() AND email_verified_at IS NULL",
    [hash]
  );
  return row ? toUser(row) : null;
}


/** Minimal user state for re-authorizing live connections in bulk. */
export async function userAuthStates(ids: string[]): Promise<Array<{ id: string; tenant_id: string; token_version: number; status: string }>> {
  if (ids.length === 0) return [];
  return queryAll("SELECT id, tenant_id, token_version, status FROM users WHERE id = ANY($1::uuid[])", [ids]) as Promise<Array<{ id: string; tenant_id: string; token_version: number; status: string }>>;
}

export async function listUsers(tenantId: string): Promise<User[]> {
  const rows = await queryAll(
    "SELECT * FROM users WHERE tenant_id = $1 ORDER BY created_at ASC",
    [tenantId]
  );
  return rows.map(toUser);
}

export async function findUserInTenant(tenantId: string, userId: string): Promise<User | null> {
  const row = await queryOne("SELECT * FROM users WHERE id = $1 AND tenant_id = $2", [
    userId, tenantId,
  ]);
  return row ? toUser(row) : null;
}

/** Active admins in the tenant other than `excludeUserId`. Guards the
 *  "a tenant must keep at least one admin" rule. */
export async function countOtherActiveAdmins(
  tenantId: string,
  excludeUserId: string
): Promise<number> {
  const row = await queryOne<{ count: number }>(
    `SELECT count(*)::bigint AS count FROM users
     WHERE tenant_id = $1 AND id <> $2 AND role = 'admin' AND status = 'active'`,
    [tenantId, excludeUserId]
  );
  return Number(row?.count ?? 0);
}

export interface NewUser {
  email: string;
  password_hash: string;
  tenant_id: string;
  role: Role;
  status?: UserStatus;
  /** SHA-256 of the invitation token (auth-tokens.ts), never the token. */
  invite_token_hash?: string | null;
  invite_expires?: string | null;
  invited_by?: string | null;
  /** False only for hosted self-sign-up, where the address is unproven.
   *  Everything else (invites, first-run setup, fixtures) proves it otherwise. */
  email_verified?: boolean;
}

export async function insertUser(input: NewUser, client?: PoolClient): Promise<User> {
  const run = client
    ? (text: string, params: unknown[]) => client.query(text, params)
    : (text: string, params: unknown[]) => query(text, params);
  const result = await run(
    `INSERT INTO users (id, email, password_hash, tenant_id, role, status,
                        invite_token_hash, invite_expires, invited_by, email_verified_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CASE WHEN $10::boolean THEN now() END)
     RETURNING *`,
    [
      randomUUID(), input.email, input.password_hash, input.tenant_id, input.role,
      input.status ?? "active", input.invite_token_hash ?? null,
      input.invite_expires ?? null, input.invited_by ?? null,
      input.email_verified !== false,
    ]
  );
  return toUser(result.rows[0]);
}

/**
 * Creates a tenant and its first admin atomically. Without the transaction a
 * failure between the two inserts would leave an unreachable tenant behind.
 */
export async function createTenantWithAdmin(
  tenantName: string,
  email: string,
  passwordHash: string,
  opts: { emailVerified?: boolean; locale?: Locale } = {}
): Promise<{ tenant: Tenant; user: User }> {
  return transaction((client) => createTenantWithAdminTx(client, tenantName, email, passwordHash, opts));
}

/** Same, inside a transaction the caller already holds — used by first-run
 *  setup, which must check, consume the setup token and create under one lock. */
export async function createTenantWithAdminTx(
  client: PoolClient,
  tenantName: string,
  email: string,
  passwordHash: string,
  opts: { emailVerified?: boolean; locale?: Locale } = {}
): Promise<{ tenant: Tenant; user: User }> {
  const tenantResult = await client.query(
    `INSERT INTO tenants (id, name, trial_ends_at, notification_locale) VALUES ($1, $2, $3, $4) RETURNING *`,
    [randomUUID(), tenantName, trialEnd(), opts.locale ?? "en"]
  );
  const tenant = toTenant(tenantResult.rows[0]);
  const user = await insertUser(
    { email, password_hash: passwordHash, tenant_id: tenant.id, role: "admin", status: "active", email_verified: opts.emailVerified },
    client
  );
  return { tenant, user };
}

/** Whitelisted so no caller can inject a column name. */
const USER_COLUMNS = [
  "email", "password_hash", "role", "status", "token_version",
  "reset_token_hash", "reset_expires", "invite_token_hash", "invite_expires",
  // mfa_secret is the legacy plaintext column: only ever set to NULL.
  "mfa_secret_enc", "mfa_secret", "mfa_enabled", "mfa_enrolled_at",
  "email_verified_at", "verify_token_hash", "verify_expires",
] as const;
type UserColumn = (typeof USER_COLUMNS)[number];
export type UserPatch = Partial<Record<UserColumn, unknown>> & {
  bump_token_version?: boolean;
};

export async function updateUser(id: string, patch: UserPatch): Promise<User | null> {
  const sets: string[] = [];
  const params: unknown[] = [id];

  for (const column of USER_COLUMNS) {
    if (!(column in patch)) continue;
    params.push(patch[column]);
    sets.push(`${column} = $${params.length}`);
  }
  // Incremented in SQL rather than read-modify-write, so two concurrent
  // revocations can't overwrite each other and leave a token still valid.
  if (patch.bump_token_version) sets.push("token_version = token_version + 1");
  if (!sets.length) return findUserById(id);

  const row = await queryOne(
    `UPDATE users SET ${sets.join(", ")} WHERE id = $1 RETURNING *`,
    params
  );
  return row ? toUser(row) : null;
}

// --- Alerts ------------------------------------------------------------------

export interface AlertFilters {
  severity?: string;
  status?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export async function listAlerts(tenantId: string, filters: AlertFilters = {}, client?: PoolClient): Promise<Alert[]> {
  const params: unknown[] = [tenantId];
  const where = ["tenant_id = $1"];

  if (filters.severity) { params.push(filters.severity); where.push(`severity = $${params.length}`); }
  if (filters.status) { params.push(filters.status); where.push(`status = $${params.length}`); }
  if (filters.q) {
    // Parameterised: the value never reaches the SQL text.
    params.push(`%${filters.q.toLowerCase()}%`);
    where.push(`(lower(id) LIKE $${params.length} OR lower(title) LIKE $${params.length})`);
  }

  params.push(Math.min(Math.max(filters.limit ?? 100, 1), 500));
  const limitIndex = params.length;
  params.push(Math.max(filters.offset ?? 0, 0));

  const sql = `SELECT * FROM alerts WHERE ${where.join(" AND ")}
     ORDER BY created_at DESC, seq DESC
     LIMIT $${limitIndex} OFFSET $${params.length}`;
  const rows = client ? (await client.query(sql, params)).rows : await queryAll(sql, params);
  return rows.map(toAlert);
}

// --- Change cursor (realtime) --------------------------------------------------
// See the alerts_assign_seq trigger in schema.sql for what seq guarantees.

/** The tenant's latest alert version: "you have everything up to here". */
export async function alertCursor(tenantId: string): Promise<number> {
  const row = await queryOne("SELECT alert_seq FROM tenants WHERE id = $1", [tenantId]);
  return row ? Number(row.alert_seq) : 0;
}

/**
 * The alert list AND the cursor it corresponds to, from one snapshot. Every
 * alert with seq <= cursor is either in `alerts` (subject to the filters and
 * the limit) or not wanted; every later change is what /alerts/sync returns.
 * Reading them separately would leave a window in which a change is in neither.
 */
export async function listAlertsWithCursor(
  tenantId: string, filters: AlertFilters = {}
): Promise<{ alerts: Alert[]; cursor: number }> {
  return transaction(async (client) => {
    await client.query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
    const c = await client.query("SELECT alert_seq FROM tenants WHERE id = $1", [tenantId]);
    const alerts = await listAlerts(tenantId, filters, client);
    return { alerts, cursor: Number(c.rows[0]?.alert_seq ?? 0) };
  });
}

export interface AlertSync {
  /** Changes with seq in (after, cursor], oldest first. Latest version of each alert. */
  alerts: Alert[];
  /** Everything up to and including this is delivered (or is in this page). */
  cursor: number;
  has_more: boolean;
  /** The client's position is unusable — from the future (a restored database) or
   *  further behind than is worth paging — so it must reload the list instead. */
  reset: boolean;
}

/**
 * Everything that changed after `after`. Bounded above by the cursor read at
 * the start: rows with seq <= cursor are all committed (numbers are assigned in
 * commit order), so a page can never be missing a row below the number it
 * reports, however many writers are running.
 */
export async function syncAlerts(tenantId: string, after: number, limit: number): Promise<AlertSync> {
  const current = await alertCursor(tenantId);
  if (after > current || current - after > config.alertSyncMaxCatchup) {
    return { alerts: [], cursor: current, has_more: false, reset: true };
  }
  const rows = await queryAll(
    "SELECT * FROM alerts WHERE tenant_id = $1 AND seq > $2 AND seq <= $3 ORDER BY seq ASC LIMIT $4",
    [tenantId, after, current, limit + 1]
  );
  const hasMore = rows.length > limit;
  const page = rows.slice(0, limit).map(toAlert);
  return { alerts: page, cursor: hasMore ? page[page.length - 1]!.seq : current, has_more: hasMore, reset: false };
}

/** Current cursors for a set of tenants, for the socket heartbeat. */
export async function listTenantCursors(tenantIds: string[]): Promise<Map<string, number>> {
  if (tenantIds.length === 0) return new Map();
  const rows = await queryAll("SELECT id, alert_seq FROM tenants WHERE id = ANY($1::uuid[])", [tenantIds]);
  return new Map(rows.map((r) => [String(r.id), Number(r.alert_seq)]));
}

export async function getAlert(tenantId: string, id: string): Promise<Alert | null> {
  const row = await queryOne("SELECT * FROM alerts WHERE tenant_id = $1 AND id = $2", [tenantId, id]);
  return row ? toAlert(row) : null;
}

export async function recentAlerts(tenantId: string, limit: number): Promise<Alert[]> {
  const rows = await queryAll(
    "SELECT * FROM alerts WHERE tenant_id = $1 ORDER BY created_at DESC, seq DESC LIMIT $2",
    [tenantId, limit]
  );
  return rows.map(toAlert);
}

/** Filters for the security skills' reads (agent-identity SkillDataSource). All parameterised and tenant-scoped. */
export interface SkillAlertQuery {
  ids?: string[];
  since?: string;
  until?: string;
  asset?: string;
  sourceIp?: string;
  minSeverity?: Severity;
  limit: number;
}

const SEVERITY_AT_LEAST: Record<Severity, Severity[]> = {
  low: ["low", "medium", "high", "critical"],
  medium: ["medium", "high", "critical"],
  high: ["high", "critical"],
  critical: ["critical"],
};

export async function listAlertsForSkills(tenantId: string, q: SkillAlertQuery): Promise<Alert[]> {
  const params: unknown[] = [tenantId];
  const where = ["tenant_id = $1"];
  const add = (sql: string, value: unknown) => { params.push(value); where.push(sql.replace("?", `$${params.length}`)); };
  if (q.ids) add("id = ANY(?::text[])", q.ids.slice(0, 500));
  if (q.since) add("created_at >= ?::timestamptz", q.since);
  if (q.until) add("created_at <= ?::timestamptz", q.until);
  if (q.asset) add("target = ?", q.asset);
  if (q.sourceIp) add("source_ip = ?", q.sourceIp);
  if (q.minSeverity) add("severity = ANY(?::text[])", SEVERITY_AT_LEAST[q.minSeverity]);
  params.push(Math.min(Math.max(q.limit, 1), 500));
  const rows = await queryAll(
    `SELECT * FROM alerts WHERE ${where.join(" AND ")} ORDER BY created_at DESC, id DESC LIMIT $${params.length}`,
    params,
  );
  return rows.map(toAlert);
}

/** Wazuh vulnerability-detector alerts ("CVE-… affects <package>"), newest first. */
export async function listVulnerabilityAlerts(tenantId: string, limit: number): Promise<Alert[]> {
  const rows = await queryAll(
    `SELECT * FROM alerts WHERE tenant_id = $1 AND title ~* 'CVE-[0-9]{4}-[0-9]{4,7} affects '
     ORDER BY created_at DESC, id DESC LIMIT $2`,
    [tenantId, Math.min(Math.max(limit, 1), 500)],
  );
  return rows.map(toAlert);
}

export type NewAlert = Omit<Alert, "created_at" | "ai_explanation_locale" | "ai_explanation_source" | "seq" | "created_seq"> & { created_at?: string; ai_explanation_locale?: Locale | null };

/**
 * Inserts an alert, returning null if that (tenant, id) already exists.
 *
 * ON CONFLICT is what makes ingestion idempotent under concurrency: Wazuh
 * retries deliver the same event more than once, and a check-then-insert would
 * let two simultaneous retries both pass the check.
 */
export async function insertAlert(alert: NewAlert, client?: PoolClient): Promise<Alert | null> {
  const run = client
    ? async (text: string, params: unknown[]) => (await client.query(text, params)).rows[0] ?? null
    : queryOne;
  const row = await run(
    // The NOT EXISTS keeps a duplicate from reaching the row trigger at all, so a
    // re-sent event neither takes the tenant's cursor lock nor burns a number.
    // (ON CONFLICT still guards the race between two identical inserts.)
    `INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary,
                         confidence, ai_explanation, explained_at, source_ip, target,
                         mitre_technique, source, created_at)
     SELECT $1::uuid,$2,$3,$4,$5,$6,$7,$8::real,$9,$10::timestamptz,$11,$12,$13,$14, COALESCE($15::timestamptz, now())
      WHERE NOT EXISTS (SELECT 1 FROM alerts WHERE tenant_id = $1::uuid AND id = $2)
     ON CONFLICT (tenant_id, id) DO NOTHING
     RETURNING *`,
    [
      alert.tenant_id, alert.id, alert.title, alert.severity, alert.agent, alert.status,
      alert.summary, alert.confidence, alert.ai_explanation, alert.explained_at,
      alert.source_ip, alert.target, alert.mitre_technique, alert.source,
      alert.created_at ?? null,
    ]
  );
  return row ? toAlert(row) : null;
}

export async function updateAlertStatus(
  tenantId: string, id: string, status: AlertStatus
): Promise<Alert | null> {
  const row = await queryOne(
    "UPDATE alerts SET status = $3 WHERE tenant_id = $1 AND id = $2 RETURNING *",
    [tenantId, id, status]
  );
  return row ? toAlert(row) : null;
}

export async function setAlertExplanation(
  tenantId: string, id: string, explanation: string, locale: Locale = "en", source: "ai" | "local" = "local"
): Promise<Alert | null> {
  const row = await queryOne(
    "UPDATE alerts SET ai_explanation = $3, ai_explanation_locale = $4, ai_explanation_source = $5, explained_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING *",
    [tenantId, id, explanation, locale, source]
  );
  return row ? toAlert(row) : null;
}

export interface AlertStats {
  total: number;
  open: number;
  investigating: number;
  resolved: number;
  by_severity: Record<Severity, number>;
}

/** Aggregated in one query rather than by loading every alert. */
export async function alertStats(tenantId: string): Promise<AlertStats> {
  const row = await queryOne<Record<string, number>>(
    `SELECT
       count(*)                                              AS total,
       count(*) FILTER (WHERE status = 'open')               AS open,
       count(*) FILTER (WHERE status = 'investigating')      AS investigating,
       count(*) FILTER (WHERE status = 'resolved')           AS resolved,
       count(*) FILTER (WHERE severity = 'critical')         AS critical,
       count(*) FILTER (WHERE severity = 'high')             AS high,
       count(*) FILTER (WHERE severity = 'medium')           AS medium,
       count(*) FILTER (WHERE severity = 'low')              AS low
     FROM alerts WHERE tenant_id = $1`,
    [tenantId]
  );
  const n = (key: string) => Number(row?.[key] ?? 0);
  return {
    total: n("total"), open: n("open"), investigating: n("investigating"), resolved: n("resolved"),
    by_severity: {
      critical: n("critical"), high: n("high"), medium: n("medium"), low: n("low"),
    },
  };
}

// --- Assets ------------------------------------------------------------------

export interface AssetFilters { risk?: string; online?: boolean; q?: string }

export async function listAssets(tenantId: string, filters: AssetFilters = {}): Promise<Asset[]> {
  const params: unknown[] = [tenantId];
  const where = ["tenant_id = $1"];
  if (filters.risk) { params.push(filters.risk); where.push(`risk = $${params.length}`); }
  if (filters.online !== undefined) { params.push(filters.online); where.push(`online = $${params.length}`); }
  if (filters.q) { params.push(`%${filters.q.toLowerCase()}%`); where.push(`lower(name) LIKE $${params.length}`); }

  const rows = await queryAll(
    `SELECT * FROM assets WHERE ${where.join(" AND ")} ORDER BY last_seen DESC`,
    params
  );
  return rows.map(toAsset);
}

const RISK_WINDOW_DAYS = 7;

/**
 * Records that a host reported in, and recalculates its risk from the alerts
 * raised against it in a trailing window.
 *
 * Both halves happen in a single statement so concurrent events for the same
 * host cannot race: without ON CONFLICT, two sensors reporting simultaneously
 * would both see "no such asset" and one insert would fail.
 *
 * Risk is recomputed rather than latched to the worst severity ever seen, so a
 * host that has been quiet for a week drops back down on its own.
 */
export async function upsertAsset(
  tenantId: string,
  name: string,
  ip: string | null,
  os: string | null,
  /** Run inside the caller's transaction (alert ingestion does). */
  client?: PoolClient
): Promise<void> {
  const run = client ? (text: string, params: unknown[]) => client.query(text, params) : query;
  await run(
    `WITH computed AS (
       SELECT COALESCE(
         (SELECT severity FROM alerts
          WHERE tenant_id = $1 AND target = $2
            AND created_at > now() - ($5 || ' days')::interval
          ORDER BY CASE severity
            WHEN 'critical' THEN 4 WHEN 'high' THEN 3
            WHEN 'medium' THEN 2 ELSE 1 END DESC
          LIMIT 1),
         'low'
       ) AS risk
     )
     INSERT INTO assets (id, tenant_id, name, os, ip_address, risk, online, last_seen)
     SELECT $6, $1, $2, COALESCE($4, 'unknown'), $3, computed.risk, true, now() FROM computed
     ON CONFLICT (tenant_id, name) DO UPDATE SET
       last_seen  = now(),
       online     = true,
       risk       = EXCLUDED.risk,
       ip_address = COALESCE(EXCLUDED.ip_address, assets.ip_address),
       -- Only fill in the OS if we never learned it; sensors report it
       -- inconsistently and a later blank must not erase a known value.
       os         = CASE WHEN assets.os = 'unknown' THEN EXCLUDED.os ELSE assets.os END`,
    [tenantId, name, ip, os, String(RISK_WINDOW_DAYS), `AST-${randomUUID().slice(0, 12).toUpperCase()}`]
  );
}

// --- Audit log ---------------------------------------------------------------

export async function audit(entry: Omit<AuditLog, "id" | "created_at">): Promise<void> {
  await query(
    `INSERT INTO audit_log (id, tenant_id, user_id, user_email, action,
                            resource_type, resource_id, detail, ip_address)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      randomUUID(), entry.tenant_id, entry.user_id, entry.user_email, entry.action,
      entry.resource_type, entry.resource_id, entry.detail, entry.ip_address,
    ]
  );
}

export interface AuditFilters { action?: string; resource_id?: string; limit?: number }

export async function listAudit(tenantId: string, filters: AuditFilters = {}): Promise<AuditLog[]> {
  const params: unknown[] = [tenantId];
  const where = ["tenant_id = $1"];
  if (filters.action) { params.push(filters.action); where.push(`action = $${params.length}`); }
  if (filters.resource_id) { params.push(filters.resource_id); where.push(`resource_id = $${params.length}`); }
  params.push(Math.min(Math.max(filters.limit ?? 100, 1), 500));

  const rows = await queryAll(
    `SELECT * FROM audit_log WHERE ${where.join(" AND ")}
     ORDER BY created_at DESC LIMIT $${params.length}`,
    params
  );
  return rows.map(toAudit);
}

// --- Subscriptions -----------------------------------------------------------

export async function getSubscription(tenantId: string): Promise<Subscription | null> {
  const row = await queryOne("SELECT * FROM subscriptions WHERE tenant_id = $1", [tenantId]);
  return row ? toSubscription(row) : null;
}

export async function getSubscriptionByPaddleId(
  paddleSubscriptionId: string
): Promise<Subscription | null> {
  const row = await queryOne(
    "SELECT * FROM subscriptions WHERE paddle_subscription_id = $1",
    [paddleSubscriptionId]
  );
  return row ? toSubscription(row) : null;
}

/**
 * Applies a Paddle event.
 *
 * `last_event_at` guards ordering inside the statement itself: Paddle does not
 * guarantee delivery order, and checking in the application would leave a
 * window where a stale retry overwrites a newer state.
 */
export async function applySubscriptionEvent(
  sub: Subscription
): Promise<Subscription | null> {
  const row = await queryOne(
    `INSERT INTO subscriptions (tenant_id, status, paddle_customer_id, paddle_subscription_id,
                                paddle_price_id, current_period_end, cancel_at_period_end, last_event_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     ON CONFLICT (tenant_id) DO UPDATE SET
       status                 = EXCLUDED.status,
       paddle_customer_id     = COALESCE(NULLIF(EXCLUDED.paddle_customer_id, ''), subscriptions.paddle_customer_id),
       paddle_subscription_id = EXCLUDED.paddle_subscription_id,
       paddle_price_id        = COALESCE(EXCLUDED.paddle_price_id, subscriptions.paddle_price_id),
       current_period_end     = EXCLUDED.current_period_end,
       cancel_at_period_end   = EXCLUDED.cancel_at_period_end,
       last_event_at          = EXCLUDED.last_event_at
     WHERE subscriptions.last_event_at IS NULL
        OR EXCLUDED.last_event_at >= subscriptions.last_event_at
     RETURNING *`,
    [
      sub.tenant_id, sub.status, sub.paddle_customer_id, sub.paddle_subscription_id,
      sub.paddle_price_id, sub.current_period_end, sub.cancel_at_period_end, sub.last_event_at,
    ]
  );
  return row ? toSubscription(row) : null;
}
