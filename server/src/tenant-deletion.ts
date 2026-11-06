/**
 * Erasing a workspace: everything it holds, in one transaction, with proof.
 *
 * Irreversible, so it is deliberate:
 *  - dry run first (`plan`), and `delete` needs the workspace's exact name;
 *  - refused while the workspace is on a legal hold, or has a paid subscription;
 *  - refused if somebody's account lives in this workspace but they also belong
 *    to another one (erasing would erase their account there too);
 *  - leaves a tombstone (tenant_deletions) with no personal data, and appends a
 *    line to DELETION_LEDGER_FILE so a restored backup can replay the deletion.
 *
 * The audit logs are append-only; the erasure runs inside the database as
 * legion_erase_tenant (migration 0008), which drops the workspace's whole
 * chains as a unit and records the tombstone in the same transaction.
 */
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { config } from "./config.js";
import { inTenant, pool, query } from "./db/pool.js";
import { mailEnabled, sendMail, workspaceDeletionNoticeEmail } from "./mailer.js";

export interface DeletionPlan {
  tenantId: string;
  name: string | null;
  /** Reasons the deletion is refused. Empty: it may go ahead. */
  blockers: string[];
  /** Rows per table that would go. */
  counts: Record<string, number>;
}

/** Tables with a tenant_id column (uuid or text) other than the two handled by hand. */
async function tenantTables(client: { query: (text: string) => Promise<{ rows: Array<{ table_name: string }> }> }): Promise<string[]> {
  const r = await client.query(
    `SELECT c.table_name FROM information_schema.columns c
       JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
      WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id'
        AND c.table_name NOT IN ('tenants', 'users', 'tenant_deletions')
      ORDER BY c.table_name`);
  return r.rows.map((x) => x.table_name);
}

const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

export async function planDeletion(tenantId: string, opts: { force?: boolean } = {}): Promise<DeletionPlan> {
  // F-04: counting a workspace's rows reads that workspace (CLI and the auto-delete job have no request).
  return inTenant(tenantId, () => planWorkspaceDeletion(tenantId, opts));
}

async function planWorkspaceDeletion(tenantId: string, opts: { force?: boolean }): Promise<DeletionPlan> {
  const tenant = (await query<{ name: string; legal_hold: boolean }>("SELECT name, legal_hold FROM tenants WHERE id = $1", [tenantId])).rows[0];
  if (!tenant) return { tenantId, name: null, blockers: ["No such workspace"], counts: {} };
  const blockers: string[] = [];
  if (tenant.legal_hold && !opts.force) blockers.push("The workspace is on a legal hold");
  const sub = (await query<{ status: string }>("SELECT status FROM subscriptions WHERE tenant_id = $1", [tenantId])).rows[0];
  if (sub && ["active", "trialing", "past_due"].includes(sub.status) && !opts.force) blockers.push(`It has a ${sub.status} subscription: cancel it first`);
  const shared = (await query<{ n: number }>(
    `SELECT count(*)::int AS n FROM users u
      WHERE u.tenant_id = $1 AND EXISTS (SELECT 1 FROM workspace_memberships m WHERE m.user_id = u.id AND m.tenant_id <> $1)`, [tenantId])).rows[0]!.n;
  if (shared) blockers.push(`${shared} person(s) have an account that lives in this workspace but belong to other workspaces too`);

  const counts: Record<string, number> = {};
  for (const table of await tenantTables({ query })) {
    counts[table] = Number((await query(`SELECT count(*)::bigint AS n FROM ${ident(table)} WHERE tenant_id::text = $1`, [tenantId])).rows[0]!.n);
  }
  counts.users = Number((await query("SELECT count(*)::bigint AS n FROM users WHERE tenant_id = $1", [tenantId])).rows[0]!.n);
  return { tenantId, name: tenant.name, blockers, counts };
}

export interface DeletionResult { tenantId: string; counts: Record<string, number> }

/** Erases the workspace. `confirmName` must be its exact name (the operator typed it). */
export async function deleteTenant(
  tenantId: string,
  opts: { by: string; confirmName?: string; reason?: string; force?: boolean; ledgerFile?: string | null } = { by: "operator" },
): Promise<DeletionResult> {
  const plan = await planDeletion(tenantId, { force: opts.force });
  if (plan.blockers.length) throw new Error(`Refused: ${plan.blockers.join("; ")}`);
  if (opts.confirmName !== undefined && opts.confirmName !== plan.name) throw new Error("Refused: the confirmation does not match the workspace name");

  // F-02: the erasure itself runs inside the database (legion_erase_tenant, migration 0008):
  // one transaction, refused under a legal hold unless forced, always recorded in tenant_deletions.
  await query("SELECT legion_erase_tenant($1, $2, $3, $4, $5)",
    [tenantId, opts.by.slice(0, 80), opts.reason?.slice(0, 300) ?? null, JSON.stringify(plan.counts), opts.force === true]);

  // After the commit: a ledger line for a workspace that still existed would make a replay delete it.
  const file = opts.ledgerFile === undefined ? config.deletionLedgerFile : opts.ledgerFile;
  if (file) appendFileSync(file, `${JSON.stringify({ tenant_id: tenantId, deleted_at: new Date().toISOString(), by: opts.by })}\n`, { mode: 0o600 });
  return { tenantId, counts: plan.counts };
}

/**
 * After a backup is restored it brings back workspaces deleted since it was
 * taken. The ledger (kept outside the database) says which; this erases them again.
 * Returns the workspace ids it found (and, unless `dryRun`, erased).
 */
export async function replayLedger(file: string, opts: { dryRun?: boolean } = {}): Promise<string[]> {
  if (!existsSync(file)) throw new Error(`No such ledger: ${file}`);
  const ids = new Set<string>();
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try { const id = (JSON.parse(line) as { tenant_id?: unknown }).tenant_id; if (typeof id === "string" && /^[0-9a-f-]{36}$/i.test(id)) ids.add(id); } catch { /* a damaged line is skipped */ }
  }
  const back: string[] = [];
  for (const id of ids) {
    if (!(await query("SELECT 1 FROM tenants WHERE id = $1", [id])).rowCount) continue;
    back.push(id);
    if (!opts.dryRun) await deleteTenant(id, { by: "ledger-replay", reason: "deleted before the backup was restored", force: true, ledgerFile: null });
  }
  return back;
}

export interface ExpiredWorkspace { id: string; name: string; ended_at: string; notice_at: string | null; scheduled_for: string | null }

/**
 * Locked workspaces whose subscription (or trial) ended more than `days` ago.
 * The caller decides what to do: list them, or (TENANT_AUTO_DELETE_DAYS) warn
 * their administrators and then erase them.
 */
export async function expiredWorkspaces(days: number): Promise<ExpiredWorkspace[]> {
  if (!(days > 0)) return [];
  const r = await query<{ id: string; name: string; ended_at: Date; deletion_notice_at: Date | null; deletion_scheduled_for: Date | null }>(
    `SELECT t.id, t.name, e.ended_at, t.deletion_notice_at, t.deletion_scheduled_for FROM tenants t
       LEFT JOIN subscriptions s ON s.tenant_id = t.id
       CROSS JOIN LATERAL (SELECT COALESCE(
           CASE WHEN s.status IN ('canceled', 'paused') THEN COALESCE(s.current_period_end, s.last_event_at) END,
           CASE WHEN s.tenant_id IS NULL THEN t.trial_ends_at END) AS ended_at) e
      WHERE NOT t.legal_hold AND e.ended_at IS NOT NULL AND e.ended_at < now() - make_interval(days => $1)
      ORDER BY e.ended_at`, [Math.floor(days)]);
  return r.rows.map((x) => ({
    id: x.id, name: x.name, ended_at: x.ended_at.toISOString(),
    notice_at: x.deletion_notice_at?.toISOString() ?? null, scheduled_for: x.deletion_scheduled_for?.toISOString() ?? null,
  }));
}

/** The people to warn: active administrators of the workspace, and its notification address. */
export async function noticeRecipients(tenantId: string): Promise<string[]> {
  const r = await query<{ email: string }>(
    `SELECT u.email FROM workspace_memberships m JOIN users u ON u.id = m.user_id
      WHERE m.tenant_id = $1 AND m.role = 'admin' AND m.status = 'active'
     UNION
     SELECT notification_email FROM tenants WHERE id = $1 AND notification_email IS NOT NULL`, [tenantId]);
  return [...new Set(r.rows.map((x) => x.email.trim().toLowerCase()).filter(Boolean))];
}

/**
 * E-mails the administrators that the workspace will be erased on `deleteOn`.
 * True only if the mail server accepted it for at least one person: with no
 * mail server, or nobody to tell, nothing is deleted (the warning is the point).
 */
async function sendDeletionNotice(w: { id: string; name: string }, deleteOn: Date): Promise<boolean> {
  if (!mailEnabled()) return false;
  const to = await noticeRecipients(w.id);
  if (!to.length) return false;
  const when = deleteOn.toISOString().slice(0, 10);
  const mail = workspaceDeletionNoticeEmail({ workspace: w.name, deleteOn: when, billingUrl: `${config.frontendUrl}/billing`, exportUrl: `${config.frontendUrl}/settings` });
  let delivered = 0;
  for (const address of to) if ((await sendMail({ to: address, ...mail })).sent) delivered++;
  return delivered > 0;
}

const AUTO_DELETE_LOCK = 7_450_911;

/**
 * The opt-in job (TENANT_AUTO_DELETE_DAYS). Hosted only. For a workspace locked longer than that:
 *   1. the first time, its administrators are e-mailed and a date is set
 *      (TENANT_DELETE_NOTICE_DAYS from now, never fewer than 7 days); nothing is deleted;
 *   2. once that date has passed, and it is still locked, it is erased;
 *   3. if it stopped being locked meanwhile (subscribed again, legal hold), the notice is cleared.
 * Without a working mail server, or anyone to warn, a workspace is never erased by this job.
 * Returns the ids erased; notices sent are reported through `onNotice`.
 */
export async function autoDeleteExpired(days = config.tenantAutoDeleteDays, onNotice?: (id: string, deleteOn: Date) => void): Promise<string[]> {
  if (config.deploymentMode === "self-hosted" || !(days > 0)) return [];
  // One instance at a time: two must not both send the same warning.
  const lock = await pool.connect();
  const gone: string[] = [];
  try {
    if (!(await lock.query<{ ok: boolean }>("SELECT pg_try_advisory_lock($1) AS ok", [AUTO_DELETE_LOCK])).rows[0]?.ok) return [];
    const expired = await expiredWorkspaces(days);
    await query(
      "UPDATE tenants SET deletion_notice_at = NULL, deletion_scheduled_for = NULL WHERE deletion_notice_at IS NOT NULL AND NOT (id = ANY($1::uuid[]))",
      [expired.map((w) => w.id)]);
    for (const w of expired) {
      try {
        if (!w.notice_at || !w.scheduled_for) {
          const deleteOn = new Date(Date.now() + config.tenantDeleteNoticeDays * 86_400_000);
          if (!(await sendDeletionNotice(w, deleteOn))) {
            console.warn(`Legion: not warning or deleting ${w.id}: the warning e-mail could not be sent (no mail server, or no administrator to tell)`);
            continue;
          }
          await query("UPDATE tenants SET deletion_notice_at = now(), deletion_scheduled_for = $2 WHERE id = $1", [w.id, deleteOn.toISOString()]);
          onNotice?.(w.id, deleteOn);
        } else if (new Date(w.scheduled_for).getTime() <= Date.now()) {
          await deleteTenant(w.id, { by: "auto", reason: `locked since ${w.ended_at.slice(0, 10)}; warned ${w.notice_at.slice(0, 10)}` });
          gone.push(w.id);
        }
      } catch (error) {
        console.warn(`Legion: not auto-deleting ${w.id}: ${error instanceof Error ? error.message : error}`);
      }
    }
  } finally {
    await lock.query("SELECT pg_advisory_unlock($1)", [AUTO_DELETE_LOCK]).catch(() => {});
    lock.release();
  }
  return gone;
}
