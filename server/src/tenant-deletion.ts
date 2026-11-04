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
 * The audit logs are append-only; the deletion transaction sets the
 * transaction-local switch (legion.audit_erasure) the database requires, drops
 * the workspace's whole chain as a unit, and nothing else can.
 */
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { config } from "./config.js";
import { pool, query } from "./db/pool.js";

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

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('legion.audit_erasure', 'on', true)");
    // Tables without a foreign key to tenants (the agent layer) and any with one: try each,
    // and retry the ones a foreign key held back until a pass makes no progress.
    let pending = await tenantTables(client);
    while (pending.length) {
      const stuck: string[] = [];
      for (const table of pending) {
        await client.query("SAVEPOINT t");
        try {
          await client.query(`DELETE FROM ${ident(table)} WHERE tenant_id::text = $1`, [tenantId]);
          await client.query("RELEASE SAVEPOINT t");
        } catch (error) {
          await client.query("ROLLBACK TO SAVEPOINT t");
          if ((error as { code?: string }).code !== "23503") throw error;
          stuck.push(table);
        }
      }
      if (stuck.length === pending.length) break;
      pending = stuck;
    }
    await client.query("DELETE FROM users WHERE tenant_id = $1", [tenantId]);
    await client.query("DELETE FROM tenants WHERE id = $1", [tenantId]);
    await client.query(
      "INSERT INTO tenant_deletions (tenant_id, deleted_by, reason, counts) VALUES ($1, $2, $3, $4)",
      [tenantId, opts.by.slice(0, 80), opts.reason?.slice(0, 300) ?? null, JSON.stringify(plan.counts)],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    throw error;
  } finally {
    client.release();
  }

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

/**
 * Locked workspaces whose subscription (or trial) ended more than `days` ago.
 * The caller decides what to do: list them, or (TENANT_AUTO_DELETE_DAYS) erase them.
 */
export async function expiredWorkspaces(days: number): Promise<Array<{ id: string; name: string; ended_at: string }>> {
  if (!(days > 0)) return [];
  const r = await query<{ id: string; name: string; ended_at: Date }>(
    `SELECT t.id, t.name, e.ended_at FROM tenants t
       LEFT JOIN subscriptions s ON s.tenant_id = t.id
       CROSS JOIN LATERAL (SELECT COALESCE(
           CASE WHEN s.status IN ('canceled', 'paused') THEN COALESCE(s.current_period_end, s.last_event_at) END,
           CASE WHEN s.tenant_id IS NULL THEN t.trial_ends_at END) AS ended_at) e
      WHERE NOT t.legal_hold AND e.ended_at IS NOT NULL AND e.ended_at < now() - make_interval(days => $1)
      ORDER BY e.ended_at`, [Math.floor(days)]);
  return r.rows.map((x) => ({ id: x.id, name: x.name, ended_at: x.ended_at.toISOString() }));
}

/** The opt-in job: erases workspaces that have been locked for longer than TENANT_AUTO_DELETE_DAYS. Hosted only. */
export async function autoDeleteExpired(days = config.tenantAutoDeleteDays): Promise<string[]> {
  if (config.deploymentMode === "self-hosted" || !(days > 0)) return [];
  const gone: string[] = [];
  for (const w of await expiredWorkspaces(days)) {
    try { await deleteTenant(w.id, { by: "auto", reason: `locked since ${w.ended_at.slice(0, 10)}` }); gone.push(w.id); }
    catch (error) { console.warn(`Legion: not auto-deleting ${w.id}: ${error instanceof Error ? error.message : error}`); }
  }
  return gone;
}
