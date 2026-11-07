/**
 * Prometheus metrics (text exposition format 0.0.4) for operators.
 *
 * Platform-wide counts only: no tenant ids, no recipients, no alert or action
 * text, no payloads. The endpoint is not public — it exists only when
 * HEALTH_METRICS_TOKEN is set and requires it (see index.ts).
 *
 * What a pilot needs to see: is the runtime worker alive, is work piling up,
 * is anything dead or stuck, are approvals waiting, is any workspace paused,
 * how often do shadow decisions diverge, and — above all — is any action
 * running outside shadow/simulation (that number must be 0).
 */
import { pool, query } from "./db/pool.js";
import { aiCircuit } from "./ai.js";
import { queueMetrics, workerStatus } from "./outbox.js";
import { RUNNING_STALE_SECONDS } from "./actions/engine.js";
import { runtimeHealth } from "./runtime/worker.js";
import { auditKeyring, currentAuditKeyId } from "./audit/events.js";
import { renderHttpStats } from "./http-stats.js";
import { config } from "./config.js";

type Sample = { name: string; help: string; type: "gauge" | "counter"; values: Array<{ labels?: Record<string, string>; value: number }> };

const esc = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
export function render(samples: Sample[]): string {
  const out: string[] = [];
  for (const s of samples) {
    out.push(`# HELP ${s.name} ${s.help}`, `# TYPE ${s.name} ${s.type}`);
    for (const v of s.values) {
      const l = v.labels ? `{${Object.entries(v.labels).map(([k, x]) => `${k}="${esc(x)}"`).join(",")}}` : "";
      out.push(`${s.name}${l} ${Number.isFinite(v.value) ? v.value : 0}`);
    }
  }
  return out.join("\n") + "\n";
}

const g = (name: string, help: string, value: number, labels?: Record<string, string>): Sample => ({ name, help, type: "gauge", values: [{ labels, value }] });
const byLabel = (name: string, help: string, label: string, keys: readonly string[], rows: Array<Record<string, unknown>>, key: string): Sample => ({
  name, help, type: "gauge",
  values: keys.map((k) => ({ labels: { [label]: k }, value: Number(rows.find((r) => r[key] === k)?.n ?? 0) })),
});

/**
 * Every statement below is partitioned BY TENANT (GROUP BY tenant_id) and the
 * totals are summed here, so no query reads across workspaces unscoped (the
 * tenant-query guard test holds these tables to that rule) and no tenant id
 * leaves this file.
 */
const sum = (rows: Array<Record<string, unknown>>, key: string) => rows.reduce((a, r) => a + Number(r[key] ?? 0), 0);
const sumBy = (rows: Array<Record<string, unknown>>, keyCol: string) => {
  const m = new Map<string, number>();
  for (const r of rows) m.set(String(r[keyCol]), (m.get(String(r[keyCol])) ?? 0) + Number(r.n ?? 0));
  return [...m].map(([k, n]) => ({ k, n }));
};
const maxOf = (rows: Array<Record<string, unknown>>, key: string) => rows.reduce((a, r) => Math.max(a, Number(r[key] ?? 0)), 0);

export async function collectMetrics(): Promise<string> {

  // One call: the aggregate runs in the database as the schema owner (migration 0010), so it also works
  // under row-level security, and the API receives counts per workspace, never rows.
  type Rows = Array<Record<string, unknown>>;
  type Agg = { jobs: Rows; job_ages: Rows; actions: Rows; act: Rows; appr: Rows; paused: Rows; pol: Rows; div: Rows; audit: Rows; heads: Rows; wf: Rows; db_bytes: number };
  const m = (await query<{ m: Agg }>("SELECT legion_soc_metrics($1) AS m", [Number(RUNNING_STALE_SECONDS)])).rows[0]!.m;
  const jobs = sumBy(m.jobs, "k");
  const jobAges = m.job_ages;
  const actions = sumBy(m.actions, "k");
  const act = m.act;
  const appr = m.appr;
  const paused = m.paused;
  const pol = sumBy(m.pol, "k");
  const div = m.div;
  const audit = m.audit;
  // Workspaces whose newest audit event was signed with a different key than this process holds.
  const heads = m.heads;
  // A head signed with a key in SOC_AUDIT_PREVIOUS_KEYS is a rotation in progress, not a mismatch.
  const ring = auditKeyring();
  const keyMismatch = heads.filter((h) => h.key_id !== currentAuditKeyId() && !ring.has(String(h.key_id))).length;
  const wf = m.wf;
  // Counted from the tenants table itself (no workspace data, no RLS on it): how many opted in, with the notice accepted.
  const protectionActive = Number((await query<{ n: number }>("SELECT count(*) FILTER (WHERE protection_mode <> 'manual' AND protection_ack_at IS NOT NULL)::int AS n FROM tenants")).rows[0]?.n ?? 0);
  const outbox = await queueMetrics();
  const rt = runtimeHealth();
  const ob = workerStatus();

  const samples: Sample[] = [
    g("legion_up", "The API answered.", 1),
    g("legion_database_size_bytes", "Size of Legion's database on disk (retention keeps it bounded: DATA-RETENTION.md).", Number(m.db_bytes)),
    g("legion_process_uptime_seconds", "Seconds since this process started.", Math.round(process.uptime())),
    g("legion_build_info", "Version of this instance.", 1, { version: config.version, mode: config.deploymentMode }),
    // --- SOC runtime
    g("legion_soc_runtime_worker_running", "1 when this instance runs the SOC job worker.", rt.running ? 1 : 0),
    g("legion_soc_runtime_last_tick_age_seconds", "Seconds since this instance's SOC worker finished a pass (-1: never).", rt.last_tick_seconds_ago ?? -1),
    { name: "legion_soc_runtime_ticks_total", help: "SOC worker passes since start.", type: "counter", values: [{ value: rt.ticks }] },
    { name: "legion_soc_runtime_tick_errors_total", help: "SOC worker passes that threw.", type: "counter", values: [{ value: rt.errors }] },
    byLabel("legion_soc_jobs", "SOC jobs by status.", "status", ["queued", "running", "done", "dead"], jobs, "k"),
    g("legion_soc_jobs_oldest_due_age_seconds", "Age of the longest-waiting job that is due now.", maxOf(jobAges, "oldest_due")),
    g("legion_soc_jobs_expired_leases", "Running jobs whose worker lease ran out (a worker died).", sum(jobAges, "expired_leases")),
    // --- actions / approvals
    byLabel("legion_soc_actions", "Action requests by status.", "status", ["denied", "recorded", "awaiting_approval", "rejected", "expired", "cancelled", "queued", "running", "simulated", "executed", "failed"], actions, "k"),
    g("legion_soc_actions_live", "Actions in live mode. Must be 0 unless a workspace opted in (legion_soc_workspaces_protection_active).", sum(act, "live")),
    g("legion_soc_workspaces_protection_active", "Workspaces whose administrator allowed Legion to act on its own (hybrid or automatic).", protectionActive),
    g("legion_soc_actions_stuck_running", "Actions stuck in running past the recovery window.", sum(act, "stuck")),
    g("legion_soc_approvals_pending", "Approval requests waiting for a person.", sum(appr, "pending")),
    g("legion_soc_approvals_oldest_pending_age_seconds", "Age of the longest-waiting approval request.", maxOf(appr, "oldest")),
    g("legion_soc_approvals_approved_unused", "Approved requests not yet used (held by a pause, or waiting for the next sync).", sum(appr, "approved_unused")),
    g("legion_soc_workspaces_paused", "Workspaces whose emergency stop is on.", sum(paused, "n")),
    // --- policy / audit / workflows
    byLabel("legion_soc_policy_decisions_5m", "Policy decisions in the last 5 minutes.", "decision", ["ALLOW", "REQUIRE_APPROVAL", "RECORD_ONLY", "DENY"], pol, "k"),
    g("legion_soc_shadow_divergent_24h", "Shadow decisions in 24h where existing code acted but the policy would not have allowed it.", sum(div, "n")),
    g("legion_soc_audit_events", "Events in the SOC audit chains.", sum(audit, "n")),
    g("legion_soc_audit_key_mismatch_workspaces", "Workspaces whose audit chain was signed with a different key than this process has (SOC_AUDIT_KEY wrong or changed). Appending is refused for them.", keyMismatch),
    g("legion_soc_workflow_runs_1h", "Workflow runs in the last hour.", sum(wf, "total")),
    g("legion_soc_workflow_runs_failed_1h", "Failed workflow runs in the last hour.", sum(wf, "failed")),
    // --- notifications
    g("legion_outbox_pending", "Notifications waiting.", outbox.pending),
    g("legion_outbox_dead", "Notifications that failed permanently.", outbox.dead),
    g("legion_outbox_oldest_pending_age_seconds", "Age of the oldest undelivered notification.", outbox.oldest_pending_age_seconds ?? 0),
    g("legion_outbox_worker_running", "1 when this instance runs the notification worker.", ob.running ? 1 : 0),
    // --- dependencies
    g("legion_ai_circuit_open", "1 while the AI provider circuit breaker is open.", aiCircuit().state === "open" ? 1 : 0),
    g("legion_db_pool_total", "Database connections open.", pool.totalCount),
    g("legion_db_pool_waiting", "Requests waiting for a database connection.", pool.waitingCount),
  ];
  return render(samples) + renderHttpStats();
}
