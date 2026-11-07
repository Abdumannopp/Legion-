/**
 * Protection modes: how much Legion may do on its own in a workspace, and only because a person said so.
 *
 *   manual     (the default) nothing runs on its own. Legion detects, explains and proposes; a person acts.
 *   hybrid     the actions the administrator pre-authorised run on their own; everything else asks first.
 *   automatic  every action Legion can carry out that is not critical runs on its own.
 *
 * What is always true, in every mode (policy/evaluate.ts, the database, actions/engine.ts):
 *   - critical (R4) actions always wait for a person's approval;
 *   - an action an AI model produced always waits for a person's approval;
 *   - only actions with a real executor can be pre-authorised (LIVE_ACTION_IDS);
 *   - the emergency stop halts everything at once, and every automatic action is audited and e-mailed.
 *
 * Turning it on needs an administrator, a recent password confirmation, a plan with automatic protection,
 * and a written notice accepted by name. The notice is versioned: when its meaning changes the workspace
 * falls back to manual until an administrator accepts the new text.
 */
import type { PoolClient } from "pg";
import { queryAll, queryOne } from "./db/pool.js";
import { appendAuditEventNow } from "./audit/events.js";
import { LIVE_ACTION_IDS } from "./policy/catalog.js";
import { allows, resolvePlan } from "./plan-limits.js";

export const PROTECTION_MODES = ["manual", "hybrid", "automatic"] as const;
export type ProtectionMode = (typeof PROTECTION_MODES)[number];

/** Bump when the notice's meaning changes: every workspace is asked again and runs as manual until then. */
export const PROTECTION_NOTICE_VERSION = "1";

export interface Protection {
  /** What the administrator chose. */
  mode: ProtectionMode;
  auto_actions: string[];
  acknowledged: boolean;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  /** What is in force: the chosen mode, unless the acknowledgement is missing or out of date (then manual). */
  effective_mode: ProtectionMode;
}

export class ProtectionError extends Error {
  constructor(readonly status: number, readonly code: "acknowledgement_required" | "plan_feature" | "unknown_action" | "invalid", message: string) { super(message); }
}

interface Row {
  protection_mode: ProtectionMode; protection_auto_actions: string[];
  protection_ack_at: Date | null; protection_ack_by: string | null; protection_ack_version: string | null;
}

export async function getProtection(tenantId: string): Promise<Protection> {
  const r = await queryOne<Row>(
    "SELECT protection_mode, protection_auto_actions, protection_ack_at, protection_ack_by, protection_ack_version FROM tenants WHERE id = $1", [tenantId],
  );
  const acknowledged = r?.protection_ack_version === PROTECTION_NOTICE_VERSION && r.protection_ack_at !== null;
  const mode = r?.protection_mode ?? "manual";
  return {
    mode, auto_actions: r?.protection_auto_actions ?? [], acknowledged,
    acknowledged_at: r?.protection_ack_at?.toISOString() ?? null, acknowledged_by: r?.protection_ack_by ?? null,
    effective_mode: acknowledged ? mode : "manual",
  };
}

/** What the policy engine is told: the mode in force and the pre-authorised actions, nothing else. */
export interface PolicyProtection { mode: ProtectionMode; auto_actions: readonly string[] }
export const policyView = (p: Protection): PolicyProtection => ({ mode: p.effective_mode, auto_actions: p.auto_actions });

export interface ProtectionPatch { mode?: ProtectionMode; auto_actions?: string[]; acknowledge?: boolean }

export async function updateProtection(tenantId: string, patch: ProtectionPatch, by: { id: string; email: string }): Promise<Protection> {
  const current = await getProtection(tenantId);
  const mode = patch.mode ?? current.mode;
  const auto = [...new Set(patch.auto_actions ?? current.auto_actions)];
  for (const a of auto) {
    if (!LIVE_ACTION_IDS.includes(a)) throw new ProtectionError(422, "unknown_action", `Legion cannot carry out "${a.slice(0, 40)}" on its own: it is simulation-only`);
  }
  if (mode !== "manual") {
    const plan = await resolvePlan(tenantId);
    if (!allows(plan, "autoBlocking")) throw new ProtectionError(402, "plan_feature", "Automatic protection is not part of this plan");
    if (!current.acknowledged && patch.acknowledge !== true) {
      throw new ProtectionError(400, "acknowledgement_required", "Read and accept the notice before Legion may act on its own");
    }
  }
  const ack = patch.acknowledge === true && mode !== "manual";
  await queryOne(
    `UPDATE tenants SET protection_mode = $2, protection_auto_actions = $3,
       protection_ack_at = CASE WHEN $4 THEN now() ELSE protection_ack_at END,
       protection_ack_by = CASE WHEN $4 THEN $5 ELSE protection_ack_by END,
       protection_ack_version = CASE WHEN $4 THEN $6 ELSE protection_ack_version END
     WHERE id = $1`,
    [tenantId, mode, auto, ack, by.email.slice(0, 254), PROTECTION_NOTICE_VERSION],
  );
  // The chained audit trail records who changed what; the route adds the ordinary audit-log line (with the address).
  await appendAuditEventNow(tenantId, {
    category: "controls", event: "protection.changed", actor: { kind: "human", user_id: by.id, role: "admin" },
    subject_type: "tenant", subject_id: tenantId, detail: { from: current.mode, to: mode, auto_actions: auto, acknowledged: ack },
  });
  return getProtection(tenantId);
}

/** The text an administrator accepts. Shown in the dashboard; PROTECTION_NOTICE_VERSION changes with its meaning. */
export const PROTECTION_NOTICE: readonly string[] = [
  "In hybrid and automatic mode Legion acts on your systems without waiting for a person: today that means blocking an attacker's internet address for a limited time (through the sensor that reads your blocklist) and e-mailing your administrators.",
  "It decides from what the sensors report. A report can be wrong or forged: an address in a log may not be the real attacker, and a block can interrupt a legitimate user. Addresses on your allowlist, private addresses and your own network are never blocked.",
  "Critical actions (disabling accounts, isolating hosts, moving money) are never done without a person's approval, and neither is anything an AI model proposed. Legion cannot do those today; they stay in simulation.",
  "Every action is recorded in the audit trail and e-mailed to your administrators. You can turn this off, or press the emergency stop, at any time; both take effect immediately.",
  "You are responsible for the settings you choose here. Legion does not guarantee that it will stop an attack.",
];

/**
 * Alert sources that never start anything on their own: a test alert, a sample, the demo, Legion's own
 * monitors. Only what a real sensor or integration reported may lead to a real action.
 */
export const NON_ACTING_SOURCES: readonly string[] = ["legion-test", "mock", "demo", "legion-monitor", "legion-agent-security"];

/**
 * In the alert's own transaction: does this workspace want a live response run for this new alert?
 * (Which steps then really happen is decided later, per step, by the policy engine and the settings in
 * force at that moment; this only avoids queueing work for workspaces that are in manual mode.)
 */
export async function wantsLiveResponse(client: PoolClient, tenantId: string, source: string): Promise<boolean> {
  if (NON_ACTING_SOURCES.includes(source)) return false;
  const r = await client.query<Row>(
    "SELECT protection_mode, protection_auto_actions, protection_ack_at, protection_ack_by, protection_ack_version FROM tenants WHERE id = $1", [tenantId],
  );
  const t = r.rows[0];
  return Boolean(t) && t!.protection_mode !== "manual" && t!.protection_ack_version === PROTECTION_NOTICE_VERSION && t!.protection_ack_at !== null;
}

// --- the report: what Legion did, what it asked, what it could not do ------------------------------

export interface ProtectionReport {
  days: number;
  protection: Protection;
  totals: { automatic: number; approved_by_person: number; by_person: number; awaiting_approval: number; failed: number; refused_or_cancelled: number };
  by_action: Array<{ action_id: string; executed: number; failed: number }>;
  recent: Array<{ id: string; action_id: string; target: string | null; status: string; by: string; did: string | null; error: string | null; at: string }>;
  changes: Array<{ at: string; by: string | null; detail: string | null }>;
}

/** Everything Legion did in live mode over the last `days` days, in one place, for the people who answer for it. */
export async function protectionReport(tenantId: string, days: number): Promise<ProtectionReport> {
  const d = Math.min(90, Math.max(1, Math.floor(days) || 7));
  const [protection, rows, recent, changes] = await Promise.all([
    getProtection(tenantId),
    queryAll<{ action_id: string; status: string; approval_id: string | null; kind: string; n: number }>(
      `SELECT action_id, status, approval_id, actor->>'kind' AS kind, count(*)::int AS n
         FROM action_requests WHERE tenant_id = $1 AND execution_mode = 'live' AND created_at > now() - make_interval(days => $2)
        GROUP BY action_id, status, approval_id IS NULL, approval_id, actor->>'kind'`, [tenantId, d]),
    queryAll<{ id: string; action_id: string; target: string | null; status: string; actor: { kind: string; agent?: string }; result: { did?: string } | null; error: string | null; updated_at: Date }>(
      `SELECT id, action_id, target, status, actor, result, error, updated_at FROM action_requests
        WHERE tenant_id = $1 AND execution_mode = 'live' AND created_at > now() - make_interval(days => $2)
        ORDER BY created_at DESC, id LIMIT 25`, [tenantId, d]),
    queryAll<{ created_at: Date; user_email: string | null; detail: string | null }>(
      `SELECT created_at, user_email, detail FROM audit_log WHERE tenant_id = $1 AND action = 'protection.changed' ORDER BY created_at DESC LIMIT 10`, [tenantId]),
  ]);
  const totals = { automatic: 0, approved_by_person: 0, by_person: 0, awaiting_approval: 0, failed: 0, refused_or_cancelled: 0 };
  const per = new Map<string, { executed: number; failed: number }>();
  for (const r of rows) {
    const cur = per.get(r.action_id) ?? { executed: 0, failed: 0 };
    if (r.status === "executed") {
      cur.executed += r.n;
      if (r.kind === "human") totals.by_person += r.n;
      else if (r.approval_id) totals.approved_by_person += r.n;
      else totals.automatic += r.n;
    } else if (r.status === "failed") { cur.failed += r.n; totals.failed += r.n; }
    else if (r.status === "awaiting_approval") totals.awaiting_approval += r.n;
    else if (["denied", "rejected", "expired", "cancelled"].includes(r.status)) totals.refused_or_cancelled += r.n;
    per.set(r.action_id, cur);
  }
  return {
    days: d, protection, totals,
    by_action: [...per].map(([action_id, v]) => ({ action_id, ...v })).sort((a, b) => a.action_id.localeCompare(b.action_id)),
    recent: recent.map((r) => ({
      id: r.id, action_id: r.action_id, target: r.target, status: r.status,
      by: r.actor.kind === "agent" ? String(r.actor.agent) : r.actor.kind === "human" ? "person" : "system",
      did: r.result?.did ?? null, error: r.error, at: r.updated_at.toISOString(),
    })),
    changes: changes.map((c) => ({ at: c.created_at.toISOString(), by: c.user_email, detail: c.detail })),
  };
}
