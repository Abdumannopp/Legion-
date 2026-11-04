/**
 * Simulators: what an action WOULD do, computed from current data with reads
 * only. Nothing here writes, sends, blocks or calls out — v0 has no live
 * executors at all, so there is no code path from an action to a side effect.
 */
import { queryOne } from "../db/pool.js";
import * as blocklist from "../blocklist.js";
import { allows, resolvePlan } from "../plan-limits.js";
import * as store from "../store.js";
import { connectedFor, previews } from "../integrations/action-connectors.js";

export type SimulationResult = Record<string, unknown> & { would: string; side_effects: "none" };

type Simulator = (tenantId: string, input: Record<string, unknown>) => Promise<Omit<SimulationResult, "side_effects">>;

const SIMULATORS: Record<string, Simulator> = {
  "alert.explain": async (t, i) => {
    const alert = await store.getAlert(t, String(i.alert_id));
    return alert ? { would: "explain", alert_id: alert.id, has_explanation: Boolean(alert.ai_explanation) } : { would: "refuse", why: "alert_not_found" };
  },
  "alert.triage": async (t, i) => {
    const alert = await store.getAlert(t, String(i.alert_id));
    if (!alert) return { would: "refuse", why: "alert_not_found" };
    const weight = { critical: 4, high: 3, medium: 2, low: 1 }[alert.severity] ?? 1;
    const score = Math.min(100, weight * 20 + Math.round((alert.confidence ?? 0) / 5));
    return { would: "triage", alert_id: alert.id, score, bucket: score >= 70 ? "now" : score >= 45 ? "today" : "this_week" };
  },
  "alert.set_status": async (t, i) => {
    const alert = await store.getAlert(t, String(i.alert_id));
    if (!alert) return { would: "refuse", why: "alert_not_found" };
    return alert.status === i.status ? { would: "nothing", why: "already_in_status", status: alert.status } : { would: "change_status", from: alert.status, to: i.status };
  },
  "notify.admins": async (t) => {
    const n = await queryOne<{ n: number }>(
      "SELECT count(*)::int AS n FROM workspace_memberships WHERE tenant_id = $1 AND role = 'admin' AND status = 'active'", [t],
    );
    return { would: "email", recipients: n?.n ?? 0 };
  },
  "ip.block": async (t, i) => {
    const ip = String(i.ip);
    if (!(await allows(await resolvePlan(t), "ipBlocking"))) return { would: "refuse", why: "plan" };
    if (!blocklist.isPublicAddress(ip)) return { would: "refuse", why: "not_public", ip };
    const settings = await blocklist.getSettings(t);
    if (blocklist.isAllowlisted(settings.allowlist, ip)) return { would: "refuse", why: "allowlisted", ip };
    const active = (await blocklist.listBlocks(t, { activeOnly: true })).find((b) => b.ip === ip);
    return { would: active ? "extend_block" : "block", ip, minutes: Number(i.minutes), currently_blocked_until: active?.expires_at ?? null };
  },
  "ip.unblock": async (t, i) => {
    const active = (await blocklist.listBlocks(t, { activeOnly: true })).find((b) => b.ip === String(i.ip));
    return active ? { would: "unblock", ip: active.ip } : { would: "nothing", why: "not_blocked" };
  },
  "payment.release": async (t, i) => paymentSim(t, String(i.payment_id), "release"),
  "payment.reject": async (t, i) => paymentSim(t, String(i.payment_id), "reject"),
  "account.disable": async (t, i) => connectorSim(t, "account.disable", i),
  "host.isolate": async (t, i) => connectorSim(t, "host.isolate", i),
};

/** What a connected system would be asked to do (integrations/action-connectors.ts). Nothing is sent. */
async function connectorSim(tenantId: string, actionId: string, input: Record<string, unknown>) {
  const connected = await connectedFor(tenantId, actionId);
  return { would: "call_connector", connector_available: connected.length > 0, connected, previews: previews(actionId, input) };
}

async function paymentSim(tenantId: string, id: string, verb: "release" | "reject") {
  const row = await queryOne<{ amount: string; currency: string; beneficiary_hint: string }>(
    "SELECT amount, currency, beneficiary_hint FROM payment_checks WHERE tenant_id = $1 AND id = $2 AND decision = 'hold' AND resolution IS NULL",
    [tenantId, id],
  );
  return row ? { would: verb, payment_id: id, amount: row.amount, currency: row.currency, beneficiary_hint: row.beneficiary_hint } : { would: "refuse", why: "no_such_held_payment" };
}

export function hasSimulator(actionId: string): boolean {
  return actionId in SIMULATORS;
}

export async function simulate(tenantId: string, actionId: string, input: Record<string, unknown>): Promise<SimulationResult> {
  const fn = SIMULATORS[actionId];
  if (!fn) throw new Error(`no simulator for ${actionId}`);
  const out = await fn(tenantId, input);
  return { ...out, would: String(out.would), side_effects: "none" };
}
