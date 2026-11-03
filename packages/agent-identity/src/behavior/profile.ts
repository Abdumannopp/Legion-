import type { Pool } from "pg";
import { destinationKey, isExternal, isPeer } from "./keys.js";
import type { BehaviorProfile, WindowEvent } from "./types.js";

/*
 * Builds an agent's baseline from its own firewall decisions — every action
 * it took (or tried) passed the firewall, so that log is its complete
 * behavioural record. The current window is excluded, so an attack in
 * progress does not become "normal" while it happens.
 */

export interface BaselineRange {
  tenantId: string;
  identityId: string;
  from: Date;
  to: Date;
  /** Reviewed-and-rejected activity kept out of the baseline. */
  excluded?: { from: Date; to: Date } | null;
  minEvents: number;
  minDays: number;
}

export async function buildProfile(pool: Pool, r: BaselineRange): Promise<BehaviorProfile> {
  const base = `tenant_id = $1 AND principal_id = $2 AND occurred_at >= $3 AND occurred_at < $4
    AND NOT (occurred_at >= coalesce($5::timestamptz, 'infinity') AND occurred_at <= coalesce($6::timestamptz, '-infinity'))`;
  const args = [r.tenantId, r.identityId, r.from, r.to, r.excluded?.from ?? null, r.excluded?.to ?? null];

  const [hours, actions, resources, destinations, users] = await Promise.all([
    pool.query(
      `SELECT date_trunc('hour', occurred_at) AS h, count(*)::int AS n,
              count(*) FILTER (WHERE decision = 'BLOCK')::int AS b,
              count(*) FILTER (WHERE sensitivity IN ('confidential', 'restricted'))::int AS s,
              count(*) FILTER (WHERE destination LIKE 'agent:%')::int AS m
         FROM firewall_decisions WHERE ${base} GROUP BY 1 ORDER BY 1`, args),
    pool.query(`SELECT action AS k, count(*)::int AS n FROM firewall_decisions WHERE ${base} GROUP BY 1 ORDER BY 2 DESC LIMIT 1000`, args),
    pool.query(`SELECT resource_type AS k, count(*)::int AS n FROM firewall_decisions WHERE ${base} AND resource_type IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 500`, args),
    pool.query(`SELECT destination AS k, count(*)::int AS n FROM firewall_decisions WHERE ${base} AND destination IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 5000`, args),
    pool.query(`SELECT delegated_user AS k, count(*)::int AS n FROM firewall_decisions WHERE ${base} AND delegated_user IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 500`, args),
  ]);

  const counts: number[] = hours.rows.map((h) => h.n);
  const events = counts.reduce((a, b) => a + b, 0);
  const mean = counts.length ? events / counts.length : 0;
  const std = counts.length ? Math.sqrt(counts.reduce((a, n) => a + (n - mean) ** 2, 0) / counts.length) : 0;
  const sorted = [...counts].sort((a, b) => a - b);
  const p95 = sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))]! : 0;
  const sum = (k: "b" | "s" | "m") => hours.rows.reduce((a, h) => a + h[k], 0);
  const hoursOfDay = Array.from({ length: 24 }, () => 0);
  for (const h of hours.rows) hoursOfDay[new Date(h.h).getUTCHours()]! += h.n;

  const toMap = (rows: { k: string; n: number }[]) => Object.fromEntries(rows.map((x) => [x.k, x.n]));
  const dest: Record<string, number> = {};
  const ext: Record<string, number> = {};
  const peers: Record<string, number> = {};
  for (const row of destinations.rows as { k: string; n: number }[]) {
    const key = destinationKey(row.k);
    if (!key) continue;
    dest[key] = (dest[key] ?? 0) + row.n;
    if (isExternal(key)) ext[key] = (ext[key] ?? 0) + row.n;
    if (isPeer(key)) peers[key] = (peers[key] ?? 0) + row.n;
  }

  const since = hours.rows[0] ? new Date(hours.rows[0].h).toISOString() : null;
  const spanDays = since ? (r.to.getTime() - new Date(since).getTime()) / 86_400_000 : 0;
  return {
    events,
    since,
    until: r.to.toISOString(),
    hourly: { mean, std, p95, activeHours: counts.length },
    actions: toMap(actions.rows),
    resourceTypes: toMap(resources.rows),
    destinations: dest,
    externalDestinations: ext,
    peers,
    delegatedUsers: toMap(users.rows),
    blockRate: events ? sum("b") / events : 0,
    sensitiveRate: events ? sum("s") / events : 0,
    messagesPerHour: counts.length ? sum("m") / counts.length : 0,
    hoursOfDay,
    established: events >= r.minEvents && spanDays >= r.minDays,
  };
}

export async function windowEvents(pool: Pool, tenantId: string, identityId: string, from: Date): Promise<WindowEvent[]> {
  const res = await pool.query(
    `SELECT occurred_at, surface, action, resource_type, destination, sensitivity, decision, rule_hits, delegated_user, via_message_id
       FROM firewall_decisions
      WHERE tenant_id = $1 AND principal_id = $2 AND occurred_at >= $3
      ORDER BY occurred_at DESC LIMIT 5000`,
    [tenantId, identityId, from],
  );
  return res.rows.map((r) => ({
    occurredAt: new Date(r.occurred_at).toISOString(),
    surface: r.surface,
    action: r.action,
    resourceType: r.resource_type,
    destination: r.destination,
    sensitivity: r.sensitivity,
    decision: r.decision,
    ruleIds: (r.rule_hits as { id: string }[]).map((h) => h.id),
    delegatedUser: r.delegated_user,
    viaMessage: !!r.via_message_id,
  }));
}

export async function windowFailures(pool: Pool, tenantId: string, identityId: string, from: Date): Promise<number> {
  const res = await pool.query(
    `SELECT count(*)::int AS n FROM principal_audit_log
      WHERE tenant_id = $1 AND principal_id = $2 AND outcome = 'failure' AND occurred_at >= $3`,
    [tenantId, identityId, from],
  );
  return res.rows[0].n;
}
