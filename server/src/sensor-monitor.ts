/**
 * "Wazuh is down" is otherwise invisible.
 *
 * Legion is pushed to: when a Wazuh manager stops (crash, network cut, a full
 * disk, a broken integration), Legion receives nothing — and nothing looks
 * wrong on the dashboard. An empty alert list reads as "all quiet".
 *
 * So a sensor credential that was sending and has gone silent for
 * SENSOR_SILENCE_MINUTES raises an alert of its own, through the normal
 * pipeline (stored, versioned, emailed, pushed). When the sensor speaks
 * again the alert is resolved automatically.
 *
 * Safe on any number of instances at once: the alert id is derived from the
 * credential and the moment it went quiet, so every instance (and every tick)
 * computes the same id and the (tenant, id) key admits it once.
 */
import { createHash } from "node:crypto";
import { config } from "./config.js";
import { query, withLeaderLock } from "./db/pool.js";

const SENSOR_CHECK_LOCK = 734_012_031;
import * as outbox from "./outbox.js";
import * as store from "./store.js";
import type { Alert } from "./types.js";

/** Only credentials that sent something within this window are watched:
 *  one retired months ago is not "a sensor that stopped". */
const WATCH_DAYS = 7;

/** SENSOR-SILENT-<12 hex of sha256(key id)>-<unix second it went quiet>. Hex
 *  only, so the id splits on "-" unambiguously (a key id may contain "-"). */
export const silenceAlertId = (keyId: string, lastUsed: Date) =>
  `SENSOR-SILENT-${createHash("sha256").update(keyId, "utf8").digest("hex").slice(0, 12).toUpperCase()}-${Math.floor(lastUsed.getTime() / 1000)}`;

interface Silent { key_id: string; tenant_id: string; label: string; last_used_at: Date; minutes: number }

export interface SensorCheckReport { raised: number; resolved: number }

export async function checkSensors(opts: {
  silenceMinutes?: number;
  /** Builds the dashboard frame (index.ts newAlertFrame), queued durably with the alert. */
  realtimeFrame?: (alert: Alert) => unknown;
} = {}): Promise<SensorCheckReport> {
  const minutes = opts.silenceMinutes ?? config.sensorSilenceMinutes;
  const report: SensorCheckReport = { raised: 0, resolved: 0 };
  if (minutes <= 0) return report;

  const silent = await query<Silent>(
    `SELECT key_id, tenant_id, label, last_used_at,
            floor(extract(epoch FROM now() - last_used_at) / 60)::int AS minutes
       FROM webhook_credentials
      WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
        AND last_used_at IS NOT NULL
        AND last_used_at < now() - make_interval(mins => $1)
        AND last_used_at > now() - make_interval(days => $2)`,
    [minutes, WATCH_DAYS],
  );
  for (const s of silent.rows) {
    const label = s.label ? `"${s.label.slice(0, 80)}"` : `credential ${s.key_id.slice(0, 12)}…`;
    const alert = await outbox.insertAlertAndNotify({
      id: silenceAlertId(s.key_id, new Date(s.last_used_at)), tenant_id: s.tenant_id,
      title: `Sensor silent: no events from ${label} for ${s.minutes} minutes`,
      severity: "high", agent: "Guardian", status: "open",
      summary: `Legion has received nothing from the sensor using ${label} since ${new Date(s.last_used_at).toISOString()}. `
        + "The Wazuh manager may be down, unable to reach Legion, or its integration may be failing. Events it could not deliver "
        + "are kept in its spool and will arrive when it reconnects. This alert resolves itself when the sensor sends again.",
      confidence: 90, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null,
      source: "legion-monitor",
    }, { realtime: opts.realtimeFrame });
    if (alert) report.raised++;
  }

  // The sensor is back: resolve its open silence alerts. Their id encodes the
  // quiet moment, so a credential used after it is proof of life.
  const back = await query<{ tenant_id: string; id: string }>(
    `SELECT a.tenant_id, a.id FROM alerts a
       JOIN webhook_credentials c ON c.tenant_id = a.tenant_id
        AND a.id LIKE 'SENSOR-SILENT-' || upper(substr(encode(sha256(convert_to(c.key_id, 'UTF8')), 'hex'), 1, 12)) || '-%'
      WHERE a.source = 'legion-monitor' AND a.status <> 'resolved'
        -- The id holds the quiet moment rounded DOWN to the second, so "used
        -- again" means at or after the next whole second; otherwise the very
        -- timestamp that caused the alert would count as proof of life.
        AND c.last_used_at >= to_timestamp(split_part(a.id, '-', 4)::bigint + 1)`,
  );
  for (const r of back.rows) {
    if (await store.updateAlertStatus(r.tenant_id, r.id, "resolved")) report.resolved++;
  }
  return report;
}

let timer: NodeJS.Timeout | null = null;
export function startSensorMonitor(intervalMs: number, realtimeFrame?: (alert: Alert) => unknown): void {
  stopSensorMonitor();
  timer = setInterval(() => {
    // One instance checks at a time (the result is idempotent either way; this
    // just stops N instances doing the same scan every five minutes).
    withLeaderLock(SENSOR_CHECK_LOCK, () => checkSensors({ realtimeFrame })).catch((error) => {
      console.error("Legion: sensor check failed:", error instanceof Error ? error.message : "unknown error");
    });
  }, intervalMs);
  timer.unref();
}
export function stopSensorMonitor(): void {
  if (timer) clearInterval(timer);
  timer = null;
}
