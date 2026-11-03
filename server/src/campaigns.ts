/**
 * Attack campaigns: recognising automated and AI-driven attacks by their shape.
 *
 * A single alert rarely says "this is an AI agent attacking you". What gives
 * automation away is tempo and breadth, which no single alert shows:
 *
 *   rapid_chain      one address works through several different techniques
 *                    within minutes (recon → access → execution …). People
 *                    attacking by hand take hours; tools and AI agents do not.
 *   wide_sweep       one address hits many hosts within minutes.
 *   swarm            many addresses converge on one host at once (botnets,
 *                    distributed credential stuffing, AI agent swarms).
 *   velocity         one address produces a burst of alerts.
 *   ai_manipulation  an event carries text written to steer an AI reading the
 *                    logs ("ignore previous instructions", "mark as benign",
 *                    hidden characters) — an attacker who expects AI triage.
 *
 * Each detection becomes one campaign row and ONE alert (source
 * 'legion-correlation', agent 'Hunter'), however many further events it
 * absorbs. A campaign silent for QUIET_MS is over; activity after that starts a
 * new one. Correlation alerts are never correlated themselves.
 *
 * Detection runs after ingestion and never blocks or fails it (ingest.ts).
 * The thresholds below are deliberately conservative: a correlation alert that
 * cries wolf is worse than none.
 */
import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { clip, manipulationSignals } from "./ai-safety.js";
import { queryAll, queryOne } from "./db/pool.js";
import * as outbox from "./outbox.js";
import type { Alert, Severity } from "./types.js";

export const CORRELATION_SOURCE = "legion-correlation";
export type CampaignRule = "rapid_chain" | "wide_sweep" | "swarm" | "velocity" | "ai_manipulation";

export const THRESHOLDS = {
  rapid_chain: { windowMinutes: 15, techniques: 3 },
  wide_sweep: { windowMinutes: 10, targets: 5 },
  swarm: { windowMinutes: 10, sources: 10 },
  velocity: { windowMinutes: 5, alerts: 30 },
} as const;
/** A campaign with no new activity for this long is over. */
export const QUIET_MS = 60 * 60_000;
const MAX_LIST = 50;

export interface Campaign {
  tenant_id: string;
  id: string;
  rule: CampaignRule;
  subject: string;
  status: "active" | "closed";
  first_seen: string;
  last_seen: string;
  alert_count: number;
  sources: string[];
  targets: string[];
  techniques: string[];
  alert_id: string | null;
}

interface Detection {
  rule: CampaignRule;
  subject: string;
  alertCount: number;
  sources: string[];
  targets: string[];
  techniques: string[];
  minutes: number;
  /** For the announcing alert's source_ip / target. */
  sourceIp: string | null;
  target: string | null;
  signals?: string[];
}

/** "T1110.001, T1021" → ["T1110", "T1021"]: different stages, not sub-variants. */
export function parentTechniques(values: Array<string | null>): string[] {
  const out = new Set<string>();
  for (const v of values) {
    for (const part of String(v ?? "").split(/[,\s]+/)) {
      const m = /^(T\d{4})(?:\.\d{3})?$/.exec(part.trim());
      if (m) out.add(m[1]!);
    }
  }
  return [...out].sort();
}

// Event time where the sensor gave one (spooled events re-sent after an outage
// must not look like a burst), arrival time otherwise. The created_at bound
// keeps the scan on the index.
const EVENT_TIME = "coalesce(occurred_at, created_at)";

async function bySource(tenantId: string, ip: string): Promise<Detection[]> {
  const longest = Math.max(THRESHOLDS.rapid_chain.windowMinutes, THRESHOLDS.wide_sweep.windowMinutes, THRESHOLDS.velocity.windowMinutes);
  const rows = await queryAll<{ t: Date; target: string | null; mitre_technique: string | null }>(
    `SELECT ${EVENT_TIME} AS t, target, mitre_technique
       FROM alerts
      WHERE tenant_id = $1 AND source_ip = $2 AND source <> $3
        AND created_at >= now() - interval '1 day'
        AND ${EVENT_TIME} >= now() - make_interval(mins => $4)
      ORDER BY created_at DESC
      LIMIT 5000`,
    [tenantId, ip, CORRELATION_SOURCE, longest],
  );
  const now = Date.now();
  const within = (min: number) => rows.filter((r) => now - new Date(r.t).getTime() <= min * 60_000);
  const found: Detection[] = [];

  const chain = within(THRESHOLDS.rapid_chain.windowMinutes);
  const techniques = parentTechniques(chain.map((r) => r.mitre_technique));
  if (techniques.length >= THRESHOLDS.rapid_chain.techniques) {
    found.push({
      rule: "rapid_chain", subject: ip, alertCount: chain.length, sources: [ip],
      targets: distinct(chain.map((r) => r.target)), techniques, minutes: spanMinutes(chain), sourceIp: ip, target: null,
    });
  }
  const sweep = within(THRESHOLDS.wide_sweep.windowMinutes);
  const targets = distinct(sweep.map((r) => r.target));
  if (targets.length >= THRESHOLDS.wide_sweep.targets) {
    found.push({
      rule: "wide_sweep", subject: ip, alertCount: sweep.length, sources: [ip], targets,
      techniques: parentTechniques(sweep.map((r) => r.mitre_technique)), minutes: spanMinutes(sweep), sourceIp: ip, target: null,
    });
  }
  const burst = within(THRESHOLDS.velocity.windowMinutes);
  if (burst.length >= THRESHOLDS.velocity.alerts) {
    found.push({
      rule: "velocity", subject: ip, alertCount: burst.length, sources: [ip], targets: distinct(burst.map((r) => r.target)),
      techniques: parentTechniques(burst.map((r) => r.mitre_technique)), minutes: spanMinutes(burst), sourceIp: ip, target: null,
    });
  }
  return found;
}

async function byTarget(tenantId: string, target: string): Promise<Detection[]> {
  const rows = await queryAll<{ t: Date; source_ip: string; mitre_technique: string | null }>(
    `SELECT ${EVENT_TIME} AS t, source_ip, mitre_technique
       FROM alerts
      WHERE tenant_id = $1 AND target = $2 AND source <> $3 AND source_ip IS NOT NULL
        AND created_at >= now() - interval '1 day'
        AND ${EVENT_TIME} >= now() - make_interval(mins => $4)
      ORDER BY created_at DESC
      LIMIT 5000`,
    [tenantId, target, CORRELATION_SOURCE, THRESHOLDS.swarm.windowMinutes],
  );
  const sources = distinct(rows.map((r) => r.source_ip));
  if (sources.length < THRESHOLDS.swarm.sources) return [];
  return [{
    rule: "swarm", subject: target, alertCount: rows.length, sources, targets: [target],
    techniques: parentTechniques(rows.map((r) => r.mitre_technique)), minutes: spanMinutes(rows), sourceIp: null, target,
  }];
}

function manipulation(alert: Alert): Detection | null {
  const signals = manipulationSignals(`${alert.title}\n${alert.summary}`);
  if (!signals.length) return null;
  const subject = alert.source_ip ?? alert.target ?? alert.id;
  return {
    rule: "ai_manipulation", subject, alertCount: 1, sources: alert.source_ip ? [alert.source_ip] : [],
    targets: alert.target ? [alert.target] : [], techniques: parentTechniques([alert.mitre_technique]), minutes: 0,
    sourceIp: alert.source_ip, target: alert.target, signals,
  };
}

function distinct(values: Array<string | null>): string[] {
  return [...new Set(values.filter((v): v is string => typeof v === "string" && v.length > 0))].sort();
}
function spanMinutes(rows: Array<{ t: Date }>): number {
  if (rows.length < 2) return 1;
  const ts = rows.map((r) => new Date(r.t).getTime());
  return Math.max(1, Math.ceil((Math.max(...ts) - Math.min(...ts)) / 60_000));
}
const list = (xs: string[], n = 8) => (xs.length > n ? `${xs.slice(0, n).join(", ")} and ${xs.length - n} more` : xs.join(", "));

const SEVERITY: Record<CampaignRule, Severity> = {
  rapid_chain: "critical", swarm: "critical", wide_sweep: "high", velocity: "high", ai_manipulation: "high",
};

/** The announcing alert's wording. English, like every sensor alert title. */
export function describe(d: Detection): { title: string; summary: string } {
  switch (d.rule) {
    case "rapid_chain":
      return {
        title: `Automated attack: ${d.subject} used ${d.techniques.length} techniques in ${d.minutes} min`,
        summary: `One address (${d.subject}) worked through ${d.techniques.length} different attack techniques (${list(d.techniques)}) `
          + `against ${d.targets.length || "unknown"} host(s)${d.targets.length ? ` (${list(d.targets)})` : ""} within ${d.minutes} minute(s), across ${d.alertCount} alert(s). `
          + "People attacking by hand rarely move between stages this fast; this pace is typical of automated tools and AI-driven attack agents. "
          + "Treat it as one attack in progress: contain the source and check the hosts it reached.",
      };
    case "wide_sweep":
      return {
        title: `Automated sweep: ${d.subject} hit ${d.targets.length} hosts in ${d.minutes} min`,
        summary: `One address (${d.subject}) triggered alerts on ${d.targets.length} different hosts (${list(d.targets)}) within ${d.minutes} minute(s). `
          + "Touching this many machines this quickly is the signature of an automated scanner or attack agent looking for a way in.",
      };
    case "swarm":
      return {
        title: `Coordinated attack on ${d.subject}: ${d.sources.length} addresses in ${d.minutes} min`,
        summary: `${d.sources.length} different addresses (${list(d.sources)}) attacked ${d.subject} within ${d.minutes} minute(s). `
          + "Many sources converging on one host at once is how botnets, distributed password guessing and automated attack swarms work; "
          + "blocking one address will not stop it — protect the host (lock the targeted accounts, require MFA, restrict access).",
      };
    case "velocity":
      return {
        title: `Attack burst: ${d.alertCount} alerts from ${d.subject} in ${d.minutes} min`,
        summary: `One address (${d.subject}) produced ${d.alertCount} alerts within ${d.minutes} minute(s)`
          + `${d.targets.length ? ` against ${list(d.targets)}` : ""}. A human cannot generate activity at this rate; it is automated.`,
      };
    case "ai_manipulation":
      return {
        title: `Attempt to manipulate AI analysis${d.sourceIp ? ` from ${d.sourceIp}` : ""}`,
        summary: `An event contains text written to instruct an AI system rather than a person (${(d.signals ?? []).join(", ")}). `
          + "Attackers plant such text in usernames, URLs, user agents or file names, expecting an AI to triage the logs and be told to ignore them. "
          + "Legion does not follow instructions found in alert data, but the attempt itself shows a deliberate attacker who knows AI is watching.",
      };
  }
}

/**
 * Records a detection: a new campaign (with its alert) or an update of the
 * active one. Returns the campaign when it is NEW, null when it already existed.
 */
async function record(tenantId: string, d: Detection, realtime?: (a: Alert) => unknown): Promise<Campaign | null> {
  // Over since QUIET_MS: close it, so this activity starts a new campaign.
  await queryOne(
    `UPDATE attack_campaigns SET status = 'closed'
      WHERE tenant_id = $1 AND rule = $2 AND subject = $3 AND status = 'active' AND last_seen < now() - make_interval(secs => $4)`,
    [tenantId, d.rule, d.subject, QUIET_MS / 1000],
  );
  const id = `CMP-${randomBytes(8).toString("hex").toUpperCase()}`;
  const row = await queryOne<Campaign & { inserted: boolean }>(
    `INSERT INTO attack_campaigns (tenant_id, id, rule, subject, alert_count, sources, targets, techniques)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (tenant_id, rule, subject) WHERE status = 'active' DO UPDATE SET
       last_seen   = now(),
       alert_count = GREATEST(attack_campaigns.alert_count, EXCLUDED.alert_count),
       sources     = (SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{}') FROM unnest(attack_campaigns.sources || EXCLUDED.sources) x)[1:${MAX_LIST}],
       targets     = (SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{}') FROM unnest(attack_campaigns.targets || EXCLUDED.targets) x)[1:${MAX_LIST}],
       techniques  = (SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{}') FROM unnest(attack_campaigns.techniques || EXCLUDED.techniques) x)[1:${MAX_LIST}]
     RETURNING *, (xmax = 0) AS inserted`,
    [tenantId, id, d.rule, clip(d.subject, 255), d.alertCount, d.sources.slice(0, MAX_LIST), d.targets.slice(0, MAX_LIST).map((t) => clip(t, 255)), d.techniques.slice(0, MAX_LIST)],
  );
  if (!row?.inserted) return null;

  const { title, summary } = describe(d);
  const alert = await outbox.insertAlertAndNotify({
    id: row.id, tenant_id: tenantId, title: clip(title, 300), severity: SEVERITY[d.rule], agent: "Hunter", status: "open",
    summary: clip(summary, 4000), confidence: d.rule === "ai_manipulation" ? 80 : 90, ai_explanation: null, explained_at: null,
    source_ip: d.sourceIp, target: d.target ? clip(d.target, 255) : null,
    mitre_technique: d.techniques.length ? clip(d.techniques.join(", "), 200) : null,
    source: CORRELATION_SOURCE, occurred_at: null,
  }, { realtime });
  await queryOne("UPDATE attack_campaigns SET alert_id = $3 WHERE tenant_id = $1 AND id = $2", [tenantId, row.id, alert?.id ?? row.id]);
  const { inserted: _inserted, ...campaign } = row;
  return { ...campaign, alert_id: alert?.id ?? row.id };
}

/**
 * Looks at what the newly stored alerts change. Returns the campaigns that are
 * NEW (each already announced by its own alert), for the automatic response.
 */
export async function correlate(tenantId: string, alerts: Alert[], opts: { realtime?: (a: Alert) => unknown } = {}): Promise<Campaign[]> {
  const fresh = alerts.filter((a) => a.source !== CORRELATION_SOURCE);
  if (!fresh.length) return [];
  const detections: Detection[] = [];
  for (const ip of distinct(fresh.map((a) => a.source_ip)).filter((ip) => isIP(ip) !== 0)) detections.push(...await bySource(tenantId, ip));
  for (const target of distinct(fresh.map((a) => a.target))) detections.push(...await byTarget(tenantId, target));
  for (const a of fresh) { const m = manipulation(a); if (m) detections.push(m); }

  const created: Campaign[] = [];
  for (const d of detections) {
    const c = await record(tenantId, d, opts.realtime);
    if (c) created.push(c);
  }
  return created;
}

/** The workspace's campaigns, newest activity first. */
export async function listCampaigns(tenantId: string, limit = 100): Promise<Campaign[]> {
  return queryAll<Campaign>(
    `SELECT tenant_id, id, rule, subject,
            CASE WHEN status = 'active' AND last_seen < now() - make_interval(secs => $3) THEN 'closed' ELSE status END AS status,
            first_seen, last_seen, alert_count, sources, targets, techniques, alert_id
       FROM attack_campaigns WHERE tenant_id = $1 ORDER BY last_seen DESC LIMIT $2`,
    [tenantId, Math.min(Math.max(1, limit), 500), QUIET_MS / 1000],
  );
}
