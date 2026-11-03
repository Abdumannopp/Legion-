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
 * And the most damaging attack types, by what they leave in the logs
 * (signs: packages/agent-identity/src/skills/threats.ts):
 *
 *   ransomware          shadow copies deleted, recovery disabled, a ransom note,
 *                       or a mass of file changes on one host within minutes.
 *   mailbox_takeover    business email compromise: mail forwarded or hidden by
 *                       a new rule, an app given mailbox access, the second
 *                       factor removed, payment details changed, impersonation.
 *   phishing_execution  an Office document started a script, a macro ran, a
 *                       malicious link was clicked.
 *   supply_chain        a signature or checksum failed, a malicious package, or
 *                       a software install followed by attacker activity.
 *   slow_intrusion      cyber espionage: on one host over days, persistence
 *                       plus command-and-control, exfiltration or credential
 *                       dumping — quiet, patient, the opposite of rapid_chain.
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
import { ACTIVITY_AFTER_INSTALL, assessCoverage, readEvent, threatSigns, type ThreatCoverage, type SecurityEvent, type ThreatSign } from "@legion/agent-identity";
import { clip, manipulationSignals } from "./ai-safety.js";
import { queryAll, queryOne } from "./db/pool.js";
import { userFromLog } from "./log-fields.js";
import * as outbox from "./outbox.js";
import type { Alert, Severity } from "./types.js";

export const CORRELATION_SOURCE = "legion-correlation";
export const CAMPAIGN_RULES = [
  "rapid_chain", "wide_sweep", "swarm", "velocity", "ai_manipulation",
  "ransomware", "mailbox_takeover", "phishing_execution", "supply_chain", "slow_intrusion",
] as const;
export type CampaignRule = (typeof CAMPAIGN_RULES)[number];

export const THRESHOLDS = {
  rapid_chain: { windowMinutes: 15, techniques: 3 },
  wide_sweep: { windowMinutes: 10, targets: 5 },
  swarm: { windowMinutes: 10, sources: 10 },
  velocity: { windowMinutes: 5, alerts: 30 },
  /** File changes on one host that look like encryption in progress. */
  ransomware: { windowMinutes: 10, fileChanges: 50 },
  /** An install, then attacker activity on the same host. */
  supply_chain: { windowMinutes: 60 },
  /** Espionage: stages spread over days on one host. */
  slow_intrusion: { days: 7, minHours: 6, stages: 3 },
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

const strong = (signs: ThreatSign[], ...threats: ThreatSign["threat"][]) => signs.filter((s) => s.strong && threats.includes(s.threat));
const labels = (signs: ThreatSign[]) => [...new Set(signs.map((s) => s.label))];

/** Attack types one alert shows on its own. */
function threatDetections(alert: Alert): Detection[] {
  const signs = threatSigns(`${alert.title}\n${alert.summary}`);
  if (!signs.length) return [];
  const techniques = parentTechniques([alert.mitre_technique]);
  const host = alert.target ?? alert.source_ip ?? alert.id;
  const base = { alertCount: 1, sources: alert.source_ip ? [alert.source_ip] : [], targets: alert.target ? [alert.target] : [], techniques, minutes: 0, sourceIp: alert.source_ip, target: alert.target };
  const found: Detection[] = [];
  const ransom = strong(signs, "ransomware");
  if (ransom.length) found.push({ ...base, rule: "ransomware", subject: host, signals: labels(ransom) });
  const mailbox = strong(signs, "bec", "ai_deception");
  if (mailbox.length) {
    const account = userFromLog(alert.summary) ?? userFromLog(alert.title);
    found.push({ ...base, rule: "mailbox_takeover", subject: account ?? host, signals: labels(mailbox) });
  }
  const phish = strong(signs, "phishing");
  if (phish.length) found.push({ ...base, rule: "phishing_execution", subject: host, signals: labels(phish) });
  const supply = strong(signs, "supply_chain");
  if (supply.length) found.push({ ...base, rule: "supply_chain", subject: host, signals: labels(supply) });
  return found;
}

const FILE_CHANGE_SQL = "(integrity checksum changed|file (was )?(modified|deleted|added|created|renamed))";

/** Encryption in progress: a mass of file changes on one host within minutes. */
async function massFileChanges(tenantId: string, target: string): Promise<Detection[]> {
  const w = THRESHOLDS.ransomware;
  const row = await queryOne<{ n: number }>(
    `SELECT count(*)::int AS n FROM alerts
      WHERE tenant_id = $1 AND target = $2 AND source <> $3
        AND created_at >= now() - interval '1 day'
        AND ${EVENT_TIME} >= now() - make_interval(mins => $4)
        AND title ~* $5`,
    [tenantId, target, CORRELATION_SOURCE, w.windowMinutes, FILE_CHANGE_SQL],
  );
  const n = row?.n ?? 0;
  if (n < w.fileChanges) return [];
  return [{
    rule: "ransomware", subject: target, alertCount: n, sources: [], targets: [target], techniques: ["T1486"], minutes: w.windowMinutes,
    sourceIp: null, target, signals: [`${n} file changes in ${w.windowMinutes} minutes`],
  }];
}

/** A software install followed, on the same host, by attacker activity. */
async function installThenActivity(tenantId: string, alert: Alert): Promise<Detection[]> {
  if (!alert.target || !ACTIVITY_AFTER_INSTALL.test(`${alert.title}\n${alert.summary}`)) return [];
  const w = THRESHOLDS.supply_chain;
  const rows = await queryAll<{ id: string; title: string; summary: string }>(
    `SELECT id, title, left(summary, 2000) AS summary FROM alerts
      WHERE tenant_id = $1 AND target = $2 AND source <> $3 AND id <> $4
        AND created_at >= now() - interval '1 day'
        AND ${EVENT_TIME} >= now() - make_interval(mins => $5)
        AND ${EVENT_TIME} <= $6
      ORDER BY created_at DESC LIMIT 200`,
    [tenantId, alert.target, CORRELATION_SOURCE, alert.id, w.windowMinutes, alert.occurred_at ?? alert.created_at],
  );
  const install = rows.find((r) => threatSigns(`${r.title}\n${r.summary}`).some((s) => s.id === "software_install"));
  if (!install) return [];
  return [{
    rule: "supply_chain", subject: alert.target, alertCount: 2, sources: alert.source_ip ? [alert.source_ip] : [], targets: [alert.target],
    techniques: ["T1195", ...parentTechniques([alert.mitre_technique])], minutes: w.windowMinutes, sourceIp: alert.source_ip, target: alert.target,
    signals: [`software installed (${clip(install.title, 120)}), then: ${clip(alert.title, 120)}`],
  }];
}

const ESPIONAGE_STAGES = new Set(["persistence", "command_and_control", "exfiltration", "credential_access"]);

function stagesOf(r: { id: string; title: string; summary: string; mitre_technique: string | null }): string[] {
  const reading = readEvent({
    id: r.id, tenantId: "x", title: r.title, summary: r.summary, severity: "low", createdAt: new Date().toISOString(), source: "x",
    mitreTechniques: parentTechniques([r.mitre_technique]), ruleGroups: [],
  } as SecurityEvent);
  const stages = new Set<string>(reading.stages);
  for (const s of threatSigns(`${r.title}\n${r.summary}`)) {
    if (s.id === "credential_dumping") stages.add("credential_access");
    if (s.id === "c2_beacon") stages.add("command_and_control");
    if (s.id === "persistence") stages.add("persistence");
  }
  return [...stages];
}

/** Espionage: on one host, over days, persistence plus a way to control it or take data. */
async function slowIntrusion(tenantId: string, alert: Alert): Promise<Detection[]> {
  if (!alert.target) return [];
  const own = stagesOf({ id: alert.id, title: alert.title, summary: alert.summary, mitre_technique: alert.mitre_technique });
  if (!own.some((s) => ESPIONAGE_STAGES.has(s))) return [];
  const w = THRESHOLDS.slow_intrusion;
  const rows = await queryAll<{ id: string; t: Date; title: string; summary: string; mitre_technique: string | null; source_ip: string | null }>(
    `SELECT id, ${EVENT_TIME} AS t, title, left(summary, 2000) AS summary, mitre_technique, source_ip FROM alerts
      WHERE tenant_id = $1 AND target = $2 AND source <> $3
        AND created_at >= now() - make_interval(days => $4)
      ORDER BY created_at DESC LIMIT 2000`,
    [tenantId, alert.target, CORRELATION_SOURCE, w.days + 1],
  );
  const staged = rows.map((r) => ({ r, stages: stagesOf(r) })).filter((x) => x.stages.length);
  const stages = new Set(staged.flatMap((x) => x.stages));
  const hasPersistence = stages.has("persistence");
  const hasControl = stages.has("command_and_control") || stages.has("exfiltration") || stages.has("credential_access");
  if (!hasPersistence || !hasControl || stages.size < w.stages) return [];
  const times = staged.map((x) => new Date(x.r.t).getTime());
  const hours = (Math.max(...times) - Math.min(...times)) / 3_600_000;
  if (hours < w.minHours) return [];
  return [{
    rule: "slow_intrusion", subject: alert.target, alertCount: staged.length, sources: distinct(staged.map((x) => x.r.source_ip)),
    targets: [alert.target], techniques: parentTechniques(staged.map((x) => x.r.mitre_technique)), minutes: Math.round(hours * 60),
    sourceIp: null, target: alert.target, signals: [...stages].sort(),
  }];
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
  ransomware: "critical", mailbox_takeover: "high", phishing_execution: "high", supply_chain: "high", slow_intrusion: "critical",
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
    case "ransomware":
      return {
        title: `Ransomware activity on ${d.subject}`,
        summary: `Signs of ransomware on ${d.subject}: ${list(d.signals ?? [])}. `
          + "Ransomware deletes the way back (shadow copies, recovery) and then encrypts files; minutes matter. "
          + "Isolate the host from the network now (keep it powered on), take backups offline, and check other hosts for the same signs. Do not pay before talking to your incident responder.",
      };
    case "mailbox_takeover":
      return {
        title: `Possible mailbox takeover (business email compromise): ${d.subject}`,
        summary: `Signs that someone controls the mailbox or payments of ${d.subject}: ${list(d.signals ?? [])}. `
          + "Business email compromise ends in a payment to the attacker: a forwarding or hiding rule, an app with mailbox access, a removed second factor, or changed bank details come before it. "
          + "Reset the password, revoke sessions and app consents, remove the rule, and confirm any payment change by calling a known number — never one from the email. A familiar voice or video on a call can be synthetic.",
      };
    case "phishing_execution":
      return {
        title: `Phishing payload ran on ${d.subject}`,
        summary: `${list(d.signals ?? [])} on ${d.subject}. A document or link from a phishing message has started code. `
          + "Isolate the workstation, reset the user's password, find the message and remove it from every mailbox, and block the link or sender.",
      };
    case "supply_chain":
      return {
        title: `Possible supply-chain compromise on ${d.subject}`,
        summary: `${list(d.signals ?? [])} on ${d.subject}. Attackers who compromise a vendor, an update or a package reach every customer that trusts it. `
          + "Stop the update or package on other hosts, check the publisher's advisory, compare hashes with the vendor's, and look for the same activity elsewhere.",
      };
    case "slow_intrusion":
      return {
        title: `Long-running intrusion (possible espionage) on ${d.subject}`,
        summary: `Over ${Math.max(1, Math.round(d.minutes / 60))} hours, ${d.subject} showed ${list(d.signals ?? [])} across ${d.alertCount} alert(s). `
          + "Espionage stays quiet and patient: it sets up persistence, keeps a control channel and takes data over days. "
          + "Treat the host as compromised: preserve evidence, find the persistence and the control channel, and check which data and accounts it reached.",
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
  for (const a of fresh) {
    detections.push(...threatDetections(a));
    detections.push(...await installThenActivity(tenantId, a));
    detections.push(...await slowIntrusion(tenantId, a));
  }
  const changedHosts = distinct(fresh.filter((a) => a.target && threatSigns(a.title).some((s) => s.id === "file_change")).map((a) => a.target));
  for (const target of changedHosts) detections.push(...await massFileChanges(tenantId, target));

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

export const COVERAGE_DAYS = 7;

/**
 * For each of the seven most dangerous attack types: detected, watching (the
 * right data arrives, no sign found) or blind (the data never arrives). Read
 * from the workspace's own recent alerts; the newest 2000 at most.
 */
export async function threatCoverage(tenantId: string): Promise<{ windowDays: number; eventsAnalyzed: number; threats: ThreatCoverage[] }> {
  const rows = await queryAll<{ id: string; created_at: Date; title: string; summary: string }>(
    `SELECT id, created_at, title, left(summary, 4000) AS summary FROM alerts
      WHERE tenant_id = $1 AND source <> $2 AND created_at >= now() - make_interval(days => $3)
      ORDER BY created_at DESC LIMIT 2000`,
    [tenantId, CORRELATION_SOURCE, COVERAGE_DAYS],
  );
  const events = rows.map((r) => ({ id: r.id, createdAt: new Date(r.created_at).toISOString(), text: `${r.title}\n${r.summary}` }));
  const aiTextAttempts = events.filter((e) => manipulationSignals(e.text).length > 0).map((e) => e.id);
  return { windowDays: COVERAGE_DAYS, eventsAnalyzed: rows.length, threats: assessCoverage(events, { aiTextAttempts }) };
}
