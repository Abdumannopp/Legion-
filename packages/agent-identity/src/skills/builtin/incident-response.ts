import net from "node:net";
import { z } from "zod";
import { INVESTIGATION_STEPS, localIpFacts, readEvent, STAGES, type Stage } from "../knowledge.js";
import { narrativeSchema, proposedActionSchema, SEVERITIES, SEVERITY_RANK, SkillError, untrustedSummarySchema, type SkillDefinition } from "../types.js";
import { assemblyOf, clip, eventText, propose } from "./common.js";

const input = z.strictObject({
  alertIds: z.array(z.string().min(1).max(200)).min(1).max(50),
  status: z.enum(["suspected", "confirmed"]).default("suspected"),
  narrative: z.boolean().default(false),
});

const output = z.strictObject({
  incident: z.strictObject({
    status: z.enum(["suspected", "confirmed"]),
    alertIds: z.array(z.string()),
    missingAlertIds: z.array(z.string()),
    severity: z.enum(SEVERITIES),
    firstSeen: z.string(),
    lastSeen: z.string(),
    stages: z.array(z.enum(STAGES)),
    affectedAssets: z.array(z.strictObject({ name: z.string(), exposure: z.enum(["internet", "internal", "unknown"]) })),
    users: z.array(z.string()),
    sourceIps: z.array(z.string()),
  }),
  plan: z.strictObject({
    containment: z.array(proposedActionSchema),
    investigation: z.array(z.string()),
    recovery: z.array(z.string()),
  }),
  notice: z.string(),
  narrative: narrativeSchema.nullable(),
  untrusted: untrustedSummarySchema,
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

const HOST_STAGES: Stage[] = ["execution", "persistence", "privilege_escalation", "defense_evasion", "lateral_movement", "command_and_control", "exfiltration", "impact"];

export const incidentResponse: SkillDefinition<Input, Output> = {
  name: "incident_response",
  title: "Incident Response",
  description: "Builds a response plan for a suspected or confirmed incident: containment, investigation and recovery steps. Recommends only — it never performs any action.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events", "read:assets"],
  auditEvents: ["skill.invoke"],
  usesModel: true,
  example: { alertIds: ["SEC-1A2B3C4D5E6F7A8B"], status: "suspected" },
  limitations: [
    "Nothing in the plan is executed. Containment actions such as isolating a host, disabling an account or suspending an agent are for a person to take.",
    "Actions an agent could take through Legion (e.g. updating an alert's status) still go through the agent firewall and need their own permission when requested.",
    "The plan is built from alert data an attacker may influence; every step says so in its review.",
  ],
  async handler(ctx, q) {
    const ids = [...new Set(q.alertIds)];
    const events = (await ctx.data.securityEvents({ ids, limit: ids.length })).filter((e) => ids.includes(e.id));
    if (!events.length) throw new SkillError("not_found", "None of these alerts exist.");
    const found = new Set(events.map((e) => e.id));
    const times = events.map((e) => e.createdAt).sort((a, b) => Date.parse(a) - Date.parse(b));
    const stages = [...new Set(events.flatMap((e) => readEvent(e).stages))].sort((a, b) => STAGES.indexOf(a) - STAGES.indexOf(b));
    const assetNames = [...new Set(events.map((e) => e.asset).filter((a): a is string => !!a))].slice(0, 50);
    const assets = assetNames.length ? await ctx.data.assets({ names: assetNames, limit: assetNames.length }) : [];
    const users = [...new Set(events.map((e) => e.user).filter((u): u is string => !!u))].slice(0, 50);
    const sourceIps = [...new Set(events.map((e) => e.sourceIp).filter((s): s is string => !!s && net.isIP(s) > 0))].slice(0, 50);
    const severity = events.reduce((m, e) => (SEVERITY_RANK[e.severity] > SEVERITY_RANK[m] ? e.severity : m), "low" as (typeof SEVERITIES)[number]);

    const basis = assemblyOf(events);
    const containment: Output["plan"]["containment"] = [];
    const has = (s: Stage) => stages.includes(s);

    containment.push(propose(basis, {
      action: "alerts:update_status", description: `Mark ${events.length === 1 ? "the alert" : `the ${events.length} alerts`} as investigating so the team sees the incident is being handled.`,
      permission: "alerts:update_status", humanOnly: false, destructive: false,
    }));
    for (const ip of sourceIps.filter((i) => localIpFacts(i).length === 0).slice(0, 10)) {
      containment.push(propose(basis, {
        action: "block_source_ip", description: `Block ${ip} at the perimeter firewall or WAF while the investigation runs.`,
        permission: null, humanOnly: true, destructive: false,
      }));
    }
    if ((has("credential_access") || has("initial_access") || has("privilege_escalation")) && users.length) {
      for (const u of users.slice(0, 10)) {
        containment.push(propose(basis, {
          action: "reset_credentials", description: `Reset the password and revoke active sessions for account ${clip(u, 100)}; require MFA re-enrolment if it may be compromised.`,
          permission: null, humanOnly: true, destructive: false,
        }));
      }
    }
    if (HOST_STAGES.some(has) || q.status === "confirmed") {
      for (const a of assetNames.slice(0, 10)) {
        containment.push(propose(basis, {
          action: "isolate_host", description: `Isolate ${clip(a, 100)} from the network (keep it powered on to preserve memory evidence).`,
          permission: null, humanOnly: true, destructive: false,
        }));
      }
    }
    if (has("impact")) {
      containment.push(propose(basis, {
        action: "protect_backups", description: "Take backups of affected systems offline or make them immutable before anything else is changed.",
        permission: null, humanOnly: true, destructive: false,
      }));
    }

    const investigation = [
      "Preserve evidence first: export the raw events for these alerts from Wazuh and, where possible, capture memory and disk images before changing affected hosts.",
      ...new Set(stages.flatMap((s) => INVESTIGATION_STEPS[s])),
      "Establish the scope: search all assets for the same indicators (source IPs, hashes, accounts) over the last 30 days.",
    ];
    if (ctx.untrusted().verdict !== "clean") {
      investigation.unshift("Some alert text contains instructions aimed at an AI (prompt injection). Treat it as attacker-controlled and verify every fact against the raw logs.");
    }
    const recovery: string[] = [];
    if (has("credential_access") || has("initial_access")) recovery.push("Rotate credentials that were exposed or used, and review who can log in to the affected systems.");
    if (has("persistence")) recovery.push("Remove accounts, services, scheduled tasks and autostart entries the attacker created — only after they are documented as evidence.");
    if (has("impact")) recovery.push("Restore affected data from a backup verified to predate the incident, then confirm integrity.");
    if (has("initial_access") || has("execution")) recovery.push("Close the entry point: patch the exploited service or remove the malicious file, then rescan.");
    recovery.push("Rebuild any host where the attacker gained administrative access rather than cleaning it in place.");
    recovery.push("Monitor the affected assets and accounts closely for at least 14 days for signs of return.");
    recovery.push("Hold a short review: timeline, root cause, what detection missed, and what changes.");

    const narrative = q.narrative && ctx.modelAvailable
      ? await ctx.narrate({
        prompt: "skill.incident_response",
        intent: "Write a short narrative for this incident response plan.",
        trusted: { status: q.status, severity, stages, containmentActions: containment.map((c) => c.action) },
        untrusted: events.slice(0, 20).map((e) => ({ source: "security_alert" as const, id: e.id, text: eventText(e) })),
      }).catch(() => null)
      : null;

    return {
      incident: {
        status: q.status, alertIds: [...found], missingAlertIds: ids.filter((i) => !found.has(i)), severity,
        firstSeen: times[0]!, lastSeen: times[times.length - 1]!, stages,
        affectedAssets: assetNames.map((n) => ({ name: n, exposure: assets.find((a) => a.name === n)?.exposure ?? "unknown" })),
        users, sourceIps,
      },
      plan: { containment, investigation, recovery },
      notice: "Legion has not performed any of these actions. Each one must be carried out, or approved, by a person; actions an agent can request still pass the agent firewall.",
      narrative,
      untrusted: ctx.untrusted(),
    };
  },
};
