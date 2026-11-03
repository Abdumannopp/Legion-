import net from "node:net";
import { z } from "zod";
import { localIpFacts, readEvent, type EventReading } from "../knowledge.js";
import { proposedActionSchema, riskLevel, untrustedSummarySchema, type SecurityEvent, type SkillDefinition } from "../types.js";
import { assemblyOf, clip, isoMinusHours, levelOf, propose } from "./common.js";

/*
 * Sentinel: who is signing in, from where, and does it look like somebody
 * else is using the account. Most intrusions, on servers and on exchanges
 * alike, start with a stolen or guessed credential, so the account is the
 * thing to watch. Rule-based and traceable to fields in the events.
 */

const MANY_SOURCES = 3;
const FAILURES_BEFORE_SUCCESS = 3;
const SPRAY_USERS = 5;

const input = z.strictObject({
  windowHours: z.number().int().min(1).max(168).default(24),
  limit: z.number().int().min(1).max(1_000).default(500),
});

const account = z.strictObject({
  user: z.string(),
  riskLevel,
  score: z.number().int().min(0).max(100),
  patterns: z.array(z.string()),
  reasons: z.array(z.string()),
  sourceIps: z.array(z.string()).max(20),
  eventIds: z.array(z.string()).max(50),
  firstSeen: z.string(),
  lastSeen: z.string(),
});

const source = z.strictObject({
  sourceIp: z.string(),
  riskLevel,
  score: z.number().int().min(0).max(100),
  usersTargeted: z.number().int(),
  failedAuthentications: z.number().int(),
  patterns: z.array(z.string()),
  reasons: z.array(z.string()),
  eventIds: z.array(z.string()).max(50),
});

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  eventsAnalyzed: z.number().int(),
  accounts: z.array(account).max(50),
  sources: z.array(source).max(50),
  overallRisk: riskLevel,
  proposedActions: z.array(proposedActionSchema).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

interface Item { event: SecurityEvent; reading: EventReading }

const has = (i: Item, signal: string) => i.reading.signals.some((s) => s.id === signal);
const hasTechnique = (i: Item, ...ids: string[]) => i.event.mitreTechniques.some((t) => ids.includes(t.split(".")[0]!));
const byTime = (a: Item, b: Item) => a.event.createdAt.localeCompare(b.event.createdAt);

export const accountActivityWatch: SkillDefinition<Input, Output> = {
  name: "account_activity_watch",
  agent: "Sentinel",
  title: "Account Activity Watch",
  description: "Watches sign-ins and account changes for signs that an account is being used by someone else: a login after repeated failures, one account used from many addresses, one address trying many accounts (password spraying), and new privileges or accounts right after a login.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:security_events"],
  auditEvents: ["skill.invoke"],
  example: { windowHours: 24 },
  limitations: [
    "It only sees sign-ins that reach Legion as events with a user and an address; an application that does not log sign-ins is invisible to it.",
    "A VPN, a mobile network or shared office address makes one person look like several sources. Treat patterns as leads, not proof.",
    "Event timestamps are in the sensor's time; it does not judge 'unusual hours' because it does not know the user's time zone.",
    "Addresses in logs can be forged by a sender who controls the log text. Check before acting on one.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowHours);
    const events = await ctx.data.securityEvents({ since: from, until: to, limit: q.limit });
    const items: Item[] = events.map((event) => ({ event, reading: readEvent(event) })).sort(byTime);

    // ---- per account ------------------------------------------------------
    const perUser = new Map<string, { label: string; items: Item[] }>();
    for (const i of items) {
      const u = i.event.user?.trim();
      if (!u) continue;
      const key = u.toLowerCase();
      const entry = perUser.get(key) ?? { label: clip(u, 120), items: [] };
      entry.items.push(i);
      perUser.set(key, entry);
    }

    const accounts: Output["accounts"] = [];
    for (const { label, items: list } of perUser.values()) {
      const failures = list.filter((i) => has(i, "failed_authentication"));
      const firstFailure = failures[0]?.event.createdAt;
      const success = firstFailure ? list.find((i) => i.event.createdAt > firstFailure && has(i, "successful_login")) : undefined;
      const sources = [...new Set(list.map((i) => i.event.sourceIp).filter((x): x is string => !!x))];
      const afterLogin = (pred: (i: Item) => boolean) => {
        const login = list.find((i) => has(i, "successful_login"));
        return login ? list.some((i) => i.event.createdAt >= login.event.createdAt && pred(i)) : false;
      };
      const privileged = afterLogin((i) => has(i, "privilege_use") || hasTechnique(i, "T1548", "T1068"));
      const changed = list.some((i) => has(i, "account_created") || hasTechnique(i, "T1136", "T1098"));

      const patterns: string[] = [];
      const reasons: string[] = [];
      let score = 0;
      if (failures.length >= FAILURES_BEFORE_SUCCESS && success) {
        patterns.push("success_after_failures");
        reasons.push(`${failures.length} failed sign-ins were followed by a successful one (${success.event.id}); the password may have been guessed.`);
        score += 35;
      } else if (failures.length >= 10) {
        patterns.push("brute_force");
        reasons.push(`${failures.length} failed sign-ins in ${q.windowHours} hours.`);
        score += 20;
      }
      if (sources.length >= MANY_SOURCES) {
        patterns.push("many_sources");
        reasons.push(`The account appears from ${sources.length} different addresses.`);
        score += 20;
      }
      if (privileged) {
        patterns.push("privilege_after_login");
        reasons.push("Privilege use or escalation followed a successful login.");
        score += 25;
      }
      if (changed) {
        patterns.push("account_change");
        reasons.push("An account was created or changed; confirm an administrator did it.");
        score += 15;
      }
      if (!patterns.length) continue;
      score = Math.min(100, score + (list.some((i) => i.event.severity === "critical" || i.event.severity === "high") ? 10 : 0));
      accounts.push({
        user: label, riskLevel: levelOf(score), score, patterns, reasons,
        sourceIps: sources.slice(0, 20), eventIds: list.map((i) => i.event.id).slice(0, 50),
        firstSeen: list[0]!.event.createdAt, lastSeen: list[list.length - 1]!.event.createdAt,
      });
    }
    accounts.sort((a, b) => b.score - a.score);

    // ---- per source address: one address, many accounts -----------------------
    const perIp = new Map<string, Item[]>();
    for (const i of items) {
      const ip = i.event.sourceIp;
      if (!ip || !has(i, "failed_authentication")) continue;
      perIp.set(ip, [...(perIp.get(ip) ?? []), i]);
    }
    const sources: Output["sources"] = [];
    for (const [ip, list] of perIp) {
      const users = new Set(list.map((i) => i.event.user?.trim().toLowerCase()).filter(Boolean));
      if (users.size < SPRAY_USERS) continue;
      const score = Math.min(100, 40 + 3 * (users.size - SPRAY_USERS) + (list.length >= 20 ? 10 : 0));
      sources.push({
        sourceIp: clip(ip, 100), riskLevel: levelOf(score), score, usersTargeted: users.size, failedAuthentications: list.length,
        patterns: ["password_spraying"],
        reasons: [`${users.size} different accounts failed to sign in from this address (${list.length} failures): consistent with password spraying.`],
        eventIds: list.map((i) => i.event.id).slice(0, 50),
      });
    }
    sources.sort((a, b) => b.score - a.score);

    // ---- recommendations: never executed ----------------------------------------
    const topAccounts = accounts.filter((a) => a.score >= 50).slice(0, 5);
    const topSources = sources.slice(0, 5);
    const involved = new Set([...topAccounts.flatMap((a) => a.eventIds), ...topSources.flatMap((s) => s.eventIds)]);
    const assembly = assemblyOf(events.filter((e) => involved.has(e.id)));
    const proposedActions: Output["proposedActions"] = [
      ...topAccounts.map((a) => propose(assembly, {
        action: "reset_credentials", humanOnly: true, permission: null, destructive: false,
        description: `Reset the password and revoke active sessions for account ${a.user}; require MFA re-enrolment if it may be compromised.`,
      })),
      ...topSources.filter((s) => net.isIP(s.sourceIp) !== 0 && localIpFacts(s.sourceIp).length === 0).map((s) => propose(assembly, {
        action: "block_source_ip", humanOnly: true, permission: null, destructive: false,
        description: `Block ${s.sourceIp} (Dashboard → Defense, or the perimeter firewall) while the accounts it tried are checked.`,
      })),
    ];

    const top = Math.max(0, ...accounts.map((a) => a.score), ...sources.map((s) => s.score));
    return {
      window: { from, to },
      eventsAnalyzed: events.length,
      accounts: accounts.slice(0, 50),
      sources: sources.slice(0, 50),
      overallRisk: levelOf(top),
      proposedActions,
      untrusted: ctx.untrusted(),
      limitations: [...accountActivityWatch.limitations],
    };
  },
};
