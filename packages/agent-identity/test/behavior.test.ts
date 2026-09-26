import { randomUUID } from "node:crypto";
import request from "supertest";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { DecisionLog } from "../src/firewall/log.js";
import type { BehaviorChange, MachinePrincipal } from "../src/index.js";
import { agentWithToken, as, auditRows, bearer, makeApp, resetDb, TENANT_A, TENANT_B, type TestApp } from "./helpers.js";

let t: TestApp;
let changes: BehaviorChange[];

beforeEach(async () => {
  if (t) await t.pool.end();
  changes = [];
  t = await makeApp({ extra: { behaviorRefreshSeconds: 0, onBehaviorChange: (c) => { changes.push(c); } } });
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  t.host.add("anna", TENANT_A, "analyst");
  t.host.add("bob", TENANT_B, "admin");
  await setPolicy({
    thresholds: { warnAt: 70, blockAt: 95 }, // keep generic risk scoring out of the way; behaviour rules are under test
    toolSecurity: { slack: { channels: { C0SECOPS1: "write", C0NEWCHAN1: "write" } } },
  });
});
afterAll(async () => { await t?.pool.end(); });

async function setPolicy(policy: Record<string, unknown>) {
  const res = await request(t.app).put("/firewall/policy").set(as("alice")).send(policy);
  if (res.status !== 200) throw new Error(JSON.stringify(res.body));
}

interface Seed { action: string; surface?: string; destination?: string; resourceType?: string; sensitivity?: string; decision?: string; ruleIds?: string[] }

/** Writes history as real, chained firewall decisions with past timestamps. */
async function seed(agent: { id: string; name: string }, items: (Seed & { minutesAgo: number })[]) {
  const log = new DecisionLog(t.pool);
  for (const it of items) {
    await log.record({
      decisionId: randomUUID(), occurredAt: new Date(Date.now() - it.minutesAgo * 60_000).toISOString(),
      tenantId: TENANT_A, principalType: "ai_agent", principalId: agent.id, principalName: agent.name, ownerUserId: "alice",
      credentialId: null, tokenId: null, delegatedUser: null, delegationId: null, agentChain: [], viaMessageId: null,
      surface: it.surface ?? "api", action: it.action, permission: null, resourceType: it.resourceType ?? "alert", resourceId: null,
      sensitivity: it.sensitivity ?? "internal", destination: it.destination ?? "api:alert", decision: it.decision ?? "ALLOW",
      wouldBlock: false, mode: "enforce", riskScore: 0, riskFactors: [],
      ruleHits: (it.ruleIds ?? []).map((id) => ({ id, effect: "BLOCK", hard: true, reason: "seeded" })),
      advisor: [], policyVersion: 1, inputDigest: "0".repeat(64), inputPreview: {}, requestId: null, ip: null,
    });
  }
}

const SLACK_KNOWN = { action: "tool:slack.post_message", surface: "tool_call", resourceType: "tool:slack", destination: "slack:C0SECOPS1" };

/** Five days of a triage agent's normal work: reading alerts and posting to one channel, spread over every hour. */
async function establish(agent: { id: string; name: string }) {
  const items = Array.from({ length: 160 }, (_, i) => ({
    ...(i % 4 === 0 ? SLACK_KNOWN : { action: "alerts:read" }),
    minutesAgo: 90 + i * 43, // 43-minute steps: ~5 days, every hour of the day
  }));
  await seed(agent, items);
}

const post = (token: string, channel: string) =>
  request(t.app).post("/agent/v1/tools/authorize").set(bearer(token))
    .send({ call: { kind: "slack", operation: "post_message", channel, text: "Scan finished" } });

describe("profiles are learned from each agent's own history", () => {
  it("builds a baseline of volume, tools, resources, destinations and rates", async () => {
    const { agent } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await establish(agent);
    const res = await request(t.app).get(`/behavior/agents/${agent.id}`).set(as("anna"));
    expect(res.status).toBe(200);
    expect(res.body.profile).toMatchObject({ established: true, events: 160, peers: [] });
    expect(res.body.profile.topActions).toEqual([["alerts:read", 120], ["tool:slack.post_message", 40]]);
    expect(res.body.profile.externalDestinations).toEqual(["slack:C0SECOPS1"]);
    expect(res.body.assessment.level).toBe("NORMAL");
  });

  it("normal work stays NORMAL and is not slowed down", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await establish(agent);
    for (let i = 0; i < 3; i++) expect((await request(t.app).get("/agent/v1/alerts").set(bearer(token))).status).toBe(200);
    expect((await post(token, "C0SECOPS1")).status).toBe(200);
    expect((await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name)).assessment.level).toBe("NORMAL");
    expect(changes).toEqual([]);
  });
});

describe("risk-based enforcement", () => {
  it("SUSPICIOUS is recorded and raises risk, but blocks nothing", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await establish(agent);
    // An extreme burst of the agent's own normal action: a volume anomaly only.
    // (A moderate spike alone stays NORMAL by design; it needs company.)
    await seed(agent, Array.from({ length: 100 }, (_, i) => ({ action: "alerts:read", minutesAgo: 1 + (i % 50) })));
    const res = await post(token, "C0NEWCHAN1"); // even a new channel
    expect(res.status).toBe(200);
    const [state] = (await request(t.app).get("/behavior/agents").set(as("anna"))).body.agents;
    expect(state).toMatchObject({ identityId: agent.id, level: "SUSPICIOUS" });
    const d = (await t.pool.query("SELECT risk_factors FROM firewall_decisions WHERE decision_id = $1", [res.body.decisionId])).rows[0];
    expect(d.risk_factors).toContainEqual({ factor: "new behaviour while suspicious", points: 10 });
  });

  it("HIGH_RISK holds NEW unsafe behaviour; established work and reads continue", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await establish(agent);
    // Last hour: a burst of outbound HTTP posts to hosts it never used.
    await seed(agent, Array.from({ length: 40 }, (_, i) => ({
      action: "tool:http.post", surface: "tool_call", resourceType: "tool:http", destination: `url:https://h${i % 4}.example.net/x`, minutesAgo: 1 + i,
    })));
    const novel = await post(token, "C0NEWCHAN1");
    expect(novel.status).toBe(403);
    expect(novel.body.error.rules).toContain("behavior.high_risk_novel_action");

    const known = await post(token, "C0SECOPS1");
    expect(known.status).toBe(200); // its usual channel still works
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(token))).status).toBe(200);

    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ identityId: agent.id, from: "NORMAL", to: "HIGH_RISK", autoSuspended: false });
    expect(changes[0]!.assessment.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["tools.new_unsafe", "destinations.many_new", "volume.spike"]));
  });

  it("CRITICAL contains every unsafe action; reads continue", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await establish(agent);
    const rules = ["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"];
    await seed(agent, Array.from({ length: 12 }, (_, i) => ({ action: "tool:database.select", decision: "BLOCK", ruleIds: [rules[i % 4]!], minutesAgo: 1 + i })));
    const res = await post(token, "C0SECOPS1"); // even its established action
    expect(res.status).toBe(403);
    expect(res.body.error.rules).toContain("behavior.critical_containment");
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(token))).status).toBe(200);
    expect(changes.at(-1)).toMatchObject({ to: "CRITICAL", autoSuspended: false });
  });

  it("automatic suspension on CRITICAL is opt-in, and recorded", async () => {
    await setPolicy({ behavior: { autoSuspendOnCritical: true }, toolSecurity: { slack: { channels: { C0SECOPS1: "write" } } } });
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    const rules = ["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"];
    await seed(agent, Array.from({ length: 12 }, (_, i) => ({ action: "tool:database.select", decision: "BLOCK", ruleIds: [rules[i % 4]!], minutesAgo: 1 + i })));
    await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    expect(changes.at(-1)).toMatchObject({ to: "CRITICAL", autoSuspended: true });
    const id = (await request(t.app).get(`/agents/${agent.id}`).set(as("alice"))).body.identity;
    expect(id.status).toBe("suspended");
    expect(id.statusReason).toMatch(/^Behaviour CRITICAL/);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(token))).status).toBe(401);
    const [audit] = await auditRows(t.pool, "action = 'identity.suspended'");
    expect(audit).toMatchObject({ principal_type: "external_system", principal_id: "legion-behavior-monitor" });
    const kinds = (await t.identity.behavior.events(TENANT_A, { identityId: agent.id })).map((e) => e.kind);
    expect(kinds).toEqual(["auto_suspended", "level_change"]);
    // Through the kill switch: same effect as an administrator's suspension.
    const [event] = await t.identity.killSwitch.events(TENANT_A, { identityId: agent.id });
    expect(event).toMatchObject({ kind: "agent_auto_suspended", severity: "high", compromise: "suspected", actorId: "legion-behavior-monitor" });
    expect((await t.pool.query("SELECT count(*)::int AS n FROM security_notifications WHERE $1 = ANY(event_ids)", [event!.eventId])).rows[0].n).toBe(1);
  });

  it("a brand-new agent doing new things is not treated as an attack", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await seed(agent, Array.from({ length: 30 }, (_, i) => ({ ...SLACK_KNOWN, destination: `slack:C0CH${String(i).padStart(5, "0")}`, minutesAgo: 1 + i })));
    expect((await post(token, "C0NEWCHAN1")).status).toBe(200);
    const { assessment } = await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    expect(assessment.established).toBe(false);
    expect(assessment.score).toBeLessThan(60);
  });

  it("if behaviour cannot be assessed, decisions continue with a visible warning", async () => {
    const { token } = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    await t.pool.query("ALTER TABLE agent_behavior_state RENAME TO agent_behavior_state_gone");
    try {
      const res = await request(t.app).get("/agent/v1/alerts").set(bearer(token));
      expect(res.status).toBe(200);
      const { rows } = await t.pool.query("SELECT rule_hits FROM firewall_decisions ORDER BY seq DESC LIMIT 1");
      expect(rows[0].rule_hits).toContainEqual(expect.objectContaining({ id: "behavior.unavailable", effect: "WARN" }));
    } finally {
      await t.pool.query("ALTER TABLE agent_behavior_state_gone RENAME TO agent_behavior_state");
    }
  });
});

describe("review", () => {
  async function highRisk() {
    const a = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    await establish(a.agent);
    await seed(a.agent, Array.from({ length: 40 }, (_, i) => ({
      action: "tool:http.post", surface: "tool_call", resourceType: "tool:http", destination: `url:https://h${i % 4}.example.net/x`, minutesAgo: 1 + i,
    })));
    await t.identity.behavior.refresh(TENANT_A, a.agent.id, a.agent.name);
    return a;
  }
  const ack = (id: string, body: Record<string, unknown>, user = "alice") =>
    request(t.app).post(`/behavior/agents/${id}/acknowledge`).set(as(user)).send(body);

  it("only administrators, with a reason, can acknowledge", async () => {
    const { agent, token } = await highRisk();
    expect((await ack(agent.id, { reason: "Reviewed, fine.", learn: true }, "anna")).status).toBe(403);
    expect((await ack(agent.id, { reason: "ok", learn: true })).status).toBe(400);
    expect((await request(t.app).post(`/behavior/agents/${agent.id}/acknowledge`).set(bearer(token)).send({ reason: "trust me, all good", learn: true })).status).toBe(403);
  });

  it("learn: the reviewed activity becomes part of the agent's normal role", async () => {
    const { agent } = await highRisk();
    const res = await ack(agent.id, { reason: "New integration with the partner webhook service, approved in CHG-1182.", learn: true });
    expect(res.body).toMatchObject({ level: "NORMAL", learned: true });
    const { profile, assessment } = await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    expect(assessment.level).toBe("NORMAL");
    expect(profile.actions["tool:http.post"]).toBe(40);
    const [audit] = await auditRows(t.pool, "action = 'behavior.acknowledged'");
    expect(audit).toMatchObject({ principal_id: "alice", resource_id: agent.id });
  });

  it("exclude: the reviewed activity is kept out of the baseline", async () => {
    const { agent } = await highRisk();
    await ack(agent.id, { reason: "Compromised prompt, credentials rotated; not its role.", learn: false });
    const { profile, assessment } = await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    expect(assessment.level).toBe("NORMAL"); // window restarted
    expect(profile.actions["tool:http.post"]).toBeUndefined();
    const kinds = (await t.identity.behavior.events(TENANT_A, { identityId: agent.id })).map((e) => `${e.kind}:${e.toLevel}`);
    expect(kinds).toEqual(["acknowledged:NORMAL", "level_change:HIGH_RISK"]);
  });
});

describe("records and visibility", () => {
  it("a level change is recorded once, however often or concurrently it is assessed", async () => {
    const { agent } = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    const rules = ["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"];
    await seed(agent, Array.from({ length: 12 }, (_, i) => ({ action: "x", decision: "BLOCK", ruleIds: [rules[i % 4]!], minutesAgo: 1 + i })));
    await Promise.all(Array.from({ length: 8 }, () => t.identity.behavior.refresh(TENANT_A, agent.id, agent.name)));
    await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    const events = await t.identity.behavior.events(TENANT_A, { identityId: agent.id });
    expect(events.filter((e) => e.kind === "level_change")).toHaveLength(1);
    await vi.waitFor(() => expect(changes).toHaveLength(1));
  });

  it("the event log is append-only and tamper-evident", async () => {
    const { agent } = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    await seed(agent, Array.from({ length: 12 }, (_, i) => ({ action: "x", decision: "BLOCK", ruleIds: [["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"][i % 4]!], minutesAgo: 1 + i })));
    await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    expect((await request(t.app).get("/behavior/events/verify").set(as("alice"))).body).toMatchObject({ ok: true, rows: 1 });
    await expect(t.pool.query("UPDATE agent_behavior_events SET to_level = 'NORMAL'")).rejects.toThrow(/append-only/);
    await t.pool.query("ALTER TABLE agent_behavior_events DISABLE TRIGGER agent_behavior_events_no_update");
    await t.pool.query("UPDATE agent_behavior_events SET to_level = 'NORMAL'");
    await t.pool.query("ALTER TABLE agent_behavior_events ENABLE TRIGGER agent_behavior_events_no_update");
    expect((await request(t.app).get("/behavior/events/verify").set(as("alice"))).body.ok).toBe(false);
  });

  it("a sweep reassesses active agents without waiting for traffic", async () => {
    const { agent } = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    await seed(agent, Array.from({ length: 12 }, (_, i) => ({ action: "x", decision: "BLOCK", ruleIds: [["sql.foreign_tenant", "egress.internal_address", "shell.denied_command", "db.protected_table"][i % 4]!], minutesAgo: 1 + i })));
    const res = await request(t.app).post("/behavior/sweep").set(as("alice"));
    expect(res.body.agents).toContainEqual({ identityId: agent.id, level: "CRITICAL" });
    expect((await request(t.app).post("/behavior/sweep").set(as("anna"))).status).toBe(403);
  });

  it("is per tenant, for staff only", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    await t.identity.behavior.refresh(TENANT_A, agent.id, agent.name);
    expect((await request(t.app).get("/behavior/agents").set(as("anna"))).body.agents).toHaveLength(1);
    expect((await request(t.app).get("/behavior/agents").set(as("bob"))).body.agents).toHaveLength(0);
    expect((await request(t.app).get(`/behavior/agents/${agent.id}`).set(as("bob"))).status).toBe(404);
    expect((await request(t.app).get("/behavior/agents").set(bearer(token))).status).toBe(403);
    const who = (await request(t.app).get("/agent/v1/whoami").set(bearer(token))).body.principal as MachinePrincipal;
    expect(who.id).toBe(agent.id);
  });
});
