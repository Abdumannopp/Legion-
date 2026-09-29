/**
 * Security skills, end to end: discovery, explicit assignment, every built-in
 * skill's normal result, and the controls every skill runs under
 * (authorization, tenant isolation, untrusted content, audit, fail-closed).
 * Attacks on these controls are in test/skills-redteam.test.ts.
 */
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { agentWithToken, as, bearer, TENANT_A, TENANT_B } from "./helpers.js";
import { ATTACKER_IP, FAKE_AWS_KEY, FakeData, FakeModel, skillAuditRows, skillEnv, type SkillTestEnv } from "./skills-fixtures.js";

let env: SkillTestEnv | undefined;
afterEach(async () => { await env?.t.pool.end(); env = undefined; });

const setup = async (...a: Parameters<typeof skillEnv>) => (env = await skillEnv(...a));

describe("discovery and explicit assignment", () => {
  it("people see the catalogue: eight skills, each with version, schemas, capabilities and the permissions they need", async () => {
    const e = await setup();
    const res = await request(e.t.app).get("/skills").set(as("anna"));
    expect(res.status).toBe(200);
    const byName = Object.fromEntries(res.body.skills.map((s: { name: string }) => [s.name, s]));
    expect(Object.keys(byName).sort()).toEqual([
      "ai_security_red_team", "alert_analysis", "attack_investigation", "incident_response",
      "security_reporting", "threat_detection", "threat_intelligence", "vulnerability_analysis",
    ]);
    expect(byName.threat_detection).toMatchObject({ version: "1.0.0", requiredPermissions: ["alerts:read"], capabilities: [{ name: "read:security_events", permission: "alerts:read" }] });
    expect(byName.incident_response.requiredPermissions).toEqual(["alerts:read", "assets:read"]);
    expect(byName.ai_security_red_team.requiredPermissions).toEqual(["security:self_test"]);
    for (const s of res.body.skills) {
      expect(s.inputSchema).toMatchObject({ type: "object", additionalProperties: false });
      expect(s.outputSchema).toBeTruthy();
    }
  });

  it("an agent sees and runs nothing until a person assigns a skill to it", async () => {
    const e = await setup();
    expect((await request(e.t.app).get("/agent/v1/skills").set(bearer(e.token))).body.skills).toEqual([]);
    const r = await e.invoke("threat_detection", {});
    expect(r.status).toBe(403);
    expect(r.body.error.code).toBe("not_assigned");

    expect((await e.assign("threat_detection")).status).toBe(201);
    const list = await request(e.t.app).get("/agent/v1/skills").set(bearer(e.token));
    expect(list.body.skills.map((s: { name: string }) => s.name)).toEqual(["threat_detection"]);
    expect(list.body.skills[0]).toMatchObject({ runnable: true, missingPermissions: [] });
  });

  it("assigning a skill grants no permission", async () => {
    const e = await setup({ permissions: ["alerts:read"] });
    const r = await e.assign("threat_intelligence");
    expect(r.status).toBe(201);
    expect(r.body.missingPermissions).toEqual(["intel:read"]);
    const identity = await request(e.t.app).get(`/agents/${e.agent.id}`).set(as("alice"));
    expect(identity.body.identity.permissions).toEqual(["alerts:read"]);
    const run = await e.invoke("threat_intelligence", { indicators: [{ value: ATTACKER_IP }] });
    expect(run.status).toBe(403);
    expect(run.body.error).toMatchObject({ code: "capability_missing", missing: ["read:threat_intel"] });
    expect(e.data.calls).toEqual([]); // nothing was read
  });

  it("only administrators assign; analysts and agents cannot", async () => {
    const e = await setup();
    expect((await e.assign("threat_detection", e.agent.id, "anna")).status).toBe(403);
    const byAgent = await request(e.t.app).post("/skills/assignments").set(bearer(e.token)).send({ identityId: e.agent.id, skill: "threat_detection" });
    expect(byAgent.status).toBe(403); // agents are confined to the agent API before the route is even reached
    expect(["outside_agent_api", "human_required"]).toContain(byAgent.body.error.code);
  });

  it("another organisation's administrator cannot assign skills to this tenant's agent", async () => {
    const e = await setup();
    const r = await e.assign("threat_detection", e.agent.id, "bob");
    expect(r.status).toBe(404);
    expect((await e.t.pool.query("SELECT count(*)::int AS n FROM agent_skill_assignments")).rows[0].n).toBe(0);
  });

  it("unknown or malformed skill names are refused", async () => {
    const e = await setup();
    expect((await e.assign("not_a_skill")).status).toBe(404);
    expect((await e.assign("../etc/passwd")).status).toBe(400);
    const r = await e.invoke("..%2F..%2Fadmin", {});
    expect(r.status).toBe(404);
    expect(r.body.error.code).toBe("unknown_skill");
  });

  it("an unassigned skill stops working at once", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    expect((await e.invoke("threat_detection", {})).status).toBe(200);
    const del = await request(e.t.app).delete(`/skills/assignments/${e.agent.id}/threat_detection`).set(as("alice"));
    expect(del.status).toBe(200);
    expect((await e.invoke("threat_detection", {})).body.error.code).toBe("not_assigned");
  });
});

describe("the eight skills", () => {
  it("Threat Detection groups the brute force, notices the successful login after it, and flags the poisoned alert", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    const r = await e.invoke("threat_detection", { windowHours: 24 });
    expect(r.status).toBe(200);
    const out = r.body.output;
    expect(out.eventsAnalyzed).toBe(10);
    const ipGroup = out.groups.find((g: { kind: string; key: string }) => g.kind === "source_ip" && g.key === ATTACKER_IP);
    expect(ipGroup.patterns).toEqual(expect.arrayContaining(["brute_force", "success_after_failures"]));
    expect(["high", "critical"]).toContain(ipGroup.riskLevel);
    const poisoned = out.findings.find((f: { eventId: string }) => f.eventId === "EINJ");
    expect(poisoned.patterns).toContain("ai_manipulation_attempt");
    expect(out.untrusted.flaggedIds).toContain("EINJ");
    expect(out.findings.every((f: { reasons: string[] }) => f.reasons.length > 0)).toBe(true);
    expect(["high", "critical"]).toContain(out.overallRisk);
  });

  it("Alert Analysis explains one alert: asset, user, attack type, indicators, related events, next steps", async () => {
    const e = await setup();
    await e.assign("alert_analysis");
    const r = await e.invoke("alert_analysis", { alertId: "E7" });
    expect(r.status).toBe(200);
    const out = r.body.output;
    expect(out.affected).toMatchObject({ asset: "web-01", user: "admin", sourceIp: ATTACKER_IP, assetDetails: { exposure: "internet" } });
    expect(out.stage).toBe("execution");
    expect(out.attackType).toMatch(/execution/i);
    expect(out.techniques).toEqual([{ id: "T1059", name: "Command and scripting interpreter" }]);
    expect(out.indicators).toEqual(expect.arrayContaining([{ type: "ip", value: "198.51.100.77", origin: "alert_text" }, { type: "ip", value: ATTACKER_IP, origin: "event_field" }]));
    expect(out.related.map((x: { id: string }) => x.id)).toEqual(expect.arrayContaining(["E6", "E8"]));
    expect(out.investigationSteps.length).toBeGreaterThan(2);
    expect(out.narrative).toBeNull(); // not asked for
  });

  it("Alert Analysis says 'not found' for another tenant's alert, exactly as for one that does not exist", async () => {
    const e = await setup();
    await e.assign("alert_analysis");
    const foreign = await e.invoke("alert_analysis", { alertId: "EB1" });
    const missing = await e.invoke("alert_analysis", { alertId: "NOPE" });
    expect(foreign.status).toBe(404);
    expect(foreign.body).toEqual(missing.body);
  });

  it("Incident Response recommends containment, investigation and recovery — and performs none of it", async () => {
    const e = await setup();
    await e.assign("incident_response");
    const r = await e.invoke("incident_response", { alertIds: ["E1", "E6", "E7", "E8", "MISSING"], status: "confirmed" });
    expect(r.status).toBe(200);
    const { incident, plan, notice } = r.body.output;
    expect(incident.missingAlertIds).toEqual(["MISSING"]);
    expect(incident.stages).toEqual(expect.arrayContaining(["credential_access", "initial_access", "execution", "command_and_control"]));
    const actions = Object.fromEntries(plan.containment.map((a: { action: string }) => [a.action, a]));
    expect(actions.isolate_host).toMatchObject({ humanOnly: true, executed: false, review: "confirm" });
    expect(actions.block_source_ip).toMatchObject({ humanOnly: true, executed: false });
    expect(actions.reset_credentials).toMatchObject({ humanOnly: true, executed: false });
    // The one action an agent could request still needs a person, because the plan came from external content.
    expect(actions["alerts:update_status"]).toMatchObject({ humanOnly: false, permission: "alerts:update_status", review: "confirm", executed: false });
    expect(plan.containment.every((a: { executed: boolean }) => a.executed === false)).toBe(true);
    expect(plan.investigation.length).toBeGreaterThan(3);
    expect(plan.recovery.length).toBeGreaterThan(2);
    expect(notice).toMatch(/has not performed/);
    // Nothing changed: no alert status call was made.
    expect(e.data.calls.every((c) => c.method.startsWith("list"))).toBe(true);
  });

  it("Threat Intelligence distinguishes known malicious, suspicious, unknown and known safe — and never guesses", async () => {
    const e = await setup();
    await e.assign("threat_intelligence");
    const r = await e.invoke("threat_intelligence", {
      indicators: [
        { value: ATTACKER_IP }, { value: "example.com" }, { value: "contested.example.org" }, { value: "8.8.4.4" },
        { value: "d41d8cd98f00b204e9800998ecf8427e" }, { value: "cve-2021-44228" }, { value: "10.1.2.3" },
        { value: "not an indicator!" }, { value: "999.1.1.1", type: "ip" },
      ],
    });
    expect(r.status).toBe(200);
    const out = r.body.output;
    const v = Object.fromEntries(out.results.map((x: { indicator: { value: string }; verdict: string }) => [x.indicator.value, x]));
    expect(v[ATTACKER_IP].verdict).toBe("known_malicious");
    expect(v[ATTACKER_IP].sightings.count).toBeGreaterThanOrEqual(6);
    expect(v["example.com"].verdict).toBe("known_safe");
    expect(v["contested.example.org"].verdict).toBe("suspicious");
    expect(v["contested.example.org"].reasons[0]).toMatch(/disagree/);
    expect(v["8.8.4.4"].verdict).toBe("unknown");
    expect(v["d41d8cd98f00b204e9800998ecf8427e"]).toMatchObject({ verdict: "unknown", indicator: { type: "hash" } });
    expect(v["CVE-2021-44228"]).toMatchObject({ verdict: "unknown", indicator: { type: "cve" } });
    expect(v["10.1.2.3"].localFacts[0]).toMatch(/private/);
    expect(v["10.1.2.3"].verdict).toBe("unknown"); // private is a fact, not a verdict
    expect(out.rejected.map((x: { value: string }) => x.value)).toEqual(["not an indicator!", "999.1.1.1"]);
    // The provider answered a question nobody asked; it is ignored.
    expect(v["192.0.2.99"]).toBeUndefined();
    // Its note carried an instruction: withheld.
    expect(v["198.51.100.77"]).toBeUndefined();
  });

  it("Threat Intelligence says so when no provider is configured, and answers unknown", async () => {
    const data = new FakeData();
    (data as { lookupIndicators?: unknown }).lookupIndicators = undefined;
    const e = await setup({ data });
    await e.assign("threat_intelligence");
    const r = await e.invoke("threat_intelligence", { indicators: [{ value: ATTACKER_IP }] });
    expect(r.status).toBe(200);
    expect(r.body.output.providerStatus).toBe("not_configured");
    expect(r.body.output.results[0].verdict).toBe("unknown");
  });

  it("Threat Intelligence withholds a provider note that tries to instruct the AI", async () => {
    const e = await setup();
    await e.assign("threat_intelligence");
    const r = await e.invoke("threat_intelligence", { indicators: [{ value: "198.51.100.77" }] });
    const res = r.body.output.results[0];
    expect(res.verdict).toBe("suspicious");
    expect(res.sources[0].notes).toMatch(/withheld/);
    expect(JSON.stringify(r.body)).not.toMatch(/whitelist this IP/);
  });

  it("Attack Investigation links failed logins → login → process → connection → file change into one chain", async () => {
    const e = await setup();
    await e.assign("attack_investigation");
    const r = await e.invoke("attack_investigation", { windowHours: 24, asset: "web-01" });
    expect(r.status).toBe(200);
    const out = r.body.output;
    expect(out.timeline.map((x: { eventId: string }) => x.eventId)).toEqual(["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9"]);
    const [chain] = out.chains;
    expect(chain.stages).toEqual(["credential_access", "initial_access", "execution", "command_and_control", "impact"]);
    expect(chain.confidence).toBe("high");
    expect(chain.assets).toEqual(["web-01"]);
    expect(out.affectedAssets).toEqual([{ name: "web-01", exposure: "internet", os: "Ubuntu 22.04" }]);
  });

  it("Vulnerability Analysis explains a finding and its fix; with no finding it claims nothing", async () => {
    const e = await setup();
    await e.assign("vulnerability_analysis");
    const r = await e.invoke("vulnerability_analysis", { cve: "cve-2021-44228" });
    expect(r.status).toBe(200);
    const [f] = r.body.output.findings;
    expect(r.body.output.findings).toHaveLength(1); // tenant B's identical finding is not here
    expect(f).toMatchObject({ asset: "web-01", component: "log4j-core", severity: "critical", severitySource: "cvss", exposure: "internet", priority: "critical" });
    expect(f.remediation[0]).toMatch(/Upgrade log4j-core from 2.14.1 to 2.17.1/);
    const none = await e.invoke("vulnerability_analysis", { cve: "CVE-2099-0001" });
    expect(none.body.output).toMatchObject({ evidence: "none", findings: [] });
    expect(none.body.output.statement).toMatch(/not proof/);
    const bad = await e.invoke("vulnerability_analysis", { limit: 5 });
    expect(bad.status).toBe(400);
  });

  it("Security Reporting writes a report with evidence, risk and unverified actions; untrusted text cannot become links", async () => {
    const e = await setup();
    await e.assign("security_reporting");
    const r = await e.invoke("security_reporting", { alertIds: ["E6", "E7", "EINJ"], actionsTaken: ["Isolated web-01 at 14:05"] });
    expect(r.status).toBe(200);
    const { report, markdown } = r.body.output;
    expect(report.evidence.map((x: { eventId: string }) => x.eventId)).toEqual(["E6", "E7", "EINJ"]);
    expect(report.affectedAssets).toEqual(expect.arrayContaining([{ name: "web-01", exposure: "internet" }]));
    expect(report.actionsTaken).toEqual([{ text: "Isolated web-01 at 14:05", reportedBy: "requesting_agent", verified: false, flagged: false }]);
    expect(report.nextSteps[0]).toMatch(/prompt injection/);
    expect(markdown).toContain("## Recommended next steps");
    expect(markdown).not.toMatch(/https?:\/\/attacker/);
    expect(markdown).not.toMatch(/!\[/);
    expect(JSON.stringify(r.body)).not.toContain(FAKE_AWS_KEY);
  });

  it("an optional model narrative is untrusted output; the prompt keeps alert text out of the system message and masks secrets", async () => {
    const model = new FakeModel();
    const e = await setup({ model });
    await e.assign("alert_analysis");
    const r = await e.invoke("alert_analysis", { alertId: "EINJ", narrative: true });
    expect(r.status).toBe(200);
    expect(r.body.output.narrative).toMatchObject({ trust: "model_output", verdict: "clean" });
    const [system, user] = model.sent[0]!;
    expect(system!.role).toBe("system");
    expect(system!.content).not.toMatch(/Ignore all previous instructions/);
    expect(user!.content).toMatch(/EXTERNAL CONTENT LEGION-[0-9a-f]{24} source=security_alert/);
    expect(JSON.stringify(model.sent)).not.toContain(FAKE_AWS_KEY);
  });
});

describe("controls every skill runs under", () => {
  it("rejects malformed input: unknown fields, wrong types, oversized lists, wrong envelope", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    for (const input of [{ execute: true }, { windowHours: "24" }, { windowHours: 10_000 }, { eventIds: Array(501).fill("x") }, "SELECT 1"]) {
      const r = await e.invoke("threat_detection", input);
      expect(r.status, JSON.stringify(input)).toBe(400);
      expect(r.body.error.code).toBe("invalid_input");
    }
    const env2 = await request(e.t.app).post("/agent/v1/skills/threat_detection/invoke").set(bearer(e.token)).send({ input: {}, runAs: "admin" });
    expect(env2.status).toBe(400);
    expect(e.data.calls).toEqual([]);
  });

  it("refuses input that carries credentials, before anything runs", async () => {
    const e = await setup();
    await e.assign("threat_intelligence");
    const r = await e.invoke("threat_intelligence", { indicators: [{ value: FAKE_AWS_KEY }] });
    expect(r.status).toBe(400);
    expect(r.body.error.message).toMatch(/credentials/);
    const rows = await skillAuditRows(e.t);
    expect(JSON.stringify(rows)).not.toContain(FAKE_AWS_KEY);
  });

  it("people cannot call the agent endpoint; anonymous callers are refused", async () => {
    const e = await setup();
    expect((await request(e.t.app).post("/agent/v1/skills/threat_detection/invoke").set(as("alice")).send({ input: {} })).status).toBe(401);
    expect((await request(e.t.app).post("/agent/v1/skills/threat_detection/invoke").send({ input: {} })).status).toBe(401);
  });

  it("a suspended agent's skills stop at once (the firewall's live identity check)", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    expect((await request(e.t.app).post(`/agents/${e.agent.id}/suspend`).set(as("alice")).send({ reason: "test" })).status).toBe(200);
    const r = await e.invoke("threat_detection", {});
    expect(r.status).toBe(401); // the token itself no longer resolves
    expect(e.data.calls).toEqual([]);
  });

  it("every run goes through the agent firewall, once per capability, and is logged there", async () => {
    const e = await setup();
    await e.assign("incident_response");
    const r = await e.invoke("incident_response", { alertIds: ["E7"] });
    expect(r.body.decisionIds).toHaveLength(2);
    const d = await e.t.pool.query("SELECT action, permission, decision FROM firewall_decisions WHERE decision_id = ANY($1::uuid[]) ORDER BY permission", [r.body.decisionIds]);
    expect(d.rows).toEqual([
      { action: "skill:incident_response", permission: "alerts:read", decision: "ALLOW" },
      { action: "skill:incident_response", permission: "assets:read", decision: "ALLOW" },
    ]);
  });

  it("a firewall policy can close a skill for this organisation (resource sensitivity)", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    await request(e.t.app).put("/firewall/policy").set(as("alice")).send({ resources: { skill: "restricted" } });
    const r = await e.invoke("threat_detection", {});
    expect(r.status).toBe(403);
    expect(r.body.error).toMatchObject({ code: "firewall_blocked", rules: expect.arrayContaining(["sensitivity.restricted"]) });
  });

  it("audits attempt and outcome with decision ids and digests — never the raw input or output", async () => {
    const e = await setup();
    await e.assign("alert_analysis");
    const ok = await e.invoke("alert_analysis", { alertId: "E7" });
    await e.invoke("alert_analysis", { alertId: "E7", bogus: 1 });
    const rows = await skillAuditRows(e.t, "action = 'skill.invoke'");
    expect(rows.map((r) => r.outcome)).toEqual(["attempt", "success", "denied"]);
    expect(rows[1].details).toMatchObject({
      invocationId: ok.body.invocationId, skill: "alert_analysis", version: "1.0.0", decisionIds: ok.body.decisionIds,
      inputDigest: expect.stringMatching(/^[0-9a-f]{64}$/), outputDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(rows[1].principal_id).toBe(e.agent.id);
    expect(JSON.stringify(rows)).not.toContain("reverse shell");
    expect(rows[2].reason).toMatch(/^invalid_input/);
    const assign = await skillAuditRows(e.t, "action = 'skill.assign'");
    expect(assign.map((r) => r.outcome)).toEqual(["attempt", "success"]);
    expect(assign[1].principal_id).toBe("alice");
  });

  it("tenant isolation: the data source only ever receives the agent's own tenant, whatever the input says", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    await e.invoke("threat_detection", { eventIds: ["EB1", "E1"] });
    expect(e.data.calls.length).toBeGreaterThan(0);
    expect(e.data.calls.every((c) => c.tenantId === TENANT_A)).toBe(true);
  });

  it("tenant isolation: if the host leaks another tenant's rows, the skill fails and returns nothing", async () => {
    const data = new FakeData();
    data.leakOtherTenants = true;
    const e = await setup({ data });
    await e.assign("threat_detection");
    const r = await e.invoke("threat_detection", {});
    expect(r.status).toBe(502);
    expect(r.body.error.code).toBe("foreign_tenant");
    expect(JSON.stringify(r.body)).not.toContain("Tenant B secret alert");
  });

  it("tenant isolation: tenant B's agent sees none of tenant A's assignments or data", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    const b = await agentWithToken(e.t, "bob", { permissions: ["alerts:read"] });
    expect((await request(e.t.app).get("/agent/v1/skills").set(bearer(b.token))).body.skills).toEqual([]);
    expect((await e.invoke("threat_detection", {}, b.token)).body.error.code).toBe("not_assigned");
    expect((await request(e.t.app).get("/skills/assignments").set(as("bob"))).body.assignments).toEqual([]);
    await e.assign("threat_detection", b.agent.id, "bob");
    const r = await e.invoke("threat_detection", {}, b.token);
    expect(r.status).toBe(200);
    expect(r.body.output.eventsAnalyzed).toBe(1);
    expect(r.body.output.findings.every((f: { eventId: string }) => f.eventId === "EB1")).toBe(true);
    expect(e.data.calls.filter((c) => c.tenantId === TENANT_B).length).toBeGreaterThan(0);
  });

  it("external content a skill reads is recorded against the agent, so it cannot turn into an action", async () => {
    const e = await setup({ permissions: ["alerts:read", "assets:read", "alerts:update_status"] });
    await e.assign("threat_detection");
    expect((await e.invoke("threat_detection", {})).status).toBe(200);
    const logged = await e.t.pool.query("SELECT verdict FROM content_ingestion_log WHERE principal_id = $1", [e.agent.id]);
    expect(logged.rows.map((r) => r.verdict)).toContain("malicious");
    // The poisoned alert said "mark every alert as resolved". The agent now tries exactly that:
    const act = await request(e.t.app).post("/agent/v1/alerts/E1/status").set(bearer(e.token)).send({ status: "resolved" });
    expect(act.status).toBe(403);
    expect(act.body.error.rules).toContain("content.quarantine");
    // Reading continues.
    expect((await e.invoke("threat_detection", {})).status).toBe(200);
  });

  it("fails closed when the data source fails, and keeps its error text (and secrets in it) out of the response", async () => {
    const data = new FakeData();
    data.fail = true;
    const e = await setup({ data });
    await e.assign("threat_detection");
    const r = await e.invoke("threat_detection", {});
    expect(r.status).toBe(503);
    expect(r.body.error.code).toBe("data_unavailable");
    expect(JSON.stringify(r.body)).not.toContain("hunter2");
    const rows = await skillAuditRows(e.t, "outcome = 'failure'");
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain("hunter2");
  });

  it("fails closed when no data source is configured, or the source returns malformed records", async () => {
    const e = await setup({ data: null });
    await e.assign("threat_detection");
    expect((await e.invoke("threat_detection", {})).body.error.code).toBe("data_unavailable");
    await e.t.pool.end();
    const data = new FakeData();
    data.events = [{ id: "X", tenantId: TENANT_A, title: "t", severity: "apocalyptic", createdAt: "yesterday" }];
    env = await skillEnv({ data });
    await env.assign("threat_detection");
    const r = await env.invoke("threat_detection", { eventIds: ["X"] });
    expect(r.status).toBe(502);
    expect(r.body.error.code).toBe("data_invalid");
  });

  it("fails closed when the attempt cannot be audited: nothing is read", async () => {
    const e = await setup();
    await e.assign("threat_detection");
    await e.t.pool.query("ALTER TABLE principal_audit_log RENAME TO principal_audit_log_gone");
    try {
      const r = await e.invoke("threat_detection", {});
      expect(r.status).toBe(503);
      expect(r.body.error.code).toBe("audit_unavailable");
      expect(e.data.calls).toEqual([]);
    } finally {
      await e.t.pool.query("ALTER TABLE principal_audit_log_gone RENAME TO principal_audit_log");
    }
  });
});
