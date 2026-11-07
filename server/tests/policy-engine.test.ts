/**
 * Task 10, module 1 — Policy Engine v0.
 *
 * The evaluator is pure and deterministic; the floors (critical actions,
 * high-risk by machines, anything a model proposed) cannot be lowered by any
 * policy; DENY always wins; documents are strict; versions are immutable and
 * written with optimistic concurrency; and in v0 the engine only SHADOWS:
 * it records what it would decide and never changes what happens.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as blocklist from "../src/blocklist.js";
import type { User } from "../src/types.js";
import type { Campaign } from "../src/campaigns.js";
import { evaluatePolicy, type PolicyRequest } from "../src/policy/evaluate.js";
import { parsePolicyDocument, type PolicyDocument } from "../src/policy/document.js";
import { flushShadow, shadowEvaluate, shadowFailures } from "../src/policy/shadow.js";
import { putPolicy, PolicyConflict } from "../src/policy/store.js";
import { catalogList } from "../src/policy/catalog.js";

const doc = (d: Partial<PolicyDocument> & { default_autonomy: PolicyDocument["default_autonomy"] }): PolicyDocument => ({ schema: 1, rules: [], ...d } as PolicyDocument);
const agentReq = (action_id: string, agent: string, extra: Partial<PolicyRequest> = {}): PolicyRequest =>
  ({ action_id, actor: { kind: "agent", agent: agent as never }, origin: "agent", mode: "simulation", ...extra });
const human = { kind: "human" as const, user_id: randomUUID(), role: "admin" as const };

describe("evaluator: hard refusals", () => {
  it("an action outside the catalog is denied", () => {
    expect(evaluatePolicy(agentReq("shell.exec", "Vanguard"), null)).toMatchObject({ decision: "DENY", reason_codes: ["UNKNOWN_ACTION"] });
  });
  it("an agent may only propose actions the catalog gives it", () => {
    expect(evaluatePolicy(agentReq("ip.block", "Oracle"), doc({ default_autonomy: "AUTONOMOUS", rules: [{ id: "all", effect: "ALLOW", actions: ["*"] }] })))
      .toMatchObject({ decision: "DENY", reason_codes: ["AGENT_NOT_ALLOWED"] });
  });
  it("an unknown agent name is denied", () => {
    expect(evaluatePolicy(agentReq("alert.triage", "Executor"), null).decision).toBe("DENY");
    expect(evaluatePolicy(agentReq("alert.triage", "root"), null).reason_codes).toEqual(["UNKNOWN_AGENT"]);
  });
  it("live mode is denied unless an administrator opted in AND Legion can really do the action — whatever the policy says", () => {
    const allowAll = doc({ default_autonomy: "AUTONOMOUS", rules: [{ id: "all", effect: "ALLOW", actions: ["*"] }] });
    // No protection settings, or manual: refused, for a person and for an agent.
    expect(evaluatePolicy(agentReq("ip.block", "Vanguard", { mode: "live" }), allowAll)).toMatchObject({ decision: "DENY", reason_codes: ["LIVE_NOT_ENABLED"] });
    expect(evaluatePolicy({ action_id: "ip.block", actor: human, origin: "human", mode: "live" }, allowAll).decision).toBe("DENY");
    expect(evaluatePolicy({ action_id: "ip.block", actor: human, origin: "human", mode: "live", protection: { mode: "manual", auto_actions: ["ip.block"] } }, allowAll).reason_codes).toEqual(["LIVE_NOT_ENABLED"]);
    // Opted in, but there is nothing to call for these: simulation only.
    const auto = { mode: "automatic", auto_actions: [] } as const;
    for (const id of ["alert.set_status", "ip.unblock", "payment.reject", "payment.release", "account.disable", "host.isolate"]) {
      expect(evaluatePolicy({ action_id: id, actor: human, origin: "human", mode: "live", protection: auto }, allowAll).reason_codes, id).toEqual(["NO_LIVE_EXECUTOR"]);
    }
  });
  it("actor and origin must agree: an agent cannot claim to be a human, a human request cannot be marked as model output", () => {
    expect(evaluatePolicy(agentReq("alert.set_status", "Oracle", { origin: "human" }), null).reason_codes).toEqual(["ACTOR_ORIGIN_MISMATCH"]);
    expect(evaluatePolicy({ action_id: "ip.block", actor: human, origin: "llm", mode: "simulation" }, null).decision).toBe("DENY");
  });
});

describe("evaluator: autonomy and rules", () => {
  it("D0 (no policy): reads are allowed, every effectful agent action is only recorded", () => {
    expect(evaluatePolicy(agentReq("alert.triage", "Oracle"), null).decision).toBe("ALLOW");
    for (const a of catalogList().filter((c) => c.effect === "write")) {
      expect(evaluatePolicy(agentReq(a.id, a.agents[0]!), null).decision, a.id).toBe("RECORD_ONLY");
    }
  });
  it("ASSIST asks a person; AUTONOMOUS acts on R1/R2 but still asks for R3", () => {
    expect(evaluatePolicy(agentReq("alert.set_status", "Oracle"), doc({ default_autonomy: "ASSIST" })).decision).toBe("REQUIRE_APPROVAL");
    const auto = doc({ default_autonomy: "AUTONOMOUS" });
    expect(evaluatePolicy(agentReq("alert.set_status", "Oracle"), auto).decision).toBe("ALLOW");
    expect(evaluatePolicy(agentReq("ip.unblock", "Vanguard"), auto).decision).toBe("ALLOW");
    expect(evaluatePolicy(agentReq("ip.block", "Vanguard"), auto)).toMatchObject({ decision: "REQUIRE_APPROVAL", reason_codes: ["AUTONOMY_LIMIT_R3"] });
  });
  it("specificity: per-action autonomy beats per-agent, which beats the workspace default", () => {
    const d = doc({ default_autonomy: "OBSERVE", agents: { Oracle: { autonomy: "ASSIST" } }, actions: { "alert.set_status": { autonomy: "AUTONOMOUS" } } });
    expect(evaluatePolicy(agentReq("alert.set_status", "Oracle"), d)).toMatchObject({ decision: "ALLOW", autonomy: "AUTONOMOUS" });
    expect(evaluatePolicy(agentReq("notify.admins", "Oracle"), d)).toMatchObject({ decision: "REQUIRE_APPROVAL", autonomy: "ASSIST" });
    expect(evaluatePolicy(agentReq("notify.admins", "Sentinel"), d)).toMatchObject({ decision: "RECORD_ONLY", autonomy: "OBSERVE" });
  });
  it("an explicit DENY cannot be overridden by any ALLOW", () => {
    const d = doc({ default_autonomy: "AUTONOMOUS", rules: [
      { id: "allow-all", effect: "ALLOW", actions: ["*"] },
      { id: "no-status", effect: "DENY", actions: ["alert.set_status"] },
      { id: "allow-status", effect: "ALLOW", actions: ["alert.set_status"], agents: ["Oracle"] },
    ] });
    const out = evaluatePolicy(agentReq("alert.set_status", "Oracle"), d);
    expect(out.decision).toBe("DENY");
    expect(out.matched_rule_ids.sort()).toEqual(["allow-all", "allow-status", "no-status"]);
  });
  it("a DENY rule also stops reads", () => {
    expect(evaluatePolicy(agentReq("alert.explain", "Oracle"), doc({ default_autonomy: "OBSERVE", rules: [{ id: "no-ai", effect: "DENY", actions: ["alert.explain"] }] })).decision).toBe("DENY");
  });
  it("rule conditions: agents, origins and classes all have to match", () => {
    const d = doc({ default_autonomy: "OBSERVE", rules: [{ id: "oracle-r1", effect: "ALLOW", actions: ["*"], agents: ["Oracle"], origins: ["agent"], classes: ["R1"] }] });
    expect(evaluatePolicy(agentReq("alert.set_status", "Oracle"), d).decision).toBe("ALLOW");
    expect(evaluatePolicy(agentReq("notify.admins", "Sentinel"), d).decision).toBe("RECORD_ONLY");
  });
});

describe("evaluator: floors no policy can lower", () => {
  const allowAll = doc({ default_autonomy: "AUTONOMOUS", rules: [{ id: "all", effect: "ALLOW", actions: ["*"] }] });
  it("critical (R4) actions always need approval — for agents and for people", () => {
    for (const id of ["payment.release", "account.disable", "host.isolate"]) {
      expect(evaluatePolicy(agentReq(id, "Vanguard"), allowAll), id).toMatchObject({ decision: "REQUIRE_APPROVAL" });
      expect(evaluatePolicy({ action_id: id, actor: human, origin: "human", mode: "simulation" }, allowAll).decision, id).toBe("REQUIRE_APPROVAL");
    }
    expect(evaluatePolicy(agentReq("payment.release", "Vanguard"), allowAll).reason_codes).toContain("FLOOR_CRITICAL");
  });
  it("high-risk (R3) actions by an agent or by Legion itself need approval even if a rule allows them", () => {
    expect(evaluatePolicy(agentReq("ip.block", "Vanguard"), allowAll)).toMatchObject({ decision: "REQUIRE_APPROVAL", reason_codes: expect.arrayContaining(["FLOOR_R3_NON_HUMAN"]) });
    expect(evaluatePolicy({ action_id: "ip.block", actor: { kind: "system", component: "auto_response" }, origin: "system", mode: "shadow" }, allowAll).decision).toBe("REQUIRE_APPROVAL");
    // A person acting directly (their role checked by the route) is not held back for R3.
    expect(evaluatePolicy({ action_id: "ip.block", actor: human, origin: "human", mode: "shadow" }, null).decision).toBe("ALLOW");
  });
  it("anything a model proposed needs approval above read-only", () => {
    const out = evaluatePolicy(agentReq("alert.set_status", "Oracle", { origin: "llm" }), allowAll);
    expect(out).toMatchObject({ decision: "REQUIRE_APPROVAL", reason_codes: expect.arrayContaining(["FLOOR_LLM_ORIGIN"]) });
    expect(evaluatePolicy(agentReq("alert.triage", "Oracle", { origin: "llm" }), allowAll).decision).toBe("ALLOW");
  });
  it("a floor never relaxes a stricter decision", () => {
    const d = doc({ default_autonomy: "AUTONOMOUS", rules: [{ id: "rec", effect: "RECORD_ONLY", actions: ["payment.release"] }] });
    expect(evaluatePolicy(agentReq("payment.release", "Vanguard"), d).decision).toBe("RECORD_ONLY");
  });
  it("is deterministic and does not touch its inputs", () => {
    const d = doc({ default_autonomy: "ASSIST", rules: [{ id: "x", effect: "DENY", actions: ["ip.unblock"] }] });
    const snapshot = JSON.stringify(d);
    const r = agentReq("ip.block", "Vanguard");
    const a = evaluatePolicy(r, d); const b = evaluatePolicy(r, d);
    expect(a).toEqual(b);
    expect(JSON.stringify(d)).toBe(snapshot);
  });
});

describe("policy documents are strict", () => {
  const bad: Array<[string, unknown]> = [
    ["unknown top-level field", { schema: 1, default_autonomy: "OBSERVE", rules: [], admin: true }],
    ["unknown action", { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "a", effect: "ALLOW", actions: ["shell.exec"] }] }],
    ["unknown agent", { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "a", effect: "ALLOW", actions: ["*"], agents: ["Executor"] }] }],
    ["unknown effect", { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "a", effect: "GRANT", actions: ["*"] }] }],
    ["unknown rule field (no expressions)", { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "a", effect: "ALLOW", actions: ["*"], when: "ip ~ '.*'" }] }],
    ["duplicate rule ids", { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "a", effect: "ALLOW", actions: ["*"] }, { id: "a", effect: "DENY", actions: ["*"] }] }],
    ["too many rules", { schema: 1, default_autonomy: "OBSERVE", rules: Array.from({ length: 101 }, (_, i) => ({ id: `r${i}`, effect: "DENY", actions: ["*"] })) }],
    ["too large", { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "a", effect: "DENY", actions: ["*"], reason: "x".repeat(200) }], pad: "y".repeat(70_000) }],
    ["wildcard per-action autonomy", { schema: 1, default_autonomy: "OBSERVE", actions: { "*": { autonomy: "AUTONOMOUS" } } }],
    ["wrong schema version", { schema: 2, default_autonomy: "OBSERVE", rules: [] }],
    ["unknown autonomy", { schema: 1, default_autonomy: "GOD_MODE", rules: [] }],
  ];
  for (const [name, raw] of bad) it(`refuses: ${name}`, () => expect(parsePolicyDocument(raw).ok).toBe(false));
  it("accepts a valid document", () => {
    expect(parsePolicyDocument({ schema: 1, default_autonomy: "ASSIST", agents: { Vanguard: { autonomy: "OBSERVE" } }, rules: [{ id: "no-pay", effect: "DENY", actions: ["payment.release"], reason: "finance only" }] }).ok).toBe(true);
  });
});

// --- with the database -------------------------------------------------------

let tenantA: string; let tenantB: string;
let adminA: User; let analystA: User; let viewerA: User; let adminB: User;
const bearer = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;
const as = (u: User) => ["Authorization", bearer(u)] as const;
const hash = () => bcrypt.hash("password123", 4);

beforeAll(async () => { await migrate(); });
afterAll(async () => { await flushShadow(); await closePool(); });
beforeEach(async () => {
  await flushShadow();
  await truncateAll();
  config.policyEngineMode = "shadow";
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  adminA = await store.insertUser({ email: "admin@a.io", password_hash: await hash(), tenant_id: tenantA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@a.io", password_hash: await hash(), tenant_id: tenantA, role: "analyst", status: "active" });
  viewerA = await store.insertUser({ email: "viewer@a.io", password_hash: await hash(), tenant_id: tenantA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "admin@b.io", password_hash: await hash(), tenant_id: tenantB, role: "admin", status: "active" });
});

const decisions = async (tenant: string) => (await query("SELECT * FROM policy_decisions WHERE tenant_id = $1 ORDER BY created_at", [tenant])).rows;
const validDoc = { schema: 1, default_autonomy: "ASSIST", rules: [{ id: "no-block", effect: "DENY", actions: ["ip.block"] }] };

describe("versioned migrations", () => {
  it("record each applied migration with its checksum", async () => {
    const rows = (await query("SELECT version, name, checksum FROM legion_migrations ORDER BY version")).rows;
    expect(rows[0]).toMatchObject({ version: 1, name: "policy_engine" });
    expect(rows[0].checksum).toMatch(/^[0-9a-f]{64}$/);
  });
  it("refuse to start when an applied migration's file changed", async () => {
    await query("UPDATE legion_migrations SET checksum = $1 WHERE version = 1", ["0".repeat(64)]);
    try {
      await expect(migrate()).rejects.toThrow(/was changed after it was applied/);
    } finally {
      const { migrationFiles } = await import("../src/db/pool.js");
      await query("UPDATE legion_migrations SET checksum = $1 WHERE version = 1", [migrationFiles()[0]!.checksum]);
    }
    await migrate();
  });
});

describe("policy API", () => {
  it("reading needs policy:read (analyst); viewers are refused", async () => {
    await request(app).get("/policy").set(...as(viewerA)).expect(403);
    const res = await request(app).get("/policy").set(...as(analystA)).expect(200);
    expect(res.body).toMatchObject({ enforcement: "shadow", active: null, default: { default_autonomy: "OBSERVE" } });
    expect(res.body.catalog.map((c: { id: string }) => c.id)).toContain("payment.release");
  });

  it("writing needs policy:manage (admin), validates, and uses optimistic concurrency", async () => {
    await request(app).put("/policy").set(...as(analystA)).send({ document: validDoc, expected_version: 0 }).expect(403);
    await request(app).put("/policy").set(...as(adminA)).send({ document: { ...validDoc, rules: [{ id: "x", effect: "ALLOW", actions: ["rm.rf"] }] }, expected_version: 0 }).expect(422);
    const v1 = await request(app).put("/policy").set(...as(adminA)).send({ document: validDoc, expected_version: 0 }).expect(200);
    expect(v1.body.active).toMatchObject({ version: 1, hash: expect.stringMatching(/^[0-9a-f]{64}$/) });
    const stale = await request(app).put("/policy").set(...as(adminA)).send({ document: { ...validDoc, default_autonomy: "AUTONOMOUS" }, expected_version: 0 }).expect(409);
    expect(stale.body.current_version).toBe(1);
    await request(app).put("/policy").set(...as(adminA)).send({ document: { ...validDoc, default_autonomy: "OBSERVE" }, expected_version: 1 }).expect(200);
    const audit = (await query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'policy.%'", [tenantA])).rows.map((r) => r.action);
    expect(audit).toEqual(["policy.updated", "policy.updated"]);
  });

  it("two admins saving at once: exactly one wins, the other gets a conflict", async () => {
    const results = await Promise.allSettled([
      putPolicy(tenantA, validDoc, { expectedVersion: 0, userId: adminA.id }),
      putPolicy(tenantA, { ...validDoc, default_autonomy: "OBSERVE" }, { expectedVersion: 0, userId: adminA.id }),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
    expect(rejected.reason).toBeInstanceOf(PolicyConflict);
    expect((await query("SELECT count(*)::int AS n FROM policy_documents WHERE tenant_id = $1", [tenantA])).rows[0].n).toBe(1);
  });

  it("rollback stores the old content as a NEW version; history is kept", async () => {
    await request(app).put("/policy").set(...as(adminA)).send({ document: validDoc, expected_version: 0 }).expect(200);
    await request(app).put("/policy").set(...as(adminA)).send({ document: { ...validDoc, default_autonomy: "AUTONOMOUS", rules: [] }, expected_version: 1 }).expect(200);
    const back = await request(app).post("/policy/rollback").set(...as(adminA)).send({ version: 1, expected_version: 2 }).expect(200);
    expect(back.body.active.version).toBe(3);
    expect(back.body.active.document.default_autonomy).toBe("ASSIST");
    const versions = (await request(app).get("/policy/versions").set(...as(analystA)).expect(200)).body.versions;
    expect(versions.map((v: { version: number; active: boolean }) => [v.version, v.active])).toEqual([[3, true], [2, false], [1, false]]);
    await request(app).post("/policy/rollback").set(...as(adminA)).send({ version: 99, expected_version: 3 }).expect(404);
  });

  it("stored versions and decisions are append-only in the database", async () => {
    await putPolicy(tenantA, validDoc, { expectedVersion: 0, userId: adminA.id });
    await expect(query("UPDATE policy_documents SET document = '{}' WHERE tenant_id = $1", [tenantA])).rejects.toThrow(/append-only/);
    await expect(query("DELETE FROM policy_documents WHERE tenant_id = $1", [tenantA])).rejects.toThrow(/append-only/);
    shadowEvaluate(tenantA, { call_site: "test", action_id: "ip.block", actor: { kind: "system", component: "t" }, origin: "system", input: { ip: "203.0.113.5", minutes: 5 }, legacy_outcome: "blocked" });
    await flushShadow();
    await expect(query("UPDATE policy_decisions SET decision = 'ALLOW' WHERE tenant_id = $1", [tenantA])).rejects.toThrow(/append-only/);
  });

  it("a stored document that no longer validates is treated as no policy (safe default), never as allow-all", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] }, { expectedVersion: 0, userId: adminA.id });
    // Simulate drift: the stored hash no longer matches the content.
    await query("SELECT set_config('legion.audit_erasure', 'on', false)");
    await query("UPDATE policy_documents SET hash = $2 WHERE tenant_id = $1", [tenantA, "f".repeat(64)]);
    await query("SELECT set_config('legion.audit_erasure', '', false)");
    const res = await request(app).get("/policy").set(...as(analystA)).expect(200);
    expect(res.body.active).toBeNull();
  });

  it("simulate evaluates the active policy or a draft and records nothing", async () => {
    const sim = await request(app).post("/policy/simulate").set(...as(analystA))
      .send({ action_id: "ip.block", actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", document: { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] } }).expect(200);
    expect(sim.body).toMatchObject({ recorded: false, outcome: { decision: "REQUIRE_APPROVAL" } });
    const me = await request(app).post("/policy/simulate").set(...as(analystA)).send({ action_id: "payment.release", actor: { kind: "human" }, origin: "human" }).expect(200);
    expect(me.body.outcome.decision).toBe("REQUIRE_APPROVAL");
    await request(app).post("/policy/simulate").set(...as(analystA)).send({ action_id: "ip.block", actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", document: { schema: 9 } }).expect(422);
    // The caller cannot pose as another user: "human" carries no user id field.
    await request(app).post("/policy/simulate").set(...as(analystA)).send({ action_id: "ip.block", actor: { kind: "human", user_id: adminA.id, role: "admin" }, origin: "human" }).expect(422);
    expect(await decisions(tenantA)).toHaveLength(0);
  });

  it("each workspace sees only its own policy and decisions", async () => {
    await putPolicy(tenantA, validDoc, { expectedVersion: 0, userId: adminA.id });
    shadowEvaluate(tenantA, { call_site: "test", action_id: "ip.unblock", actor: { kind: "system", component: "t" }, origin: "system", input: { ip: "203.0.113.5" }, legacy_outcome: "x" });
    await flushShadow();
    const b = await request(app).get("/policy").set(...as(adminB)).expect(200);
    expect(b.body.active).toBeNull();
    expect((await request(app).get("/policy/decisions").set(...as(adminB)).expect(200)).body.decisions).toEqual([]);
    expect((await request(app).get("/policy/versions").set(...as(adminB)).expect(200)).body.versions).toEqual([]);
    expect((await request(app).get("/policy/decisions").set(...as(adminA)).expect(200)).body.decisions).toHaveLength(1);
    await request(app).get("/policy/decisions?action_id=shell.exec").set(...as(adminA)).expect(422);
  });
});

describe("shadow mode observes and never enforces", () => {
  it("a manual block is recorded with the engine's view — and still happens even when the policy would deny it", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "OBSERVE", rules: [{ id: "never-block", effect: "DENY", actions: ["ip.block"] }] }, { expectedVersion: 0, userId: adminA.id });
    const res = await request(app).post("/security/blocks").set(...as(adminA)).send({ ip: "203.0.113.7", minutes: 30 }).expect(201);
    expect(res.body.block.ip).toBe("203.0.113.7");
    await flushShadow();
    const [d] = await decisions(tenantA);
    expect(d).toMatchObject({ enforcement: "shadow", call_site: "route:manual_block", action_id: "ip.block", risk_class: "R3", decision: "DENY",
      legacy_outcome: "blocked", target: "203.0.113.7", policy_version: 1, matched_rule_ids: ["never-block"], origin: "human" });
    expect(d.actor).toMatchObject({ kind: "human", user_id: adminA.id, role: "admin" });
    expect(d.input_digest).toMatch(/^[0-9a-f]{64}$/);
    expect((await blocklist.listBlocks(tenantA, { activeOnly: true })).map((b) => b.ip)).toEqual(["203.0.113.7"]);
  });

  it("unblock, alert status and payment resolution are shadowed too", async () => {
    await request(app).post("/security/blocks").set(...as(adminA)).send({ ip: "203.0.113.8", minutes: 30 }).expect(201);
    await request(app).delete("/security/blocks/203.0.113.8").set(...as(adminA)).expect(200);
    await store.insertAlert({ id: "SEC-9", tenant_id: tenantA, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 50,
      ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
    await request(app).patch("/alerts/SEC-9/status").set(...as(analystA)).send({ status: "resolved" }).expect(200);
    await flushShadow();
    const sites = (await decisions(tenantA)).map((d) => `${d.call_site}:${d.action_id}:${d.decision}`);
    expect(sites).toEqual(expect.arrayContaining(["route:manual_unblock:ip.unblock:ALLOW", "route:alert_status:alert.set_status:ALLOW"]));
  });

  it("Legion's own automatic block is shadowed as a machine action: the engine would have asked a person", async () => {
    // Even a policy that allows everything cannot let Legion block on its own without a person (R3 floor).
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [{ id: "all", effect: "ALLOW", actions: ["*"] }] }, { expectedVersion: 0, userId: adminA.id });
    await blocklist.updateSettings(tenantA, { mode: "auto", minutes: 30 });
    await blocklist.acknowledgeNotice(tenantA, "admin@a.io");
    const id = `CMP-${randomUUID().slice(0, 8)}`;
    await query("INSERT INTO attack_campaigns (tenant_id, id, rule, subject) VALUES ($1, $2, 'wide_sweep', '185.220.101.20')", [tenantA, id]);
    const campaign = { tenant_id: tenantA, id, rule: "wide_sweep", subject: "185.220.101.20", sources: ["185.220.101.20"] } as unknown as Campaign;
    const out = await blocklist.respondToCampaigns(tenantA, [campaign]);
    expect(out[0]).toMatchObject({ action: "blocked" });
    await flushShadow();
    const [d] = await decisions(tenantA);
    expect(d).toMatchObject({ call_site: "auto_response", decision: "REQUIRE_APPROVAL", legacy_outcome: "blocked", origin: "system" });
    expect(d.reason_codes).toContain("FLOOR_R3_NON_HUMAN");
  });

  it("with no policy at all (D0), Legion's automatic block is shadowed as record-only", async () => {
    await blocklist.updateSettings(tenantA, { mode: "auto", minutes: 30 });
    await blocklist.acknowledgeNotice(tenantA, "admin@a.io");
    const id = `CMP-${randomUUID().slice(0, 8)}`;
    await query("INSERT INTO attack_campaigns (tenant_id, id, rule, subject) VALUES ($1, $2, 'wide_sweep', '185.220.101.21')", [tenantA, id]);
    await blocklist.respondToCampaigns(tenantA, [{ tenant_id: tenantA, id, rule: "wide_sweep", subject: "185.220.101.21", sources: ["185.220.101.21"] } as unknown as Campaign]);
    await flushShadow();
    const [d] = await decisions(tenantA);
    expect(d).toMatchObject({ decision: "RECORD_ONLY", reason_codes: ["AUTONOMY_OBSERVE"], policy_version: null, legacy_outcome: "blocked" });
  });

  it("a failing policy store never breaks or delays the action: the error is counted, nothing is thrown", async () => {
    const before = shadowFailures();
    expect(() => shadowEvaluate(randomUUID(), { call_site: "test", action_id: "ip.block", actor: { kind: "system", component: "t" }, origin: "system", input: {}, legacy_outcome: "x" })).not.toThrow();
    await flushShadow();
    expect(shadowFailures()).toBe(before + 1);
  });

  it("POLICY_ENGINE_MODE=off records nothing", async () => {
    config.policyEngineMode = "off";
    await request(app).post("/security/blocks").set(...as(adminA)).send({ ip: "203.0.113.9", minutes: 30 }).expect(201);
    await flushShadow();
    expect(await decisions(tenantA)).toHaveLength(0);
  });
});
