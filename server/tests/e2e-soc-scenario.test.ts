/**
 * Task 11 — end-to-end SOC investigation, simulation only.
 *
 * Wazuh event → Sentinel → Hunter → Guardian → Oracle → Vanguard → Policy →
 * Approval → Action (simulated) → verification → audit, in every autonomy
 * mode. Mock connectors, an isolated tenant, no production side effects: the
 * tests assert that NOTHING real changed (no block row, no alert change).
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import type { Agent, User } from "../src/types.js";
import { putPolicy } from "../src/policy/store.js";
import { flushShadow } from "../src/policy/shadow.js";
import { runOnce } from "../src/runtime/worker.js";
import { auditEventsOf, createAgents, investigate, verify, type AgentSession } from "./helpers/soc-conductor.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

export const OUT = process.env.E2E_REPORT_DIR || join(process.env.TMPDIR || "/tmp", "legion-e2e");
export const ATTACKER = "45.155.205.12";

let tenantA: string; let tenantB: string;
let admin: User; let approver2: User; let adminB: User;
let credA: TestCredential;
let agents: Record<Agent, AgentSession>;
const savedMode = config.deploymentMode;
const tokenOf = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });
const as = (u: User) => ["Authorization", `Bearer ${tokenOf(u)}`] as const;

let n = 0;
/** A Wazuh event as the sensor sends it (same shape as the webhook tests). */
const wazuh = (o: { ip?: string; host?: string; mitre?: string[]; level?: number; log?: string; desc?: string; groups?: string[] } = {}) => ({
  provider: "wazuh",
  event: {
    id: `wz-${++n}-${randomUUID()}`,
    rule: { description: o.desc ?? "sshd: brute force attempt", level: o.level ?? 12, mitre: { id: o.mitre ?? ["T1110"] }, groups: o.groups ?? ["sshd"] },
    agent: { name: o.host ?? "web-01", ip: "10.0.0.5" },
    data: { srcip: o.ip ?? ATTACKER },
    full_log: o.log ?? "sshd[812]: Failed password for root from " + (o.ip ?? ATTACKER) + " port 22 ssh2",
  },
});
const sendWazuh = (cred: TestCredential, body: unknown) => sendSigned(app, cred, body).expect(202);
const alertsFor = async (tenant: string, ip = ATTACKER) => (await query("SELECT id, severity, title FROM alerts WHERE tenant_id = $1 AND source_ip = $2 AND source = 'wazuh' ORDER BY created_at", [tenant, ip])).rows;

/** Realistic attack: scan → brute force x4 → command execution, from one public address. */
async function attack(cred: TestCredential, ip = ATTACKER) {
  await sendWazuh(cred, wazuh({ ip, mitre: ["T1595"], desc: "Port scan detected", groups: ["recon"], level: 7 }));
  for (let i = 0; i < 4; i++) await sendWazuh(cred, wazuh({ ip, mitre: ["T1110"] }));
  await sendWazuh(cred, wazuh({ ip, mitre: ["T1059"], desc: "Suspicious command execution after login", level: 13, log: `sudo: www-data : COMMAND=/bin/bash; from ${ip}` }));
}
const realSideEffects = async (tenant: string) => ({
  blocks: (await query("SELECT count(*)::int AS n FROM ip_blocks WHERE tenant_id = $1", [tenant])).rows[0].n as number,
  statuses: JSON.stringify((await query("SELECT id, status FROM alerts WHERE tenant_id = $1 ORDER BY id", [tenant])).rows),
});

beforeAll(async () => { await migrate(); config.deploymentMode = "self-hosted"; mkdirSync(OUT, { recursive: true }); });
afterAll(async () => { await flushShadow(); config.deploymentMode = savedMode; await closePool(); });
beforeEach(async () => {
  await flushShadow();
  await truncateAll();
  config.socAuditKey = ""; config.policyEngineMode = "shadow"; config.orchestratorAutoMode = "off";
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "admin@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  approver2 = await store.insertUser({ email: "admin2@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "admin@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
  credA = await issueCredential(tenantA);
  agents = await createAgents(admin, tokenOf(admin));
});

const policy = (d: Record<string, unknown>) => putPolicy(tenantA, { schema: 1, rules: [], ...d } as never, { expectedVersion: 0, userId: admin.id });
const save = (name: string, data: unknown) => writeFileSync(join(OUT, `${name}.json`), JSON.stringify(data, null, 2));

describe("the main scenario: Wazuh to audited, simulated response", () => {
  it("ASSIST: all five agents cooperate; a person approves; the action is simulated and verified; nothing real changes", async () => {
    await policy({ default_autonomy: "ASSIST" });
    await attack(credA);
    // Wazuh's vulnerability detector reported a critical weakness on the attacked host (Guardian's evidence).
    await store.insertAlert({ id: `VULN-${randomUUID().slice(0, 8)}`, tenant_id: tenantA, title: "CVE-2021-44228 affects log4j", severity: "critical", agent: "Guardian", status: "open",
      summary: "Package log4j-core 2.14.1 is vulnerable", confidence: 90, ai_explanation: null, explained_at: null, source_ip: null, target: "web-01", mitre_technique: null, source: "wazuh" });
    const alerts = await alertsFor(tenantA);
    expect(alerts.length).toBeGreaterThanOrEqual(6);
    const worst = alerts.find((a) => a.title.includes("Suspicious command execution")) ?? alerts[alerts.length - 1]!;
    const before = await realSideEffects(tenantA);

    const inv = await investigate({ tenantId: tenantA, alertId: worst.id, sourceIp: ATTACKER, asset: "web-01", agents });
    // Each agent contributed its own evidence.
    expect(inv.sentinel.score).toBeGreaterThan(0);
    expect(inv.hunter.events).toBeGreaterThanOrEqual(6);
    expect(inv.hunter.chains).toBeGreaterThan(0);
    expect(inv.guardian.findings).toBe(1); // Guardian found the log4j weakness on the attacked host
    expect(["high", "critical"]).toContain(inv.risk);
    expect(inv.candidate).toMatchObject({ ip: ATTACKER });
    // Vanguard proposed; policy (enforced on this path) asked for a person.
    expect(inv.action).toMatchObject({ status: "awaiting_approval", policy_decision: "REQUIRE_APPROVAL", actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", execution_mode: "simulation" });

    // The approver sees exactly what will be done, and approves THAT.
    const approval = (await request(app).get(`/approvals/${inv.action!.approval_id}`).set(...as(admin)).expect(200)).body;
    expect(approval).toMatchObject({ action_id: "ip.block", risk_class: "R3", action_digest: inv.action!.action_digest, status: "pending" });
    const decided = await inv.trace.step("Human", "approve (digest-bound)", () =>
      request(app).post(`/approvals/${approval.id}/decision`).set(...as(admin)).send({ decision: "approve", action_digest: approval.action_digest }).expect(200),
      (r) => `approved by ${admin.email}; action now ${r.body.action.status}`);
    expect(decided.body.action.status).toBe("simulated");

    const v = await verify(inv.trace, tenantA, inv.action!.id, ATTACKER);
    expect(v.status).toBe("simulated");
    expect(v.result).toMatchObject({ would: "block", ip: ATTACKER, side_effects: "none" });
    expect(v.events).toEqual(["awaiting_approval", "queued", "running", "simulated"]);
    expect(v.chain).toMatchObject({ ok: true });
    // Nothing real: no block, no alert status change.
    expect(v.blocks).toBe(0);
    expect(await realSideEffects(tenantA)).toEqual(before);

    // The audit record covers the workflow end to end, in order.
    const audit = (await auditEventsOf(tenantA)).map((e) => e.event);
    expect(audit).toEqual(expect.arrayContaining(["policy.activated", "approval.requested", "action.awaiting_approval", "approval.approve", "action.queued", "action.running", "action.simulated"]));
    expect(audit.indexOf("approval.requested")).toBeLessThan(audit.indexOf("approval.approve"));
    expect(audit.indexOf("approval.approve")).toBeLessThan(audit.indexOf("action.simulated"));
    // Agents' own audit trail records what each one read.
    const agentLog = (await query("SELECT count(*)::int AS n FROM principal_audit_log WHERE tenant_id = $1 AND action LIKE 'skill.%'", [tenantA]).catch(() => ({ rows: [{ n: -1 }] }))).rows[0].n;
    save("trace-main-assist", { alert: worst, investigation: { risk: inv.risk, conflict: inv.conflict, sentinel: inv.sentinel, hunter: inv.hunter, guardian: inv.guardian, oracle: inv.oracle, candidate: inv.candidate }, steps: inv.trace.steps, totalMs: inv.trace.totalMs, audit, agentAuditRows: agentLog });
  });

  it("the Wazuh webhook itself is the front door: unsigned or forged events create no alert", async () => {
    await sendSigned(app, credA, wazuh(), { signWithSecret: "wrong-secret" }).expect(401);
    await request(app).post("/security-events/webhook").send(wazuh()).expect(401);
    expect(await alertsFor(tenantA)).toHaveLength(0);
  });
});

describe("every autonomy mode", () => {
  async function run(mode: "shadow" | "simulation", doc: Record<string, unknown> | null) {
    if (doc) await policy(doc);
    await attack(credA);
    const worst = (await alertsFor(tenantA)).slice(-1)[0]!;
    return investigate({ tenantId: tenantA, alertId: worst.id, sourceIp: ATTACKER, asset: "web-01", agents, mode });
  }

  it("no policy (D0 / OBSERVE): recorded only — no approval request, nothing queued", async () => {
    const inv = await run("simulation", null);
    expect(inv.action).toMatchObject({ status: "recorded", policy_decision: "RECORD_ONLY", approval_id: null });
    expect((await query("SELECT count(*)::int AS n FROM approval_requests")).rows[0].n).toBe(0);
    expect((await query("SELECT count(*)::int AS n FROM soc_jobs")).rows[0].n).toBe(0);
  });

  it("OBSERVE explicitly: same", async () => {
    expect((await run("simulation", { default_autonomy: "OBSERVE" })).action!.status).toBe("recorded");
  });

  it("ASSIST: waits for a person", async () => {
    expect((await run("simulation", { default_autonomy: "ASSIST" })).action).toMatchObject({ status: "awaiting_approval", policy_decision: "REQUIRE_APPROVAL" });
  });

  it("AUTONOMOUS: a high-risk block STILL waits for a person (R3 floor); only low-risk actions run by themselves", async () => {
    const inv = await run("simulation", { default_autonomy: "AUTONOMOUS", rules: [{ id: "allow-all", effect: "ALLOW", actions: ["*"] }] });
    expect(inv.action).toMatchObject({ status: "awaiting_approval" });
    const low = await (await import("../src/actions/engine.js")).proposeAction(tenantA, {
      action_id: "alert.set_status", input: { alert_id: (await alertsFor(tenantA))[0]!.id, status: "investigating" },
      actor: { kind: "agent", agent: "Oracle" }, origin: "agent", mode: "simulation", idempotency_key: "low-risk-auto-1",
    });
    expect(low.action.status).toBe("queued");
    await runOnce();
    expect((await query("SELECT status FROM action_requests WHERE id = $1", [low.action.id])).rows[0].status).toBe("simulated");
    // ... and the alert itself is unchanged: simulated, not done.
    expect((await store.getAlert(tenantA, (await alertsFor(tenantA))[0]!.id))!.status).toBe("open");
  });

  it("SHADOW execution mode: evaluated and recorded under any policy; never an approval request", async () => {
    const inv = await run("shadow", { default_autonomy: "ASSIST" });
    expect(inv.action).toMatchObject({ status: "recorded", policy_decision: "REQUIRE_APPROVAL", execution_mode: "shadow" });
    expect((await query("SELECT count(*)::int AS n FROM approval_requests")).rows[0].n).toBe(0);
  });

  it("LIVE is refused everywhere", async () => {
    await policy({ default_autonomy: "AUTONOMOUS", rules: [{ id: "allow-all", effect: "ALLOW", actions: ["*"] }] });
    const r = await request(app).post("/actions").set(...as(admin)).send({ action_id: "ip.block", input: { ip: ATTACKER, minutes: 60 }, mode: "live", idempotency_key: "live-attempt-1" });
    expect(r.status).toBe(422);
    await expect(query("INSERT INTO action_requests (tenant_id, id, idempotency_key, action_id, risk_class, input, action_digest, actor, origin, execution_mode, status, policy_decision, policy_decision_id) VALUES ($1,$2,'live-direct-1','ip.block','R3','{}',$3,'{}','agent','live','queued','ALLOW',$2)", [tenantA, randomUUID(), "a".repeat(64)])).rejects.toThrow(/check constraint/);
  });

  it("critical (R4) in the full flow: two other people with two-factor; not one", async () => {
    const r = await request(app).post("/actions").set(...as(admin)).send({ action_id: "account.disable", input: { account: "jdoe", system: "entra" }, mode: "simulation", idempotency_key: "r4-flow-0001" }).expect(201);
    const a = r.body.action;
    expect(a).toMatchObject({ status: "awaiting_approval", risk_class: "R4" });
    // a mock Entra connection makes the simulation name it
    await query("INSERT INTO integration_connections (id, tenant_id, kind, name) VALUES ($1, $2, 'entra', 'Mock Entra')", [randomUUID(), tenantA]);
    // approver2 has no two-factor: refused
    const no2fa = await request(app).post(`/approvals/${a.approval_id}/decision`).set(...as(approver2)).send({ decision: "approve", action_digest: a.action_digest });
    expect(no2fa.status).toBe(403);
    expect(no2fa.body.code).toBe("mfa_required");
    expect((await query("SELECT status FROM action_requests WHERE id = $1", [a.id])).rows[0].status).toBe("awaiting_approval");
  });
});

describe("the automatic path: webhook → background runtime → workflow", () => {
  it("ORCHESTRATOR_AUTO_MODE=shadow: each new alert queues the alert workflow with the alert; the runtime runs it in shadow; nothing is approved or done", async () => {
    config.orchestratorAutoMode = "shadow";
    await policy({ default_autonomy: "ASSIST" });
    await attack(credA);
    const queued = (await query("SELECT kind, status, payload FROM soc_jobs WHERE tenant_id = $1 ORDER BY created_at", [tenantA])).rows;
    expect(queued.length).toBeGreaterThanOrEqual(6);
    expect(queued.every((j) => j.kind === "workflow.run" && j.payload.mode === "shadow")).toBe(true);
    const before = await realSideEffects(tenantA);
    let done = 0;
    for (let i = 0; i < 10 && done < queued.length; i++) done += (await runOnce({ limit: 50 })).done;
    expect(done).toBe(queued.length);
    const runs = (await query("SELECT status, mode, started_by FROM workflow_runs WHERE tenant_id = $1", [tenantA])).rows;
    expect(runs.length).toBe(queued.length);
    expect(runs.every((r) => r.status === "completed" && r.mode === "shadow" && r.started_by.component === "runtime")).toBe(true);
    // shadow: decisions recorded, no approval requests, no jobs for actions, nothing real changed
    expect((await query("SELECT count(*)::int AS n FROM approval_requests")).rows[0].n).toBe(0);
    expect((await query("SELECT count(*)::int AS n FROM policy_decisions WHERE call_site = 'action_engine' AND enforcement = 'enforced'")).rows[0].n).toBeGreaterThan(0);
    expect(await realSideEffects(tenantA)).toEqual(before);
    // tenant B received none of it
    expect((await query("SELECT count(*)::int AS n FROM soc_jobs WHERE tenant_id = $1", [tenantB])).rows[0].n).toBe(0);
  });
});
