/**
 * Task 10, module 3 — Action Engine v0.
 *
 * One door for every action: closed catalog, strict input, enforced policy,
 * approvals bound to the exact action and consumed once, idempotent
 * proposals, run-once simulation, an emergency stop — and in v0 nothing is
 * ever executed: simulation reads, it never writes.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";
import { putPolicy } from "../src/policy/store.js";
import { proposeAction, runQueued, syncWithApproval, type Proposal } from "../src/actions/engine.js";
import { catalogList, LIVE_ACTION_IDS } from "../src/policy/catalog.js";

let tenantA: string; let tenantB: string;
let admin1: User; let admin2: User; let analyst: User; let viewer: User; let adminB: User;
const bearer = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;
const as = (u: User) => ["Authorization", bearer(u)] as const;
const key = () => `k-${randomUUID()}`;
const vanguard = (action_id: string, input: unknown, over: Partial<Proposal> = {}): Proposal =>
  ({ action_id, input, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "simulation", idempotency_key: key(), ...over });
const propose = (u: User, body: Record<string, unknown>) => request(app).post("/actions").set(...as(u)).send({ idempotency_key: key(), mode: "simulation", ...body });
const assist = () => putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin1.id });

/** Everything an executed action could have touched. */
async function sideEffectSnapshot() {
  const one = async (sql: string) => JSON.stringify((await query(sql)).rows);
  return [
    await one("SELECT tenant_id, ip, revoked_at, expires_at FROM ip_blocks ORDER BY ip"),
    await one("SELECT id, status FROM alerts ORDER BY id"),
    await one("SELECT id, resolution FROM payment_checks ORDER BY id"),
    await one("SELECT count(*)::int AS n FROM notification_outbox"),
    await one("SELECT id, status FROM users ORDER BY id"),
  ].join("|");
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  admin1 = await store.insertUser({ email: "a1@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  admin2 = await store.insertUser({ email: "a2@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tenantA, role: "analyst", status: "active" });
  viewer = await store.insertUser({ email: "v@a.io", password_hash: h, tenant_id: tenantA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "a@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
  await store.insertAlert({ id: "SEC-1", tenant_id: tenantA, title: "Brute force", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 80,
    ai_explanation: null, explained_at: null, source_ip: "185.220.101.4", target: "web-01", mitre_technique: null, source: "wazuh" });
});

describe("the door: validation", () => {
  it("unknown actions, bad input, extra fields, live mode and bad keys are refused before anything is stored", async () => {
    await propose(analyst, { action_id: "shell.exec", input: {} }).expect(422);
    await propose(analyst, { action_id: "ip.block", input: { ip: "not-an-ip", minutes: 30 } }).expect(422);
    await propose(analyst, { action_id: "ip.block", input: { ip: "185.220.101.4", minutes: 30, sudo: true } }).expect(422);
    await propose(analyst, { action_id: "ip.block", input: { ip: "185.220.101.4", minutes: 30 }, mode: "live" }).expect(403);   // only an administrator, and only where protection is on
    await propose(analyst, { action_id: "ip.block", input: { ip: "185.220.101.4", minutes: 30 }, mode: "autopilot" }).expect(422);
    await propose(analyst, { action_id: "ip.block", input: { ip: "185.220.101.4", minutes: 30 }, idempotency_key: "x" }).expect(422);
    // The caller cannot say who is acting or where the request came from.
    await propose(analyst, { action_id: "alert.set_status", input: { alert_id: "SEC-1", status: "resolved" }, actor: { kind: "agent", agent: "Vanguard" } }).expect(422);
    await propose(analyst, { action_id: "alert.set_status", input: { alert_id: "SEC-1", status: "resolved" }, origin: "system" }).expect(422);
    expect((await query("SELECT count(*)::int AS n FROM action_requests")).rows[0].n).toBe(0);
  });

  it("the database itself refuses an unknown mode, and a high-risk action that runs without approval", async () => {
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    await expect(query("UPDATE action_requests SET execution_mode = 'autopilot' WHERE id = $1", [action.id])).rejects.toThrow(/check constraint/);
    await expect(query("UPDATE action_requests SET status = 'queued' WHERE id = $1", [action.id])).rejects.toThrow(/check constraint/);
    // An AI-produced action never runs live on its own, even if code tried: it needs an approval.
    await expect(query("UPDATE action_requests SET execution_mode = 'live', origin = 'llm', status = 'queued', policy_decision = 'ALLOW' WHERE id = $1", [action.id])).rejects.toThrow(/check constraint/);
  });

  it("needs actions:propose (analyst) to propose and actions:read to look", async () => {
    await propose(viewer, { action_id: "alert.triage", input: { alert_id: "SEC-1" } }).expect(403);
    await request(app).get("/actions").set(...as(viewer)).expect(403);
    await propose(analyst, { action_id: "alert.triage", input: { alert_id: "SEC-1" } }).expect(201);
  });
});

describe("the door: policy decides, enforced on this path", () => {
  it("D0 (no policy): an agent's block is only recorded — no approval request, nothing runs", async () => {
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    expect(action).toMatchObject({ status: "recorded", policy_decision: "RECORD_ONLY", approval_id: null, actor: { kind: "agent", agent: "Vanguard" } });
    expect((await query("SELECT enforcement, call_site FROM policy_decisions WHERE tenant_id = $1", [tenantA])).rows).toEqual([{ enforcement: "enforced", call_site: "action_engine" }]);
  });

  it("a DENY rule refuses it", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [{ id: "no", effect: "DENY", actions: ["ip.block"] }] }, { expectedVersion: 0, userId: admin1.id });
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    expect(action).toMatchObject({ status: "denied", approval_id: null });
  });

  it("an agent may not propose what the catalog does not give it", async () => {
    const { action } = await proposeAction(tenantA, vanguard("alert.set_status", { alert_id: "SEC-1", status: "resolved" }, { actor: { kind: "agent", agent: "Hunter" } }));
    expect(action.status).toBe("denied");
  });

  it("shadow mode only evaluates and records — even when approval would be needed", async () => {
    await assist();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }, { mode: "shadow" }));
    expect(action).toMatchObject({ status: "recorded", policy_decision: "REQUIRE_APPROVAL", approval_id: null });
    expect((await query("SELECT count(*)::int AS n FROM approval_requests")).rows[0].n).toBe(0);
  });
});

describe("the response agent was renamed from Executor to Vanguard", () => {
  it("an action and an approval stored under the old name are shown (and decided) under the new one", async () => {
    await assist();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.9", minutes: 30 }));
    // Simulate rows written before the rename. The digest covers the action, not this label, so approving still works.
    await query("UPDATE action_requests SET actor = jsonb_set(actor, '{agent}', '\"Executor\"') WHERE id = $1", [action.id]);
    await query("UPDATE approval_requests SET requested_by = jsonb_set(requested_by, '{agent}', '\"Executor\"') WHERE id = $1", [action.approval_id]);
    const shown = (await request(app).get(`/approvals/${action.approval_id}`).set(...as(analyst)).expect(200)).body;
    expect(shown.requested_by).toMatchObject({ kind: "agent", agent: "Vanguard" });
    const list = (await request(app).get("/actions").set(...as(analyst)).expect(200)).body.actions as Array<{ id: string; actor: { agent?: string } }>;
    expect(list.find((a) => a.id === action.id)!.actor.agent).toBe("Vanguard");
    const res = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin1)).send({ decision: "approve", action_digest: action.action_digest }).expect(200);
    expect(res.body.action.status).toBe("simulated");
  });
});

describe("approval → simulation, end to end", () => {
  it("ASSIST: an agent's block waits for a person; once approved it is simulated, and nothing is blocked", async () => {
    await assist();
    const before = await sideEffectSnapshot();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    expect(action).toMatchObject({ status: "awaiting_approval", approval_id: expect.any(String) });
    const approval = (await request(app).get(`/approvals/${action.approval_id}`).set(...as(analyst)).expect(200)).body;
    expect(approval).toMatchObject({ subject_id: action.id, action_digest: action.action_digest, risk_class: "R3", status: "pending" });

    const res = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin1)).send({ decision: "approve", action_digest: action.action_digest }).expect(200);
    expect(res.body.action).toMatchObject({ id: action.id, status: "simulated", result: { would: "block", ip: "185.220.101.4", side_effects: "none" } });
    expect((await query("SELECT status FROM approval_requests WHERE id = $1", [action.approval_id])).rows[0].status).toBe("consumed");
    expect(await sideEffectSnapshot()).toBe(before);
    const events = (await request(app).get(`/actions/${action.id}`).set(...as(analyst)).expect(200)).body.events.map((e: { to_status: string }) => e.to_status);
    expect(events).toEqual(["awaiting_approval", "queued", "running", "simulated"]);
  });

  it("a rejection ends it; nothing runs", async () => {
    await assist();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    const res = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin1)).send({ decision: "reject", action_digest: action.action_digest }).expect(200);
    expect(res.body.action.status).toBe("rejected");
    expect((await runQueued(tenantA, action.id))!.status).toBe("rejected");
  });

  it("critical (R4): a person's own request still needs two OTHER people; the asker cannot approve", async () => {
    const res = await propose(admin1, { action_id: "account.disable", input: { account: "jdoe", system: "entra" } }).expect(201);
    const action = res.body.action;
    expect(action).toMatchObject({ status: "awaiting_approval", risk_class: "R4", actor: { kind: "human", user_id: admin1.id } });
    const r = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin1)).send({ decision: "approve", action_digest: action.action_digest }).expect(403);
    expect(r.body.code).toBe("self_approval");
  });

  it("an approval that expired before it could be used expires the action instead of running it", async () => {
    await assist();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    // Paused: the approval is granted but cannot be used yet.
    await request(app).post("/actions/controls").set(...as(admin1)).send({ paused: true }).expect(200);
    const res = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin1)).send({ decision: "approve", action_digest: action.action_digest }).expect(200);
    expect(res.body.action.status).toBe("awaiting_approval");
    await query("UPDATE approval_requests SET created_at = now() - interval '5 hours', expires_at = now() - interval '1 second' WHERE id = $1", [action.approval_id]);
    await request(app).post("/actions/controls").set(...as(admin1)).send({ paused: false }).expect(200);
    expect((await syncWithApproval(tenantA, action.id, { kind: "system", component: "t" }))!.status).toBe("expired");
    expect((await runQueued(tenantA, action.id))!.status).toBe("expired");
    // Settled: syncing again changes nothing.
    expect((await syncWithApproval(tenantA, action.id, { kind: "system", component: "t" }))!.status).toBe("expired");
  });

  it("a person acting directly on R1–R3 is simulated at once; a model-proposed action is not", async () => {
    const res = await propose(analyst, { action_id: "alert.set_status", input: { alert_id: "SEC-1", status: "resolved" } }).expect(201);
    expect(res.body.action).toMatchObject({ status: "simulated", result: { would: "change_status", from: "open", to: "resolved" } });
    expect((await store.getAlert(tenantA, "SEC-1"))!.status).toBe("open"); // simulated, not done
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [{ id: "all", effect: "ALLOW", actions: ["*"] }] }, { expectedVersion: 0, userId: admin1.id });
    const { action } = await proposeAction(tenantA, { ...vanguard("alert.set_status", { alert_id: "SEC-1", status: "resolved" }), actor: { kind: "agent", agent: "Oracle" }, origin: "llm" });
    expect(action.status).toBe("awaiting_approval");
  });
});

describe("idempotency and run-once", () => {
  it("the same key returns the same request; the same key for a different action is refused", async () => {
    const k = key();
    const first = await propose(analyst, { action_id: "alert.triage", input: { alert_id: "SEC-1" }, idempotency_key: k }).expect(201);
    const again = await propose(analyst, { action_id: "alert.triage", input: { alert_id: "SEC-1" }, idempotency_key: k }).expect(200);
    expect(again.body).toMatchObject({ replayed: true, action: { id: first.body.action.id } });
    const other = await propose(analyst, { action_id: "alert.explain", input: { alert_id: "SEC-1" }, idempotency_key: k }).expect(409);
    expect(other.body.code).toBe("idempotency_conflict");
  });

  it("five identical proposals at once make one request", async () => {
    const p = vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 });
    const out = await Promise.all(Array.from({ length: 5 }, () => proposeAction(tenantA, p)));
    expect(new Set(out.map((o) => o.action.id)).size).toBe(1);
    expect((await query("SELECT count(*)::int AS n FROM action_requests")).rows[0].n).toBe(1);
  });

  it("a queued action is simulated exactly once, however many workers try", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] }, { expectedVersion: 0, userId: admin1.id });
    const { action } = await proposeAction(tenantA, { ...vanguard("alert.set_status", { alert_id: "SEC-1", status: "investigating" }), actor: { kind: "agent", agent: "Oracle" } });
    expect(action.status).toBe("queued");
    await Promise.all(Array.from({ length: 5 }, () => runQueued(tenantA, action.id)));
    const row = (await query("SELECT status, attempts FROM action_requests WHERE id = $1", [action.id])).rows[0];
    expect(row).toEqual({ status: "simulated", attempts: 1 });
    expect((await query("SELECT count(*)::int AS n FROM action_events WHERE action_id = $1 AND to_status = 'running'", [action.id])).rows[0].n).toBe(1);
  });
});

describe("emergency stop, cancel, isolation, audit trail", () => {
  it("pausing refuses new actions and holds queued ones until resumed (admin only)", async () => {
    await request(app).post("/actions/controls").set(...as(analyst)).send({ paused: true }).expect(403);
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] }, { expectedVersion: 0, userId: admin1.id });
    const { action } = await proposeAction(tenantA, { ...vanguard("alert.set_status", { alert_id: "SEC-1", status: "investigating" }), actor: { kind: "agent", agent: "Oracle" } });
    await request(app).post("/actions/controls").set(...as(admin1)).send({ paused: true, reason: "incident review" }).expect(200);
    expect((await propose(analyst, { action_id: "alert.triage", input: { alert_id: "SEC-1" } }).expect(423)).body.code).toBe("paused");
    expect((await runQueued(tenantA, action.id))!.status).toBe("queued");
    await request(app).post("/actions/controls").set(...as(admin1)).send({ paused: false }).expect(200);
    expect((await runQueued(tenantA, action.id))!.status).toBe("simulated");
    const audit = (await query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'actions.%' ORDER BY created_at", [tenantA])).rows.map((r) => r.action);
    expect(audit).toEqual(["actions.paused", "actions.resumed"]);
  });

  it("cancelling a waiting action withdraws its approval request", async () => {
    await assist();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    await request(app).post(`/actions/${action.id}/cancel`).set(...as(analyst)).expect(200);
    const late = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin1)).send({ decision: "approve", action_digest: action.action_digest }).expect(409);
    expect(late.body.code).toBe("already_settled");
    await request(app).post(`/actions/${action.id}/cancel`).set(...as(analyst)).expect(409);
  });

  it("another workspace cannot see, cancel or approve it", async () => {
    await assist();
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    await request(app).get(`/actions/${action.id}`).set(...as(adminB)).expect(404);
    await request(app).post(`/actions/${action.id}/cancel`).set(...as(adminB)).expect(404);
    expect((await request(app).get("/actions").set(...as(adminB)).expect(200)).body.actions).toEqual([]);
    // An alert id from another workspace is simply not found by the simulator.
    const res = await request(app).post("/actions").set(...as(adminB)).send({ idempotency_key: key(), mode: "simulation", action_id: "alert.triage", input: { alert_id: "SEC-1" } }).expect(201);
    expect(res.body.action.result).toMatchObject({ would: "refuse", why: "alert_not_found" });
  });

  it("the state history is append-only", async () => {
    const { action } = await proposeAction(tenantA, vanguard("ip.block", { ip: "185.220.101.4", minutes: 30 }));
    await expect(query("UPDATE action_events SET to_status = 'simulated' WHERE action_id = $1", [action.id])).rejects.toThrow(/append-only/);
    await expect(query("DELETE FROM action_events WHERE action_id = $1", [action.id])).rejects.toThrow(/append-only/);
  });
});

describe("v0 has no path to a side effect", () => {
  it("simulating every catalog action changes nothing anywhere", async () => {
    await query(
      `INSERT INTO payment_checks (tenant_id, id, amount, currency, beneficiary_hash, beneficiary_hint, decision, reasons)
       VALUES ($1, 'PAY-00000000000000AA', 9000, 'EUR', $2, '…1234', 'hold', '{}')`, [tenantA, "a".repeat(64)],
    );
    const inputs: Record<string, unknown> = {
      "alert.explain": { alert_id: "SEC-1" }, "alert.triage": { alert_id: "SEC-1" }, "alert.set_status": { alert_id: "SEC-1", status: "resolved" },
      "notify.admins": { subject: "Look at SEC-1", alert_id: "SEC-1" }, "ip.unblock": { ip: "185.220.101.4" }, "ip.block": { ip: "185.220.101.4", minutes: 30 },
      "payment.reject": { payment_id: "PAY-00000000000000AA" }, "payment.release": { payment_id: "PAY-00000000000000AA" },
      "account.disable": { account: "jdoe", system: "okta" }, "host.isolate": { host: "web-01" },
    };
    expect(Object.keys(inputs).sort()).toEqual(catalogList().map((c) => c.id).sort());
    const before = await sideEffectSnapshot();
    for (const [action_id, input] of Object.entries(inputs)) {
      const res = await propose(admin1, { action_id, input }).expect(201);
      let action = res.body.action;
      if (action.status === "awaiting_approval") {
        // R4: two other admins approve (MFA is enforced by the approval route; here the engine is exercised directly).
        await query("UPDATE approval_requests SET status = 'approved', approvals = required_approvals, decided_at = now() WHERE id = $1", [action.approval_id]);
        await syncWithApproval(tenantA, action.id, { kind: "system", component: "test" });
        action = await runQueued(tenantA, action.id);
      }
      expect(action.status, action_id).toBe("simulated");
      expect(action.result.side_effects, action_id).toBe("none");
    }
    expect(await sideEffectSnapshot()).toBe(before);
  });

  it("only actions/live.ts can change anything outside the engine's own tables — the engine and the simulator cannot", () => {
    const dir = join(__dirname, "..", "src", "actions");
    const read = (f: string) => readFileSync(join(dir, f), "utf8");
    expect(readdirSync(dir).sort()).toEqual(["engine.ts", "live.ts", "simulate.ts"]);   // a new file here needs this test read again
    const engine = read("engine.ts"), sim = read("simulate.ts"), live = read("live.ts");

    // The engine decides, queues and records. It reaches the outside world only through live.ts (and queues
    // the administrators' notices, which are rows in the outbox, sent later by the worker).
    for (const forbidden of [/\baddBlock\b/, /\brevokeBlock\b/, /\bresolvePayment\b/, /\bupdateAlertStatus\b/, /\bsendMail\b/, /\bfetch\(/, /mailer\.js/, /outbox\.js/, /child_process/,
      /\benqueue(?!Job\(|ProtectionNotice\()\w*\(/]) {
      expect(engine, `engine ${forbidden}`).not.toMatch(forbidden);
      expect(sim, `simulate ${forbidden}`).not.toMatch(forbidden);
    }
    // The only job the engine may queue is the running of its own action (runtime/worker.ts "action.run").
    const kinds = [...engine.matchAll(/enqueueJob\([^,]+,[^,]+,\s*"([^"]+)"/g)].map((m) => m[1]);
    expect(new Set(kinds)).toEqual(new Set(["action.run"]));
    expect(sim).not.toMatch(/\b(INSERT|UPDATE|DELETE)\b/);
    expect(engine).not.toMatch(/blocklist\.js/);   // the simulator reads the blocklist; only live.ts (and not the engine) may write to it

    // live.ts is the one door out, and it is small and closed: exactly the catalog's live actions, no shell,
    // no network call, no way to send mail directly, nothing that moves money or edits an alert.
    for (const forbidden of [/child_process/, /\bfetch\(/, /\bsendMail\b/, /mailer\.js/, /\bresolvePayment\b/, /\bupdateAlertStatus\b/, /\brevokeBlock\b/]) {
      expect(live, `live ${forbidden}`).not.toMatch(forbidden);
    }
    const executors = [...live.matchAll(/^  "([a-z]+\.[a-z_]+)": async/gm)].map((m) => m[1]).sort();
    expect(executors).toEqual([...LIVE_ACTION_IDS].sort());
  });
});
