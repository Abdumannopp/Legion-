/**
 * Task 10, module 5 — Background Runtime.
 *
 * Jobs are enqueued atomically with the change that needs them, deduplicated,
 * claimed by one worker at a time, fenced by lease (a worker that lost its
 * lease cannot finish), retried with backoff, dead-lettered, deferred (not
 * failed) while a workspace is paused, and handlers stay inside their tenant.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query, transaction } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { insertAlertAndNotify } from "../src/outbox.js";
import type { User } from "../src/types.js";
import { putPolicy } from "../src/policy/store.js";
import { proposeAction, setPaused } from "../src/actions/engine.js";
import { claimJobs, completeJob, enqueueJob, failJob } from "../src/runtime/queue.js";
import { runOnce } from "../src/runtime/worker.js";

let tenantA: string; let tenantB: string;
let admin: User; let analyst: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const jobs = async (tenant?: string) => (await query("SELECT kind, status, attempts, last_error, payload, run_after > now() AS later FROM soc_jobs WHERE ($1::uuid IS NULL OR tenant_id = $1) ORDER BY created_at", [tenant ?? null])).rows;
const newAlert = (id: string, tenant = tenantA) => ({
  id, tenant_id: tenant, title: "Brute force", severity: "critical" as const, agent: "Sentinel" as const, status: "open" as const, summary: "s", confidence: 80,
  ai_explanation: null, explained_at: null, source_ip: "185.220.101.4", target: "web-01", mitre_technique: null, source: "wazuh",
});
const autonomous = (tenant: string, by: string) => putPolicy(tenant, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] }, { expectedVersion: 0, userId: by });
const oracleStatus = (tenant: string) => proposeAction(tenant, {
  action_id: "alert.set_status", input: { alert_id: "SEC-1", status: "investigating" }, actor: { kind: "agent", agent: "Oracle" }, origin: "agent",
  mode: "simulation", idempotency_key: `k-${randomUUID()}`,
});

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
afterEach(() => { config.orchestratorAutoMode = "off"; });
beforeEach(async () => {
  await truncateAll();
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "ad@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tenantA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "a@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
  await store.insertAlert(newAlert("SEC-1"));
});

describe("the queue", () => {
  it("a job enqueued in a transaction that rolls back does not exist", async () => {
    await expect(transaction(async (c) => {
      await enqueueJob(c, tenantA, "action.run", { action_request_id: randomUUID() }, "x");
      throw new Error("boom");
    })).rejects.toThrow("boom");
    expect(await jobs()).toEqual([]);
  });

  it("the same work is queued once", async () => {
    const a = await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: randomUUID() }, "same"));
    const b = await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: randomUUID() }, "same"));
    expect([a, b]).toEqual([true, false]);
    expect(await jobs()).toHaveLength(1);
  });

  it("two workers claiming at once never get the same job", async () => {
    for (let i = 0; i < 10; i++) await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: randomUUID() }, `j${i}`));
    const [w1, w2] = await Promise.all([claimJobs("w1", 10), claimJobs("w2", 10)]);
    const ids = [...w1, ...w2].map((j) => j.id);
    expect(ids).toHaveLength(10);
    expect(new Set(ids).size).toBe(10);
  });

  it("a worker that lost its lease cannot finish the job; the new owner can", async () => {
    await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: randomUUID() }, "lease"));
    const [old] = await claimJobs("old", 1);
    await query("UPDATE soc_jobs SET lease_until = now() - interval '1 second'");
    const [fresh] = await claimJobs("new", 1);
    expect(fresh!.id).toBe(old!.id);
    expect(fresh!.attempts).toBe(2);
    expect(await completeJob(old!)).toBe(false);
    expect(await failJob(old!, "late")).toBe("lost");
    expect(await completeJob(fresh!)).toBe(true);
    expect((await jobs())[0]).toMatchObject({ status: "done", attempts: 2 });
  });

  it("a failing job backs off, then is dead after its last attempt", async () => {
    // A payload the handler refuses (not a UUID) fails every time.
    await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: "nope" }, "bad", { maxAttempts: 2 }));
    expect(await runOnce()).toMatchObject({ claimed: 1, retried: 1 });
    expect((await jobs())[0]).toMatchObject({ status: "queued", attempts: 1, later: true, last_error: expect.any(String) });
    await query("UPDATE soc_jobs SET run_after = now()");
    expect(await runOnce()).toMatchObject({ claimed: 1, dead: 1 });
    expect((await jobs())[0]).toMatchObject({ status: "dead", attempts: 2 });
    expect(await runOnce()).toMatchObject({ claimed: 0 });
  });

  it("a job abandoned during its final attempt is dead-lettered, not retried forever", async () => {
    await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: randomUUID() }, "crash", { maxAttempts: 1 }));
    await claimJobs("crashed", 1);
    await query("UPDATE soc_jobs SET lease_until = now() - interval '1 second'");
    expect(await runOnce()).toMatchObject({ dead: 1, claimed: 0 });
    expect((await jobs())[0]).toMatchObject({ status: "dead", last_error: expect.stringMatching(/final attempt/) });
  });
});

describe("the SOC core runs through it", () => {
  it("a queued action is enqueued with it, so it is simulated even if nothing ran it inline (crash after commit)", async () => {
    await autonomous(tenantA, admin.id);
    const { action } = await oracleStatus(tenantA);
    expect(action.status).toBe("queued");
    expect(await jobs(tenantA)).toEqual([expect.objectContaining({ kind: "action.run", status: "queued" })]);
    expect(await runOnce()).toMatchObject({ claimed: 1, done: 1 });
    expect((await query("SELECT status, attempts FROM action_requests WHERE id = $1", [action.id])).rows[0]).toEqual({ status: "simulated", attempts: 1 });
    expect(await runOnce()).toMatchObject({ claimed: 0 });
  });

  it("an action already simulated inline is not run again by its job", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin.id });
    const { action } = await proposeAction(tenantA, { action_id: "ip.block", input: { ip: "185.220.101.4", minutes: 30 }, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "simulation", idempotency_key: `k-${randomUUID()}` });
    const res = await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin)).send({ decision: "approve", action_digest: action.action_digest }).expect(200);
    expect(res.body.action.status).toBe("simulated");
    expect(await runOnce()).toMatchObject({ claimed: 1, done: 1 });
    expect((await query("SELECT attempts FROM action_requests WHERE id = $1", [action.id])).rows[0].attempts).toBe(1);
  });

  it("while the workspace is paused, its jobs wait without spending attempts", async () => {
    await autonomous(tenantA, admin.id);
    const { action } = await oracleStatus(tenantA);
    await setPaused(tenantA, true, admin.id);
    expect(await runOnce()).toMatchObject({ claimed: 1, deferred: 1 });
    expect((await jobs(tenantA))[0]).toMatchObject({ status: "queued", attempts: 0, later: true });
    await setPaused(tenantA, false, admin.id);
    await query("UPDATE soc_jobs SET run_after = now()");
    expect(await runOnce()).toMatchObject({ done: 1 });
    expect((await query("SELECT status FROM action_requests WHERE id = $1", [action.id])).rows[0].status).toBe("simulated");
  });

  it("a handler works only inside its job's workspace", async () => {
    await autonomous(tenantA, admin.id);
    const { action } = await oracleStatus(tenantA);
    await query("DELETE FROM soc_jobs");
    // A job in workspace B naming A's action finds nothing there.
    await transaction((c) => enqueueJob(c, tenantB, "action.run", { action_request_id: action.id }, "cross"));
    expect(await runOnce()).toMatchObject({ done: 1 });
    expect((await query("SELECT status FROM action_requests WHERE id = $1", [action.id])).rows[0].status).toBe("queued");
  });

  it("ORCHESTRATOR_AUTO_MODE=shadow: a new alert queues the alert workflow in shadow mode, atomically with the alert", async () => {
    config.orchestratorAutoMode = "shadow";
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin.id });
    await insertAlertAndNotify(newAlert("SEC-2"));
    expect(await jobs(tenantA)).toEqual([expect.objectContaining({ kind: "workflow.run", payload: { workflow: "alert_response", alert_id: "SEC-2", mode: "shadow" } })]);
    expect(await runOnce()).toMatchObject({ done: 1 });
    const run = (await query("SELECT mode, status, started_by FROM workflow_runs WHERE tenant_id = $1", [tenantA])).rows[0];
    expect(run).toMatchObject({ mode: "shadow", status: "completed", started_by: { kind: "system", component: "runtime" } });
    expect((await query("SELECT count(*)::int AS n FROM approval_requests")).rows[0].n).toBe(0);
    expect((await query("SELECT count(*)::int AS n FROM ip_blocks")).rows[0].n).toBe(0);
    // A duplicate alert queues nothing more.
    await insertAlertAndNotify(newAlert("SEC-2"));
    expect(await jobs(tenantA)).toHaveLength(1);
  });

  it("ORCHESTRATOR_AUTO_MODE=off (default): new alerts queue no workflow", async () => {
    await insertAlertAndNotify(newAlert("SEC-3"));
    expect(await jobs(tenantA)).toEqual([]);
  });

  it("status is per workspace and for administrators", async () => {
    await autonomous(tenantA, admin.id);
    await oracleStatus(tenantA);
    await request(app).get("/runtime/status").set(...as(analyst)).expect(403);
    expect((await request(app).get("/runtime/status").set(...as(admin)).expect(200)).body).toMatchObject({ queued: 1, dead: 0, jobs: [expect.objectContaining({ kind: "action.run" })] });
    expect((await request(app).get("/runtime/status").set(...as(adminB)).expect(200)).body).toMatchObject({ queued: 0, jobs: [] });
  });
});
