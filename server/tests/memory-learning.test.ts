/**
 * Task 10, module 7 — Memory and Learning foundation.
 *
 * Memory is written by people (never by a model), cleaned, bounded, expiring
 * and per workspace; it can only make Legion more careful. Learning counts
 * people's decisions on agents' proposals and only ever SUGGESTS.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";
import { putPolicy } from "../src/policy/store.js";
import { cancelAction, proposeAction } from "../src/actions/engine.js";
import { addMemory, pruneExpiredMemory, MAX_PER_TENANT } from "../src/memory/store.js";
import { learningSummary } from "../src/memory/learning.js";

let tenantA: string; let tenantB: string;
let admin: User; let analyst: User; let analyst2: User; let viewer: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const remember = (u: User, body: Record<string, unknown>) => request(app).post("/memory").set(...as(u)).send({ kind: "false_positive", subject_type: "ip", subject_key: "185.220.101.4", content: "Our external scanner", ...body });

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "ad@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tenantA, role: "analyst", status: "active" });
  analyst2 = await store.insertUser({ email: "an2@a.io", password_hash: h, tenant_id: tenantA, role: "analyst", status: "active" });
  viewer = await store.insertUser({ email: "v@a.io", password_hash: h, tenant_id: tenantA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "a@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
});

describe("memory", () => {
  it("people write it; the source is the session's person, never a body field", async () => {
    await remember(viewer, {}).expect(403);
    const res = await remember(analyst, {}).expect(201);
    expect(res.body.memory).toMatchObject({ source: "human", created_by: analyst.id, subject_key: "185.220.101.4", kind: "false_positive" });
    await remember(analyst, { source: "llm" }).expect(422);
    await remember(analyst, { source: "system" }).expect(422);
    await remember(analyst, { created_by: admin.id }).expect(422);
  });

  it("validates subjects per type, cleans text, bounds lifetime", async () => {
    await remember(analyst, { subject_key: "not-an-ip" }).expect(422);
    await remember(analyst, { subject_type: "host", subject_key: "web 01; rm -rf /" }).expect(422);
    await remember(analyst, { ttl_days: 400 }).expect(422);
    await remember(analyst, { kind: "allow_everything" }).expect(422);
    const res = await remember(analyst, { content: "Scanner​ of‮ ours\u0007" + String.fromCodePoint(0xe0041) }).expect(201);
    expect(res.body.memory.content).toBe("Scanner of ours");
    const days = (Date.parse(res.body.memory.expires_at) - Date.parse(res.body.memory.created_at)) / 86_400_000;
    expect(Math.round(days)).toBe(90);
    // The database refuses an entry that lives longer than a year, whatever the code does.
    await expect(query("INSERT INTO soc_memory (tenant_id, id, kind, subject_type, subject_key, content, source, expires_at) VALUES ($1, $2, 'note', 'ip', '1.2.3.4', 'x', 'human', now() + interval '2 years')", [tenantA, randomUUID()])).rejects.toThrow(/check constraint/);
    await expect(query("INSERT INTO soc_memory (tenant_id, id, kind, subject_type, subject_key, content, source, expires_at) VALUES ($1, $2, 'note', 'ip', '1.2.3.4', 'x', 'llm', now() + interval '1 day')", [tenantA, randomUUID()])).rejects.toThrow(/check constraint/);
  });

  it("is per workspace; only its author or an administrator removes it", async () => {
    const id = (await remember(analyst, {}).expect(201)).body.memory.id;
    expect((await request(app).get("/memory").set(...as(adminB)).expect(200)).body.memory).toEqual([]);
    await request(app).delete(`/memory/${id}`).set(...as(adminB)).expect(404);
    await request(app).delete(`/memory/${id}`).set(...as(analyst2)).expect(403);
    await request(app).get("/memory").set(...as(viewer)).expect(403); // memory:read is analyst and up
    expect((await request(app).get("/memory?subject_type=ip&subject_key=185.220.101.4").set(...as(analyst2)).expect(200)).body.memory).toHaveLength(1);
    await request(app).delete(`/memory/${id}`).set(...as(admin)).expect(200);
    expect((await request(app).get("/memory").set(...as(analyst)).expect(200)).body.memory).toEqual([]);
  });

  it("expired entries are invisible and pruned", async () => {
    const m = await addMemory(tenantA, { kind: "note", subject_type: "host", subject_key: "web-01", content: "x", source: "human", created_by: analyst.id, ttl_days: 1 });
    await query("UPDATE soc_memory SET created_at = now() - interval '3 days', expires_at = now() - interval '1 day' WHERE id = $1", [m.id]);
    expect((await request(app).get("/memory").set(...as(analyst)).expect(200)).body.memory).toEqual([]);
    expect(await pruneExpiredMemory()).toBe(1);
  });

  it("a workspace's memory is capped, exactly, even under concurrent writes", async () => {
    await query(
      `INSERT INTO soc_memory (tenant_id, id, kind, subject_type, subject_key, content, source, expires_at)
       SELECT $1, gen_random_uuid(), 'note', 'host', 'h' || g, 'x', 'system', now() + interval '1 day' FROM generate_series(1, $2::int) g`,
      [tenantA, MAX_PER_TENANT - 2],
    );
    const results = await Promise.all(Array.from({ length: 5 }, (_, i) => remember(analyst, { subject_type: "host", subject_key: `x${i}` })));
    expect(results.filter((r) => r.status === 201)).toHaveLength(2);
    expect(results.filter((r) => r.status === 409)).toHaveLength(3);
  });

  it("can only make Legion more careful: a harmless-marked address is not even proposed for blocking", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin.id });
    for (const [id, ip] of [["SEC-1", "185.220.101.4"], ["SEC-2", "185.220.101.5"]] as const) {
      await store.insertAlert({ id, tenant_id: tenantA, title: "Brute force", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 80,
        ai_explanation: null, explained_at: null, source_ip: ip, target: "web-01", mitre_technique: null, source: "wazuh" });
    }
    await remember(analyst, {}).expect(201);
    const marked = (await request(app).post("/workflows/alert_response/runs").set(...as(analyst)).send({ alert_id: "SEC-1", mode: "simulation" }).expect(201)).body.run;
    expect(marked.steps.find((s: { name: string }) => s.name === "contain_source")).toMatchObject({ outcome: "skipped", note: expect.stringMatching(/harmless/) });
    const other = (await request(app).post("/workflows/alert_response/runs").set(...as(analyst)).send({ alert_id: "SEC-2", mode: "simulation" }).expect(201)).body.run;
    expect(other.steps.find((s: { name: string }) => s.name === "contain_source").action_status).toBe("awaiting_approval");
    // Memory in ANOTHER workspace has no effect here.
    await query("DELETE FROM soc_memory");
    await addMemory(tenantB, { kind: "false_positive", subject_type: "ip", subject_key: "185.220.101.4", content: "x", source: "human", created_by: adminB.id, ttl_days: 1 });
    await query("DELETE FROM workflow_runs");
    const again = (await request(app).post("/workflows/alert_response/runs").set(...as(analyst)).send({ alert_id: "SEC-1", mode: "shadow" }).expect(201)).body.run;
    expect(again.steps.find((s: { name: string }) => s.name === "contain_source").outcome).toBe("proposed");
  });
});

describe("learning", () => {
  const vanguardBlock = (ip: string) => proposeAction(tenantA, { action_id: "ip.block", input: { ip, minutes: 30 }, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "simulation", idempotency_key: `k-${randomUUID()}` });

  it("counts people's decisions on machine proposals, not people's own requests", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin.id });
    const a = (await vanguardBlock("185.220.101.4")).action;
    const b = (await vanguardBlock("185.220.101.5")).action;
    const c = (await vanguardBlock("185.220.101.6")).action;
    await request(app).post(`/approvals/${a.approval_id}/decision`).set(...as(admin)).send({ decision: "approve", action_digest: a.action_digest }).expect(200);
    await request(app).post(`/approvals/${b.approval_id}/decision`).set(...as(admin)).send({ decision: "reject", action_digest: b.action_digest }).expect(200);
    await cancelAction(tenantA, c.id, { kind: "human", user_id: analyst.id, role: "analyst" });
    // A person's own R4 request is not a learning signal.
    const own = (await request(app).post("/actions").set(...as(analyst)).send({ action_id: "host.isolate", input: { host: "web-01" }, mode: "simulation", idempotency_key: `k-${randomUUID()}` }).expect(201)).body.action;
    await request(app).post(`/actions/${own.id}/cancel`).set(...as(analyst)).expect(200);
    await request(app).get("/learning").set(...as(viewer)).expect(403);
    const res = (await request(app).get("/learning").set(...as(analyst)).expect(200)).body;
    expect(res.automatic_changes).toBe(false);
    expect(res.signals.map((s: { action_id: string; signal: string; count: number }) => `${s.action_id}:${s.signal}:${s.count}`).sort())
      .toEqual(["ip.block:approved:1", "ip.block:cancelled:1", "ip.block:rejected:1"]);
    expect((await request(app).get("/learning").set(...as(adminB)).expect(200)).body.signals).toEqual([]);
  });

  it("suggests, never applies — and never suggests more autonomy for high-risk actions", async () => {
    await query("INSERT INTO learning_signals (tenant_id, action_id, signal, count) VALUES ($1, 'alert.set_status', 'approved', 40), ($1, 'ip.block', 'approved', 100), ($1, 'notify.admins', 'rejected', 30), ($1, 'notify.admins', 'approved', 5)", [tenantA]);
    const policiesBefore = (await query("SELECT count(*)::int AS n FROM policy_documents")).rows[0].n;
    const { suggestions } = await learningSummary(tenantA);
    expect(suggestions.map((s) => `${s.action_id}:${s.kind}:${s.applied}`).sort()).toEqual(["alert.set_status:consider_more_autonomy:false", "notify.admins:review_detection:false"]);
    expect(suggestions.find((s) => s.action_id === "ip.block")).toBeUndefined();
    expect((await query("SELECT count(*)::int AS n FROM policy_documents")).rows[0].n).toBe(policiesBefore);
  });
});
