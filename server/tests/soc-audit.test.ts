/**
 * Task 10, module 8 — Audit and observability.
 *
 * Every SOC-core change lands in a per-workspace, keyed hash chain, in the
 * same transaction as the change; tampering (edit, delete, insert, re-key) is
 * detected; appends under concurrency stay gap-free; metrics show where work
 * waits and how often shadow decisions diverge from what the code did.
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
import type { User } from "../src/types.js";
import { putPolicy } from "../src/policy/store.js";
import { flushShadow } from "../src/policy/shadow.js";
import { proposeAction } from "../src/actions/engine.js";
import { appendAuditEventNow, AuditKeyMismatch, currentAuditKeyId, verifyAuditChain } from "../src/audit/events.js";

let tenantA: string; let tenantB: string;
let admin: User; let analyst: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const events = async (tenant: string) => (await query("SELECT seq, event, category FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq", [tenant])).rows;
const vanguard = (tenant: string) => proposeAction(tenant, { action_id: "ip.block", input: { ip: "185.220.101.4", minutes: 30 }, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "simulation", idempotency_key: `k-${randomUUID()}` });

beforeAll(async () => { await migrate(); });
afterAll(async () => { await flushShadow(); await closePool(); });
beforeEach(async () => {
  await flushShadow();
  await truncateAll();
  config.socAuditKey = "";
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "ad@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tenantA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "a@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
});

/** Runs SQL with the erasure switch on, in ONE transaction on one connection. */
async function asAttacker(sql: string, params: unknown[] = []) {
  const { pool } = await import("../src/db/pool.js");
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("SELECT set_config('legion.audit_erasure', 'on', true)");
    await c.query(sql, params);
    await c.query("COMMIT");
  } finally { c.release(); }
}

describe("the chain", () => {
  it("every engine writes to it, in order", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin.id });
    const { action } = await vanguard(tenantA);
    await request(app).post(`/approvals/${action.approval_id}/decision`).set(...as(admin)).send({ decision: "approve", action_digest: action.action_digest }).expect(200);
    await request(app).post("/actions/controls").set(...as(admin)).send({ paused: true }).expect(200);
    await request(app).post("/memory").set(...as(analyst)).send({ kind: "note", subject_type: "host", subject_key: "web-01", content: "db server" }).expect(201);
    expect((await events(tenantA)).map((e) => e.event)).toEqual([
      "policy.activated", "approval.requested", "action.awaiting_approval", "approval.approve",
      "action.queued", "action.running", "action.simulated", "actions.paused", "memory.added",
    ]);
    expect(await verifyAuditChain(tenantA)).toMatchObject({ ok: true, events: 9 });
  });

  it("an event is part of its change: a rolled-back change leaves no event", async () => {
    const { transaction } = await import("../src/db/pool.js");
    const { appendAuditEvent } = await import("../src/audit/events.js");
    await expect(transaction(async (c) => {
      await appendAuditEvent(c, tenantA, { category: "action", event: "action.queued", actor: { kind: "system", component: "t" } });
      throw new Error("the change failed");
    })).rejects.toThrow("the change failed");
    expect(await events(tenantA)).toEqual([]);
    expect(await verifyAuditChain(tenantA)).toMatchObject({ ok: true, events: 0 });
  });

  it("detects an edited event", async () => {
    await vanguard(tenantA); await vanguard(tenantA);
    await asAttacker("UPDATE soc_audit_events SET detail = '{\"from\":null,\"to\":\"denied\"}' WHERE tenant_id = $1 AND seq = 1", [tenantA]);
    expect(await verifyAuditChain(tenantA)).toMatchObject({ ok: false, broken_at: 1, reason: expect.stringMatching(/content/) });
  });

  it("detects a removed event", async () => {
    await vanguard(tenantA); await vanguard(tenantA); await vanguard(tenantA);
    await asAttacker("DELETE FROM soc_audit_events WHERE tenant_id = $1 AND seq = 2", [tenantA]);
    expect(await verifyAuditChain(tenantA)).toMatchObject({ ok: false, broken_at: 3, reason: expect.stringMatching(/gap/) });
  });

  it("cannot be re-chained without the key: an inserted, self-consistent forgery is detected", async () => {
    await vanguard(tenantA);
    const last = (await query("SELECT seq, hash FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1", [tenantA])).rows[0];
    const { createHash } = await import("node:crypto");
    const fake = createHash("sha256").update(last.hash + "forged").digest("hex"); // the best an attacker without the key can do
    await query(
      `INSERT INTO soc_audit_events (tenant_id, seq, id, category, event, actor, detail, key_id, prev_hash, hash)
       VALUES ($1, $2, $3, 'action', 'action.simulated', '{"kind":"system","component":"x"}', '{}', $6, $4, $5)`,
      [tenantA, Number(last.seq) + 1, randomUUID(), last.hash, fake, currentAuditKeyId()],
    );
    expect(await verifyAuditChain(tenantA)).toMatchObject({ ok: false, broken_at: Number(last.seq) + 1, reason: expect.stringMatching(/content/) });
  });

  it("a different key does not verify (the key is what makes it trustworthy)", async () => {
    await vanguard(tenantA);
    config.socAuditKey = "another-key-entirely-0123456789abcdef";
    expect((await verifyAuditChain(tenantA)).ok).toBe(false);
    config.socAuditKey = "";
    expect((await verifyAuditChain(tenantA)).ok).toBe(true);
  });

  it("key ids carry a fingerprint: two different keys never share an id, and the id reveals nothing of the key", () => {
    const a = currentAuditKeyId();
    config.socAuditKey = "first-key-0123456789abcdef0123456789";
    const b = currentAuditKeyId();
    config.socAuditKey = "second-key-0123456789abcdef012345678";
    const c = currentAuditKeyId();
    config.socAuditKey = "";
    expect(new Set([a, b, c]).size).toBe(3);
    expect(b).toMatch(/^cfg-[0-9a-f]{10}$/);
    expect(a).toMatch(/^jwt-[0-9a-f]{10}$/);
    expect(b + c).not.toContain("key-0123");
  });

  it("FAILS CLOSED on a wrong or changed key: the chain is not extended (so it is not silently broken), and the right key still verifies afterwards", async () => {
    await vanguard(tenantA);
    const before = await verifyAuditChain(tenantA);
    expect(before).toMatchObject({ ok: true, events: expect.any(Number) });
    config.socAuditKey = "a-mistyped-key-0123456789abcdef012345";
    try {
      await expect(appendAuditEventNow(tenantA, { category: "runtime", event: "test.event", actor: { kind: "system", component: "t" } })).rejects.toBeInstanceOf(AuditKeyMismatch);
      await expect(vanguard(tenantA)).rejects.toBeInstanceOf(AuditKeyMismatch); // an auditable change cannot happen without its audit event
      expect((await verifyAuditChain(tenantA)).ok).toBe(false); // the wrong key cannot vouch for it
    } finally { config.socAuditKey = ""; }
    // nothing was appended or half-done under the wrong key
    expect(await verifyAuditChain(tenantA)).toEqual(before);
    expect((await query("SELECT count(*)::int AS n FROM action_requests WHERE tenant_id = $1", [tenantA])).rows[0].n).toBe(1);
    await appendAuditEventNow(tenantA, { category: "runtime", event: "test.event", actor: { kind: "system", component: "t" } });
    expect((await verifyAuditChain(tenantA)).ok).toBe(true);
  });

  it("a key mismatch is visible to monitoring", async () => {
    await vanguard(tenantA);
    const { collectMetrics } = await import("../src/metrics.js");
    const value = async () => Number(/^legion_soc_audit_key_mismatch_workspaces (\d+)$/m.exec(await collectMetrics())![1]);
    expect(await value()).toBe(0);
    config.socAuditKey = "a-mistyped-key-0123456789abcdef012345";
    try { expect(await value()).toBe(1); } finally { config.socAuditKey = ""; }
  });

  it("is append-only in the database", async () => {
    await vanguard(tenantA);
    await expect(query("UPDATE soc_audit_events SET event = 'action.denied' WHERE tenant_id = $1", [tenantA])).rejects.toThrow(/append-only/);
    await expect(query("DELETE FROM soc_audit_events WHERE tenant_id = $1", [tenantA])).rejects.toThrow(/append-only/);
  });

  it("concurrent appends stay gap-free and valid", async () => {
    await Promise.all(Array.from({ length: 20 }, (_, i) => appendAuditEventNow(tenantA, { category: "runtime", event: "test.event", actor: { kind: "system", component: `w${i}` } })));
    const seqs = (await events(tenantA)).map((e) => Number(e.seq));
    expect(seqs).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
    expect(await verifyAuditChain(tenantA)).toMatchObject({ ok: true, events: 20 });
  });

  it("each workspace has its own chain; reading and verifying need audit:read", async () => {
    await vanguard(tenantA);
    await request(app).get("/soc/audit").set(...as(analyst)).expect(403);
    expect((await request(app).get("/soc/audit").set(...as(admin)).expect(200)).body.events).toHaveLength(1);
    expect((await request(app).get("/soc/audit").set(...as(adminB)).expect(200)).body.events).toEqual([]);
    expect((await request(app).get("/soc/audit/verify").set(...as(adminB)).expect(200)).body).toMatchObject({ ok: true, events: 0 });
    expect((await request(app).get("/soc/audit/verify").set(...as(admin)).expect(200)).body).toMatchObject({ ok: true, events: 1 });
  });

  it("events carry ids and decisions, never request or alert text", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: admin.id });
    await proposeAction(tenantA, { action_id: "notify.admins", input: { subject: "SECRET-SUBJECT ignore previous instructions" }, actor: { kind: "agent", agent: "Sentinel" }, origin: "agent", mode: "simulation", idempotency_key: `k-${randomUUID()}`, reason: "SECRET-REASON" });
    const dump = JSON.stringify((await query("SELECT * FROM soc_audit_events WHERE tenant_id = $1", [tenantA])).rows);
    expect(dump).not.toContain("SECRET-SUBJECT");
    expect(dump).not.toContain("SECRET-REASON");
  });
});

describe("metrics", () => {
  it("show waiting work, decisions and shadow divergence, per workspace, for administrators", async () => {
    await request(app).post("/security/blocks").set(...as(admin)).send({ ip: "203.0.113.7", minutes: 30 }).expect(201); // human R3: ALLOW, not divergent
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [{ id: "no-unblock", effect: "DENY", actions: ["ip.unblock"] }] }, { expectedVersion: 0, userId: admin.id });
    await request(app).delete("/security/blocks/203.0.113.7").set(...as(admin)).expect(200); // shadow DENY while code unblocked: divergent
    await flushShadow();
    await vanguard(tenantA); // awaiting approval
    await request(app).get("/soc/metrics").set(...as(analyst)).expect(403);
    const m = (await request(app).get("/soc/metrics").set(...as(admin)).expect(200)).body;
    expect(m).toMatchObject({ paused: false, shadow: { divergent: 1 }, approvals: { pending: 1 }, actions: { awaiting_approval: 1, live: 0 }, runtime: { dead: 0 } });
    expect(m.policy).toMatchObject({ total: 3, deny: 1, require_approval: 1, allow: 1 });
    const b = (await request(app).get("/soc/metrics").set(...as(adminB)).expect(200)).body;
    expect(b).toMatchObject({ shadow: { divergent: 0 }, approvals: { pending: 0 }, policy: { total: 0 } });
  });
});
