/**
 * K-2 (PRODUCTION-READINESS-ASSESSMENT.md): SOC history had no retention and grew without limit
 * (~6.5 KB per action). pruneSocHistory removes only FINISHED history older than the limit, keeps
 * the audit chain verifiable through an anchor, and never touches open work, legal holds or other
 * workspaces' recent data.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query, transaction } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { pruneSocHistory, SOC_TERMINAL_ACTIONS } from "../src/retention.js";
import { appendAuditEventNow, verifyAuditChain } from "../src/audit/events.js";
import type { User } from "../src/types.js";

let tA: string; let tB: string; let analystA: User; let analystB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const DAY = 86_400_000;
const count = async (table: string, tenant: string) => Number((await query(`SELECT count(*)::int AS n FROM ${table} WHERE tenant_id = $1`, [tenant])).rows[0].n);
const audit = (tenant: string, n: number) => appendAuditEventNow(tenant, { category: "controls", event: "retention.test", actor: { kind: "system" }, detail: { n } });

/** Moves every SOC row of a workspace `days` into the past (the documented erasure switch allows it). */
async function age(tenant: string, days: number) {
  await transaction(async (c) => {
    await c.query("SELECT set_config('legion.audit_erasure', 'on', true)");
    for (const t of ["action_requests", "approval_requests", "policy_decisions", "workflow_runs"]) {
      await c.query(`UPDATE ${t} SET created_at = created_at - make_interval(days => $2) WHERE tenant_id = $1`, [tenant, days]);
    }
    await c.query("UPDATE workflow_runs SET finished_at = finished_at - make_interval(days => $2) WHERE tenant_id = $1 AND finished_at IS NOT NULL", [tenant, days]);
    await c.query("UPDATE soc_jobs SET created_at = created_at - make_interval(days => $2), updated_at = updated_at - make_interval(days => $2), finished_at = finished_at - make_interval(days => $2) WHERE tenant_id = $1", [tenant, days]);
  });
}

async function propose(u: User, body: Record<string, unknown>) {
  const r = await request(app).post("/actions").set(...as(u)).send({ mode: "simulation", idempotency_key: randomUUID(), ...body });
  expect(r.status).toBe(201);
  return r.body;
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
afterEach(() => { vi.useRealTimers(); });
beforeEach(async () => {
  await truncateAll();
  await query("DELETE FROM chain_prune_anchors WHERE table_name = 'soc_audit_events'");
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  analystA = await store.insertUser({ email: "a@a.io", password_hash: h, tenant_id: tA, role: "analyst", status: "active" });
  analystB = await store.insertUser({ email: "b@b.io", password_hash: h, tenant_id: tB, role: "analyst", status: "active" });
  for (const [t, id] of [[tA, "SEC-A"], [tB, "SEC-B"]] as const) {
    await store.insertAlert({ id, tenant_id: t, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
  }
});

describe("SOC history retention", () => {
  it("removes finished history older than the limit and keeps open work, whatever its age", async () => {
    for (let i = 0; i < 3; i++) await propose(analystA, { action_id: "alert.triage", input: { alert_id: "SEC-A" } });
    // R4 always waits for two people. That action and its pending approval must survive however old they are.
    const adminA = await store.insertUser({ email: "admin@a.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tA, role: "admin", status: "active" });
    const waiting = (await propose(adminA, { action_id: "account.disable", input: { account: "jdoe", system: "entra" } })).action;
    expect(waiting.status).toBe("awaiting_approval");
    await age(tA, 400);

    const before = (await query("SELECT id, status FROM action_requests WHERE tenant_id = $1", [tA])).rows as Array<{ id: string; status: string }>;
    const finished = before.filter((r) => (SOC_TERMINAL_ACTIONS as readonly string[]).includes(r.status));
    expect(finished.length).toBeGreaterThan(0);
    expect(await count("policy_decisions", tA)).toBeGreaterThan(0);

    const removed = await pruneSocHistory(365);
    expect(removed.action_requests).toBe(finished.length);
    const left = (await query("SELECT id, status FROM action_requests WHERE tenant_id = $1", [tA])).rows as Array<{ id: string; status: string }>;
    expect(left.every((r) => !(SOC_TERMINAL_ACTIONS as readonly string[]).includes(r.status))).toBe(true);
    expect(left.map((r) => r.id)).toContain(waiting.id);
    expect(Number((await query("SELECT count(*)::int AS n FROM approval_requests WHERE tenant_id = $1 AND status = 'pending'", [tA])).rows[0].n)).toBe(1);
    expect(await count("policy_decisions", tA)).toBe(0);
    // action_events of removed actions went with them (cascade); none are orphaned.
    expect(Number((await query("SELECT count(*)::int AS n FROM action_events e WHERE NOT EXISTS (SELECT 1 FROM action_requests r WHERE r.tenant_id = e.tenant_id AND r.id = e.action_id)")).rows[0].n)).toBe(0);
  });

  it("prunes the oldest audit events and the chain still verifies from the anchor — and still detects tampering", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(Date.now() - 400 * DAY));
    for (let i = 0; i < 3; i++) await audit(tA, i);
    vi.useRealTimers();
    for (let i = 3; i < 5; i++) await audit(tA, i);
    expect((await verifyAuditChain(tA)).ok).toBe(true);
    const headBefore = (await verifyAuditChain(tA)).head;

    const removed = await pruneSocHistory(365);
    expect(removed.soc_audit_events).toBe(3);
    const v = await verifyAuditChain(tA);
    expect(v).toMatchObject({ ok: true, events: 2, head: headBefore });
    const anchor = (await query("SELECT pruned_through_seq, pruned_rows FROM chain_prune_anchors WHERE table_name = 'soc_audit_events' AND tenant_id = $1", [tA])).rows[0];
    expect(anchor).toMatchObject({ pruned_through_seq: 3, pruned_rows: 3 });

    // New events still chain on; a changed surviving event is still caught.
    await audit(tA, 5);
    expect((await verifyAuditChain(tA)).ok).toBe(true);
    await transaction(async (c) => {
      await c.query("SELECT set_config('legion.audit_erasure', 'on', true)");
      await c.query("UPDATE soc_audit_events SET detail = '{\"n\": 99}' WHERE tenant_id = $1 AND seq = 4", [tA]);
    });
    expect(await verifyAuditChain(tA)).toMatchObject({ ok: false, broken_at: 4 });
  });

  it("keeps the newest audit event even when every event is old, and a forged anchor is caught", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(Date.now() - 500 * DAY));
    for (let i = 0; i < 4; i++) await audit(tA, i);
    vi.useRealTimers();
    await pruneSocHistory(365);
    expect(await verifyAuditChain(tA)).toMatchObject({ ok: true, events: 1 });
    await query("UPDATE chain_prune_anchors SET anchor_hash = $2 WHERE table_name = 'soc_audit_events' AND tenant_id = $1", [tA, "b".repeat(64)]);
    expect(await verifyAuditChain(tA)).toMatchObject({ ok: false, reason: "previous-hash mismatch" });
  });

  it("touches nothing in a workspace on legal hold, nothing recent elsewhere, and nothing when the limit is 0", async () => {
    await propose(analystA, { action_id: "alert.triage", input: { alert_id: "SEC-A" } });
    await propose(analystB, { action_id: "alert.triage", input: { alert_id: "SEC-B" } });
    await age(tA, 400);
    const a = await count("action_requests", tA); const b = await count("action_requests", tB);
    const pa = await count("policy_decisions", tA);

    expect(Object.values(await pruneSocHistory(0)).every((n) => n === 0)).toBe(true);
    expect(await count("policy_decisions", tA)).toBe(pa);

    await query("UPDATE tenants SET legal_hold = true WHERE id = $1", [tA]);
    await pruneSocHistory(365);
    expect(await count("action_requests", tA)).toBe(a);
    expect(await count("policy_decisions", tA)).toBe(pa);
    expect(await count("action_requests", tB)).toBe(b);   // B's history is recent: kept

    await query("UPDATE tenants SET legal_hold = false WHERE id = $1", [tA]);
    await pruneSocHistory(365);
    expect(await count("policy_decisions", tA)).toBe(0);
    expect(await count("action_requests", tB)).toBe(b);
  });
});
