/**
 * Rate limits and resource budgets on the SOC core, proven by pushing past
 * them: the global limiter stops a flood, oversized bodies and payloads are
 * refused, and the growth cost of one action is measured so the retention
 * gap is a number, not a feeling.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";

let tenant: string; let admin: User; let analyst: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const OUT = process.env.E2E_REPORT_DIR || join(process.env.TMPDIR || "/tmp", "legion-e2e");

beforeAll(async () => { await migrate(); mkdirSync(OUT, { recursive: true }); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  delete process.env.LEGION_ENFORCE_RATE_LIMITS;
  await truncateAll();
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business')", [tenant]);
  const h = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "a@a.io", password_hash: h, tenant_id: tenant, role: "admin", status: "active" });
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tenant, role: "analyst", status: "active" });
});

describe("rate limits", () => {
  it("the global API limiter stops a flood against the SOC routes (429 with Retry-After), then recovers", async () => {
    const limit = config.apiRateLimit;
    const statuses: number[] = [];
    process.env.LEGION_ENFORCE_RATE_LIMITS = "1"; // limiting is off under NODE_ENV=test unless a test turns it on
    // Concurrent in modest batches so it finishes quickly but still counts every request.
    for (let i = 0; i < limit + 60; i += 30) {
      const batch = await Promise.all(Array.from({ length: 30 }, (_, j) => request(app).get("/actions").set(...as(analyst)).set("x-test-n", String(i + j))));
      statuses.push(...batch.map((r) => r.status));
      if (batch.some((r) => r.status === 429)) { expect(batch.find((r) => r.status === 429)!.headers["retry-after"]).toBeDefined(); break; }
    }
    try {
      expect(statuses.filter((s) => s === 200).length).toBeLessThanOrEqual(limit + 5);
      expect(statuses).toContain(429);
    } finally { delete process.env.LEGION_ENFORCE_RATE_LIMITS; }
  }, 120_000);
});

describe("action budget per workspace", () => {
  const saved = config.socActionsPerHour;
  it("refuses requests beyond the hourly budget (429), still serves replays, and does not touch another workspace; the window slides", async () => {
    await store.insertAlert({ id: "SEC-B", tenant_id: tenant, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
    const other = randomUUID();
    await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'B', 'business')", [other]);
    const adminB = await store.insertUser({ email: "b@b.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: other, role: "analyst", status: "active" });
    config.socActionsPerHour = 10;
    try {
      const propose = (u: User, key: string) => request(app).post("/actions").set(...as(u)).send({ action_id: "alert.triage", input: { alert_id: "SEC-B" }, mode: "simulation", idempotency_key: key });
      for (let i = 0; i < 10; i++) expect((await propose(analyst, `budget-${i}-aaaaaaaa`)).status).toBe(201);
      const over = await propose(analyst, "budget-over-aaaaaaaa");
      expect(over.status).toBe(429);
      expect(over.body.code).toBe("budget");
      expect((await propose(analyst, "budget-3-aaaaaaaa")).status).toBe(200); // a replay is free
      expect((await propose(adminB, "other-tenant-aaaaaaaa")).status).toBe(201); // per workspace
      await query("UPDATE action_requests SET created_at = now() - interval '2 hours' WHERE tenant_id = $1", [tenant]);
      expect((await propose(analyst, "budget-after-aaaaaaaa")).status).toBe(201); // the hour moved on
    } finally { config.socActionsPerHour = saved; }
  });
});

describe("payload and body budgets", () => {
  it("refuses an oversized request body before it is parsed into a handler", async () => {
    const big = "x".repeat(3 * 1024 * 1024);
    const r = await request(app).post("/actions").set(...as(analyst)).send({ action_id: "alert.triage", input: { alert_id: big }, mode: "simulation", idempotency_key: "oversize-0001" });
    expect([413, 422]).toContain(r.status);
  });
  it("action input is capped (strict schema + 8 KB), policy documents at 64 KB / 100 rules, memory text at 2,000 characters", async () => {
    expect((await request(app).post("/actions").set(...as(analyst)).send({ action_id: "notify.admins", input: { subject: "s".repeat(5000) }, mode: "simulation", idempotency_key: "cap-input-0001" })).status).toBe(422);
    const pol = await request(app).put("/policy").set(...as(admin)).send({ expected_version: 0, document: { schema: 1, default_autonomy: "OBSERVE", rules: Array.from({ length: 101 }, (_, i) => ({ id: `r${i}`, effect: "DENY", actions: ["*"] })) } });
    expect(pol.status).toBe(422);
    expect((await request(app).post("/memory").set(...as(analyst)).send({ kind: "note", subject_type: "host", subject_key: "web-01", content: "x".repeat(2001) })).status).toBe(422);
  });
});

describe("growth budget (measured)", () => {
  it("records how much storage one action costs, and shows nothing prunes the SOC history tables", async () => {
    const N = 100;
    await store.insertAlert({ id: "SEC-G", tenant_id: tenant, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
    const size = async () => Number((await query("SELECT sum(pg_total_relation_size(c.oid))::bigint AS b FROM pg_class c WHERE c.relname IN ('action_requests','action_events','policy_decisions','soc_audit_events','soc_jobs','approval_requests','approval_decisions')")).rows[0].b);
    const before = await size();
    for (let i = 0; i < N; i++) {
      const r = await request(app).post("/actions").set(...as(analyst)).send({ action_id: "alert.triage", input: { alert_id: "SEC-G" }, mode: "simulation", idempotency_key: `growth-${i}-${randomUUID()}` });
      expect(r.status).toBe(201);
      if (i % 25 === 24) await new Promise((res) => setTimeout(res, 1100)); // stay under the request limiter
    }
    const rows = {
      action_requests: (await query("SELECT count(*)::int AS n FROM action_requests")).rows[0].n,
      action_events: (await query("SELECT count(*)::int AS n FROM action_events")).rows[0].n,
      policy_decisions: (await query("SELECT count(*)::int AS n FROM policy_decisions")).rows[0].n,
      soc_audit_events: (await query("SELECT count(*)::int AS n FROM soc_audit_events")).rows[0].n,
      soc_jobs: (await query("SELECT count(*)::int AS n FROM soc_jobs")).rows[0].n,
    };
    const perAction = Math.round((await size() - before) / N);
    // Does any retention job touch these tables?  Read the code, not the docs.
    const { readFileSync } = await import("node:fs");
    const retention = readFileSync(join(__dirname, "..", "src", "retention.ts"), "utf8") + readFileSync(join(__dirname, "..", "src", "plan-limits.ts"), "utf8");
    const pruned = ["action_requests", "action_events", "policy_decisions", "soc_audit_events", "soc_jobs", "approval_requests", "workflow_runs"].filter((t) => retention.includes(t));
    writeFileSync(join(OUT, "growth.json"), JSON.stringify({ actions: N, bytes_per_action_incl_indexes: perAction, rows, tables_pruned_by_retention: pruned, request_limit_per_minute: config.apiRateLimit,
      worst_case_per_client_per_day_mb: Math.round((perAction * config.apiRateLimit * 60 * 24) / 1_048_576) }, null, 2));
    expect(perAction).toBeGreaterThan(0);
    expect(rows.action_requests).toBe(N);
    expect(rows.soc_audit_events).toBeGreaterThanOrEqual(N * 3);
    // Documented gap (K-2 in PRODUCTION-READINESS-ASSESSMENT.md): no retention on the SOC history tables yet.
    expect(pruned).toEqual([]);
  }, 120_000);
});
