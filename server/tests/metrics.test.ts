/**
 * Pilot monitoring: GET /metrics is token-protected, absent unless configured,
 * numbers only (no tenant ids or text), and shows what an operator must watch:
 * worker heartbeat, queue age, dead and stuck work, pending approvals, paused
 * workspaces and — above all — actions outside shadow/simulation (must be 0).
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query, transaction } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { proposeAction, setPaused } from "../src/actions/engine.js";
import { enqueueJob } from "../src/runtime/queue.js";
import { putPolicy } from "../src/policy/store.js";
import { runtimeHealth, startRuntime, stopRuntime } from "../src/runtime/worker.js";

const TOKEN = "metrics-token-0123456789abcdef0123456789";
let tenantA: string; let tenantB: string;
const saved = config.healthMetricsToken;
const scrape = (token = TOKEN) => request(app).get("/metrics").set("Authorization", `Bearer ${token}`);
const metric = (text: string, name: string, labels?: string) => {
  const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = new RegExp(`^${name}${labels ? `\\{${esc(labels)}\\}` : ""} (-?[0-9.]+)$`, "m").exec(text);
  return m ? Number(m[1]) : undefined;
};

beforeAll(async () => { await migrate(); });
afterAll(async () => { stopRuntime(); config.healthMetricsToken = saved; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  config.healthMetricsToken = TOKEN;
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenantA, tenantB]);
  await store.insertUser({ email: "a@a.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenantA, role: "admin", status: "active" });
});

describe("GET /metrics", () => {
  it("does not exist unless a token is configured, and refuses a wrong or missing token", async () => {
    config.healthMetricsToken = "";
    await request(app).get("/metrics").expect(404);
    config.healthMetricsToken = TOKEN;
    await request(app).get("/metrics").expect(401);
    await scrape("wrong-token-wrong-token-wrong-token-1").expect(401);
    const ok = await scrape().expect(200);
    expect(ok.headers["content-type"]).toMatch(/^text\/plain;.*version=0\.0\.4/); // parameter order is free in the exposition format
    expect(ok.headers["cache-control"]).toBe("no-store");
  });

  it("is valid exposition text: every sample has HELP/TYPE and a numeric value", async () => {
    const text = (await scrape().expect(200)).text;
    const lines = text.trim().split("\n");
    const names = new Set(lines.filter((l) => !l.startsWith("#")).map((l) => l.split(/[{ ]/)[0]));
    for (const n of names) {
      const base = n.replace(/_(bucket|sum|count)$/, ""); // histogram series share their base name's HELP/TYPE
      const declared = text.includes(`# TYPE ${n} `) ? n : base;
      expect(text, n).toContain(`# HELP ${declared} `);
      expect(text, n).toContain(`# TYPE ${declared} `);
    }
    for (const l of lines.filter((x) => !x.startsWith("#"))) expect(l).toMatch(/^[a-z0-9_]+(\{[^}]*\})? -?[0-9.]+$/);
    expect(metric(text, "legion_up")).toBe(1);
    expect(metric(text, "legion_soc_actions_live")).toBe(0);
  });

  it("reports waiting, dead, stuck and paused work across workspaces — without naming any workspace", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "ASSIST", rules: [] }, { expectedVersion: 0, userId: (await store.listUsers(tenantA))[0]!.id });
    await proposeAction(tenantA, { action_id: "ip.block", input: { ip: "45.155.205.12", minutes: 60 }, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "simulation", idempotency_key: "metrics-pending-1" });
    await setPaused(tenantB, true, randomUUID());
    await transaction((c) => enqueueJob(c, tenantA, "action.run", { action_request_id: "x" }, "dead-one", { maxAttempts: 1 }));
    await query("UPDATE soc_jobs SET status = 'dead', attempts = 1, finished_at = now() WHERE dedupe_key = 'dead-one'");
    await transaction((c) => enqueueJob(c, tenantB, "action.run", { action_request_id: "y" }, "due-old"));
    await query("UPDATE soc_jobs SET run_after = now() - interval '90 seconds' WHERE dedupe_key = 'due-old'");
    const text = (await scrape().expect(200)).text;
    expect(metric(text, "legion_soc_approvals_pending")).toBe(1);
    expect(metric(text, "legion_soc_actions", 'status="awaiting_approval"')).toBe(1);
    expect(metric(text, "legion_soc_workspaces_paused")).toBe(1);
    expect(metric(text, "legion_soc_jobs", 'status="dead"')).toBe(1);
    expect(metric(text, "legion_soc_jobs", 'status="queued"')).toBe(1);
    expect(metric(text, "legion_soc_jobs_oldest_due_age_seconds")).toBeGreaterThanOrEqual(90);
    expect(metric(text, "legion_soc_audit_events")).toBeGreaterThan(0);
    // Counts only: no workspace id, no action text, no address.
    expect(text).not.toContain(tenantA);
    expect(text).not.toContain(tenantB);
    expect(text).not.toContain("45.155.205.12");
  });

  it("flags an action stuck in running and a lapsed lease", async () => {
    await putPolicy(tenantA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] }, { expectedVersion: 0, userId: (await store.listUsers(tenantA))[0]!.id });
    await store.insertAlert({ id: "SEC-M", tenant_id: tenantA, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
    const { action } = await proposeAction(tenantA, { action_id: "alert.set_status", input: { alert_id: "SEC-M", status: "resolved" }, actor: { kind: "agent", agent: "Oracle" }, origin: "agent", mode: "simulation", idempotency_key: "metrics-stuck-001" });
    await query("UPDATE action_requests SET status = 'running', updated_at = now() - interval '20 minutes' WHERE id = $1", [action.id]);
    await query("UPDATE soc_jobs SET status = 'running', lease_owner = 'dead-worker', lease_until = now() - interval '1 minute', attempts = 1");
    const text = (await scrape().expect(200)).text;
    expect(metric(text, "legion_soc_actions_stuck_running")).toBe(1);
    expect(metric(text, "legion_soc_jobs_expired_leases")).toBe(1);
  });

  it("counts requests by status class and times them, with no route, tenant or path in any label", async () => {
    const { resetHttpStats } = await import("../src/http-stats.js");
    resetHttpStats();
    await request(app).get("/health").expect(200);
    await request(app).get("/alerts").expect(401);
    await request(app).get("/definitely-not-a-route").expect(404);
    const text = (await scrape().expect(200)).text;
    expect(metric(text, "legion_http_requests_total", 'class="2xx"')).toBeGreaterThanOrEqual(1);
    expect(metric(text, "legion_http_requests_total", 'class="4xx"')).toBeGreaterThanOrEqual(2);
    expect(metric(text, "legion_http_requests_total", 'class="5xx"')).toBe(0);
    const count = metric(text, "legion_http_request_duration_seconds_count")!;
    expect(count).toBeGreaterThanOrEqual(3);
    expect(metric(text, "legion_http_request_duration_seconds_bucket", 'le="+Inf"')).toBe(count);
    // cumulative and monotonic
    const les = [...text.matchAll(/^legion_http_request_duration_seconds_bucket\{le="([^"]+)"\} (\d+)$/gm)].map((m) => Number(m[2]));
    expect([...les].sort((a, b) => a - b)).toEqual(les);
    expect(text).not.toMatch(/legion_http_[a-z_]+\{[^}]*(route|path|tenant)/);
  });

  it("shows the worker heartbeat", async () => {
    expect(metric((await scrape().expect(200)).text, "legion_soc_runtime_worker_running")).toBe(0);
    startRuntime(40);
    await new Promise((r) => setTimeout(r, 400));
    const text = (await scrape().expect(200)).text;
    expect(metric(text, "legion_soc_runtime_worker_running")).toBe(1);
    expect(metric(text, "legion_soc_runtime_last_tick_age_seconds")).toBeLessThan(5);
    expect(metric(text, "legion_soc_runtime_ticks_total")).toBeGreaterThan(0);
    expect(runtimeHealth().errors).toBe(0);
    stopRuntime();
  });
});
