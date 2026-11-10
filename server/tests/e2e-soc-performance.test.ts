/**
 * Task 11 — performance measurements of the SOC pipeline (single process,
 * local Postgres, simulation only). Numbers are written to perf.json in
 * E2E_REPORT_DIR. Assertions are deliberately loose ceilings that catch
 * order-of-magnitude regressions, not tuning targets.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { flushShadow } from "../src/policy/shadow.js";
import { proposeAction } from "../src/actions/engine.js";
import { runOnce } from "../src/runtime/worker.js";
import { verifyAuditChain } from "../src/audit/events.js";
import { evaluatePolicy } from "../src/policy/evaluate.js";
import { investigate } from "./helpers/soc-conductor.js";
import { as, attack, resetEnv, sendWazuh, setPolicy, wazuh, worstAlert, type SocEnv } from "./helpers/soc-env.js";

const OUT = process.env.E2E_REPORT_DIR || join(process.env.TMPDIR || "/tmp", "legion-e2e");
const savedMode = config.deploymentMode;
let E: SocEnv;
const perf: Record<string, unknown> = { env: { node: process.version, cpus: (await import("node:os")).cpus().length, note: "single process, local Postgres, simulation only" } };
const pct = (xs: number[], p: number) => { const s = [...xs].sort((a, b) => a - b); return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]! * 10) / 10; };
const stats = (xs: number[]) => ({ n: xs.length, p50_ms: pct(xs, 50), p95_ms: pct(xs, 95), max_ms: pct(xs, 100), mean_ms: Math.round((xs.reduce((a, b) => a + b, 0) / xs.length) * 10) / 10 });

beforeAll(async () => { await migrate(); config.deploymentMode = "self-hosted"; mkdirSync(OUT, { recursive: true }); });
afterAll(async () => { await flushShadow(); writeFileSync(join(OUT, "perf.json"), JSON.stringify(perf, null, 2)); config.deploymentMode = savedMode; await closePool(); });
beforeEach(async () => { E = await resetEnv(); });

describe("performance", () => {
  it("policy evaluation (pure, in memory)", async () => {
    const doc = { schema: 1 as const, default_autonomy: "ASSIST" as const, rules: Array.from({ length: 100 }, (_, i) => ({ id: `r${i}`, effect: "REQUIRE_APPROVAL" as const, actions: ["ip.block"], agents: ["Vanguard" as const] })) };
    const N = 50_000; const lat: number[] = [];
    const t0 = performance.now();
    for (let i = 0; i < N; i++) { const t = performance.now(); evaluatePolicy({ action_id: "ip.block", actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "simulation" }, doc); if (i % 50 === 0) lat.push((performance.now() - t) * 1000); }
    const secs = (performance.now() - t0) / 1000;
    perf.policy_evaluation = { rules_in_policy: 100, evaluations: N, per_second: Math.round(N / secs), p99_micros: pct(lat, 99) };
    expect(N / secs).toBeGreaterThan(5_000);
  });

  it("Wazuh webhook ingest (signature check, dedupe, alert + correlation, outbox)", async () => {
    const lat: number[] = [];
    const t0 = performance.now();
    for (let i = 0; i < 60; i++) { const t = performance.now(); await sendWazuh(E.credA, wazuh({ ip: `45.155.${i % 200}.${10 + (i % 200)}`, mitre: ["T1110"] })); lat.push(performance.now() - t); }
    const seqSecs = (performance.now() - t0) / 1000;
    const t1 = performance.now();
    await Promise.all(Array.from({ length: 5 }, async (_, w) => { for (let i = 0; i < 12; i++) await sendWazuh(E.credA, wazuh({ ip: `91.240.${w}.${i + 1}`, mitre: ["T1110"] })); }));
    const concSecs = (performance.now() - t1) / 1000;
    perf.webhook_ingest = { sequential: { ...stats(lat), events_per_second: Math.round(60 / seqSecs) }, concurrent_5_writers: { events: 60, events_per_second: Math.round(60 / concSecs) } };
    expect((await query("SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1 AND source = 'wazuh'", [E.tenantA])).rows[0].n).toBe(120);
    expect(60 / seqSecs).toBeGreaterThan(5);
  });

  it("full investigation: five agents + policy + approval + simulated action + verification", async () => {
    await setPolicy(E.tenantA, E.admin, { default_autonomy: "ASSIST" });
    const total: number[] = []; const perStep = new Map<string, number[]>(); const approve: number[] = [];
    for (let i = 0; i < 10; i++) {
      const ip = `45.155.205.${20 + i}`;
      await attack(E.credA, ip);
      const alertId = (await worstAlert(E.tenantA, ip)).id;
      const inv = await investigate({ tenantId: E.tenantA, alertId, sourceIp: ip, asset: "web-01", agents: E.agentsA, key: `perf-${i}-${randomUUID()}` });
      const t = performance.now();
      await request(app).post(`/approvals/${inv.action!.approval_id}/decision`).set(...as(E.admin)).send({ decision: "approve", action_digest: inv.action!.action_digest }).expect(200);
      approve.push(performance.now() - t);
      total.push(inv.trace.totalMs + (performance.now() - t));
      for (const s of inv.trace.steps) { const k = `${s.agent}:${s.step}`; perStep.set(k, [...(perStep.get(k) ?? []), s.ms]); }
    }
    perf.full_investigation = { runs: 10, end_to_end: stats(total), approval_decision: stats(approve), per_step_p50_ms: Object.fromEntries([...perStep].map(([k, v]) => [k, pct(v, 50)])) };
    expect(pct(total, 95)).toBeLessThan(5_000);
  });

  it("action pipeline throughput: propose → policy → queue → worker pool → simulated, with audit", async () => {
    await setPolicy(E.tenantA, E.admin, { default_autonomy: "AUTONOMOUS" });
    await store.insertAlert({ id: "SEC-P", tenant_id: E.tenantA, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
    const N = 150;
    const t0 = performance.now(); const propose: number[] = [];
    for (let i = 0; i < N; i++) { const t = performance.now(); await proposeAction(E.tenantA, { action_id: "alert.set_status", input: { alert_id: "SEC-P", status: i % 2 ? "resolved" : "investigating" }, actor: { kind: "agent", agent: "Oracle" }, origin: "agent", mode: "simulation", idempotency_key: `bulk-${i}-${randomUUID()}` }); propose.push(performance.now() - t); }
    const proposeSecs = (performance.now() - t0) / 1000;
    const t1 = performance.now();
    let drained = 0;
    while (drained < N) { const rs = await Promise.all(Array.from({ length: 4 }, (_, w) => runOnce({ owner: `w${w}`, limit: 25 }))); const d = rs.reduce((a, r) => a + r.done, 0); if (!d) break; drained += d; }
    const drainSecs = (performance.now() - t1) / 1000;
    const simulated = (await query("SELECT count(*)::int AS n FROM action_requests WHERE tenant_id = $1 AND status = 'simulated'", [E.tenantA])).rows[0].n;
    const events = (await query("SELECT count(*)::int AS n FROM soc_audit_events WHERE tenant_id = $1", [E.tenantA])).rows[0].n;
    const tv = performance.now(); const chain = await verifyAuditChain(E.tenantA); const verifyMs = performance.now() - tv;
    perf.action_pipeline = { actions: N, propose: { ...stats(propose), per_second: Math.round(N / proposeSecs) }, worker_pool_4: { drained, seconds: Math.round(drainSecs * 100) / 100, actions_per_second: Math.round(N / drainSecs) }, simulated, audit: { events, chain_ok: chain.ok, verify_ms: Math.round(verifyMs), verify_events_per_second: Math.round(events / (verifyMs / 1000)) } };
    expect(simulated).toBe(N);
    expect(chain.ok).toBe(true);
  });

  it("per-workspace audit chain under concurrent appends from the whole pipeline", async () => {
    await setPolicy(E.tenantA, E.admin, { default_autonomy: "AUTONOMOUS" });
    const t0 = performance.now();
    await Promise.all(Array.from({ length: 40 }, (_, i) => proposeAction(E.tenantA, { action_id: "alert.triage", input: { alert_id: `A-${i}` }, actor: { kind: "agent", agent: "Oracle" }, origin: "agent", mode: "shadow", idempotency_key: `conc-${i}-${randomUUID()}` })));
    const secs = (performance.now() - t0) / 1000;
    const seqs = (await query("SELECT seq FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq", [E.tenantA])).rows.map((r) => Number(r.seq));
    perf.concurrent_proposals_one_workspace = { proposals: 40, seconds: Math.round(secs * 100) / 100, per_second: Math.round(40 / secs), audit_events: seqs.length, gap_free: seqs.every((s, i) => s === i + 2 || s === i + 1) };
    expect((await verifyAuditChain(E.tenantA)).ok).toBe(true);
  });
});
