/**
 * The pilot's alert rules and dashboard are only worth having if every metric
 * they name really exists. This reads monitoring/alerts.yml and the Grafana
 * dashboard and checks each legion_* name against what GET /metrics emits —
 * so renaming or dropping a metric breaks CI instead of silently blinding an alert.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import request from "supertest";
import { app } from "../src/index.js";
import { closePool, migrate } from "../src/db/pool.js";
import { config } from "../src/config.js";

const ROOT = join(__dirname, "..", "..");
const read = (p: string) => readFileSync(join(ROOT, p), "utf8");
const TOKEN = "monitoring-token-0123456789abcdef012345";
const saved = config.healthMetricsToken;
let emitted: Set<string>;

beforeAll(async () => {
  await migrate();
  config.healthMetricsToken = TOKEN;
  const text = (await request(app).get("/metrics").set("Authorization", `Bearer ${TOKEN}`).expect(200)).text;
  emitted = new Set(text.split("\n").filter((l) => l && !l.startsWith("#")).map((l) => l.split(/[{ ]/)[0]!));
});
afterAll(async () => { config.healthMetricsToken = saved; await closePool(); });

const names = (text: string) => [...new Set(text.match(/\blegion_[a-z0-9_]+/g) ?? [])];
// Prometheus appends these to counters/histograms; alert text may mention them.
const known = (n: string) => emitted.has(n) || emitted.has(n.replace(/_(total|count|sum|bucket)$/, ""));

describe("pilot monitoring references real metrics", () => {
  it("every metric used by an alert rule is emitted", () => {
    const used = names(read("monitoring/alerts.yml").split("\n").filter((l) => /^\s+expr:/.test(l)).join("\n"));
    expect(used.length).toBeGreaterThan(10);
    expect(used.filter((n) => !known(n))).toEqual([]);
  });

  it("every metric on the dashboard is emitted", () => {
    const dash = JSON.parse(read("monitoring/grafana/dashboards/legion-pilot.json"));
    const exprs = (dash.panels as Array<{ targets?: Array<{ expr: string }> }>).flatMap((p) => (p.targets ?? []).map((t) => t.expr)).join("\n");
    const used = names(exprs);
    expect(used.length).toBeGreaterThan(15);
    expect(used.filter((n) => !known(n))).toEqual([]);
    expect(dash.panels.filter((p: { type: string }) => p.type !== "row").length).toBeGreaterThanOrEqual(25);
  });

  it("the safety invariants are alerted on, with a page for the live-action check", () => {
    const alerts = read("monitoring/alerts.yml");
    expect(alerts).toMatch(/alert: LegionLiveActionDetected[\s\S]*?expr: legion_soc_actions_live > 0 and on\(\) legion_soc_workspaces_protection_active == 0[\s\S]*?severity: page/);
    for (const a of ["LegionApiDown", "LegionSocWorkerStopped", "LegionSocWorkerStale", "LegionSocJobsBacklog", "LegionSocDeadJobs", "LegionActionStuckRunning", "LegionApprovalWaitingTooLong"]) {
      expect(alerts, a).toContain(`alert: ${a}`);
    }
  });

  it("every alert has a severity and a summary", () => {
    const blocks = read("monitoring/alerts.yml").split(/\n\s+- alert: /).slice(1);
    expect(blocks.length).toBeGreaterThanOrEqual(15);
    for (const b of blocks) {
      expect(b.split("\n")[0], "alert name").toMatch(/^Legion[A-Za-z]+$/);
      expect(b).toMatch(/severity: (page|ticket|info)/);
      expect(b).toMatch(/summary: \S/);
    }
  });

  it("Prometheus scrapes /metrics with a bearer token read from a file (never inline)", () => {
    const p = read("monitoring/prometheus.yml");
    expect(p).toMatch(/metrics_path: \/metrics/);
    expect(p).toMatch(/credentials_file: \S+metrics-token/);
    expect(p).not.toMatch(/credentials: /);
  });

  it("monitoring ports are bound to loopback only", () => {
    const c = read("docker-compose.monitoring.yml");
    const ports = [...c.matchAll(/ports:\s*\["([^"]+)"\]/g)].map((m) => m[1]!);
    expect(ports.length).toBe(3);
    for (const p of ports) expect(p).toMatch(/^127\.0\.0\.1:/);
  });
});
