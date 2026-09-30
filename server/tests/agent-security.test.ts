/**
 * AI agent security, end to end through the server: the policy engine's
 * CONFIRM / QUARANTINE / KILL answers take effect before the action and
 * before the agent hears back, a person — never the agent — approves, the
 * SOC hears about it as ordinary Legion alerts, and the registry shows it.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app, agentLayer } from "../src/index.js";
import { sweepBehavior } from "../src/agents.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import type { Role, User } from "../src/types.js";

let tenantA: string, tenantB: string;
let adminA: User, analystA: User, adminB: User;
let hash = "";
let alertId = "";

const bearer = (t: string) => ["Authorization", `Bearer ${t}`] as const;
const asUser = (u: User) => bearer(mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { algorithm: "HS256", expiresIn: "1h" }));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function eventually<T>(fn: () => Promise<T | undefined | null>, ms = 5_000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error("timed out");
    await sleep(50);
  }
}

async function tenant(): Promise<string> {
  const id = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + interval '14 days')", [id, `T-${id.slice(0, 6)}`]);
  return id;
}
async function user(tenantId: string, role: Role): Promise<User> {
  return store.insertUser({ email: `${role}-${randomUUID().slice(0, 8)}@example.com`, password_hash: hash, tenant_id: tenantId, role, status: "active" });
}
async function agent(admin: User, permissions: string[]) {
  const created = await request(app).post("/agents").set(...asUser(admin)).send({ name: `bot-${randomUUID().slice(0, 6)}`, permissions });
  expect(created.status, JSON.stringify(created.body)).toBe(201);
  const tok = await request(app).post("/agent/v1/token").set(...bearer(created.body.credential.secret));
  return { id: created.body.identity.id as string, token: tok.body.access_token as string, secret: created.body.credential.secret as string };
}
const policy = (admin: User, p: Record<string, unknown>) => request(app).put("/firewall/policy").set(...asUser(admin)).send(p).expect(200);
const alertsOf = async (tenantId: string, prefix: string) =>
  (await query<{ id: string; severity: string; title: string; summary: string; source: string }>(
    "SELECT id, severity, title, summary, source FROM alerts WHERE tenant_id = $1 AND id LIKE $2 ORDER BY created_at", [tenantId, `${prefix}%`])).rows;

beforeAll(async () => {
  await migrate();
  hash = await bcrypt.hash("password123", 4);
});
afterAll(async () => { await closePool(); });

beforeEach(async () => {
  tenantA = await tenant();
  tenantB = await tenant();
  adminA = await user(tenantA, "admin");
  analystA = await user(tenantA, "analyst");
  adminB = await user(tenantB, "admin");
  alertId = `A-${randomUUID().slice(0, 8)}`;
  await store.insertAlert({
    id: alertId, tenant_id: tenantA, title: "Brute force", severity: "high", agent: "Sentinel", status: "open", summary: "sshd: authentication failure",
    confidence: 80, ai_explanation: null, explained_at: null, source_ip: "45.155.205.12", target: "web-01", mitre_technique: "T1110", source: "wazuh",
  });
});

describe("AI does not silently perform sensitive actions", () => {
  it("resolving an alert waits for a person; the alert is untouched until then", async () => {
    await policy(adminA, { responses: { confirm: { permissions: ["alerts:update_status"] } } });
    const a = await agent(adminA, ["alerts:read", "alerts:update_status"]);
    const first = await request(app).patch(`/agent/v1/alerts/${alertId}/status`).set(...bearer(a.token)).send({ status: "resolved" });
    expect(first.status).toBe(403);
    expect(first.body.error).toMatchObject({ code: "approval_required", decision: "CONFIRM" });
    expect((await store.getAlert(tenantA, alertId))!.status).toBe("open");

    // The SOC is asked, as an ordinary alert.
    const approvalId: string = first.body.error.approval.id;
    const [asked] = await eventually(async () => { const r = await alertsOf(tenantA, `AGENT-APPROVAL-${approvalId}`); return r.length ? r : null; });
    expect(asked).toMatchObject({ severity: "medium", source: "legion-agent-security" });
    expect(asked!.summary).toContain(`/firewall/approvals/${approvalId}/approve`);

    // The agent cannot answer for itself.
    expect((await request(app).post(`/firewall/approvals/${approvalId}/approve`).set(...bearer(a.token)).send({})).status).toBeGreaterThanOrEqual(401);
    expect((await request(app).post(`/firewall/approvals/${approvalId}/approve`).set(...asUser(adminB)).send({})).status).toBe(404);
    expect((await request(app).post(`/firewall/approvals/${approvalId}/approve`).set(...asUser(adminA)).send({ reason: "confirmed false positive" })).status).toBe(200);

    const retry = await request(app).patch(`/agent/v1/alerts/${alertId}/status`).set(...bearer(a.token)).set("x-legion-approval-id", approvalId).send({ status: "resolved" });
    expect(retry.status).toBe(200);
    expect((await store.getAlert(tenantA, alertId))!.status).toBe("resolved");
    // Once.
    const again = await request(app).patch(`/agent/v1/alerts/${alertId}/status`).set(...bearer(a.token)).set("x-legion-approval-id", approvalId).send({ status: "open" });
    expect(again.status).toBe(403);
    expect((await store.getAlert(tenantA, alertId))!.status).toBe("resolved");
  });

  it("tool writes need approval by default: no ticket, no tool run", async () => {
    await policy(adminA, { toolSecurity: { slack: { channels: { C0SECOPS1: "write" } } } });
    const a = await agent(adminA, ["tool.slack:write"]);
    const res = await request(app).post("/agent/v1/tools/authorize").set(...bearer(a.token))
      .send({ call: { kind: "slack", operation: "post_message", channel: "C0SECOPS1", text: "Scan finished" } });
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ decision: "CONFIRM", ticket: null });
  });
});

describe("containment happens before the agent hears back, and the SOC is told", () => {
  it("reaching into another tenant quarantines the agent and raises a high alert in its own tenant only", async () => {
    const a = await agent(adminA, ["tool.database:read"]);
    const res = await request(app).post("/agent/v1/tools/authorize").set(...bearer(a.token))
      .send({ call: { kind: "database", operation: "query", sql: "SELECT id FROM alerts WHERE tenant_id = $1 LIMIT 5", params: [tenantB] } });
    expect(res.status).toBe(403);
    expect(res.body).toMatchObject({ decision: "QUARANTINE", containment: { action: "quarantine", applied: true } });
    expect((await request(app).get("/agent/v1/alerts").set(...bearer(a.token))).status).toBe(401);
    const [raised] = await eventually(async () => { const r = await alertsOf(tenantA, `AGENT-FW-${res.body.decisionId}`); return r.length ? r : null; });
    expect(raised).toMatchObject({ severity: "high", source: "legion-agent-security" });
    expect(raised!.summary).toContain("sql.foreign_tenant");
    expect(await alertsOf(tenantB, "AGENT-")).toEqual([]);
    // One alert for it, not a second one for the kill-switch event it caused.
    await sleep(200);
    expect(await alertsOf(tenantA, "AGENT-SEC-")).toEqual([]);
  });

  it("sending Legion's own token out kills the agent: credentials revoked, critical alert", async () => {
    await policy(adminA, { egress: { allowedHosts: ["api.partner.example"] } });
    const a = await agent(adminA, ["tool.http:write"]);
    const res = await request(app).post("/agent/v1/tools/authorize").set(...bearer(a.token))
      .send({ call: { kind: "http", operation: "request", method: "POST", url: "https://api.partner.example/x", body: `t=${a.token}` } });
    expect(res.body.decision).toBe("KILL");
    expect((await request(app).post("/agent/v1/token").set(...bearer(a.secret))).status).toBe(401);
    const [raised] = await eventually(async () => { const r = await alertsOf(tenantA, `AGENT-FW-${res.body.decisionId}`); return r.length ? r : null; });
    expect(raised!.severity).toBe("critical");
  });

  it("a person's kill switch is an alert too", async () => {
    const a = await agent(adminA, ["alerts:read"]);
    const k = await request(app).post(`/kill-switch/agents/${a.id}`).set(...asUser(adminA)).send({ reason: "Exfiltration seen in egress logs", compromise: "confirmed" });
    expect(k.status).toBe(200);
    const [raised] = await eventually(async () => { const r = await alertsOf(tenantA, "AGENT-SEC-"); return r.length ? r : null; });
    expect(raised).toMatchObject({ severity: "critical" });
  });
});

describe("the registry and the behaviour sweep", () => {
  it("the registry lists identity, permissions, status and risk, per tenant, for people", async () => {
    const a = await agent(adminA, ["tool.database:read"]);
    await request(app).post("/agent/v1/tools/authorize").set(...bearer(a.token))
      .send({ call: { kind: "database", operation: "query", sql: "SELECT id FROM alerts WHERE tenant_id = $1 LIMIT 5", params: [tenantB] } });
    const res = await request(app).get("/agents/registry").set(...asUser(analystA));
    expect(res.status).toBe(200);
    expect(res.body.agents.find((x: { id: string }) => x.id === a.id)).toMatchObject({
      status: "suspended", canActNow: false, owner: { userId: adminA.id, active: true }, risk: { overall: "critical", containmentsInWindow: 1 },
    });
    expect((await request(app).get("/agents/registry").set(...asUser(adminB))).body.agents).toEqual([]);
  });

  it("the sweep re-assesses tenants with recent agent activity, one instance at a time", async () => {
    const a = await agent(adminA, ["alerts:read"]);
    await request(app).get("/agent/v1/alerts").set(...bearer(a.token));
    const [one, two] = await Promise.all([sweepBehavior(agentLayer.identity), sweepBehavior(agentLayer.identity)]);
    expect(Math.max(one, two)).toBeGreaterThanOrEqual(1);
    expect(Math.min(one, two)).toBe(0);
  });
});
