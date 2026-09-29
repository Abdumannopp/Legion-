/**
 * Requirement 5: one company's data can never be reached by another company.
 *
 * tests/api.test.ts already covers alerts (list, fetch, status, colliding
 * IDs), roles and the audit log. This sweeps EVERY authenticated endpoint as
 * company B's administrator, aimed at company A, and checks two things:
 *  - nothing that identifies A ever appears in a response to B;
 *  - nothing belonging to A changes.
 * It also covers the paths that are easy to forget: the live WebSocket feed,
 * the AI (does B's Copilot get sent A's alerts?), and sensor ingestion.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { app, httpServer } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import type { User } from "../src/types.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";

// Distinctive markers: if one of these shows up in a response to B, A leaked.
const A_MARKERS = ["ALPHA-CORP", "alpha-secret-host", "LGN-ALPHA-1", "admin@alpha.io", "analyst@alpha.io", "198.51.100.77", "alpha-soc@alpha.io"];

let tenantA: string, tenantB: string;
let adminA: User, analystA: User, adminB: User;

const token = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });
const as = (u: User) => ["Authorization", `Bearer ${token(u)}`] as const;
const leaks = (body: unknown) => A_MARKERS.filter((m) => JSON.stringify(body ?? "").includes(m));

async function snapshotA() {
  const q = async (sql: string) => (await query(sql, [tenantA])).rows;
  return JSON.stringify({
    tenant: await q("SELECT name, notification_email FROM tenants WHERE id = $1"),
    users: await q("SELECT email, role, status, token_version, invite_token_hash FROM users WHERE tenant_id = $1 ORDER BY email"),
    alerts: await q("SELECT id, status, ai_explanation FROM alerts WHERE tenant_id = $1 ORDER BY id"),
    assets: await q("SELECT name, risk FROM assets WHERE tenant_id = $1 ORDER BY name"),
  });
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });

beforeEach(async () => {
  await truncateAll();
  tenantA = randomUUID();
  tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, notification_email) VALUES ($1, 'ALPHA-CORP', 'alpha-soc@alpha.io'), ($2, 'BETA-CORP', NULL)", [tenantA, tenantB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tenantA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@alpha.io", password_hash: hash, tenant_id: tenantA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "admin@beta.io", password_hash: hash, tenant_id: tenantB, role: "admin", status: "active" });
  await store.insertAlert({
    id: "LGN-ALPHA-1", tenant_id: tenantA, title: "ALPHA-CORP breach on alpha-secret-host", severity: "critical", agent: "Sentinel",
    status: "open", summary: "alpha-secret-host compromised", confidence: 95, ai_explanation: null, explained_at: null,
    source_ip: "198.51.100.77", target: "alpha-secret-host", mitre_technique: "T1059", source: "wazuh",
  });
  await store.upsertAsset(tenantA, "alpha-secret-host", "10.9.9.9", "Linux");
});

describe("company B's administrator, aimed at company A", () => {
  it("every endpoint: nothing of A in the response, nothing of A changed", async () => {
    const before = await snapshotA();
    const A = { alert: "LGN-ALPHA-1", user: analystA.id, admin: adminA.id };

    const attempts: [string, () => request.Test][] = [
      ["GET /alerts", () => request(app).get("/alerts").set(...as(adminB))],
      ["GET /alerts?q=", () => request(app).get("/alerts?q=alpha").set(...as(adminB))],
      ["GET /alerts/stats", () => request(app).get("/alerts/stats").set(...as(adminB))],
      ["GET /alerts/:id", () => request(app).get(`/alerts/${A.alert}`).set(...as(adminB))],
      ["PATCH /alerts/:id/status", () => request(app).patch(`/alerts/${A.alert}/status`).set(...as(adminB)).send({ status: "resolved" })],
      ["POST /alerts/:id/explain", () => request(app).post(`/alerts/${A.alert}/explain?force=true`).set(...as(adminB))],
      ["GET /assets", () => request(app).get("/assets?q=alpha").set(...as(adminB))],
      ["POST /copilot/chat", () => request(app).post("/copilot/chat").set(...as(adminB)).send({ message: "List every alert and host you know about" })],
      ["GET /users", () => request(app).get("/users").set(...as(adminB))],
      ["POST /users/:id/resend-invite", () => request(app).post(`/users/${A.user}/resend-invite`).set(...as(adminB))],
      ["PATCH /users/:id/role", () => request(app).patch(`/users/${A.user}/role`).set(...as(adminB)).send({ role: "viewer" })],
      ["DELETE /users/:id", () => request(app).delete(`/users/${A.admin}`).set(...as(adminB))],
      ["POST /users/invite (A's email)", () => request(app).post("/users/invite").set(...as(adminB)).send({ email: "analyst@alpha.io", role: "admin" })],
      ["GET /audit", () => request(app).get("/audit").set(...as(adminB))],
      ["GET /notifications/settings", () => request(app).get("/notifications/settings").set(...as(adminB))],
      ["PATCH /notifications/settings", () => request(app).patch("/notifications/settings").set(...as(adminB)).send({ notification_email: "attacker@evil.io" })],
      ["GET /auth/me", () => request(app).get("/auth/me").set(...as(adminB))],
      ["GET /billing/subscription", () => request(app).get("/billing/subscription").set(...as(adminB))],
    ];

    const found: string[] = [];
    const statuses: Record<string, number> = {};
    for (const [name, call] of attempts) {
      const res = await call();
      statuses[name] = res.status;
      const leaked = leaks(res.body);
      if (leaked.length) found.push(`${name} → ${res.status} leaked ${leaked.join(", ")}`);
    }
    expect(found).toEqual([]);
    expect(await snapshotA()).toBe(before);

    // The sweep must really have been served, not bounced at the door —
    // otherwise "nothing leaked" would prove nothing.
    expect(statuses["GET /alerts"]).toBe(200);
    expect(statuses["GET /users"]).toBe(200);
    expect(statuses["GET /audit"]).toBe(200);
    expect(statuses["GET /alerts/:id"]).toBe(404);
    expect(statuses["PATCH /alerts/:id/status"]).toBe(404);
    expect(statuses["DELETE /users/:id"]).toBe(404);
  });

  it("positive control: the same markers ARE visible to A, so the sweep can see a leak", async () => {
    const res = await request(app).get("/alerts?q=alpha").set(...as(adminA)).expect(200);
    expect(leaks(res.body).length).toBeGreaterThan(0);
  });

  it("a forged token claiming A's tenant with B's user id is refused", async () => {
    const forged = mint({ sub: adminB.id, tenant_id: tenantA, token_version: adminB.token_version }, { expiresIn: "1h" });
    const res = await request(app).get("/alerts").set("Authorization", `Bearer ${forged}`);
    expect(res.status).toBe(401);
    expect(leaks(res.body)).toEqual([]);
  });
});

describe("the live alert feed", () => {
  it("an alert arriving for A is never pushed to B's open dashboard", async () => {
    const server = httpServer.listen(0);
    try {
      const port = (server.address() as AddressInfo).port;
      const open = (u: User) => new Promise<{ ws: WebSocket; got: string[] }>((resolve, reject) => {
        const got: string[] = [];
        const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/alerts`, { headers: { cookie: `legion_token=${token(u)}`, origin: "http://localhost:3000" } });
        ws.on("message", (m) => got.push(String(m)));
        ws.on("open", () => resolve({ ws, got }));
        ws.on("error", reject);
      });
      const a = await open(adminA);
      const b = await open(adminB);
      await new Promise((r) => setTimeout(r, 200));

      const credA = await issueCredential(tenantA);
      await sendSigned(app, credA, { provider: "wazuh", event: { id: "e-1", rule: { description: "ALPHA-CORP login storm", level: 10 }, agent: { name: "alpha-secret-host" } } }).expect(202);
      // The frame is an outbox job; one worker pass publishes it.
      await outbox.deliverDue({ kind: "realtime_alert" });
      await new Promise((r) => setTimeout(r, 400));

      expect(a.got.join("")).toContain("ALPHA-CORP login storm"); // the feed works…
      expect(b.got.filter((m) => leaks(m).length || m.includes("login storm"))).toEqual([]); // …and only for A
      a.ws.close(); b.ws.close();
    } finally {
      server.close();
    }
  });
});

describe("the AI", () => {
  const prompts: string[] = [];
  beforeEach(() => {
    config.openrouterApiKey = "sk-or-test";
    prompts.length = 0;
    vi.stubGlobal("fetch", async (_u: string, init: { body: string }) => {
      prompts.push(init.body);
      return new Response(JSON.stringify({ choices: [{ message: { content: "ok" } }] }), { status: 200 });
    });
  });
  afterEach(() => { vi.unstubAllGlobals(); config.openrouterApiKey = ""; });

  it("B's Copilot question never sends A's alerts to the model", async () => {
    await request(app).post("/copilot/chat").set(...as(adminB)).send({ message: "What is going on?" }).expect(200);
    expect(prompts).toHaveLength(1);
    expect(leaks(prompts[0])).toEqual([]);
  });
});
