/**
 * The first screen's answers (src/overview.ts): what is protected, what
 * threats are open, what Legion blocked and why, what is left to set up —
 * computed from this workspace's records only.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, viewerA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const get = async (u: User) => (await request(app).get("/overview").set(...bearer(u))).body;
const event = (id: string, level = 12) => ({ provider: "wazuh", event: { id, rule: { level, description: `rule ${id}` }, agent: { name: "web-01" } } });

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  viewerA = await store.insertUser({ email: "viewer@alpha.io", password_hash: hash, tenant_id: tA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
});

describe("protection status", () => {
  it("walks from not connected, to waiting, to attention, to protected", async () => {
    let o = await get(viewerA);
    expect(o).toMatchObject({ status: "not_connected", reasons: ["no_sources"] });
    expect(o.onboarding.steps.map((s: { id: string; done: boolean }) => [s.id, s.done])).toEqual([
      ["connect", false], ["first_event", false], ["notifications", false], ["team", true], ["agent", false]]);

    const cred = await issueCredential(tA, "HQ manager");
    o = await get(viewerA);
    expect(o).toMatchObject({ status: "waiting_for_data", reasons: ["no_events_yet"] });
    expect(o.protected.sources).toEqual([{ kind: "wazuh", name: "HQ manager", health: "waiting", last_event_at: null }]);

    // A test alert is not a sensor event.
    expect((await request(app).post("/security-events/test").set(...bearer(adminA))).status).toBe(201);
    expect((await get(viewerA)).status).toBe("waiting_for_data");

    expect((await sendSigned(app, cred, event("e1", 12))).status).toBe(202);
    o = await get(viewerA);
    expect(o.status).toBe("attention");
    expect(o.reasons).toContain("open_critical");
    expect(o.protected.sources[0]).toMatchObject({ health: "receiving" });
    expect(o.protected.assets).toBe(1);
    expect(o.threats).toMatchObject({ open: { critical: 1, low: 1 }, open_total: 2 });
    expect(o.threats.top[0]).toMatchObject({ severity: "critical", title: "rule e1" });

    // Resolving what is open (a resolved alert is not a threat any more).
    for (const a of await store.listAlerts(tA)) await store.updateAlertStatus(tA, a.id, "resolved");
    await query("UPDATE tenants SET notification_email = 'soc@alpha.io' WHERE id = $1", [tA]);
    o = await get(viewerA);
    expect(o).toMatchObject({ status: "protected", reasons: [], threats: { open_total: 0 } });
    expect(o.onboarding.complete).toBe(true);
  });

  it("a sensor that went quiet needs attention", async () => {
    const cred = await issueCredential(tA);
    await sendSigned(app, cred, event("e1", 3));
    await query("UPDATE alerts SET status = 'resolved' WHERE tenant_id = $1", [tA]);
    await query("UPDATE webhook_credentials SET last_used_at = now() - interval '1 day' WHERE tenant_id = $1", [tA]);
    const o = await get(viewerA);
    expect(o.protected.sources[0].health).toBe("silent");
    expect(o.reasons).toContain("source_silent");
  });

  it("shows what Legion blocked, with the rule, for this workspace only", async () => {
    const created = await request(app).post("/agents").set(...bearer(adminA)).send({ name: "exfil-bot", permissions: ["tool.database:read"] });
    const token = (await request(app).post("/agent/v1/token").set("Authorization", `Bearer ${created.body.credential.secret}`)).body.access_token;
    await request(app).post("/agent/v1/tools/authorize").set("Authorization", `Bearer ${token}`)
      .send({ call: { kind: "database", operation: "query", sql: "SELECT id FROM alerts WHERE tenant_id = $1 LIMIT 5", params: [tB] } });
    const o = await get(viewerA);
    expect(o.blocked).toMatchObject({ window_days: 7, refused: 1, contained: 1 });
    expect(o.blocked.recent[0]).toMatchObject({ agent_name: "exfil-bot", decision: "QUARANTINE", rules: expect.arrayContaining(["sql.foreign_tenant"]) });
    expect(o.reasons).toContain("agent_contained");
    expect((await get(adminB)).blocked).toMatchObject({ refused: 0, recent: [] });
  });
});

describe("the test alert and the permission catalogue", () => {
  it("test alerts are admin-only, labelled, and capped", async () => {
    expect((await request(app).post("/security-events/test").set(...bearer(viewerA))).status).toBe(403);
    const r = await request(app).post("/security-events/test").set(...bearer(adminA));
    const alert = await store.getAlert(tA, r.body.alert_id);
    expect(alert).toMatchObject({ source: "legion-test", severity: "low", title: "Test alert: Legion is working" });
    // Legion's own text, so it is written in the sender's language.
    const ru = await request(app).post("/security-events/test").set(...bearer(adminA)).set("Accept-Language", "ru");
    expect((await store.getAlert(tA, ru.body.alert_id))!.title).toBe("Тестовое оповещение: Legion работает");
    for (let i = 0; i < 8; i++) await request(app).post("/security-events/test").set(...bearer(adminA));
    expect((await request(app).post("/security-events/test").set(...bearer(adminA))).status).toBe(429);
  });

  it("lists every agent permission with its risk tier and whether it asks a person first", async () => {
    const r = (await request(app).get("/agent-permissions").set(...bearer(viewerA))).body;
    const byId = Object.fromEntries(r.permissions.map((p: { id: string }) => [p.id, p]));
    expect(byId["alerts:read"]).toEqual({ id: "alerts:read", tier: 0, asks_first: false });
    expect(byId["tool.slack:write"]).toEqual({ id: "tool.slack:write", tier: 2, asks_first: true });
    expect(r.never).toContain("manage_people");
  });
});
