/**
 * Global readiness and enterprise seams: workspace and personal regional
 * settings, currency-aware checkout, the permission matrix, audit export and
 * the configuration they rely on.
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
import { config, settingProblems } from "../src/config.js";
import { effectiveSettings } from "../src/regional.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, analystA: User, viewerA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@alpha.io", password_hash: hash, tenant_id: tA, role: "analyst", status: "active" });
  viewerA = await store.insertUser({ email: "viewer@alpha.io", password_hash: hash, tenant_id: tA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
});

describe("workspace settings", () => {
  it("defaults are English, UTC, USD, ISO dates, 24h; the region is this deployment's", async () => {
    const res = await request(app).get("/workspace/settings").set(...bearer(viewerA));
    expect(res.body).toMatchObject({ region: config.region, timezone: "UTC", locale: "en", currency: "USD", date_format: "YYYY-MM-DD", time_format: "24h" });
    expect(res.body.options.currencies).toEqual(expect.arrayContaining(["USD", "EUR"]));
  });

  it("admins change them; others cannot; bad values and the region are refused", async () => {
    const ok = await request(app).patch("/workspace/settings").set(...bearer(adminA)).send({ timezone: "Asia/Tashkent", currency: "EUR", date_format: "DD.MM.YYYY" });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ timezone: "Asia/Tashkent", currency: "EUR", date_format: "DD.MM.YYYY" });
    expect((await request(app).patch("/workspace/settings").set(...bearer(analystA)).send({ timezone: "UTC" })).status).toBe(403);
    for (const bad of [{ timezone: "Mars/Olympus" }, { currency: "BTC" }, { date_format: "YY/M/D" }, { region: "us-east" }]) {
      expect((await request(app).patch("/workspace/settings").set(...bearer(adminA)).send(bad)).status, JSON.stringify(bad)).toBe(422);
    }
    // Another workspace is untouched.
    expect((await store.getTenant(tB))!.timezone).toBe("UTC");
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'workspace.settings_updated'", [tA])).rows[0].n).toBe(1);
  });

  it("the billing currency is locked while a subscription is active", async () => {
    await store.applySubscriptionEvent({ tenant_id: tA, status: "active", paddle_customer_id: "ctm_1", paddle_subscription_id: "sub_1", paddle_price_id: "pri_usd",
      current_period_end: null, cancel_at_period_end: false, last_event_at: new Date().toISOString() });
    expect((await request(app).patch("/workspace/settings").set(...bearer(adminA)).send({ currency: "EUR" })).status).toBe(409);
    expect((await request(app).patch("/workspace/settings").set(...bearer(adminA)).send({ timezone: "Europe/Paris" })).status).toBe(200);
  });

  it("checkout uses the price for the workspace's currency, chosen by the server", async () => {
    const saved = config.paddlePriceIds;
    try {
      (config as { paddlePriceIds: Record<string, string> }).paddlePriceIds = { USD: "pri_usd", EUR: "pri_eur" };
      expect((await request(app).post("/billing/checkout-context").set(...bearer(adminA))).body).toMatchObject({ currency: "USD", price_id: "pri_usd" });
      await request(app).patch("/workspace/settings").set(...bearer(adminA)).send({ currency: "EUR" });
      expect((await request(app).post("/billing/checkout-context").set(...bearer(adminA))).body).toMatchObject({ currency: "EUR", price_id: "pri_eur" });
    } finally {
      (config as { paddlePriceIds: Record<string, string> }).paddlePriceIds = saved;
    }
  });
});

describe("personal preferences", () => {
  it("override the workspace's for that person only; null goes back to the workspace's", async () => {
    await request(app).patch("/workspace/settings").set(...bearer(adminA)).send({ timezone: "Europe/Berlin", time_format: "24h" });
    const mine = await request(app).patch("/auth/me/preferences").set(...bearer(analystA)).send({ timezone: "America/New_York", time_format: "12h", date_format: "MM/DD/YYYY" });
    expect(mine.body.settings).toMatchObject({ timezone: "America/New_York", time_format: "12h", date_format: "MM/DD/YYYY" });
    expect((await request(app).get("/auth/me").set(...bearer(viewerA))).body.settings).toMatchObject({ timezone: "Europe/Berlin", time_format: "24h" });
    const reset = await request(app).patch("/auth/me/preferences").set(...bearer(analystA)).send({ timezone: null });
    expect(reset.body.settings.timezone).toBe("Europe/Berlin");
    expect((await request(app).patch("/auth/me/preferences").set(...bearer(analystA)).send({ timezone: "Nowhere/Land" })).status).toBe(422);
  });

  it("an unknown stored value never breaks presentation", () => {
    expect(effectiveSettings({ timezone: "Bad/Zone", locale: "en", date_format: "??", time_format: "25h" }, { timezone: "Also/Bad" }))
      .toEqual({ timezone: "UTC", locale: "en", date_format: "YYYY-MM-DD", time_format: "24h" });
  });
});

describe("permissions", () => {
  it("the matrix is exposed, and routes check permissions", async () => {
    const roles = (await request(app).get("/workspace/roles").set(...bearer(viewerA))).body.roles;
    expect(roles.viewer).toContain("alerts:read");
    expect(roles.viewer).not.toContain("audit:export");
    expect(roles.admin).toEqual(expect.arrayContaining(["audit:export", "workspace:manage", "integrations:manage"]));
  });
});

describe("audit export", () => {
  const range = () => ({ from: new Date(Date.now() - 3_600_000).toISOString(), to: new Date(Date.now() + 60_000).toISOString() });

  it("streams this workspace's trail in time order, as NDJSON or CSV, admins only", async () => {
    for (let i = 0; i < 3; i++) await store.audit({ tenant_id: tA, user_id: adminA.id, user_email: adminA.email, action: `test.a${i}`, resource_type: null, resource_id: null, detail: null, ip_address: null });
    await store.audit({ tenant_id: tB, user_id: adminB.id, user_email: adminB.email, action: "test.bravo", resource_type: null, resource_id: null, detail: "BRAVO-ONLY", ip_address: null });
    const nd = await request(app).get("/audit/export").query(range()).set(...bearer(adminA));
    expect(nd.status).toBe(200);
    expect(nd.headers["content-type"]).toMatch(/ndjson/);
    const rows = nd.text.trim().split("\n").map((l) => JSON.parse(l));
    expect(rows.map((r) => r.action).filter((a: string) => a.startsWith("test."))).toEqual(["test.a0", "test.a1", "test.a2"]);
    expect(nd.text).not.toContain("BRAVO-ONLY");
    // The export itself is audited.
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'audit.exported'", [tA])).rows[0].n).toBe(1);
    expect((await request(app).get("/audit/export").query(range()).set(...bearer(analystA))).status).toBe(403);
  });

  it("CSV cells that a spreadsheet would execute are neutralised", async () => {
    await store.audit({ tenant_id: tA, user_id: null, user_email: "x@alpha.io", action: "test.csv", resource_type: null, resource_id: null, detail: '=HYPERLINK("http://evil","click"), "quoted"', ip_address: null });
    const csv = await request(app).get("/audit/export").query({ ...range(), format: "csv" }).set(...bearer(adminA));
    expect(csv.headers["content-type"]).toMatch(/text\/csv/);
    const line = csv.text.split("\r\n").find((l) => l.includes("test.csv"))!;
    expect(line).toContain(`"'=HYPERLINK(""http://evil"",""click""), ""quoted"""`);
  });

  it("refuses an empty, inverted or over-long period", async () => {
    const now = Date.now();
    for (const q of [{ from: new Date(now).toISOString(), to: new Date(now - 1).toISOString() }, { from: new Date(now - 400 * 86_400_000).toISOString(), to: new Date(now).toISOString() }, { from: "yesterday", to: "today" }]) {
      expect((await request(app).get("/audit/export").query(q).set(...bearer(adminA))).status).toBe(422);
    }
  });
});

describe("configuration", () => {
  it("region and currencies are validated at start-up", () => {
    expect(settingProblems({ LEGION_REGION: "EU Central!" })).toEqual(expect.arrayContaining([expect.stringContaining("LEGION_REGION")]));
    expect(settingProblems({ SUPPORTED_CURRENCIES: "USD,EURO" })).toEqual(expect.arrayContaining([expect.stringContaining("SUPPORTED_CURRENCIES")]));
    expect(settingProblems({ DEFAULT_CURRENCY: "GBP" })).toEqual(expect.arrayContaining([expect.stringContaining("DEFAULT_CURRENCY")]));
    expect(settingProblems({ LEGION_REGION: "eu-central", SUPPORTED_CURRENCIES: "USD,EUR,GBP", DEFAULT_CURRENCY: "GBP" })).toEqual([]);
  });
});
