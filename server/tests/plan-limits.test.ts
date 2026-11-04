/**
 * Plans (src/plans.ts) in the running API: which plan a workspace is on, what
 * Paddle's webhook turns into, and what each plan refuses.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID, createHmac } from "node:crypto";
import { spawnSync } from "node:child_process";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { classifyPrices, pruneAlertsByPlan, resolvePlan } from "../src/plan-limits.js";
import type { PlanId, AddonId } from "../src/plans.js";
import type { Role, User } from "../src/types.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";

const savedPlan = config.paddlePlanPrices, savedAddon = config.paddleAddonPrices, savedLegacy = config.paddlePriceIds, savedMode = config.deploymentMode;
const PLAN_PRICES = {
  "starter.month": "pri_starter_m", "starter.year": "pri_starter_y", "professional.month": "pri_pro_m", "professional.year": "pri_pro_y",
  "business.month": "pri_biz_m", "business.year": "pri_biz_y",
};
const ADDON_PRICES = { agent_security: "pri_addon_agents", payment_fraud: "pri_addon_pay", endpoints_100: "pri_addon_ep" };
const set = (k: string, v: unknown) => ((config as unknown as Record<string, unknown>)[k] = v);

let hash = "";
const asUser = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { algorithm: "HS256", expiresIn: "1h" })}`] as const;
async function tenant(plan?: PlanId, addons: AddonId[] = [], status = "active"): Promise<string> {
  const id = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + interval '14 days')", [id, `T-${id.slice(0, 6)}`]);
  if (plan) {
    await store.applySubscriptionEvent({
      tenant_id: id, status: status as "active", paddle_customer_id: "ctm_1", paddle_subscription_id: `sub_${id.slice(0, 8)}`,
      paddle_price_id: null, current_period_end: null, cancel_at_period_end: false, last_event_at: new Date().toISOString(), plan, addons,
    });
  }
  return id;
}
const user = (tenantId: string, role: Role, status: "active" | "invited" = "active") =>
  store.insertUser({ email: `${role}-${randomUUID().slice(0, 8)}@example.com`, password_hash: hash, tenant_id: tenantId, role, status });

beforeAll(async () => { await migrate(); hash = await bcrypt.hash("password123", 4); });
afterAll(async () => {
  set("paddlePlanPrices", savedPlan); set("paddleAddonPrices", savedAddon); set("paddlePriceIds", savedLegacy); set("deploymentMode", savedMode);
  await closePool();
});
beforeEach(async () => {
  await truncateAll();
  set("paddlePlanPrices", PLAN_PRICES); set("paddleAddonPrices", ADDON_PRICES); set("paddlePriceIds", {}); set("deploymentMode", "saas");
});

describe("which plan a workspace is on", () => {
  it("a workspace in its trial has the full Professional plan", async () => {
    const t = await tenant();
    expect(await resolvePlan(t)).toMatchObject({ plan: "professional", source: "trial", agentSecurity: true, endpoints: 100 });
  });

  it("a subscription's plan and add-ons", async () => {
    const t = await tenant("starter", ["agent_security"]);
    expect(await resolvePlan(t)).toMatchObject({ plan: "starter", source: "subscription", agentSecurity: true, aiAgents: false, endpoints: 25 });
  });

  it("a subscription from before plans existed is Professional", async () => {
    const t = await tenant();
    await store.applySubscriptionEvent({ tenant_id: t, status: "active", paddle_customer_id: "c", paddle_subscription_id: "sub_old", paddle_price_id: "pri_old", current_period_end: null, cancel_at_period_end: false, last_event_at: new Date().toISOString(), plan: null, addons: [] });
    expect(await resolvePlan(t)).toMatchObject({ plan: "professional", source: "legacy" });
  });

  it("the operator can set a plan for a contract; it wins over the subscription", async () => {
    const t = await tenant("starter");
    await query("UPDATE tenants SET plan_override = 'enterprise' WHERE id = $1", [t]);
    expect(await resolvePlan(t)).toMatchObject({ plan: "enterprise", source: "override", endpoints: null, admins: null });
    await expect(query("UPDATE tenants SET plan_override = 'platinum' WHERE id = $1", [t])).rejects.toThrow();
  });

  it("a self-hosted installation has no limits", async () => {
    set("deploymentMode", "self-hosted");
    const t = await tenant("starter");
    expect(await resolvePlan(t)).toMatchObject({ source: "self-hosted", endpoints: null, admins: null, agentSecurity: true, ipBlocking: "custom" });
  });

  it("Paddle prices classify as plans and add-ons; anything else is unknown", () => {
    expect(classifyPrices(["pri_biz_m", "pri_addon_pay", "pri_mystery"])).toMatchObject({ plan: "business", addons: ["payment_fraud"], unknown: ["pri_mystery"] });
    expect(classifyPrices(["pri_addon_pay"])).toMatchObject({ plan: null, addons: ["payment_fraud"] });
  });
});

describe("Paddle's webhook records the plan", () => {
  const SECRET = "pdl_ntfset_test_secret_0123456789";
  const paddle = (event: Record<string, unknown>) => {
    const body = JSON.stringify(event); const ts = Math.floor(Date.now() / 1000);
    const h1 = createHmac("sha256", SECRET).update(`${ts}:${body}`).digest("hex");
    return request(app).post("/billing/webhook").set({ "Paddle-Signature": `ts=${ts};h1=${h1}`, "Content-Type": "application/json" }).send(body);
  };
  const event = (items: string[], extra: Record<string, unknown> = {}) => ({
    event_id: `evt_${randomUUID()}`, event_type: "subscription.created", occurred_at: new Date().toISOString(),
    data: { id: `sub_${randomUUID().slice(0, 8)}`, status: "active", customer_id: "ctm_1", items: items.map((id) => ({ price: { id } })), ...extra },
  });
  let savedSecret = "";
  beforeEach(() => { savedSecret = config.paddleWebhookSecret; set("paddleWebhookSecret", SECRET); });
  afterAll(() => set("paddleWebhookSecret", savedSecret));

  async function checkout(admin: User, body: Record<string, unknown>) {
    return request(app).post("/billing/checkout-context").set(...asUser(admin)).send(body);
  }

  it("a plan price becomes that plan; an add-on rides along", async () => {
    const t = await tenant(); const admin = await user(t, "admin");
    const ctx = await checkout(admin, { plan: "business", interval: "month", addons: ["payment_fraud"] });
    expect(ctx.status).toBe(200);
    expect(ctx.body.items).toEqual([{ priceId: "pri_biz_m", quantity: 1 }, { priceId: "pri_addon_pay", quantity: 1 }]);
    const r = await paddle(event(["pri_biz_m", "pri_addon_pay"], { custom_data: { checkout_token: ctx.body.checkout_token } }));
    expect(r.body.subscription_status).toBe("active");
    const sub = await store.getSubscription(t);
    expect(sub).toMatchObject({ plan: "business", addons: ["payment_fraud"], paddle_price_id: "pri_biz_m" });
  });

  it("only add-ons, or a price Legion does not sell, grant nothing", async () => {
    const t = await tenant(); const admin = await user(t, "admin");
    const token = (await checkout(admin, { plan: "starter" })).body.checkout_token;
    const noPlan = await paddle(event(["pri_addon_pay"], { custom_data: { checkout_token: token } }));
    expect(noPlan.body.subscription_status).toBe("paused");
    expect((await query("SELECT 1 FROM audit_log WHERE tenant_id = $1 AND action = 'billing.no_plan'", [t])).rowCount).toBe(1);
    const stranger = await paddle(event(["pri_starter_m", "pri_cheaper"], { custom_data: { checkout_token: token } }));
    expect(stranger.body.subscription_status).toBe("paused");
  });

  it("the client can only ask for what is sold", async () => {
    const t = await tenant(); const admin = await user(t, "admin");
    expect((await checkout(admin, { plan: "enterprise" })).status).toBe(409);               // by agreement
    expect((await checkout(admin, { plan: "starter", interval: "year", addons: ["agent_security"] })).status).toBe(400); // add-ons are monthly
    expect((await checkout(admin, { plan: "starter", addons: ["threat_intel"] })).status).toBe(409); // no price configured
    // A client-chosen price is ignored: the items are the server's.
    const forged = await checkout(admin, { plan: "starter", priceId: "pri_free", tenant_id: randomUUID() });
    expect(forged.body.items).toEqual([{ priceId: "pri_starter_m", quantity: 1 }]);
    expect((await checkout(admin, { plan: "platinum" })).status).toBe(422);
    const plain = await checkout(admin, {});
    expect(plain.status).toBe(200); expect(plain.body.items).toBeUndefined();                          // the old call still works
    const analyst = await user(t, "analyst");
    expect((await checkout(analyst, { plan: "starter" })).status).toBe(403);
  });

  it("the price list is public and never shows Paddle price ids", async () => {
    const r = await request(app).get("/billing/plans").expect(200);
    expect(r.body.plans.map((p: { id: string; monthlyUsd: number | null }) => [p.id, p.monthlyUsd])).toEqual([["starter", 49], ["professional", 149], ["business", 399], ["enterprise", 999]]);
    expect(r.body.plans.find((p: { id: string }) => p.id === "starter").buy).toEqual({ month: true, year: true });
    expect(r.body.plans.find((p: { id: string }) => p.id === "enterprise").buy).toEqual({ month: false, year: false });
    expect(JSON.stringify(r.body)).not.toMatch(/pri_/);
    expect(r.body.self_hosted).toHaveLength(4);
  });

  it("a workspace sees its own plan and usage", async () => {
    const t = await tenant("starter"); const admin = await user(t, "admin");
    const r = await request(app).get("/billing/entitlements").set(...asUser(admin)).expect(200);
    expect(r.body).toMatchObject({ plan: "starter", source: "subscription", admins: 2, usage: { admins: { used: 1, limit: 2, over: false }, endpoints: { used: 0, limit: 25, over: false } } });
  });
});

describe("the operator's plan tool", () => {
  const run = (...args: string[]) => spawnSync("npx", ["tsx", "src/scripts/plan.ts", ...args], { encoding: "utf8", timeout: 60_000, env: { ...process.env, NODE_ENV: "test" } });

  it("sets, shows and clears a plan override, and audits it", async () => {
    const t = await tenant("starter");
    expect(run("set", "--tenant", t, "--plan", "enterprise").stdout).toMatch(/Plan set to enterprise/);
    expect(await resolvePlan(t)).toMatchObject({ plan: "enterprise", source: "override" });
    expect(run("show", "--tenant", t).stdout).toMatch(/enterprise \(override\)/);
    expect((await query("SELECT detail FROM audit_log WHERE tenant_id = $1 AND action = 'billing.plan_override_set'", [t])).rows[0]?.detail).toBe("enterprise");
    expect(run("clear", "--tenant", t).stdout).toMatch(/cleared/);
    expect(await resolvePlan(t)).toMatchObject({ plan: "starter", source: "subscription" });
  });

  it("refuses an unknown plan or workspace", async () => {
    const t = await tenant();
    expect(run("set", "--tenant", t, "--plan", "platinum").status).not.toBe(0);
    expect(run("set", "--tenant", randomUUID(), "--plan", "starter").status).not.toBe(0);
  });
});

describe("administrator seats", () => {
  const invite = (admin: User, role: Role) => request(app).post("/users/invite").set(...asUser(admin)).send({ email: `x-${randomUUID().slice(0, 8)}@example.com`, role });

  it("Starter includes two; the third is refused, an invited one counts, other roles are not limited", async () => {
    const t = await tenant("starter"); const admin = await user(t, "admin");
    expect((await invite(admin, "admin")).status).toBe(201);              // 2 of 2 (one invited)
    const third = await invite(admin, "admin");
    expect(third.status).toBe(403);
    expect(third.body).toMatchObject({ code: "plan_limit", limit: "admins", max: 2, plan: "starter" });
    expect((await invite(admin, "analyst")).status).toBe(201);
    expect((await invite(admin, "viewer")).status).toBe(201);
  });

  it("promoting someone to admin takes a seat; a person's own seat is not counted twice", async () => {
    const t = await tenant("starter"); const admin = await user(t, "admin"); const second = await user(t, "admin"); const analyst = await user(t, "analyst");
    const r = await request(app).patch(`/users/${analyst.id}/role`).set(...asUser(admin)).send({ role: "admin" });
    expect(r.status).toBe(403); expect(r.body.code).toBe("plan_limit");
    // Re-saving an existing admin as admin does not need a free seat.
    expect((await request(app).patch(`/users/${second.id}/role`).set(...asUser(admin)).send({ role: "admin" })).status).toBe(200);
  });

  it("Professional includes five; Enterprise (override) has no limit", async () => {
    const t = await tenant("professional"); const admin = await user(t, "admin");
    for (let i = 0; i < 4; i++) expect((await invite(admin, "admin")).status).toBe(201);
    expect((await invite(admin, "admin")).status).toBe(403);
    await query("UPDATE tenants SET plan_override = 'enterprise' WHERE id = $1", [t]);
    expect((await invite(admin, "admin")).status).toBe(201);
  });
});

describe("features by plan", () => {
  it("the Copilot assistant is Professional and up", async () => {
    const starter = await tenant("starter"); const pro = await tenant("professional");
    const a = await user(starter, "analyst"); const b = await user(pro, "analyst");
    const denied = await request(app).post("/copilot/chat").set(...asUser(a)).send({ message: "hi" });
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ code: "plan_feature", feature: "copilot", plan: "starter", upgrade_to: "professional" });
    expect((await request(app).post("/copilot/chat").set(...asUser(b)).send({ message: "hi" })).status).toBe(200);
  });

  it("blocking addresses: none on Starter, manual on Professional, automatic on Business", async () => {
    const starter = await tenant("starter"); const pro = await tenant("professional"); const biz = await tenant("business");
    const [s, p, b] = await Promise.all([user(starter, "admin"), user(pro, "admin"), user(biz, "admin")]);
    const block = (u: User) => request(app).post("/security/blocks").set(...asUser(u)).send({ ip: "203.0.113.50" });
    const auto = (u: User) => request(app).patch("/security/auto-response").set(...asUser(u)).send({ mode: "auto" });
    expect((await block(s)).status).toBe(403);
    expect((await block(p)).status).toBe(201);
    expect((await auto(p)).status).toBe(403);                                   // a person stays in the loop
    expect((await request(app).patch("/security/auto-response").set(...asUser(p)).send({ mode: "off" })).status).toBe(200); // turning off never needs a plan
    expect((await auto(b)).status).toBe(200);
  });

  it("a plan that is downgraded keeps detection but loses the automatic block", async () => {
    const t = await tenant("business"); const admin = await user(t, "admin");
    await request(app).patch("/security/auto-response").set(...asUser(admin)).send({ mode: "auto" }).expect(200);
    await store.applySubscriptionEvent({ tenant_id: t, status: "active", paddle_customer_id: "c", paddle_subscription_id: `sub_${t.slice(0, 8)}`, paddle_price_id: null, current_period_end: null, cancel_at_period_end: false, last_event_at: new Date(Date.now() + 1000).toISOString(), plan: "professional", addons: [] });
    const { respondToCampaigns } = await import("../src/blocklist.js");
    const out = await respondToCampaigns(t, [{ id: "CMP-1", rule: "credential_attack", subject: "198.51.100.7", sources: ["198.51.100.7"] } as never]);
    expect(out[0]).toMatchObject({ action: "skipped", why: "plan" });
  });

  it("the Wazuh manager gets an empty blocklist on a plan without blocking", async () => {
    const starter = await tenant("starter"); const biz = await tenant("business");
    const { addBlock } = await import("../src/blocklist.js");
    await addBlock(starter, "203.0.113.9", { minutes: 60, reason: "x", userId: null });
    await addBlock(biz, "203.0.113.9", { minutes: 60, reason: "x", userId: null });
    const sync = async (tid: string) => (await sendSigned(app, await issueCredential(tid), { action: "sync-blocklist" }, { path: "/security-events/blocklist" })).body.entries;
    expect(await sync(starter)).toEqual([]);
    expect((await sync(biz)).length).toBe(1);
  });

  it("the payment check is an add-on on Starter and included from Professional", async () => {
    const starter = await tenant("starter"); const withAddon = await tenant("starter", ["payment_fraud"]); const pro = await tenant("professional");
    const pay = async (tid: string) => sendSigned(app, await issueCredential(tid), { action: "payment-check", beneficiary: { account: "DE89 3704 0044 0532 0130 00" }, amount: 100, currency: "EUR" }, { path: "/security-events/payment-check" });
    const denied = await pay(starter);
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ code: "plan_feature", feature: "paymentCheck", addon: "payment_fraud" });
    expect((await pay(withAddon)).status).toBe(200);
    expect((await pay(pro)).status).toBe(200);
  });

  it("AI Agent Security and the five agents' skills", async () => {
    const starter = await tenant("starter"); const withAddon = await tenant("starter", ["agent_security"]); const pro = await tenant("professional");
    const [s, w, p] = await Promise.all([user(starter, "admin"), user(withAddon, "admin"), user(pro, "admin")]);
    const denied = await request(app).get("/agents").set(...asUser(s));
    expect(denied.status).toBe(403);
    expect(denied.body).toMatchObject({ code: "plan_feature", feature: "agentSecurity", addon: "agent_security" });
    expect((await request(app).get("/agents").set(...asUser(w))).status).toBe(200);          // the add-on
    expect((await request(app).get("/skills").set(...asUser(w))).status).toBe(403);          // …does not include the five agents
    expect((await request(app).get("/skills").set(...asUser(p))).status).toBe(200);
    expect((await request(app).get("/agents").set(...asUser(p))).status).toBe(200);
  });

  it("stopping agents is allowed whatever the plan", async () => {
    const starter = await tenant("starter"); const admin = await user(starter, "admin");
    const r = await request(app).post("/kill-switch/all").set(...asUser(admin)).send({});
    expect(r.status).not.toBe(403);
  });
});

describe("usage and retention", () => {
  it("endpoints over the limit are reported, never refused", async () => {
    const t = await tenant("starter"); const admin = await user(t, "admin");
    await query("INSERT INTO assets (id, tenant_id, name, os, risk, online, last_seen) SELECT gen_random_uuid()::text, $1, 'host-' || g, 'linux', 'low', true, now() FROM generate_series(1, 30) g", [t]);
    const r = await request(app).get("/billing/entitlements").set(...asUser(admin)).expect(200);
    expect(r.body.usage.endpoints.over).toBe(true);
    // Telemetry still lands: the sensor webhook is not touched by the endpoint limit.
    const cred = await issueCredential(t);
    expect((await sendSigned(app, cred, { provider: "wazuh", event: { id: "wz-over", rule: { description: "x", level: 5 }, agent: { name: "brand-new-host" } } })).status).toBe(202);
  });

  const oldAlert = (tenantId: string, id: string, status: string, days: number) =>
    query(`INSERT INTO alerts (id, tenant_id, title, severity, agent, status, summary, confidence, source, created_at)
           VALUES ($1, $2, 't', 'low', 'Sentinel', $3, 's', 50, 'wazuh', now() - make_interval(days => $4))`, [id, tenantId, status, days]);

  it("resolved alerts older than the plan keeps them are deleted; open ones never", async () => {
    const starter = await tenant("starter"); const biz = await tenant("business");
    await oldAlert(starter, "S-OLD-RES", "resolved", 45); await oldAlert(starter, "S-OLD-OPEN", "open", 45); await oldAlert(starter, "S-OLD-INV", "investigating", 45); await oldAlert(starter, "S-NEW-RES", "resolved", 10);
    await oldAlert(biz, "B-45-RES", "resolved", 45); await oldAlert(biz, "B-200-RES", "resolved", 200);
    expect(await pruneAlertsByPlan()).toBe(2);
    const left = (await query("SELECT id FROM alerts ORDER BY id")).rows.map((r) => r.id);
    expect(left).toEqual(["B-45-RES", "S-NEW-RES", "S-OLD-INV", "S-OLD-OPEN"]);
  });

  it("a self-hosted installation keeps everything", async () => {
    const t = await tenant("starter"); await oldAlert(t, "OLD", "resolved", 900);
    set("deploymentMode", "self-hosted");
    expect(await pruneAlertsByPlan()).toBe(0);
  });
});
