/**
 * The hosted (SaaS) service end to end at the API: self-sign-up with email
 * verification, the 14-day trial, and Paddle turning a payment into access.
 *
 * Paddle is not called: webhooks are signed here exactly as Paddle signs them
 * (HMAC-SHA256 over `${ts}:${rawBody}` with the notification secret).
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import { createHmac, randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query, queryOne } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";

const PADDLE_SECRET = "pdl_ntfset_test_secret_0123456789";
const PASSWORD = "a-good-password";

/** Signs a Paddle webhook body the way Paddle does. */
function paddleHeaders(body: string, secret = PADDLE_SECRET, ts = Math.floor(Date.now() / 1000)) {
  const h1 = createHmac("sha256", secret).update(`${ts}:${body}`).digest("hex");
  return { "Paddle-Signature": `ts=${ts};h1=${h1}`, "Content-Type": "application/json" };
}

async function paddleEvent(event: Record<string, unknown>, opts: { secret?: string; ts?: number } = {}) {
  const body = JSON.stringify(event);
  return request(app).post("/billing/webhook").set(paddleHeaders(body, opts.secret, opts.ts)).send(body);
}

function subscriptionEvent(type: string, data: Record<string, unknown>, occurredAt = new Date().toISOString()) {
  return {
    event_id: `evt_${randomUUID()}`, event_type: type, occurred_at: occurredAt,
    data: {
      id: "sub_01test", status: "active", customer_id: "ctm_01test",
      items: [{ price: { id: "pri_01test" } }],
      current_billing_period: { ends_at: new Date(Date.now() + 30 * 86_400_000).toISOString() },
      ...data,
    },
  };
}

/** Signs up and returns the emailed verification link (SMTP is off in tests,
 *  so the server prints the link instead of mailing it). */
async function signUp(email: string, company = "Acme SOC") {
  const info = vi.spyOn(console, "info").mockImplementation(() => {});
  const res = await request(app).post("/auth/register").send({ email, password: PASSWORD, tenant_name: company });
  const line = info.mock.calls.map((c) => String(c[0])).find((l) => l.includes("/verify-email?token="));
  info.mockRestore();
  const token = line ? new URL(line.slice(line.indexOf("http"))).searchParams.get("token") : null;
  return { res, token };
}

const login = (email: string) => request(app).post("/auth/login").send({ username: email, password: PASSWORD });

async function verifiedAdmin(email: string, company = "Acme SOC") {
  const { res, token } = await signUp(email, company);
  await request(app).post("/auth/verify-email").send({ token }).expect(200);
  const session = await login(email).expect(200);
  return { user: res.body as { id: string; tenant_id: string }, bearer: `Bearer ${session.body.access_token}` };
}

beforeAll(async () => {
  await migrate();
  config.deploymentMode = "saas";
  config.paddleWebhookSecret = PADDLE_SECRET;
});
afterAll(async () => { await closePool(); });
beforeEach(async () => { await truncateAll(); });
afterEach(() => { vi.restoreAllMocks(); });

describe("sign-up needs a confirmed email", () => {
  it("creates the workspace with a 14-day trial, but no session yet", async () => {
    const { res, token } = await signUp("Founder@Acme.example");
    expect(res.status).toBe(201);
    expect(res.body.verification_required).toBe(true);
    expect(token).toBeTruthy();
    const tenant = await store.getTenant(res.body.tenant_id);
    const days = (new Date(tenant!.trial_ends_at!).getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(13.9);
    expect(days).toBeLessThanOrEqual(14);
  });

  it("refuses to sign in until the email is confirmed, and says why", async () => {
    await signUp("wait@acme.example");
    const res = await login("wait@acme.example").expect(403);
    expect(res.body.code).toBe("email_unverified");
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("the emailed link confirms it, once", async () => {
    const { token } = await signUp("ok@acme.example");
    await request(app).post("/auth/verify-email").send({ token }).expect(200);
    await login("ok@acme.example").expect(200);
    await request(app).post("/auth/verify-email").send({ token }).expect(400);
  });

  it("stores only a hash of the link, never the link itself", async () => {
    const { token } = await signUp("hash@acme.example");
    const row = await queryOne<{ verify_token_hash: string }>("SELECT verify_token_hash FROM users WHERE email = 'hash@acme.example'");
    expect(row!.verify_token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(row!.verify_token_hash).not.toContain(token!);
  });

  it("an expired or made-up link does nothing", async () => {
    const { token } = await signUp("late@acme.example");
    await query("UPDATE users SET verify_expires = now() - interval '1 minute' WHERE email = 'late@acme.example'");
    await request(app).post("/auth/verify-email").send({ token }).expect(400);
    await request(app).post("/auth/verify-email").send({ token: "x".repeat(43) }).expect(400);
    await login("late@acme.example").expect(403);
  });

  it("a new link can be requested; the old one stops working", async () => {
    const { token: first } = await signUp("again@acme.example");
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    await request(app).post("/auth/resend-verification").send({ email: "again@acme.example" }).expect(202);
    const line = info.mock.calls.map((c) => String(c[0])).find((l) => l.includes("token="))!;
    const second = new URL(line.slice(line.indexOf("http"))).searchParams.get("token");
    await request(app).post("/auth/verify-email").send({ token: first }).expect(400);
    await request(app).post("/auth/verify-email").send({ token: second }).expect(200);
  });

  it("resend gives the same answer for unknown and already-confirmed addresses", async () => {
    await verifiedAdmin("done@acme.example");
    const a = await request(app).post("/auth/resend-verification").send({ email: "nobody@acme.example" });
    const b = await request(app).post("/auth/resend-verification").send({ email: "done@acme.example" });
    expect([a.status, b.status]).toEqual([202, 202]);
    expect(a.body).toEqual(b.body);
  });

  it("a password reset (also emailed) counts as confirming the address", async () => {
    await signUp("reset@acme.example");
    // Without SMTP the link is only printed when a developer explicitly asks.
    const savedFlag = config.devLogAuthLinks;
    config.devLogAuthLinks = true;
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    await request(app).post("/auth/forgot-password").send({ email: "reset@acme.example" }).expect(202);
    config.devLogAuthLinks = savedFlag;
    const line = info.mock.calls.map((c) => String(c[0])).find((l) => l.includes("reset-password?token="))!;
    const token = new URL(line.slice(line.indexOf("http"))).searchParams.get("token");
    await request(app).post("/auth/reset-password").send({ token, new_password: PASSWORD }).expect(200);
    await login("reset@acme.example").expect(200);
  });

  it("accounts that existed before this feature are not locked out", async () => {
    const tenant = await store.createTenantWithAdmin("Old Co", "old@acme.example", "x");
    expect(tenant.user.email_verified_at).not.toBeNull();
  });
});

describe("Paddle turns a payment into access", () => {
  it("an unsigned or wrongly signed webhook is refused", async () => {
    const body = JSON.stringify(subscriptionEvent("subscription.created", {}));
    await request(app).post("/billing/webhook").set("Content-Type", "application/json").send(body).expect(401);
    const bad = await paddleEvent(subscriptionEvent("subscription.created", {}), { secret: "wrong" });
    expect(bad.status).toBe(401);
    const old = await paddleEvent(subscriptionEvent("subscription.created", {}), { ts: Math.floor(Date.now() / 1000) - 3600 });
    expect(old.status).toBe(401);
  });

  it("checkout → subscription.created activates exactly the workspace that paid", async () => {
    const payer = await verifiedAdmin("payer@acme.example", "Payer");
    const other = await verifiedAdmin("other@beta.example", "Other");
    const ctx = await request(app).post("/billing/checkout-context").set("Authorization", payer.bearer).expect(200);

    const res = await paddleEvent(subscriptionEvent("subscription.created", { custom_data: { checkout_token: ctx.body.checkout_token } }));
    expect(res.status).toBe(202);
    expect(res.body.subscription_status).toBe("active");
    expect((await store.getSubscription(payer.user.tenant_id))?.status).toBe("active");
    expect(await store.getSubscription(other.user.tenant_id)).toBeNull();
  });

  it("a payment Paddle retries hours later still lands (checkout token past its expiry)", async () => {
    const payer = await verifiedAdmin("slow@acme.example");
    const expired = jwt.sign(
      { purpose: "paddle_checkout", tenant_id: payer.user.tenant_id, exp: Math.floor(Date.now() / 1000) - 6 * 3600 },
      config.jwtSecret, { algorithm: "HS256" },
    );
    const res = await paddleEvent(subscriptionEvent("subscription.created", { custom_data: { checkout_token: expired } }));
    expect(res.body.status).toBe("processed");
    expect((await store.getSubscription(payer.user.tenant_id))?.status).toBe("active");
  });

  it("a forged checkout token cannot assign a subscription to anyone", async () => {
    const victim = await verifiedAdmin("victim@acme.example");
    const forged = jwt.sign({ purpose: "paddle_checkout", tenant_id: victim.user.tenant_id }, "not-legions-secret", { algorithm: "HS256" });
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await paddleEvent(subscriptionEvent("subscription.created", { custom_data: { checkout_token: forged } }));
    expect(res.body.status).toBe("skipped");
    expect(err).toHaveBeenCalled();
    expect(await store.getSubscription(victim.user.tenant_id)).toBeNull();
  });

  it("a session token is not a checkout token", async () => {
    const payer = await verifiedAdmin("mix@acme.example");
    const session = payer.bearer.slice("Bearer ".length);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await paddleEvent(subscriptionEvent("subscription.created", { custom_data: { checkout_token: session } }));
    expect(res.body.status).toBe("skipped");
  });

  it("past due → read-only; cancelled → locked, but billing stays reachable to pay again", async () => {
    const payer = await verifiedAdmin("cycle@acme.example");
    const ctx = await request(app).post("/billing/checkout-context").set("Authorization", payer.bearer).expect(200);
    const t0 = Date.now();
    await paddleEvent(subscriptionEvent("subscription.created", { custom_data: { checkout_token: ctx.body.checkout_token } }, new Date(t0).toISOString()));

    await paddleEvent(subscriptionEvent("subscription.past_due", { status: "past_due" }, new Date(t0 + 1000).toISOString()));
    await request(app).get("/alerts").set("Authorization", payer.bearer).expect(200);
    await request(app).post("/copilot/chat").set("Authorization", payer.bearer).send({ message: "hi" }).expect(402);

    await paddleEvent(subscriptionEvent("subscription.canceled", { status: "canceled" }, new Date(t0 + 2000).toISOString()));
    const locked = await request(app).get("/alerts").set("Authorization", payer.bearer).expect(402);
    expect(locked.body.access_state).toBe("blocked");
    await request(app).get("/billing/subscription").set("Authorization", payer.bearer).expect(200);
    await request(app).post("/billing/checkout-context").set("Authorization", payer.bearer).expect(200);
  });

  it("an older event delivered late does not undo a newer one", async () => {
    const payer = await verifiedAdmin("order@acme.example");
    const ctx = await request(app).post("/billing/checkout-context").set("Authorization", payer.bearer).expect(200);
    const t0 = Date.now();
    await paddleEvent(subscriptionEvent("subscription.created", { custom_data: { checkout_token: ctx.body.checkout_token } }, new Date(t0).toISOString()));
    await paddleEvent(subscriptionEvent("subscription.canceled", { status: "canceled" }, new Date(t0 + 5000).toISOString()));
    const late = await paddleEvent(subscriptionEvent("subscription.updated", { status: "active" }, new Date(t0 + 1000).toISOString()));
    expect(late.body.status).toBe("skipped");
    expect((await store.getSubscription(payer.user.tenant_id))?.status).toBe("canceled");
  });

  it("when the trial runs out without a subscription, the workspace locks", async () => {
    const payer = await verifiedAdmin("trial@acme.example");
    await request(app).get("/alerts").set("Authorization", payer.bearer).expect(200);
    await query("UPDATE tenants SET trial_ends_at = now() - interval '1 minute' WHERE id = $1", [payer.user.tenant_id]);
    await request(app).get("/alerts").set("Authorization", payer.bearer).expect(402);
  });
});
