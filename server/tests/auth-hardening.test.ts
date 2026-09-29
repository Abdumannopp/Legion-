/**
 * Security hardening (2026-09) — authentication regressions.
 *
 *  - login timing: an unknown address costs a full bcrypt comparison (audit P1-14)
 *  - failed logins are audited against the account
 *  - suspicious sign-in detection: new device, success after a burst of failures
 *  - turning MFA on or off ends every other session and tells the owner
 *  - step-up checks (current password, codes) are throttled per user, from any address
 *  - reset / verification emails are capped per address and not awaited
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import * as OTPAuth from "otpauth";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as mailer from "../src/mailer.js";
import { DUMMY_PASSWORD_HASH, deviceFingerprint, hashForComparison, networkOf } from "../src/account-security.js";
import type { User } from "../src/types.js";

const PASSWORD = "correct-horse-battery-staple";
const CHROME_120 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Safari/537.36";
const CHROME_121 = CHROME_120.replace("120.0.6099.109", "121.0.6167.85");
const FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

let tenantId: string; let user: User;
const sent: Array<{ to: string; subject: string; text: string }> = [];
const savedHost = config.smtpHost;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  sent.length = 0;
  config.smtpHost = "smtp.test.invalid";
  vi.spyOn(mailer, "sendMail").mockImplementation(async (m) => { sent.push({ to: String(m.to), subject: String(m.subject), text: String(m.text) }); return { sent: true }; });
  tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'Acme', now() + interval '14 days')", [tenantId]);
  // Cost 12, like production: the timing tests compare real costs.
  user = await store.insertUser({ email: "owner@acme.io", password_hash: await bcrypt.hash(PASSWORD, 12), tenant_id: tenantId, role: "admin", status: "active" });
});
afterEach(() => { vi.restoreAllMocks(); config.smtpHost = savedHost; delete process.env.LEGION_ENFORCE_RATE_LIMITS; });

const login = (email: string, password: string, ua = CHROME_120, ip = "198.51.100.10") =>
  request(app).post("/auth/login").set("User-Agent", ua).set("X-Forwarded-For", ip).send({ username: email, password });
const cookieHeader = (res: request.Response) =>
  ((res.headers["set-cookie"] as unknown as string[] | undefined) ?? []).map((c) => c.split(";")[0]).join("; ");
const audits = async (action: string) =>
  (await query("SELECT detail FROM audit_log WHERE tenant_id = $1 AND action = $2 ORDER BY created_at", [tenantId, action])).rows as Array<{ detail: string | null }>;
const flush = () => new Promise((r) => setTimeout(r, 20)); // notices are fire-and-forget

// --- login timing ---------------------------------------------------------------

describe("login does not reveal which addresses have accounts (P1-14)", () => {
  it("the dummy hash is a real cost-12 bcrypt hash", () => {
    expect(DUMMY_PASSWORD_HASH).toMatch(/^\$2[aby]\$12\$[./A-Za-z0-9]{53}$/);
    expect(bcrypt.getRounds(DUMMY_PASSWORD_HASH)).toBe(12);
  });

  it("an empty (invited) or malformed stored hash is compared against the dummy, and can never match", async () => {
    for (const h of ["", "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidi", "plaintext"]) {
      const r = hashForComparison({ password_hash: h });
      expect(r).toEqual({ hash: DUMMY_PASSWORD_HASH, real: false });
    }
    expect(hashForComparison(null).real).toBe(false);
    expect(hashForComparison(user).real).toBe(true);
  });

  it("an unknown address takes about as long as a real account with a wrong password", async () => {
    const time = async (email: string) => { const t = performance.now(); await login(email, "wrong-password").expect(401); return performance.now() - t; };
    await time("owner@acme.io"); await time("nobody@nowhere.io"); // warm up
    const known: number[] = []; const unknown: number[] = [];
    for (let i = 0; i < 4; i++) { known.push(await time("owner@acme.io")); unknown.push(await time(`nobody-${i}@nowhere.io`)); }
    const median = (xs: number[]) => xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)]!;
    // Before the fix: ~1 ms vs ~300 ms. Now both pay one cost-12 comparison.
    expect(median(unknown)).toBeGreaterThan(median(known) * 0.5);
    expect(median(unknown)).toBeGreaterThan(50);
  }, 60_000);

  it("an invited account (no password yet) cannot sign in and costs the same as any other", async () => {
    await store.insertUser({ email: "invited@acme.io", password_hash: "", tenant_id: tenantId, role: "viewer", status: "invited" });
    const t = performance.now();
    await login("invited@acme.io", "").expect(401);
    expect(performance.now() - t).toBeGreaterThan(50);
  });
});

// --- failed-login audit and suspicious sign-in detection -----------------------------------

describe("failed and suspicious sign-ins", () => {
  it("a wrong password against a real account is audited; an unknown address writes nothing", async () => {
    await login("owner@acme.io", "nope").expect(401);
    await login("ghost@acme.io", "nope").expect(401);
    const rows = await audits("auth.login_failed");
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain("nope"); // never the attempted password
  });

  it("the first sign-in is not flagged; the same browser after an update is not flagged", async () => {
    await login("owner@acme.io", PASSWORD, CHROME_120).expect(200);
    await login("owner@acme.io", PASSWORD, CHROME_121).expect(200);
    await flush();
    expect(await audits("auth.login_suspicious")).toHaveLength(0);
    expect(sent).toHaveLength(0);
    expect(deviceFingerprint(CHROME_120)).toBe(deviceFingerprint(CHROME_121));
  });

  it("a sign-in from a device never used before is audited and the owner is emailed", async () => {
    await login("owner@acme.io", PASSWORD, CHROME_120).expect(200);
    await login("owner@acme.io", PASSWORD, FIREFOX, "203.0.113.77").expect(200);
    await flush();
    const rows = await audits("auth.login_suspicious");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.detail).toMatch(/new device; network 203\.0\.113\.0\/24/);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("owner@acme.io");
    expect(sent[0]!.text).toMatch(/device or browser it has not been used from before/);
    expect(sent[0]!.text).not.toMatch(/https?:\/\//); // no link that could act on the account
  });

  it("a success after a burst of failures is flagged even on a known device", async () => {
    await login("owner@acme.io", PASSWORD, CHROME_120).expect(200);
    for (let i = 0; i < 5; i++) await login("owner@acme.io", `guess-${i}`, CHROME_120).expect(401);
    await login("owner@acme.io", PASSWORD, CHROME_120).expect(200);
    await flush();
    const rows = await audits("auth.login_suspicious");
    expect(rows).toHaveLength(1);
    expect(rows[0]!.detail).toMatch(/5 failed attempts in the previous 15 minutes/);
  });

  it("the network shown is coarse, never the full address", () => {
    expect(networkOf("198.51.100.23")).toBe("198.51.100.0/24");
    expect(networkOf("::ffff:10.1.2.3")).toBe("10.1.2.0/24");
    expect(networkOf("2001:db8:abcd:12::1")).toBe("2001:db8:abcd::/48");
  });
});

// --- MFA changes end every other session ------------------------------------------------------

async function enableMfa(cookies: string): Promise<{ cookies: string; secret: string }> {
  const setup = await request(app).post("/auth/mfa/setup").set("Cookie", cookies).expect(200);
  const secret = setup.body.secret as string;
  const code = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30 }).generate();
  const res = await request(app).post("/auth/mfa/enable").set("Cookie", cookies).send({ code }).expect(200);
  expect(res.body.recovery_codes).toHaveLength(10);
  return { cookies: cookieHeader(res), secret };
}

describe("turning MFA on or off ends every OTHER session", () => {
  it("enable: the other browser's access and refresh tokens stop working; this one continues", async () => {
    const a = cookieHeader(await login("owner@acme.io", PASSWORD).expect(200));
    const b = cookieHeader(await login("owner@acme.io", PASSWORD, FIREFOX).expect(200));
    const { cookies: aNew } = await enableMfa(a);

    await request(app).get("/auth/me").set("Cookie", b).expect(401);        // old access token
    await request(app).post("/auth/refresh").set("Cookie", b).expect(401);  // old refresh token
    await request(app).get("/auth/me").set("Cookie", a).expect(401);        // A's OLD cookies too
    await request(app).get("/auth/me").set("Cookie", aNew).expect(200);     // A's fresh session works
    await flush();
    expect(sent.some((m) => /Two-factor authentication was turned on/.test(m.text))).toBe(true);
  });

  it("disable: needs password + code, ends other sessions and notifies", async () => {
    const a = cookieHeader(await login("owner@acme.io", PASSWORD).expect(200));
    const { cookies: aMfa, secret } = await enableMfa(a);
    // A second session, signed in with both factors.
    const challenge = await login("owner@acme.io", PASSWORD, FIREFOX).expect(200);
    await new Promise((r) => setTimeout(r, 1100));
    // The current code was spent by enable; use the next step's code to avoid replay refusal.
    const next = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret), digits: 6, period: 30 }).generate({ timestamp: Date.now() + 30_000 });
    const bRes = await request(app).post("/auth/mfa/verify").send({ mfa_token: challenge.body.mfa_token, code: next }).expect(200);
    const b = cookieHeader(bRes);

    const recovery = (await request(app).post("/auth/mfa/recovery-codes").set("Cookie", aMfa).send({ password: PASSWORD }).expect(200)).body.recovery_codes as string[];
    const off = await request(app).post("/auth/mfa/disable").set("Cookie", aMfa).send({ password: PASSWORD, code: recovery[0] }).expect(200);
    expect(off.body.enabled).toBe(false);
    await request(app).get("/auth/me").set("Cookie", b).expect(401);
    await request(app).get("/auth/me").set("Cookie", cookieHeader(off)).expect(200);
    await flush();
    expect(sent.some((m) => /turned OFF/.test(m.text))).toBe(true);
    expect(sent.some((m) => /New two-factor recovery codes/.test(m.text))).toBe(true);
  });
});

// --- step-up throttling ------------------------------------------------------------------------

describe("step-up checks are throttled per user, from any address", () => {
  it("after STEP_UP_FAILURES wrong current passwords, even the right one is refused for a while", async () => {
    process.env.LEGION_ENFORCE_RATE_LIMITS = "1";
    const cookies = cookieHeader(await login("owner@acme.io", PASSWORD).expect(200));
    // A different address every time: an attacker holding a stolen session
    // cannot spread guesses across IPs to dodge the limit.
    for (let i = 0; i < config.stepUpFailures; i++) {
      await request(app).post("/auth/change-password").set("Cookie", cookies).set("X-Forwarded-For", `192.0.2.${i + 1}`)
        .send({ current_password: `guess-${i}`, new_password: "another-long-password" }).expect(400);
    }
    const res = await request(app).post("/auth/change-password").set("Cookie", cookies).set("X-Forwarded-For", "192.0.2.200")
      .send({ current_password: PASSWORD, new_password: "another-long-password" });
    expect(res.status).toBe(429);
    // The password did not change.
    await login("owner@acme.io", PASSWORD, CHROME_120, "192.0.2.201").expect(200);
  });

  it("a successful password change tells the owner", async () => {
    const cookies = cookieHeader(await login("owner@acme.io", PASSWORD).expect(200));
    await request(app).post("/auth/change-password").set("Cookie", cookies).send({ current_password: PASSWORD, new_password: "another-long-password" }).expect(200);
    await flush();
    expect(sent.some((m) => m.to === "owner@acme.io" && /password of your Legion account was changed/.test(m.text))).toBe(true);
  });
});

// --- reset / verification emails ----------------------------------------------------------------

describe("password-reset email", () => {
  it("is capped per address, whatever the answer says, from any client address", async () => {
    process.env.LEGION_ENFORCE_RATE_LIMITS = "1";
    for (let i = 0; i < config.mailPerAddressHourly; i++) {
      await request(app).post("/auth/forgot-password").set("X-Forwarded-For", `198.18.0.${i + 1}`).send({ email: "owner@acme.io" }).expect(202);
    }
    await request(app).post("/auth/forgot-password").set("X-Forwarded-For", "198.18.1.1").send({ email: "owner@acme.io" }).expect(429);
    // The same cap applies to an address with no account, so the 429 reveals nothing.
    for (let i = 0; i < config.mailPerAddressHourly; i++) {
      await request(app).post("/auth/forgot-password").set("X-Forwarded-For", `198.18.2.${i + 1}`).send({ email: "ghost@acme.io" }).expect(202);
    }
    await request(app).post("/auth/forgot-password").set("X-Forwarded-For", "198.18.3.1").send({ email: "ghost@acme.io" }).expect(429);
    await flush();
    expect(sent.filter((m) => m.to === "owner@acme.io")).toHaveLength(config.mailPerAddressHourly);
  });

  it("does not wait for SMTP, so a slow mail server cannot reveal which addresses exist", async () => {
    vi.spyOn(mailer, "sendMail").mockImplementation(() => new Promise((r) => setTimeout(() => r({ sent: true }), 1500)));
    const t = performance.now();
    await request(app).post("/auth/forgot-password").send({ email: "owner@acme.io" }).expect(202);
    expect(performance.now() - t).toBeLessThan(1000);
  });

  it("a completed reset is audited and the owner told", async () => {
    await request(app).post("/auth/forgot-password").send({ email: "owner@acme.io" }).expect(202);
    await flush();
    const token = /token=([A-Za-z0-9_-]+)/.exec(sent[0]!.text)![1]!;
    await request(app).post("/auth/reset-password").send({ token, new_password: "brand-new-password-1" }).expect(200);
    await flush();
    expect(await audits("auth.password_reset")).toHaveLength(1);
    expect(sent.some((m) => /password of your Legion account was changed/.test(m.text))).toBe(true);
  });
});
