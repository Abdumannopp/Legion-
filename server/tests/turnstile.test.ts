/**
 * Cloudflare Turnstile on the endpoints a botnet floods (turnstile.ts), against
 * a local stand-in for Cloudflare's siteverify API.
 */
import { vi } from "vitest";
// Real limits in this file: the point is that a request without a solved
// challenge never reaches the per-account and per-address counters.
vi.hoisted(() => { process.env.LEGION_ENFORCE_RATE_LIMITS = "1"; });
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import http from "node:http";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { config } from "../src/config.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { verifyTurnstile } from "../src/turnstile.js";

const SECRET = "0x4AAAAAAA-test-secret-key";
const seen: URLSearchParams[] = [];
let stub: http.Server;
let stubUrl = "";
let ipN = 0;
const ip = () => `198.51.100.${(ipN++ % 250) + 1}`;

/** Cloudflare's siteverify, as documented: form-encoded in, JSON out. */
function startStub(): Promise<void> {
  stub = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      const form = new URLSearchParams(raw);
      seen.push(form);
      const token = form.get("response");
      res.setHeader("content-type", "application/json");
      if (token === "boom") { res.statusCode = 500; return res.end("{}"); }
      if (form.get("secret") !== SECRET) return res.end(JSON.stringify({ success: false, "error-codes": ["invalid-input-secret"] }));
      if (token?.startsWith("good")) return res.end(JSON.stringify({ success: true, "error-codes": [], hostname: "legion.test" }));
      res.end(JSON.stringify({ success: false, "error-codes": ["invalid-input-response"] }));
    });
  });
  return new Promise((r) => stub.listen(0, "127.0.0.1", () => { stubUrl = `http://127.0.0.1:${(stub.address() as { port: number }).port}/siteverify`; r(); }));
}

const login = (body: Record<string, unknown>, headers: Record<string, string> = {}) =>
  request(app).post("/auth/login").set("X-Forwarded-For", headers["x-forwarded-for"] ?? ip()).set(headers).send(body);

beforeAll(async () => {
  await startStub();
  await migrate();
  await truncateAll();
  const t = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Captcha Co')", [t]);
  await store.insertUser({ email: "person@example.com", password_hash: await bcrypt.hash("password123", 4), tenant_id: t, role: "admin", status: "active" });
  config.deploymentMode = "self-hosted";
});
beforeEach(() => {
  config.turnstileSecretKey = SECRET;
  config.turnstileVerifyUrl = stubUrl;
  seen.length = 0;
});
afterAll(async () => {
  config.turnstileSecretKey = "";
  delete process.env.LEGION_ENFORCE_RATE_LIMITS;
  stub.close();
  await closePool();
});

describe("Turnstile on sign-in", () => {
  it("the dashboard is told to show the widget", async () => {
    expect((await request(app).get("/auth/setup-status")).body.captcha).toBe(true);
    config.turnstileSecretKey = "";
    expect((await request(app).get("/auth/setup-status")).body.captcha).toBe(false);
  });

  it("no token → 400 captcha_required, and Cloudflare is not even asked", async () => {
    const r = await login({ username: "person@example.com", password: "password123" });
    expect(r.status).toBe(400);
    expect(r.body.code).toBe("captcha_required");
    expect(seen).toHaveLength(0);
  });

  it("a rejected token → 400 captcha_failed; the password is never checked", async () => {
    const r = await login({ username: "person@example.com", password: "password123", turnstile_token: "forged" });
    expect(r.status).toBe(400);
    expect(r.body.code).toBe("captcha_failed");
    expect(r.body.access_token).toBeUndefined();
  });

  it("a solved challenge + the right password signs in; Cloudflare gets our secret and the visitor's address", async () => {
    const r = await login({ username: "person@example.com", password: "password123", turnstile_token: "good-1" }, { "x-forwarded-for": "203.0.113.77" });
    expect(r.status).toBe(200);
    expect(r.body.access_token).toBeTruthy();
    expect(seen[0].get("secret")).toBe(SECRET);
    expect(seen[0].get("response")).toBe("good-1");
    expect(seen[0].get("remoteip")).toBe("203.0.113.77");
  });

  it("the token may also come in the cf-turnstile-response header", async () => {
    const r = await login({ username: "person@example.com", password: "password123" }, { "cf-turnstile-response": "good-2" });
    expect(r.status).toBe(200);
  });

  it("a solved challenge does not make a wrong password right", async () => {
    const r = await login({ username: "person@example.com", password: "nope-nope-nope", turnstile_token: "good-3" });
    expect(r.status).toBe(401);
  });

  it("an oversized token is refused without asking Cloudflare", async () => {
    expect(await verifyTurnstile("good".padEnd(3000, "x"))).toBe("failed");
    expect(seen).toHaveLength(0);
  });

  it("the refusal speaks the visitor's language", async () => {
    const r = await login({ username: "person@example.com", password: "password123" }, { "accept-language": "uz" });
    expect(r.body.detail).toMatch(/Xavfsizlik tekshiruvidan/);
  });
});

describe("fails closed when Cloudflare cannot answer", () => {
  it.each([
    ["Cloudflare answers 500", () => "boom"],
    ["our secret key is wrong", () => { config.turnstileSecretKey = "0x4AAAAAAA-wrong-secret"; return "good-4"; }],
    ["Cloudflare is unreachable", () => { config.turnstileVerifyUrl = "http://127.0.0.1:9/siteverify"; return "good-5"; }],
  ])("%s → 503 captcha_unavailable + Retry-After, never a sign-in", async (_name, setup) => {
    const token = setup();
    const r = await login({ username: "person@example.com", password: "password123", turnstile_token: token });
    expect(r.status).toBe(503);
    expect(r.body.code).toBe("captcha_unavailable");
    expect(r.headers["retry-after"]).toBe("5");
    expect(r.body.access_token).toBeUndefined();
  });
});

describe("requests without a solved challenge cannot be used against a victim", () => {
  it("25 challenge-less sign-ins from many addresses do not lock the account (they never reach the failure counter)", async () => {
    for (let i = 0; i < 25; i++) {
      expect((await login({ username: "victim@example.com", password: `guess-${i}` })).status).toBe(400);
    }
    await store.insertUser({ email: "victim@example.com", password_hash: await bcrypt.hash("victim-password", 4), tenant_id: (await store.findUserByEmail("person@example.com"))!.tenant_id, role: "analyst", status: "active" });
    const r = await login({ username: "victim@example.com", password: "victim-password", turnstile_token: "good-6" });
    expect(r.status).toBe(200);
  });

  it("challenge-less password-reset requests do not spend the address's email budget", async () => {
    for (let i = 0; i < 12; i++) {
      const r = await request(app).post("/auth/forgot-password").set("X-Forwarded-For", ip()).send({ email: "person@example.com" });
      expect(r.status).toBe(400);
      expect(r.body.code).toBe("captcha_required");
    }
    const ok = await request(app).post("/auth/forgot-password").set("X-Forwarded-For", ip()).send({ email: "person@example.com", turnstile_token: "good-7" });
    expect(ok.status).toBeLessThan(300);
  });

  it("sign-up and resend-verification require it too", async () => {
    const reg = await request(app).post("/auth/register").set("X-Forwarded-For", ip()).send({ email: "new@example.com", password: "Long-password-123", tenant_name: "New Co" });
    expect(reg.body.code).toBe("captcha_required");
    const resend = await request(app).post("/auth/resend-verification").set("X-Forwarded-For", ip()).send({ email: "new@example.com" });
    expect(resend.body.code).toBe("captcha_required");
  });
});

describe("off by default", () => {
  it("without TURNSTILE_SECRET_KEY nothing changes: sign-in needs no token", async () => {
    config.turnstileSecretKey = "";
    const r = await login({ username: "person@example.com", password: "password123" });
    expect(r.status).toBe(200);
    expect(seen).toHaveLength(0);
  });
});
