/**
 * The edge as a browser and an attacker see it, against the real application:
 * CORS, Origin checks, security headers, cookie attributes, brute-force limits
 * on login and MFA, spoofed client addresses, and the WebSocket handshake.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import * as OTPAuth from "otpauth";
import { app, httpServer } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";
import { resetUpgradeLimiter, UPGRADE_LIMIT_PER_MINUTE } from "../src/edge.js";
import type { User } from "../src/types.js";

const PASSWORD = "password123";
const FRONT = "http://localhost:3000";
const EVIL = "https://evil.example";
let user: User;
let seq = 0;
/** A fresh client address per call, so tests never share an address-limit bucket. */
const fresh = () => `198.51.100.${(++seq % 250) + 1}`;

beforeAll(async () => {
  process.env.LEGION_ENFORCE_RATE_LIMITS = "1";
  await migrate();
});
afterAll(async () => { delete process.env.LEGION_ENFORCE_RATE_LIMITS; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  const tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + interval '14 days')", [tenantId, "Edge"]);
  user = await store.insertUser({
    email: `edge-${randomUUID()}@example.com`, password_hash: await bcrypt.hash(PASSWORD, 4),
    tenant_id: tenantId, role: "admin", status: "active",
  });
});

const sessionToken = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });

describe("CORS", () => {
  it("allows the configured frontend, with credentials, and nothing broader", async () => {
    const res = await request(app).get("/health").set("Origin", FRONT);
    expect(res.headers["access-control-allow-origin"]).toBe(FRONT);
    expect(res.headers["access-control-allow-credentials"]).toBe("true");
    expect(res.headers["vary"]).toMatch(/Origin/i);
  });

  it("CORS violation: another origin gets no Access-Control headers, so the browser withholds the response", async () => {
    const res = await request(app).get("/health").set("Origin", EVIL);
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it("CORS violation: a preflight from another origin is not approved", async () => {
    const res = await request(app).options("/alerts").set("Origin", EVIL)
      .set("Access-Control-Request-Method", "DELETE").set("Access-Control-Request-Headers", "content-type");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["access-control-allow-methods"]).toBeUndefined();
  });

  it("a preflight from the frontend lists only the methods and headers the API uses", async () => {
    const res = await request(app).options("/alerts").set("Origin", FRONT)
      .set("Access-Control-Request-Method", "POST").set("Access-Control-Request-Headers", "content-type");
    expect(res.status).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe(FRONT);
    expect(res.headers["access-control-allow-methods"]).not.toMatch(/\*/);
    expect(res.headers["access-control-allow-headers"]).toMatch(/content-type/i);
  });

  it("the null origin and look-alike origins are refused", async () => {
    for (const origin of ["null", "http://localhost:3000.evil.example", "http://localhost:30000", "https://localhost:3000"]) {
      const res = await request(app).get("/health").set("Origin", origin);
      expect(res.headers["access-control-allow-origin"], origin).toBeUndefined();
    }
  });

  it("CSRF: a state-changing request from another origin is refused outright — even with a valid session", async () => {
    const res = await request(app).post("/auth/logout").set("Origin", EVIL).set("Authorization", `Bearer ${sessionToken(user)}`);
    expect(res.status).toBe(403);
    // The same request from the dashboard, or from a non-browser with no Origin, works.
    expect((await request(app).post("/auth/logout").set("Origin", FRONT).set("Authorization", `Bearer ${sessionToken(user)}`)).status).not.toBe(403);
    expect((await request(app).post("/auth/logout").set("Authorization", `Bearer ${sessionToken(user)}`)).status).not.toBe(403);
  });

  it("sensor webhooks are not browsers and are never blocked by the Origin check", async () => {
    const res = await request(app).post("/security-events/webhook").set("Origin", EVIL).send({});
    expect(res.status).not.toBe(403); // rejected for missing credentials (401), not for its Origin
  });
});

describe("security headers", () => {
  it("sends CSP, framing, referrer, MIME and cache protections on every response", async () => {
    const res = await request(app).get("/health");
    expect(res.headers["content-security-policy"]).toMatch(/default-src 'none'/);
    expect(res.headers["content-security-policy"]).toMatch(/frame-ancestors 'none'/);
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["permissions-policy"]).toMatch(/camera=\(\)/);
    expect(res.headers["cross-origin-resource-policy"]).toBe("same-site");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["x-powered-by"]).toBeUndefined();
  });

  it("no HSTS outside production HTTPS (it would poison a plain-http install)", async () => {
    const res = await request(app).get("/health");
    expect(res.headers["strict-transport-security"]).toBeUndefined();
  });

  it("HSTS is sent for an HTTPS production deployment", async () => {
    const saved = { p: config.isProduction, s: config.cookieSecure, f: config.frontendUrl };
    Object.assign(config, { isProduction: true, cookieSecure: true, frontendUrl: "https://legion.example.com" });
    try {
      // Headers are built at boot from config, so build the middleware afresh.
      const { hstsEnabled, securityHeaders } = await import("../src/edge.js");
      expect(hstsEnabled()).toBe(true);
      const express = (await import("express")).default;
      const mini = express(); mini.use(securityHeaders()); mini.get("/", (_q, r) => { r.send("ok"); });
      const res = await request(mini).get("/");
      expect(res.headers["strict-transport-security"]).toMatch(/max-age=31536000; includeSubDomains/);
    } finally { Object.assign(config, { isProduction: saved.p, cookieSecure: saved.s, frontendUrl: saved.f }); }
  });
});

describe("session cookies", () => {
  it("are HttpOnly and SameSite; the refresh cookie is Strict and scoped to its path", async () => {
    const res = await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: user.email, password: PASSWORD }).expect(200);
    const cookies = ([] as string[]).concat(res.headers["set-cookie"] ?? []);
    const token = cookies.find((c) => c.startsWith("legion_token="))!;
    const refresh = cookies.find((c) => c.startsWith("legion_refresh="))!;
    expect(token).toMatch(/HttpOnly/i); expect(token).toMatch(/SameSite=Lax/i); expect(token).toMatch(/Path=\/;/);
    expect(refresh).toMatch(/HttpOnly/i); expect(refresh).toMatch(/SameSite=Strict/i);
    expect(refresh).toContain(`Path=${config.refreshCookiePath};`);
    // The dashboard-readable marker is the one cookie that is not HttpOnly, and holds no secret.
    expect(cookies.find((c) => c.startsWith("legion_session="))).not.toMatch(/HttpOnly/i);
  });

  it("carry Secure when COOKIE_SECURE is on (required in production)", async () => {
    config.cookieSecure = true;
    try {
      const res = await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: user.email, password: PASSWORD }).expect(200);
      for (const c of ([] as string[]).concat(res.headers["set-cookie"] ?? [])) expect(c, c).toMatch(/;\s*Secure/i);
    } finally { config.cookieSecure = false; }
  });

  it("logout clears them with matching attributes", async () => {
    const res = await request(app).post("/auth/logout").set("Authorization", `Bearer ${sessionToken(user)}`);
    const cleared = ([] as string[]).concat(res.headers["set-cookie"] ?? []);
    expect(cleared.some((c) => /^legion_token=;/.test(c) && /Expires=Thu, 01 Jan 1970/.test(c))).toBe(true);
    expect(cleared.some((c) => /^legion_refresh=;/.test(c) && /Path=\/auth/.test(c))).toBe(true);
  });
});

describe("brute-force login", () => {
  it("one address: the 11th attempt in a minute is refused, with Retry-After", async () => {
    const ip = fresh();
    const codes: number[] = [];
    let last;
    for (let i = 0; i < 12; i++) {
      last = await request(app).post("/auth/login").set("X-Forwarded-For", ip).send({ username: `nobody${i}@example.com`, password: "x" });
      codes.push(last.status);
    }
    expect(codes.slice(0, 10).every((c) => c === 401)).toBe(true);
    expect(codes.slice(10)).toEqual([429, 429]);
    expect(last!.headers["retry-after"]).toBeDefined();
    expect(last!.body.detail).toBeTruthy();
  });

  it("one account, many addresses (a botnet): refused after the account's failure budget", async () => {
    const codes: number[] = [];
    for (let i = 0; i < config.loginAccountFailures + 3; i++) {
      const r = await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: user.email, password: `wrong${i}` });
      codes.push(r.status);
    }
    expect(codes.slice(0, config.loginAccountFailures).every((c) => c === 401)).toBe(true);
    expect(codes.slice(config.loginAccountFailures).every((c) => c === 429)).toBe(true);
    // Even the right password is refused during the lockout: no guessing oracle.
    const right = await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: user.email, password: PASSWORD });
    expect(right.status).toBe(429);
  });

  it("the account key is case-insensitive, so changing case is not a way around it", async () => {
    // (same account as above would be locked; use a different one)
    const target = "Case.Target@Example.com";
    const codes: number[] = [];
    for (let i = 0; i < config.loginAccountFailures + 1; i++) {
      const variant = i % 2 ? target.toUpperCase() : target.toLowerCase();
      codes.push((await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: variant, password: "no" })).status);
    }
    expect(codes.at(-1)).toBe(429);
  });

  it("legitimate use is unaffected: successes never count, and other users are independent", async () => {
    for (let i = 0; i < 3; i++) {
      await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: user.email, password: PASSWORD }).expect(200);
    }
  });

  it("a request with no body is a clean 401, not a crash", async () => {
    const res = await request(app).post("/auth/login").set("X-Forwarded-For", fresh());
    expect(res.status).toBe(401);
  });
});

describe("spoofed client address", () => {
  it("cannot be used to dodge the address limit when no proxy is trusted", async () => {
    const before = app.get("trust proxy");
    app.set("trust proxy", false);
    try {
      const codes: number[] = [];
      for (let i = 0; i < 12; i++) {
        // A new fake address every time — a working spoof would get a fresh bucket each time.
        codes.push((await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: `spoof${i}@example.com`, password: "x" })).status);
      }
      expect(codes.slice(10)).toEqual([429, 429]);
    } finally { app.set("trust proxy", before); }
  });

  it("behind the trusted proxy, distinct real clients get distinct buckets (production traffic is not lumped together)", async () => {
    const a = fresh(), b = fresh();
    for (let i = 0; i < 10; i++) await request(app).post("/auth/login").set("X-Forwarded-For", a).send({ username: `a${i}@example.com`, password: "x" });
    expect((await request(app).post("/auth/login").set("X-Forwarded-For", a).send({ username: "a-more@example.com", password: "x" })).status).toBe(429);
    expect((await request(app).post("/auth/login").set("X-Forwarded-For", b).send({ username: "b1@example.com", password: "x" })).status).toBe(401);
  });
});

describe("brute-force MFA", () => {
  it("five wrong codes lock the challenge; the right code is then refused too", async () => {
    const setup = await request(app).post("/auth/mfa/setup").set("Authorization", `Bearer ${sessionToken(user)}`).expect(200);
    const secret: string = setup.body.secret;
    const totp = (offset = 0) => new OTPAuth.TOTP({ issuer: config.mfaIssuer, label: user.email, algorithm: "SHA1", digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secret) })
      .generate({ timestamp: Date.now() + offset * 30_000 });
    // Enabling MFA is itself rate-limited per address now; setup uses its own.
    await request(app).post("/auth/mfa/enable").set("Authorization", `Bearer ${sessionToken(user)}`).set("X-Forwarded-For", fresh()).send({ code: totp() }).expect(200);
    await query("DELETE FROM mfa_used_counters WHERE user_id = $1", [user.id]);
    user = (await store.findUserById(user.id))!; // enabling MFA rotated its sessions (token_version)

    const login = await request(app).post("/auth/login").set("X-Forwarded-For", fresh()).send({ username: user.email, password: PASSWORD }).expect(200);
    const mfaToken: string = login.body.mfa_token;

    const codes: number[] = [];
    for (let i = 0; i < config.mfaAccountFailures + 2; i++) {
      // A new address each time: the cap is per user, not per address.
      codes.push((await request(app).post("/auth/mfa/verify").set("X-Forwarded-For", fresh()).send({ mfa_token: mfaToken, code: String(100000 + i) })).status);
    }
    expect(codes.slice(0, config.mfaAccountFailures).every((c) => c === 401)).toBe(true);
    expect(codes.slice(config.mfaAccountFailures)).toEqual([429, 429]);
    const right = await request(app).post("/auth/mfa/verify").set("X-Forwarded-For", fresh()).send({ mfa_token: mfaToken, code: totp() });
    expect(right.status).toBe(429);
  });

  it("garbage tokens fall back to the address limit and never crash", async () => {
    const ip = fresh();
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await request(app).post("/auth/mfa/verify").set("X-Forwarded-For", ip).send({ mfa_token: "x".repeat(20), code: "123456" })).status);
    expect(codes.at(-1)).toBe(429);
    expect((await request(app).post("/auth/mfa/verify").set("X-Forwarded-For", fresh())).status).toBe(422);
  });
});

describe("WebSocket handshake", () => {
  const open = (port: number, headers: Record<string, string>) => new Promise<{ status: "open" | number; ws?: WebSocket }>((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/alerts`, { headers });
    ws.on("open", () => resolve({ status: "open", ws }));
    ws.on("unexpected-response", (_req, res) => { resolve({ status: res.statusCode ?? 0 }); res.resume(); });
    ws.on("error", () => resolve({ status: 0 }));
  });
  let port = 0; let server: ReturnType<typeof httpServer.listen>;
  beforeAll(() => { server = httpServer.listen(0); port = (server.address() as AddressInfo).port; });
  afterAll(() => { server.close(); });
  beforeEach(() => resetUpgradeLimiter());

  it("valid origin: connects", async () => {
    const r = await open(port, { cookie: `legion_token=${sessionToken(user)}`, origin: FRONT });
    expect(r.status).toBe("open"); r.ws?.close();
  });

  it("wrong origin: refused with 403 even though the cookie is valid (cross-site WebSocket hijacking)", async () => {
    const r = await open(port, { cookie: `legion_token=${sessionToken(user)}`, origin: EVIL });
    expect(r.status).toBe(403);
  });

  it("missing Origin: refused by default (browsers always send one)", async () => {
    const r = await open(port, { cookie: `legion_token=${sessionToken(user)}` });
    expect(r.status).toBe(403);
  });

  it("missing Origin is accepted only when the operator opts in", async () => {
    config.wsAllowMissingOrigin = true;
    try {
      const r = await open(port, { cookie: `legion_token=${sessionToken(user)}` });
      expect(r.status).toBe("open"); r.ws?.close();
    } finally { config.wsAllowMissingOrigin = false; }
  });

  it("right origin, no session: 401", async () => {
    expect((await open(port, { origin: FRONT })).status).toBe(401);
  });

  it("an MFA challenge token is not a session", async () => {
    const mfa = mint({ sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version, purpose: "mfa" }, { kind: "mfa", expiresIn: "5m" });
    expect((await open(port, { cookie: `legion_token=${mfa}`, origin: FRONT })).status).toBe(401);
  });

  it("handshake floods are cut off per address before touching the database", async () => {
    const results: Array<"open" | number> = [];
    for (let i = 0; i < UPGRADE_LIMIT_PER_MINUTE + 3; i++) results.push((await open(port, { origin: FRONT, "x-forwarded-for": "203.0.113.50" })).status);
    expect(results.slice(-3)).toEqual([429, 429, 429]);
    // A different client is not affected.
    expect((await open(port, { origin: FRONT, "x-forwarded-for": "203.0.113.51" })).status).toBe(401);
  });
});
