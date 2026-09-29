/**
 * Security hardening (2026-09) — network and browser controls.
 *
 *  - CSRF: Fetch-Metadata (Sec-Fetch-Site: cross-site) refused on state changes
 *  - HSTS on every HTTPS deployment, not only NODE_ENV=production
 *  - /health tells the public only "up/down"; details are for operators
 *  - WebSocket: per-user and per-tenant connection caps, ping/pong liveness,
 *    back-pressure on slow readers
 *  - malformed settings refuse to boot (DEPLOYMENT_MODE typo, NaN numbers,
 *    a non-https billing API)
 *  - SSRF: outbound calls never follow redirects and carry no tenant-chosen URL
 *  - request size limits
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { app, httpServer } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config, settingProblems } from "../src/config.js";
import { hstsEnabled } from "../src/edge.js";
import * as realtime from "../src/realtime.js";
import * as store from "../src/store.js";
import { createPortalSession } from "../src/paddle.js";
import type { User } from "../src/types.js";

const FRONT = "http://localhost:3000";
let tenantId: string; let user: User;
const token = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'N', now() + interval '14 days')", [tenantId]);
  user = await store.insertUser({ email: `n-${randomUUID().slice(0, 6)}@n.io`, password_hash: await bcrypt.hash("password123", 4), tenant_id: tenantId, role: "admin", status: "active" });
});

// --- CSRF ------------------------------------------------------------------------------------

describe("CSRF: Fetch Metadata", () => {
  it("a state change another site started is refused, even when the browser left Origin out", async () => {
    const res = await request(app).post("/auth/logout").set("Cookie", `legion_token=${token(user)}`).set("Sec-Fetch-Site", "cross-site");
    expect(res.status).toBe(403);
    const change = await request(app).post("/auth/change-password").set("Cookie", `legion_token=${token(user)}`).set("Sec-Fetch-Site", "cross-site")
      .send({ current_password: "password123", new_password: "hijacked-password" });
    expect(change.status).toBe(403);
  });

  it("same-origin and same-site requests, reads, and non-browser clients still work", async () => {
    await request(app).post("/auth/logout").set("Sec-Fetch-Site", "same-origin").set("Origin", FRONT).expect(204);
    await request(app).get("/auth/me").set("Cookie", `legion_token=${token(user)}`).set("Sec-Fetch-Site", "cross-site").expect(200);
    await request(app).post("/auth/logout").expect(204); // curl: no Origin, no Sec-Fetch-*
  });

  it("an Origin not on the allow-list is refused as before", async () => {
    await request(app).post("/auth/logout").set("Origin", "https://evil.example").expect(403);
  });

  it("machine endpoints authenticated by signature are exempt", async () => {
    const res = await request(app).post("/security-events/webhook").set("Sec-Fetch-Site", "cross-site").set("content-type", "application/json").send("{}");
    expect(res.status).toBe(401); // reached the signature check, not the CSRF guard
  });
});

// --- HSTS ------------------------------------------------------------------------------------

describe("HSTS", () => {
  const saved = { p: config.isProduction, s: config.cookieSecure, f: config.frontendUrl };
  afterEach(() => { Object.assign(config, { isProduction: saved.p, cookieSecure: saved.s, frontendUrl: saved.f }); });

  it("is on for a self-hosted HTTPS install with NODE_ENV unset (it was not before)", () => {
    Object.assign(config, { isProduction: false, cookieSecure: true, frontendUrl: "https://legion.customer.example" });
    expect(hstsEnabled()).toBe(true);
  });

  it("is never on for a plain-http install", () => {
    Object.assign(config, { isProduction: true, cookieSecure: false, frontendUrl: "http://10.0.0.5:3000" });
    expect(hstsEnabled()).toBe(false);
  });
});

// --- /health ---------------------------------------------------------------------------------

describe("/health disclosure", () => {
  const savedToken = config.healthMetricsToken;
  afterEach(() => { config.healthMetricsToken = savedToken; });

  it("through a proxy, the public learns only up/down — no version, mode or AI vendor", async () => {
    const res = await request(app).get("/health").set("X-Forwarded-For", "198.51.100.1").expect(200);
    expect(res.body).toEqual({ status: "ok", database: "up" });
  });

  it("an operator on the machine itself (curl localhost:8000/health) still sees everything", async () => {
    const res = await request(app).get("/health").expect(200);
    expect(res.body).toMatchObject({ status: "ok", database: "up", runtime: "node" });
    expect(res.body).toHaveProperty("version");
    expect(res.body).toHaveProperty("ai_provider");
  });

  it("a monitor holding HEALTH_METRICS_TOKEN sees everything from anywhere", async () => {
    config.healthMetricsToken = "monitor-token-0123456789abcdef";
    const res = await request(app).get("/health").set("X-Forwarded-For", "198.51.100.1").set("Authorization", "Bearer monitor-token-0123456789abcdef").expect(200);
    expect(res.body).toHaveProperty("version");
    const wrong = await request(app).get("/health").set("X-Forwarded-For", "198.51.100.1").set("Authorization", "Bearer nope").expect(200);
    expect(wrong.body).toEqual({ status: "ok", database: "up" });
  });
});

// --- WebSocket -----------------------------------------------------------------------------------

describe("WebSocket limits and liveness", () => {
  let server: ReturnType<typeof httpServer.listen>; let port = 0;
  const saved = { u: config.wsMaxPerUser, t: config.wsMaxPerTenant };
  beforeAll(() => { server = httpServer.listen(0); port = (server.address() as AddressInfo).port; });
  afterAll(() => { server.close(); });
  afterEach(() => { Object.assign(config, { wsMaxPerUser: saved.u, wsMaxPerTenant: saved.t }); });

  const open = (tok: string) => new Promise<WebSocket | number>((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/alerts`, { headers: { cookie: `legion_token=${tok}`, origin: FRONT } });
    ws.on("open", () => resolve(ws));
    ws.on("unexpected-response", (_q, res) => { resolve(res.statusCode ?? 0); res.resume(); });
    ws.on("error", () => resolve(0));
  });

  it("one user cannot hold more than WS_MAX_PER_USER sockets", async () => {
    config.wsMaxPerUser = 3;
    const t = token(user);
    const opened = [await open(t), await open(t), await open(t)];
    for (const o of opened) expect(o).toBeInstanceOf(WebSocket);
    expect(await open(t)).toBe(429);
    // Closing one frees a slot.
    (opened[0] as WebSocket).close();
    await new Promise((r) => setTimeout(r, 200));
    const again = await open(t);
    expect(again).toBeInstanceOf(WebSocket);
    for (const o of [...opened, again]) if (o instanceof WebSocket) o.close();
  });

  it("a tenant cannot hold more than WS_MAX_PER_TENANT sockets across its users", async () => {
    config.wsMaxPerTenant = 2;
    const other = await store.insertUser({ email: `o-${randomUUID().slice(0, 6)}@n.io`, password_hash: "x", tenant_id: tenantId, role: "viewer", status: "active" });
    const a = await open(token(user)); const b = await open(token(other));
    expect(a).toBeInstanceOf(WebSocket); expect(b).toBeInstanceOf(WebSocket);
    expect(await open(token(other))).toBe(429);
    for (const o of [a, b]) if (o instanceof WebSocket) o.close();
  });

  it("a live client answers pings and stays; a dead one is terminated on the next round", async () => {
    const live = await open(token(user)) as WebSocket;
    await new Promise((r) => setTimeout(r, 100));
    // A registered socket that never answers (client vanished).
    const dead = { readyState: WebSocket.OPEN, bufferedAmount: 0, on: () => {}, ping: vi.fn(), terminate: vi.fn(), send: vi.fn(), close: vi.fn() } as unknown as WebSocket;
    realtime.register(tenantId, dead, { userId: randomUUID(), tokenVersion: 0 });
    expect(realtime.livenessOnce()).toBe(0);      // round 1: everyone pinged
    await new Promise((r) => setTimeout(r, 200)); // the real client's pong arrives
    expect(realtime.livenessOnce()).toBe(1);      // round 2: only the silent one goes
    expect((dead as unknown as { terminate: ReturnType<typeof vi.fn> }).terminate).toHaveBeenCalled();
    expect(live.readyState).toBe(WebSocket.OPEN);
    live.close();
  });

  it("a reader that stops reading is cut off instead of buffering without limit", async () => {
    const slow = { readyState: WebSocket.OPEN, bufferedAmount: realtime.MAX_BUFFERED_BYTES, on: () => {}, ping: vi.fn(), terminate: vi.fn(), send: vi.fn(), close: vi.fn() } as unknown as WebSocket;
    const t2 = randomUUID();
    realtime.register(t2, slow, { userId: randomUUID(), tokenVersion: 0 });
    await realtime.publish(t2, { type: "ping", cursor: 1 });
    const s = slow as unknown as { send: ReturnType<typeof vi.fn>; terminate: ReturnType<typeof vi.fn> };
    expect(s.send).not.toHaveBeenCalled();
    expect(s.terminate).toHaveBeenCalled();
    expect(realtime.connectionCounts(t2, "x").tenant).toBe(0);
  });
});

// --- configuration ---------------------------------------------------------------------------------

describe("malformed settings refuse to boot", () => {
  it.each([
    [{ DEPLOYMENT_MODE: "selfhosted" }, /DEPLOYMENT_MODE/],
    [{ DEPLOYMENT_MODE: "hosted" }, /DEPLOYMENT_MODE/],
    [{ ACCESS_TOKEN_MINUTES: "15m" }, /ACCESS_TOKEN_MINUTES/],
    [{ ACCESS_TOKEN_MINUTES: "0" }, /ACCESS_TOKEN_MINUTES/],
    [{ REFRESH_TOKEN_DAYS: "-1" }, /REFRESH_TOKEN_DAYS/],
    [{ DB_POOL_MAX: "ten" }, /DB_POOL_MAX/],
    [{ PORT: "80.5" }, /PORT/],
    [{ ALERT_EMAIL_MIN_SEVERITY: "urgent" }, /ALERT_EMAIL_MIN_SEVERITY/],
    [{ PADDLE_API_BASE: "http://paddle.attacker.example" }, /PADDLE_API_BASE/],
    [{ PADDLE_API_BASE: "https://user:pass@api.paddle.com" }, /PADDLE_API_BASE/],
  ])("%j", (env, pattern) => {
    expect(settingProblems(env).join("\n")).toMatch(pattern);
  });

  it("valid settings pass", () => {
    expect(settingProblems({ DEPLOYMENT_MODE: "self-hosted", ACCESS_TOKEN_MINUTES: "15", PORT: "8000", PADDLE_API_BASE: "https://api.paddle.com" })).toEqual([]);
    expect(settingProblems({ DEPLOYMENT_MODE: "saas", PADDLE_API_BASE: "http://127.0.0.1:9999" })).toEqual([]); // a local stub
    expect(settingProblems({})).toEqual([]);
  });

  it("the server really refuses to start (config.ts at import time)", async () => {
    vi.resetModules();
    vi.stubEnv("DEPLOYMENT_MODE", "selfhosted");
    try {
      await expect(import("../src/config.js")).rejects.toThrow(/Refusing to start with malformed settings[\s\S]*DEPLOYMENT_MODE/);
    } finally { vi.unstubAllEnvs(); vi.resetModules(); }
  });
});

// --- SSRF / outbound ---------------------------------------------------------------------------------

describe("outbound requests (SSRF)", () => {
  it("every fetch() the server makes refuses redirects", () => {
    const SRC = join(__dirname, "..", "src");
    const offenders: string[] = [];
    for (const f of readdirSync(SRC).filter((x) => x.endsWith(".ts"))) {
      const text = readFileSync(join(SRC, f), "utf8");
      for (const m of text.matchAll(/\bfetch\(/g)) {
        const lineStart = text.lastIndexOf("\n", m.index!) + 1;
        if (/^\s*(\/\/|\*|\/\*)/.test(text.slice(lineStart, m.index!))) continue; // a comment
        const window = text.slice(m.index!, m.index! + 1200);
        if (!/redirect:\s*"error"/.test(window)) offenders.push(`${f}@${m.index}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("the billing API client does not follow a redirect with its key, and leaks no transport detail", async () => {
    let followed = false;
    const target: Server = createServer((_q, r) => { followed = true; r.end("{}"); }).listen(0);
    const tport = (target.address() as AddressInfo).port;
    const redirector: Server = createServer((_q, r) => { r.writeHead(302, { Location: `http://127.0.0.1:${tport}/steal` }); r.end(); }).listen(0);
    const saved = { base: config.paddleApiBase, key: config.paddleApiKey };
    Object.assign(config, { paddleApiBase: `http://127.0.0.1:${(redirector.address() as AddressInfo).port}`, paddleApiKey: "pdl_test_key" });
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const r = await createPortalSession("ctm_1", []);
      expect(r.ok).toBe(false);
      expect(followed).toBe(false);
      if (!r.ok) {
        expect(r.detail).toBe("Could not reach the billing provider. Try again later.");
        expect(r.detail).not.toMatch(/127\.0\.0\.1|redirect|ECONN/i);
      }
    } finally {
      Object.assign(config, { paddleApiBase: saved.base, paddleApiKey: saved.key });
      err.mockRestore(); target.close(); redirector.close();
    }
  });

  it("no tenant-controlled value can choose where the server connects: outbound hosts come from configuration only", () => {
    const SRC = join(__dirname, "..", "src");
    const ai = readFileSync(join(SRC, "ai.ts"), "utf8");
    expect(ai).toMatch(/url: "https:\/\/openrouter\.ai\/api\/v1\/chat\/completions"/);
    expect(ai).toMatch(/url: "https:\/\/api\.groq\.com\/openai\/v1\/chat\/completions"/);
    expect(readFileSync(join(SRC, "paddle.ts"), "utf8")).toMatch(/fetch\(`\$\{config\.paddleApiBase\}\$\{path\}`/);
  });
});

// --- request size limits -------------------------------------------------------------------------------

describe("request size limits", () => {
  it("an API JSON body over 256 KB is refused with 413 before any handler runs", async () => {
    await request(app).post("/auth/login").set("content-type", "application/json").send(JSON.stringify({ username: "x", password: "y".repeat(300_000) })).expect(413);
  });

  it("a form body over 32 KB is refused", async () => {
    await request(app).post("/auth/login").set("content-type", "application/x-www-form-urlencoded").send(`username=${"a".repeat(40_000)}`).expect(413);
  });
});
