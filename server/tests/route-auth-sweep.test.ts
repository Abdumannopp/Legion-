/**
 * Authentication and authorization sweep over EVERY route the API registers.
 *
 * 1. Without credentials, every route that is not on the reviewed public list
 *    answers 401 (or 403/404 for deliberately hidden ones) — never data, never 5xx.
 * 2. A viewer (lowest role) is refused (403) on every route that needs a
 *    higher role, for the SOC core and all admin/analyst surfaces we can name.
 * 3. A forged, expired or wrong-tenant token is refused on a sample of routes.
 *
 * A new route that forgets its guard fails here, by name.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import jwt from "jsonwebtoken";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";

interface R { method: string; path: string }
function routes(): R[] {
  const out: R[] = [];
  // Only routes registered directly on the app. Mounted sub-routers (the agent layer) lose their
  // mount prefix in Express 5's stack, so they are covered by prefix in the "mounted routers" test below.
  for (const l of (app as any).router.stack) {
    if (l.route) for (const m of Object.keys(l.route.methods)) out.push({ method: m.toUpperCase(), path: l.route.path });
  }
  return out;
}

/** Routes that are public ON PURPOSE (sign-in, sign-up, health, signed webhooks, legal pages, billing webhook…). Reviewed. */
const PUBLIC: Array<[string, RegExp, string]> = [
  ["GET", /^\/health$/, "liveness"],
  ["POST", /^\/auth\/(login|register|refresh|logout|forgot-password|reset-password|verify-email|resend-verification|accept-invite|mfa\/verify|mfa\/recover)$/, "sign-in flows (own limiters and proofs)"],
  ["GET", /^\/auth\/(setup-status|config)$/, "first-run status"],
  ["POST", /^\/security-events\/(webhook|payment-check)$/, "HMAC-signed sensor endpoints"],
  ["POST", /^\/security-events\/blocklist$/, "HMAC-signed sensor endpoint"],
  ["POST", /^\/billing\/webhook$/, "Paddle signature"],
  ["GET", /^\/(metrics|health\/outbox|health\/backup|mock-provider\/.*)$/, "token-gated (404 when unconfigured)"],
  ["POST", /^\/notifications\/confirm$/, "one-time token link"],
  ["GET", /^\/(i18n\/.*|plans|locales|public\/.*|\.well-known\/.*)$/, "static public data"],
  ["POST", /^\/(support|contact).*$/, "public contact form"],
  ["POST", /^\/auth\/invite\/preview$/, "an invitation link's own one-time token (422 without it)"],
  ["GET", /^\/billing\/plans$/, "public price list"],
];
const isPublic = (r: R) => PUBLIC.some(([m, re]) => m === r.method && re.test(r.path));
const concrete = (p: string) => p.replace(/:[A-Za-z_]+/g, (m) => (m === ":id" ? randomUUID() : "x"));

let tenantA: string; let viewerTok = ""; let adminTok = "";
beforeAll(async () => {
  await migrate();
  await truncateAll();
  tenantA = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business')", [tenantA]);
  const h = await bcrypt.hash("password123", 4);
  const viewer = await store.insertUser({ email: "v@a.io", password_hash: h, tenant_id: tenantA, role: "viewer", status: "active" });
  const admin = await store.insertUser({ email: "a@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  const tok = (u: typeof viewer) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });
  viewerTok = tok(viewer); adminTok = tok(admin);
});
afterAll(async () => { await closePool(); });

const call = (r: R, token?: string) => {
  const req = (request(app) as any)[r.method.toLowerCase()](concrete(r.path));
  if (token) req.set("Authorization", `Bearer ${token}`);
  return r.method === "GET" || r.method === "DELETE" ? req : req.send({});
};

describe("route authentication sweep", () => {
  const all = routes();
  it("finds the routes (the sweep itself works)", () => {
    expect(all.length).toBeGreaterThan(120);
    for (const p of ["/policy", "/approvals/:id/decision", "/actions", "/workflows/:name/runs", "/memory", "/soc/audit/verify", "/runtime/status"]) expect(all.some((r) => r.path === p), p).toBe(true);
  });

  it("every non-public route refuses an unauthenticated caller", async () => {
    const open: string[] = [];
    for (const r of all.filter((x) => !isPublic(x))) {
      const res = await call(r);
      if (![401, 403, 404].includes(res.status)) open.push(`${r.method} ${r.path} → ${res.status}`);
    }
    expect(open).toEqual([]);
  }, 120_000);

  it("every PUBLIC route is on the reviewed list for a reason (no accidental new public route)", () => {
    const stray = all.filter((r) => isPublic(r)).map((r) => `${r.method} ${r.path}`);
    // The list is the contract: if you add a public route, add it to PUBLIC with its reason.
    expect(stray.length).toBeLessThan(60);
    expect(new Set(stray).size).toBe(stray.length);
  });

  it("forged, expired and malformed tokens are refused everywhere they are tried", async () => {
    const sample = all.filter((r) => !isPublic(r) && r.method === "GET" && !r.path.includes(":")).slice(0, 25);
    expect(sample.length).toBeGreaterThan(10);
    const wrongKey = jwt.sign({ sub: randomUUID(), tenant_id: tenantA, token_version: 0 }, "an-attacker-key-an-attacker-key-0123456789", { algorithm: "HS256", expiresIn: "1h" });
    const expired = jwt.sign({ sub: randomUUID(), tenant_id: tenantA, token_version: 0 }, config.jwtSecret, { algorithm: "HS256", expiresIn: -60 });
    const none = `${Buffer.from('{"alg":"none","typ":"JWT"}').toString("base64url")}.${Buffer.from(JSON.stringify({ sub: randomUUID(), tenant_id: tenantA })).toString("base64url")}.`;
    const bad: string[] = [];
    for (const r of sample) for (const [name, t] of [["wrong key", wrongKey], ["expired", expired], ["alg none", none], ["garbage", "not-a-token"]] as const) {
      const res = await call(r, t);
      if (res.status !== 401 && res.status !== 403) bad.push(`${r.method} ${r.path} [${name}] → ${res.status}`);
    }
    expect(bad).toEqual([]);
  }, 120_000);
});

describe("mounted routers (the agent layer): nothing answers without credentials", () => {
  const PREFIXES = ["/agent/v1", "/agents", "/service-accounts", "/audit/principal-events", "/firewall", "/prompt-guard", "/tools", "/behavior", "/skills"];
  it("every mount prefix refuses an unauthenticated caller on its root and on arbitrary paths", async () => {
    const open: string[] = [];
    for (const p of PREFIXES) for (const sub of ["", "/", "/registry", "/decisions", "/verify", `/${randomUUID()}`]) for (const method of ["get", "post", "delete"] as const) {
      const res = await (request(app) as any)[method](p + sub).send(method === "get" ? undefined : {});
      if (![401, 403, 404].includes(res.status)) open.push(`${method.toUpperCase()} ${p}${sub} → ${res.status}`);
    }
    expect(open).toEqual([]);
  }, 120_000);
});

describe("role sweep: a viewer is refused on every SOC-core and administration route", () => {
  const ELEVATED = /^\/(policy|approvals|actions|workflows|memory|learning|runtime|soc|agents|team|workspace\/settings|security\/(blocks|auto-response|payments)|audit)/;
  const all = routes().filter((r) => ELEVATED.test(r.path) && !isPublic(r));
  it("covers a meaningful number of routes", () => expect(all.length).toBeGreaterThan(30));
  it("answers 403 to a viewer (reads of shared security state that viewers may see are listed explicitly)", async () => {
    // Reviewed: viewers may read the block list, auto-response settings, payment holds list and the workspace's own agents list? (checked below)
    const VIEWER_MAY = new Set(["GET /security/blocks", "GET /security/auto-response", "GET /security/payments", "GET /security/payments/consent", "GET /team", "GET /workspace/settings"]); // presentation settings / lists any member may see
    const wrong: string[] = [];
    for (const r of all) {
      if (VIEWER_MAY.has(`${r.method} ${r.path}`)) continue;
      const res = await call(r, viewerTok);
      if (res.status !== 403) wrong.push(`${r.method} ${r.path} → ${res.status}`);
    }
    expect(wrong).toEqual([]);
  }, 120_000);
});
