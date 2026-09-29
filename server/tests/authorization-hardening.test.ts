/**
 * Security hardening (2026-09) — authorization regressions.
 *
 *  - RBAC matrix, built FROM THE SOURCE: every role-guarded route (dashboard and
 *    agent layer) refuses anonymous callers and roles below its minimum
 *  - the subscription gate now covers the agent layer (audit P1-6), except
 *    actions that stop agents
 *  - "a tenant keeps at least one admin" holds under concurrency (P2-4)
 *  - malformed ids and list parameters are 4xx, never a 500 (P2-5)
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import type { Role, User } from "../src/types.js";

let hash = "";
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const bearer = (t: string) => ["Authorization", `Bearer ${t}`] as const;

async function tenant(opts: { trialDays?: number } = {}): Promise<string> {
  const id = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + make_interval(days => $3))", [id, `T-${id.slice(0, 6)}`, opts.trialDays ?? 14]);
  return id;
}
const user = (tenantId: string, role: Role) =>
  store.insertUser({ email: `${role}-${randomUUID().slice(0, 8)}@example.com`, password_hash: hash, tenant_id: tenantId, role, status: "active" });

beforeAll(async () => { await migrate(); hash = await bcrypt.hash("password123", 4); });
afterAll(async () => { await closePool(); });

// --- RBAC matrix -----------------------------------------------------------------------------

type Min = "any" | "analyst" | "admin";
interface RouteSpec { method: string; path: string; min: Min }

/** Every human route and the least role it requires, read from the source. */
function humanRoutes(): RouteSpec[] {
  const out: RouteSpec[] = [];
  const idx = readFileSync(join(__dirname, "..", "src", "index.ts"), "utf8");
  for (const m of idx.matchAll(/app\.(get|post|put|patch|delete)\((?:"([^"]+)"|WEBHOOK_PATH),\s*(?:[a-zA-Z]+Limiter,\s*)*(auth(?=\s*[,)])|requireRole\("(analyst|admin|viewer)"\))/g)) {
    if (!m[2]) continue;
    out.push({ method: m[1]!.toUpperCase(), path: m[2], min: m[3] === "auth" || m[4] === "viewer" ? "any" : m[4] as Min });
  }
  const PKG = join(__dirname, "..", "..", "packages", "agent-identity", "src");
  const mounts: Record<string, string[]> = {
    "a2a/routes.ts": ["/a2a"], "behavior/routes.ts": ["/behavior"], "firewall/routes.ts": ["/firewall"], "killswitch/routes.ts": ["/kill-switch"],
    "prompt-guard/routes.ts": ["/prompt-guard"], "skills/routes.ts": ["/skills"], "tools/routes.ts": ["/tools"],
    "routes/management.ts": ["/agents", "/service-accounts"],
    // Same file, second router: the principal audit trail has its own mount.
    "routes/management.ts#auditRouter": ["/audit/principal-events"],
  };
  for (const [key, bases] of Object.entries(mounts)) {
    const [file, section] = key.split("#") as [string, string | undefined];
    const whole = readFileSync(join(PKG, file), "utf8");
    const cut = whole.indexOf("export function auditRouter");
    const src = file !== "routes/management.ts" ? whole : section ? whole.slice(cut) : whole.slice(0, cut);
    for (const m of src.matchAll(/router\.(get|post|put|patch|delete)\("([^"]+)",\s*(admin|staff|anyone)\b/g)) {
      for (const base of bases) {
        out.push({ method: m[1]!.toUpperCase(), path: base + (m[2] === "/" ? "" : m[2]), min: m[3] === "admin" ? "admin" : m[3] === "staff" ? "analyst" : "any" });
      }
    }
  }
  return out;
}
const concrete = (path: string) => path.replace(/:[A-Za-z]+/g, () => randomUUID());
const call = (r: RouteSpec) => (request(app) as unknown as Record<string, (p: string) => request.Test>)[r.method.toLowerCase()]!(concrete(r.path));

describe("RBAC matrix (from the source)", () => {
  let t: string; let viewer: User; let analyst: User;
  beforeAll(async () => { t = await tenant(); viewer = await user(t, "viewer"); analyst = await user(t, "analyst"); });

  const routes = humanRoutes();

  it("finds the routes it is meant to check", () => {
    expect(routes.length).toBeGreaterThan(60);
    expect(routes.some((r) => r.path === "/users/:id/role" && r.min === "admin")).toBe(true);
    expect(routes.some((r) => r.path === "/kill-switch/all" && r.min === "admin")).toBe(true);
    expect(routes.some((r) => r.path === "/copilot/chat" && r.min === "analyst")).toBe(true);
  });

  it("every one refuses an anonymous caller", async () => {
    const leaks: string[] = [];
    for (const r of routes) {
      const res = await call(r).send({});
      if (res.status !== 401) leaks.push(`${r.method} ${r.path} → ${res.status}`);
    }
    expect(leaks).toEqual([]);
  });

  it("every analyst- or admin-only route refuses a viewer", async () => {
    const leaks: string[] = [];
    for (const r of routes.filter((x) => x.min !== "any")) {
      const res = await call(r).set(...as(viewer)).send({});
      if (res.status !== 403) leaks.push(`${r.method} ${r.path} → ${res.status}`);
    }
    expect(leaks).toEqual([]);
  });

  it("every admin-only route refuses an analyst", async () => {
    const leaks: string[] = [];
    for (const r of routes.filter((x) => x.min === "admin")) {
      const res = await call(r).set(...as(analyst)).send({});
      if (res.status !== 403) leaks.push(`${r.method} ${r.path} → ${res.status}`);
    }
    expect(leaks).toEqual([]);
  });

  it("a machine identity cannot use any human route, whatever its permissions", async () => {
    const admin = await user(t, "admin");
    const created = await request(app).post("/agents").set(...as(admin)).send({ name: `rbac-${randomUUID().slice(0, 6)}`, permissions: ["alerts:read"] }).expect(201);
    const token = (await request(app).post("/agent/v1/token").set(...bearer(created.body.credential.secret)).expect(200)).body.access_token as string;
    const leaks: string[] = [];
    for (const r of routes) {
      const res = await call(r).set(...bearer(token)).send({});
      if (![401, 403].includes(res.status)) leaks.push(`${r.method} ${r.path} → ${res.status}`);
    }
    expect(leaks).toEqual([]);
  });
});

// --- subscription gate over the agent layer ------------------------------------------------------

describe("the subscription gate covers the agent layer (P1-6)", () => {
  let t: string; let admin: User; let agentId: string; let agentToken: string;
  beforeEach(async () => {
    t = await tenant();
    admin = await user(t, "admin");
    const created = await request(app).post("/agents").set(...as(admin)).send({ name: `gate-${randomUUID().slice(0, 6)}`, permissions: ["alerts:read"] }).expect(201);
    agentId = created.body.identity.id;
    agentToken = (await request(app).post("/agent/v1/token").set(...bearer(created.body.credential.secret)).expect(200)).body.access_token;
  });
  const expireTrial = () => query("UPDATE tenants SET trial_ends_at = now() - interval '1 day' WHERE id = $1", [t]);
  const pastDue = () => query("INSERT INTO subscriptions (tenant_id, status) VALUES ($1, 'past_due')", [t]);

  it("blocked (trial over, no subscription): people cannot create or even list agents; agents cannot act", async () => {
    await expireTrial();
    const create = await request(app).post("/agents").set(...as(admin)).send({ name: "more", permissions: ["alerts:read"] });
    expect(create.status).toBe(402);
    expect(create.body.access_state).toBe("blocked");
    expect((await request(app).get("/agents").set(...as(admin))).status).toBe(402);
    expect((await request(app).post(`/agents/${agentId}/credentials`).set(...as(admin)).send({})).status).toBe(402);
    expect((await request(app).get("/agent/v1/me").set(...bearer(agentToken))).status).toBe(402);
    expect((await request(app).get("/agent/v1/alerts").set(...bearer(agentToken))).status).toBe(402);
    expect((await request(app).post("/agent/v1/skills/alert-analysis/invoke").set(...bearer(agentToken)).send({})).status).toBe(402);
  });

  it("blocked: stopping agents is always possible", async () => {
    await expireTrial();
    expect((await request(app).post(`/agents/${agentId}/suspend`).set(...as(admin)).send({ reason: "card expired, shutting down" })).status).toBe(200);
    const ks = await request(app).post("/kill-switch/all").set(...as(admin)).send({ reason: "stop everything now", compromise: "suspected", confirmAll: true });
    expect(ks.status).toBeLessThan(300);
    expect((await request(app).post(`/agents/${agentId}/revoke`).set(...as(admin)).send({ reason: "done" })).status).toBe(200);
  });

  it("read-only (past due): reads work, changes do not", async () => {
    await pastDue();
    expect((await request(app).get("/agents").set(...as(admin))).status).toBe(200);
    expect((await request(app).get("/agent/v1/me").set(...bearer(agentToken))).status).toBe(200);
    expect((await request(app).post("/agents").set(...as(admin)).send({ name: "more", permissions: ["alerts:read"] })).status).toBe(402);
    expect((await request(app).put("/firewall/policy").set(...as(admin)).send({})).status).toBe(402);
  });

  it("an active workspace is unaffected", async () => {
    expect((await request(app).get("/agents").set(...as(admin))).status).toBe(200);
    expect((await request(app).get("/agent/v1/me").set(...bearer(agentToken))).status).toBe(200);
  });
});

// --- last admin ------------------------------------------------------------------------------------

describe("a tenant always keeps an administrator (P2-4)", () => {
  it("two admins demoting each other at the same moment: exactly one succeeds", async () => {
    for (let round = 0; round < 8; round++) {
      const t = await tenant();
      const a = await user(t, "admin"); const b = await user(t, "admin");
      const [ra, rb] = await Promise.all([
        request(app).patch(`/users/${b.id}/role`).set(...as(a)).send({ role: "viewer" }),
        request(app).patch(`/users/${a.id}/role`).set(...as(b)).send({ role: "viewer" }),
      ]);
      const statuses = [ra.status, rb.status].sort();
      // One demotion wins. The other is refused: either as the last admin, or
      // because its caller was just demoted (401/403 once its token is revoked).
      expect(statuses.filter((s) => s === 200)).toHaveLength(1);
      const admins = (await query("SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND role = 'admin' AND status = 'active'", [t])).rows[0].n;
      expect(admins).toBe(1);
    }
  });

  it("two admins deactivating each other at the same moment: the tenant keeps one", async () => {
    for (let round = 0; round < 8; round++) {
      const t = await tenant();
      const a = await user(t, "admin"); const b = await user(t, "admin");
      await Promise.all([
        request(app).delete(`/users/${b.id}`).set(...as(a)),
        request(app).delete(`/users/${a.id}`).set(...as(b)),
      ]);
      const admins = (await query("SELECT count(*)::int AS n FROM users WHERE tenant_id = $1 AND role = 'admin' AND status = 'active'", [t])).rows[0].n;
      expect(admins).toBe(1);
    }
  });
});

// --- malformed input ---------------------------------------------------------------------------------

describe("malformed ids and list parameters are 4xx, never 500 (P2-5)", () => {
  let admin: User;
  beforeAll(async () => { admin = await user(await tenant(), "admin"); });

  it.each([
    ["/alerts?limit=abc"], ["/alerts?limit=0"], ["/alerts?limit=100000"], ["/alerts?offset=-1"], ["/alerts?offset=99999999"],
    ["/alerts/feed?limit=NaN"], ["/audit?limit=abc"], ["/assets?online=maybe"], ["/assets?limit=abc"],
  ])("GET %s → 422", async (path) => {
    expect((await request(app).get(path).set(...as(admin))).status).toBe(422);
  });

  it.each([
    ["patch", "/users/not-a-uuid/role", { role: "viewer" }],
    ["delete", "/users/1%27%20OR%201=1--", {}],
    ["post", "/users/../../etc/resend-invite", {}],
  ] as const)("%s %s → 404", async (method, path, body) => {
    const res = await (request(app) as unknown as Record<string, (p: string) => request.Test>)[method]!(path).set(...as(admin)).send(body);
    expect([404]).toContain(res.status);
  });

  it("valid parameters still work", async () => {
    expect((await request(app).get("/alerts?limit=5&offset=0").set(...as(admin))).status).toBe(200);
    expect((await request(app).get("/assets?online=true&limit=10").set(...as(admin))).status).toBe(200);
  });
});
