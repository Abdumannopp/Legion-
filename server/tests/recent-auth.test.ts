/**
 * Dangerous actions need a RECENT proof of identity, not only a session (index.ts recentAuth): removing
 * a person, changing a role, rotating or revoking a sensor key, deleting an integration, exporting the
 * whole workspace. A stolen or unattended admin session is refused until the person enters their
 * password again (POST /auth/step-up; plus a code when MFA is on). Signing in opens the same window.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app, RECENT_AUTH_SECONDS } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { issueCredential } from "./helpers/webhook.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";

const PASSWORD = "password123";
let tA: string; let admin: User; let other: User;
const now = () => Math.floor(Date.now() / 1000);
/** A session token: no auth_time (a refreshed session), or one from `ago` seconds back. */
const session = (u: User, ago?: number) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version, auth_time: ago === undefined ? undefined : now() - ago }, { expiresIn: "15m" })}`] as const;
const payload = (tok: string) => JSON.parse(Buffer.from(tok.split(".")[1]!, "base64url").toString());

/** Each guarded route, with what proves it did nothing. */
async function routes() {
  const cred = await issueCredential(tA, "ra");
  const integ = randomUUID();
  await query("INSERT INTO integration_connections (id, tenant_id, kind, name, status) VALUES ($1, $2, 'fakecloud', 'c', 'active')", [integ, tA]);
  return [
    { name: "remove a person", call: (h: readonly [string, string]) => request(app).delete(`/users/${other.id}`).set(...h),
      unchanged: async () => (await query("SELECT status FROM workspace_memberships WHERE user_id = $1", [other.id])).rows[0].status === "active" },
    { name: "change a role", call: (h: readonly [string, string]) => request(app).patch(`/users/${other.id}/role`).set(...h).send({ role: "viewer" }),
      unchanged: async () => (await query("SELECT role FROM workspace_memberships WHERE user_id = $1", [other.id])).rows[0].role === "admin" },
    { name: "rotate a sensor key", call: (h: readonly [string, string]) => request(app).post(`/security-events/credentials/${cred.keyId}/rotate`).set(...h),
      unchanged: async () => (await query("SELECT revoked_at FROM webhook_credentials WHERE key_id = $1", [cred.keyId])).rows[0].revoked_at === null },
    { name: "revoke a sensor key", call: (h: readonly [string, string]) => request(app).delete(`/security-events/credentials/${cred.keyId}`).set(...h),
      unchanged: async () => (await query("SELECT revoked_at FROM webhook_credentials WHERE key_id = $1", [cred.keyId])).rows[0].revoked_at === null },
    { name: "delete an integration", call: (h: readonly [string, string]) => request(app).delete(`/integrations/${integ}`).set(...h),
      unchanged: async () => (await query("SELECT count(*)::int AS n FROM integration_connections WHERE id = $1", [integ])).rows[0].n === 1 },
    { name: "export the whole workspace", call: (h: readonly [string, string]) => request(app).get("/workspace/export").set(...h),
      unchanged: async () => true },
  ];
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'enterprise')", [tA]);
  const h = await bcrypt.hash(PASSWORD, 4);
  admin = await store.insertUser({ email: "admin@a.io", password_hash: h, tenant_id: tA, role: "admin", status: "active" });
  other = await store.insertUser({ email: "other@a.io", password_hash: h, tenant_id: tA, role: "admin", status: "active" });
});

describe("a session alone is not enough for a dangerous action", () => {
  it("each guarded route refuses a session without a recent sign-in, changes nothing, and says how to continue", async () => {
    for (const r of await routes()) {
      for (const h of [session(admin), session(admin, RECENT_AUTH_SECONDS + 60)]) {
        const res = await r.call(h);
        expect(res.status, r.name).toBe(403);
        expect(res.body.code, r.name).toBe("reauth_required");
        expect(await r.unchanged(), r.name).toBe(true);
      }
    }
  });

  it("a recent sign-in is accepted (the window is RECENT_AUTH_SECONDS)", async () => {
    const r = (await routes()).find((x) => x.name === "change a role")!;
    expect((await r.call(session(admin, 30))).status).toBe(200);
  });

  it("a viewer is still refused by role first, recent sign-in or not", async () => {
    const viewer = await store.insertUser({ email: "v@a.io", password_hash: await bcrypt.hash(PASSWORD, 4), tenant_id: tA, role: "viewer", status: "active" });
    expect((await request(app).delete(`/users/${other.id}`).set(...session(viewer, 5))).status).toBe(403);
    expect((await request(app).delete(`/users/${other.id}`).set(...session(viewer, 5))).body.code).not.toBe("reauth_required");
  });
});

describe("confirming identity again (POST /auth/step-up)", () => {
  it("a wrong password opens nothing and is audited; the right one gives a token that works", async () => {
    const wrong = await request(app).post("/auth/step-up").set(...session(admin)).send({ password: "not-the-password" });
    expect(wrong.status).toBe(400);
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE action = 'auth.step_up_failed'")).rows[0].n).toBe(1);

    const ok = await request(app).post("/auth/step-up").set(...session(admin)).send({ password: PASSWORD });
    expect(ok.status).toBe(200);
    expect(ok.body.valid_for_seconds).toBe(RECENT_AUTH_SECONDS);
    expect(Math.abs(payload(ok.body.access_token).auth_time - now())).toBeLessThan(5);
    const res = await request(app).patch(`/users/${other.id}/role`).set("Authorization", `Bearer ${ok.body.access_token}`).send({ role: "viewer" });
    expect(res.status).toBe(200);
  });

  it("with MFA on, the password alone is not enough", async () => {
    await query("UPDATE users SET mfa_enabled = true WHERE id = $1", [admin.id]);
    const r = await request(app).post("/auth/step-up").set(...session(admin)).send({ password: PASSWORD });
    expect(r.status).toBe(400);
    expect(r.body.code).toBe("mfa_code_required");
  });

  it("needs a session: an anonymous caller cannot use it to test passwords", async () => {
    expect((await request(app).post("/auth/step-up").send({ password: PASSWORD })).status).toBe(401);
  });
});

describe("where the window comes from", () => {
  it("signing in with the password opens it; refreshing the session does not carry it over", async () => {
    const login = await request(app).post("/auth/login").send({ username: admin.email, password: PASSWORD }).expect(200);
    expect(typeof payload(login.body.access_token).auth_time).toBe("number");
    const refreshCookie = (login.headers["set-cookie"] as unknown as string[]).find((c) => c.startsWith("legion_refresh="))!.split(";")[0]!;
    const refreshed = await request(app).post("/auth/refresh").set("Cookie", refreshCookie);
    expect(refreshed.status).toBe(200);
    const token = refreshed.body.access_token ?? decodeURIComponent((refreshed.headers["set-cookie"] as unknown as string[]).find((c) => c.startsWith("legion_token="))!.split(";")[0]!.slice("legion_token=".length));
    expect(payload(token).auth_time).toBeUndefined();
  });
});
