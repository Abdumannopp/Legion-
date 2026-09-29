import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query, queryOne } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import * as sessions from "../src/sessions.js";
import type { User } from "../src/types.js";

const PASSWORD = "password123";
let passwordHash = "";
let tenantId: string;
let user: User;

/** Pulls one cookie's value out of a Set-Cookie header list. */
function cookie(res: request.Response, name: string): string | null {
  const raw = res.headers["set-cookie"] as unknown as string[] | undefined;
  if (!raw) return null;
  for (const line of raw) {
    const match = line.match(new RegExp(`^${name}=([^;]*)`));
    if (match) return decodeURIComponent(match[1]!);
  }
  return null;
}

const loginAndGetRefresh = async (): Promise<string> => {
  const res = await request(app)
    .post("/auth/login")
    .send({ username: user.email, password: PASSWORD })
    .expect(200);
  return cookie(res, "legion_refresh")!;
};

const refreshWith = (token: string) =>
  request(app).post("/auth/refresh").set("Cookie", `legion_refresh=${token}`);

beforeAll(async () => {
  await migrate();
  passwordHash = await bcrypt.hash(PASSWORD, 10);
});
afterAll(async () => { await closePool(); });

beforeEach(async () => {
  await truncateAll();
  tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + interval '14 days')", [tenantId, "Session Tenant"]);
  user = await store.insertUser({
    email: "session@example.com", password_hash: passwordHash,
    tenant_id: tenantId, role: "admin", status: "active",
  });
});

describe("issuing sessions", () => {
  it("sets an access cookie and a refresh cookie on login", async () => {
    const res = await request(app)
      .post("/auth/login").send({ username: user.email, password: PASSWORD }).expect(200);

    expect(cookie(res, "legion_token")).toBeTruthy();
    expect(cookie(res, "legion_refresh")).toBeTruthy();
    expect(cookie(res, "legion_session")).toBe("1");
  });

  it("scopes the refresh cookie to /auth so it isn't sent with every API call", async () => {
    const res = await request(app)
      .post("/auth/login").send({ username: user.email, password: PASSWORD }).expect(200);
    const raw = (res.headers["set-cookie"] as unknown as string[]).find((c) => c.startsWith("legion_refresh="))!;
    expect(raw).toContain("Path=/auth");
    expect(raw).toContain("HttpOnly");
  });

  it("stores only a hash of the refresh token", async () => {
    const token = await loginAndGetRefresh();
    const row = await queryOne<{ token_hash: string }>("SELECT token_hash FROM refresh_tokens LIMIT 1");
    expect(row!.token_hash).not.toBe(token);
    expect(row!.token_hash).toMatch(/^[0-9a-f]{64}$/); // sha256 hex
  });
});

describe("refreshing", () => {
  it("issues a new access token", async () => {
    const token = await loginAndGetRefresh();
    const res = await refreshWith(token).expect(200);
    expect(res.body.access_token).toBeDefined();
    await request(app).get("/auth/me").set("Authorization", `Bearer ${res.body.access_token}`).expect(200);
  });

  it("rotates the refresh token on every use", async () => {
    const first = await loginAndGetRefresh();
    const res = await refreshWith(first).expect(200);
    const second = cookie(res, "legion_refresh");
    expect(second).toBeTruthy();
    expect(second).not.toBe(first);
  });

  it("rejects a refresh with no cookie", async () => {
    await request(app).post("/auth/refresh").expect(401);
  });

  it("rejects an unknown token", async () => {
    await refreshWith("not-a-real-token").expect(401);
  });

  it("keeps a session alive well past the access-token lifetime", async () => {
    // The point of the whole mechanism: an analyst watching the dashboard
    // through a shift must not be signed out every few minutes.
    let token = await loginAndGetRefresh();
    for (let i = 0; i < 5; i++) {
      const res = await refreshWith(token).expect(200);
      token = cookie(res, "legion_refresh")!;
      await request(app).get("/auth/me").set("Authorization", `Bearer ${res.body.access_token}`).expect(200);
    }
  });
});

describe("theft detection", () => {
  it("revokes the whole family when a rotated token is replayed", async () => {
    const stolen = await loginAndGetRefresh();

    // The legitimate client refreshes, rotating the token.
    const res = await refreshWith(stolen).expect(200);
    const legitimate = cookie(res, "legion_refresh")!;

    // The thief replays the copy they captured earlier.
    const replay = await refreshWith(stolen).expect(401);
    expect(replay.body.detail).toMatch(/reuse/i);

    // Both sides are now locked out: there is no way to tell which holder is
    // the real user, so the safe move is to end the session entirely.
    await refreshWith(legitimate).expect(401);
  });

  it("leaves other sessions alone when one family is revoked", async () => {
    const laptop = await loginAndGetRefresh();
    const phone = await loginAndGetRefresh();

    await refreshWith(laptop).expect(200);
    await refreshWith(laptop).expect(401); // replay kills the laptop family

    // A different login is a different family and must survive.
    await refreshWith(phone).expect(200);
  });

  it("rejects a revoked token", async () => {
    const token = await loginAndGetRefresh();
    await sessions.revokeAllForUser(user.id);
    await refreshWith(token).expect(401);
  });

  it("rejects an expired token", async () => {
    const token = await loginAndGetRefresh();
    await query("UPDATE refresh_tokens SET expires_at = now() - interval '1 day'");
    await refreshWith(token).expect(401);
  });

  it("survives two tabs refreshing at the same moment", async () => {
    // Concurrent refreshes race on the same row; the transaction takes FOR
    // UPDATE so exactly one rotates rather than both appearing to succeed.
    const token = await loginAndGetRefresh();
    const results = await Promise.all([refreshWith(token), refreshWith(token), refreshWith(token)]);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  });
});

describe("revocation on account changes", () => {
  it("ends every session when the password changes", async () => {
    const token = await loginAndGetRefresh();
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });

    await request(app)
      .post("/auth/change-password")
      .set("Authorization", `Bearer ${login.body.access_token}`)
      .send({ current_password: PASSWORD, new_password: "a-brand-new-password" })
      .expect(200);

    // Without this, a stolen refresh token would outlive the password change
    // that was meant to shut it out.
    await refreshWith(token).expect(401);
  });

  it("ends every session when a role changes", async () => {
    const analyst = await store.insertUser({
      email: "analyst@example.com", password_hash: passwordHash,
      tenant_id: tenantId, role: "analyst", status: "active",
    });
    const res = await request(app)
      .post("/auth/login").send({ username: analyst.email, password: PASSWORD }).expect(200);
    const token = cookie(res, "legion_refresh")!;

    const admin = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .patch(`/users/${analyst.id}/role`)
      .set("Authorization", `Bearer ${admin.body.access_token}`)
      .send({ role: "viewer" })
      .expect(200);

    // A demotion that leaves the old permissions live until expiry is the
    // wrong way round.
    await refreshWith(token).expect(401);
  });

  it("ends every session when an account is deactivated", async () => {
    const other = await store.insertUser({
      email: "other@example.com", password_hash: passwordHash,
      tenant_id: tenantId, role: "analyst", status: "active",
    });
    const res = await request(app)
      .post("/auth/login").send({ username: other.email, password: PASSWORD }).expect(200);
    const token = cookie(res, "legion_refresh")!;

    const admin = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .delete(`/users/${other.id}`)
      .set("Authorization", `Bearer ${admin.body.access_token}`)
      .expect(200);

    await refreshWith(token).expect(401);
  });

  it("revokes server-side on logout, not just in the browser", async () => {
    const token = await loginAndGetRefresh();
    await request(app).post("/auth/logout").set("Cookie", `legion_refresh=${token}`).expect(204);
    // Clearing the cookie alone would leave the token working for anyone
    // holding a copy.
    await refreshWith(token).expect(401);
  });
});

describe("housekeeping", () => {
  it("prunes rows that can no longer authenticate anything", async () => {
    await loginAndGetRefresh();
    await loginAndGetRefresh();
    await query("UPDATE refresh_tokens SET expires_at = now() - interval '30 days'");

    const before = await queryOne<{ count: number }>("SELECT count(*)::bigint AS count FROM refresh_tokens");
    expect(Number(before!.count)).toBe(2);

    const removed = await sessions.pruneExpired();
    expect(removed).toBe(2);

    const after = await queryOne<{ count: number }>("SELECT count(*)::bigint AS count FROM refresh_tokens");
    expect(Number(after!.count)).toBe(0);
  });

  it("keeps tokens that are still usable", async () => {
    await loginAndGetRefresh();
    expect(await sessions.pruneExpired()).toBe(0);
    expect(await sessions.activeSessionCount(user.id)).toBe(1);
  });
});
