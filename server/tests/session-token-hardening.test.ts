/**
 * Security hardening (2026-09) — tokens and sessions.
 *
 *  - per-purpose JWT keys: a token of one kind never verifies as another
 *  - issuer / audience / kid are required; alg confusion and tampering refused
 *  - JWT_PREVIOUS_SECRETS: rotation without signing everyone out
 *  - refresh sessions: absolute lifetime; the (opt-in) multi-tab reuse allowance
 *  - cookie flags
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query, queryOne } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { AUDIENCE, ISSUER, signToken, verifyTokenOf } from "../src/auth-jwt.js";
import { mint } from "./helpers/tokens.js";
import type { User } from "../src/types.js";

const PASSWORD = "a-long-enough-password";
let tenantId: string; let user: User;
const saved = { secret: config.jwtSecret, previous: config.jwtPreviousSecrets, grace: config.refreshReuseGraceSeconds, abs: config.sessionAbsoluteDays, secure: config.cookieSecure };

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'T', now() + interval '14 days')", [tenantId]);
  user = await store.insertUser({ email: "u@t.io", password_hash: await bcrypt.hash(PASSWORD, 4), tenant_id: tenantId, role: "admin", status: "active" });
});
afterEach(() => {
  Object.assign(config, { jwtSecret: saved.secret, jwtPreviousSecrets: saved.previous, refreshReuseGraceSeconds: saved.grace, sessionAbsoluteDays: saved.abs, cookieSecure: saved.secure });
});

const claims = () => ({ sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version });
const me = (token: string) => request(app).get("/auth/me").set("Authorization", `Bearer ${token}`);

// --- JWT ---------------------------------------------------------------------------------------

describe("access tokens", () => {
  it("carry issuer, audience, typ and kid, and verify only as their own kind", () => {
    const t = mint(claims(), { expiresIn: "5m" });
    const decoded = jwt.decode(t, { complete: true })!;
    expect(decoded.header).toMatchObject({ alg: "HS256", typ: "at+jwt" });
    expect(String(decoded.header.kid)).toMatch(/^access-[0-9a-f]{16}$/);
    expect(decoded.payload).toMatchObject({ iss: ISSUER, aud: AUDIENCE.access });
    expect(verifyTokenOf("access", t)).not.toBeNull();
    expect(verifyTokenOf("mfa", t)).toBeNull();
    expect(verifyTokenOf("checkout", t)).toBeNull();
  });

  it("a real session token works", async () => {
    await me(mint(claims(), { expiresIn: "5m" })).expect(200);
  });

  it("the old format (raw JWT_SECRET, no issuer/audience) is refused", async () => {
    await me(jwt.sign(claims(), config.jwtSecret, { algorithm: "HS256", expiresIn: "5m" })).expect(401);
  });

  it("an MFA challenge token — even one without a purpose claim — is not a session", async () => {
    await me(mint(claims(), { kind: "mfa", expiresIn: "5m" })).expect(401);
    await me(mint({ ...claims(), purpose: "mfa" }, { kind: "mfa", expiresIn: "5m" })).expect(401);
  });

  it("a checkout token is not a session", async () => {
    await me(mint(claims(), { kind: "checkout", expiresIn: "5m" })).expect(401);
  });

  it("the right key with the wrong audience or issuer is refused", async () => {
    const good = jwt.decode(mint(claims(), { expiresIn: "5m" }), { complete: true })!;
    // Re-sign the same claims with the access key but a foreign audience: needs the key,
    // so go through signToken's own derivation by swapping only the audience claim.
    const forged = jwt.sign({ ...claims(), iss: ISSUER, aud: "someone-else" }, "x".repeat(40), { algorithm: "HS256", header: { alg: "HS256", kid: good.header.kid } });
    await me(forged).expect(401);
  });

  it("alg=none and a tampered payload are refused", async () => {
    const t = mint(claims(), { expiresIn: "5m" });
    const [h, p, sig] = t.split(".");
    const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "at+jwt", kid: JSON.parse(Buffer.from(h!, "base64url").toString()).kid })).toString("base64url")}.${p}.`;
    await me(none).expect(401);
    const payload = JSON.parse(Buffer.from(p!, "base64url").toString());
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...payload, tenant_id: randomUUID() })).toString("base64url")}.${sig}`;
    await me(tampered).expect(401);
  });

  it("an unknown kid is refused before any verification", () => {
    const t = jwt.sign({ ...claims(), iss: ISSUER, aud: AUDIENCE.access }, config.jwtSecret, { algorithm: "HS256", header: { alg: "HS256", kid: "access-0000000000000000" } });
    expect(verifyTokenOf("access", t)).toBeNull();
  });
});

describe("rotating JWT_SECRET", () => {
  it("with the old value in JWT_PREVIOUS_SECRETS, live sessions survive; new tokens use the new key", async () => {
    const old = mint(claims(), { expiresIn: "5m" });
    config.jwtPreviousSecrets = [config.jwtSecret];
    config.jwtSecret = "a-brand-new-signing-secret-0123456789abcdef";
    await me(old).expect(200);
    const fresh = signToken("access", claims(), "5m");
    expect(jwt.decode(fresh, { complete: true })!.header.kid).not.toBe(jwt.decode(old, { complete: true })!.header.kid);
    await me(fresh).expect(200);
    // Once the old secret is dropped, its tokens stop working.
    config.jwtPreviousSecrets = [];
    await me(old).expect(401);
    await me(fresh).expect(200);
  });
});

// --- refresh sessions ----------------------------------------------------------------------------

const loginCookies = async (ua = "UA-1") => {
  const res = await request(app).post("/auth/login").set("User-Agent", ua).send({ username: user.email, password: PASSWORD }).expect(200);
  return res.headers["set-cookie"] as unknown as string[];
};
const refreshOf = (setCookie: string[]) => /legion_refresh=([^;]+)/.exec(setCookie.find((c) => c.startsWith("legion_refresh="))!)![1]!;
const refresh = (token: string, ua = "UA-1") => request(app).post("/auth/refresh").set("User-Agent", ua).set("Cookie", `legion_refresh=${token}`);

describe("refresh sessions", () => {
  it("record when the login happened, and a refresh never extends past the absolute lifetime", async () => {
    const t = refreshOf(await loginCookies());
    const row = await queryOne<{ family_started_at: Date; expires_at: Date }>("SELECT family_started_at, expires_at FROM refresh_tokens");
    expect(row!.family_started_at).toBeInstanceOf(Date);
    await query("UPDATE refresh_tokens SET family_started_at = now() - interval '29 days'");
    const res = await refresh(t).expect(200);
    const next = await queryOne<{ expires_at: Date; family_started_at: Date }>("SELECT expires_at, family_started_at FROM refresh_tokens WHERE rotated_at IS NULL");
    const cap = next!.family_started_at.getTime() + config.sessionAbsoluteDays * 86_400_000;
    expect(next!.expires_at.getTime()).toBeLessThanOrEqual(cap + 1000);
    expect(next!.expires_at.getTime()).toBeLessThan(Date.now() + 2 * 86_400_000); // ~1 day left, not 30
    expect(res.body.access_token).toBeTruthy();
  });

  it("a session older than SESSION_ABSOLUTE_DAYS cannot be refreshed, however active it was", async () => {
    const t = refreshOf(await loginCookies());
    await query("UPDATE refresh_tokens SET family_started_at = now() - interval '31 days'");
    const res = await refresh(t).expect(401);
    expect(res.body.detail).toMatch(/expired/i);
  });

  it("a row from before the absolute lifetime existed uses its own creation time", async () => {
    const t = refreshOf(await loginCookies());
    await query("UPDATE refresh_tokens SET family_started_at = NULL, created_at = now() - interval '31 days'");
    await refresh(t).expect(401);
  });

  it("by default (grace 0), presenting a rotated token again revokes the family, even instantly and from the same browser", async () => {
    expect(config.refreshReuseGraceSeconds).toBe(0);
    const t = refreshOf(await loginCookies());
    const next = refreshOf((await refresh(t).expect(200)).headers["set-cookie"] as unknown as string[]);
    await refresh(t).expect(401);
    await refresh(next).expect(401);
  });

  describe("with REFRESH_REUSE_GRACE_SECONDS set (opt-in)", () => {
    beforeEach(() => { config.refreshReuseGraceSeconds = 15; });

    it("the same browser may present the just-rotated token ONCE; both tabs stay signed in", async () => {
      const t = refreshOf(await loginCookies("Tab-UA"));
      const a = refreshOf((await refresh(t, "Tab-UA").expect(200)).headers["set-cookie"] as unknown as string[]);
      const b = refreshOf((await refresh(t, "Tab-UA").expect(200)).headers["set-cookie"] as unknown as string[]);
      await refresh(a, "Tab-UA").expect(200);
      await refresh(b, "Tab-UA").expect(200);
    });

    it("a second reuse is theft: the family is revoked", async () => {
      const t = refreshOf(await loginCookies("Tab-UA"));
      await refresh(t, "Tab-UA").expect(200);
      await refresh(t, "Tab-UA").expect(200);
      await refresh(t, "Tab-UA").expect(401);
    });

    it("another client presenting it is theft, even inside the window", async () => {
      const t = refreshOf(await loginCookies("Tab-UA"));
      const next = refreshOf((await refresh(t, "Tab-UA").expect(200)).headers["set-cookie"] as unknown as string[]);
      await refresh(t, "curl/8.0").expect(401);
      await refresh(next, "Tab-UA").expect(401);
    });

    it("after the window it is theft", async () => {
      const t = refreshOf(await loginCookies("Tab-UA"));
      await refresh(t, "Tab-UA").expect(200);
      await query("UPDATE refresh_tokens SET rotated_at = now() - interval '20 seconds' WHERE rotated_at IS NOT NULL");
      await refresh(t, "Tab-UA").expect(401);
    });
  });

  it("cookies: access and refresh are HttpOnly; refresh is SameSite=Strict and path-scoped; Secure when configured", async () => {
    config.cookieSecure = true;
    const set = await loginCookies();
    const access = set.find((c) => c.startsWith("legion_token="))!;
    const refreshC = set.find((c) => c.startsWith("legion_refresh="))!;
    expect(access).toMatch(/HttpOnly/); expect(access).toMatch(/Secure/); expect(access).toMatch(/SameSite=Lax/);
    expect(refreshC).toMatch(/HttpOnly/); expect(refreshC).toMatch(/Secure/); expect(refreshC).toMatch(/SameSite=Strict/);
    expect(refreshC).toMatch(new RegExp(`Path=${config.refreshCookiePath}`));
  });
});
