import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomUUID } from "node:crypto";
import * as OTPAuth from "otpauth";
import { app } from "../src/index.js";
import { closePool, migrate, query, queryOne } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";
import type { User } from "../src/types.js";

const PASSWORD = "password123";
let passwordHash = "";
let tenantId: string;
let user: User;

/** Produces a valid code the same way an authenticator app would. */
function codeFor(secret: string, email: string, offsetSteps = 0): string {
  const totp = new OTPAuth.TOTP({
    issuer: config.mfaIssuer, label: email, algorithm: "SHA1",
    digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secret),
  });
  return totp.generate({ timestamp: Date.now() + offsetSteps * 30_000 });
}

const reload = async (u: User): Promise<User> => (await store.findUserById(u.id))!;

function tokenFor(u: User): string {
  return jwt.sign(
    { sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version },
    config.jwtSecret, { algorithm: "HS256", expiresIn: "1h" }
  );
}
const asUser = (u: User) => ["Authorization", `Bearer ${tokenFor(u)}`] as const;

/** Runs the whole enrolment flow and returns the secret and recovery codes. */
async function enroll(u: User): Promise<{ secret: string; recoveryCodes: string[] }> {
  const setup = await request(app).post("/auth/mfa/setup").set(...asUser(u)).expect(200);
  const secret: string = setup.body.secret;
  const enabled = await request(app)
    .post("/auth/mfa/enable")
    .set(...asUser(u))
    .send({ code: codeFor(secret, u.email) })
    .expect(200);

  // Enrolment spends the current counter, and replay protection then refuses
  // that same code for the rest of its 30-second step. That is correct in
  // production (see "refuses to reuse the enrolment code" below) but it is not
  // what these tests are exercising, so start each one from a clean slate.
  await query("DELETE FROM mfa_used_counters WHERE user_id = $1", [u.id]);

  return { secret, recoveryCodes: enabled.body.recovery_codes };
}

beforeAll(async () => {
  await migrate();
  passwordHash = await bcrypt.hash(PASSWORD, 10);
});
afterAll(async () => { await closePool(); });

beforeEach(async () => {
  await truncateAll();
  tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + interval '14 days')", [tenantId, "MFA Tenant"]);
  user = await store.insertUser({
    email: "mfa@example.com", password_hash: passwordHash,
    tenant_id: tenantId, role: "admin", status: "active",
  });
});

describe("enrolment", () => {
  it("reports MFA as disabled before setup", async () => {
    const res = await request(app).get("/auth/mfa").set(...asUser(user)).expect(200);
    expect(res.body).toMatchObject({ enabled: false, recovery_codes_remaining: 0 });
  });

  it("returns a provisioning URI an authenticator app can consume", async () => {
    const res = await request(app).post("/auth/mfa/setup").set(...asUser(user)).expect(200);
    expect(res.body.otpauth_uri).toMatch(/^otpauth:\/\/totp\//);
    expect(res.body.otpauth_uri).toContain("mfa%40example.com");
    expect(res.body.secret).toMatch(/^[A-Z2-7]+$/); // base32
  });

  it("does not enable MFA until a code is confirmed", async () => {
    await request(app).post("/auth/mfa/setup").set(...asUser(user)).expect(200);
    // A mis-scanned QR must not be able to lock the user out.
    expect((await reload(user)).mfa_enabled).toBe(false);
    await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD }).expect(200);
  });

  it("rejects a wrong confirmation code", async () => {
    await request(app).post("/auth/mfa/setup").set(...asUser(user)).expect(200);
    await request(app).post("/auth/mfa/enable").set(...asUser(user)).send({ code: "000000" }).expect(400);
    expect((await reload(user)).mfa_enabled).toBe(false);
  });

  it("enables MFA and issues recovery codes exactly once", async () => {
    const { recoveryCodes } = await enroll(user);
    expect(recoveryCodes).toHaveLength(10);
    expect(new Set(recoveryCodes).size).toBe(10);
    expect((await reload(user)).mfa_enabled).toBe(true);

    // Only hashes are persisted — a database leak must not bypass MFA.
    const stored = await queryOne<{ code_hash: string }>(
      "SELECT code_hash FROM mfa_recovery_codes WHERE user_id = $1 LIMIT 1", [user.id]
    );
    expect(recoveryCodes).not.toContain(stored!.code_hash);
    expect(stored!.code_hash).toMatch(/^\$2[aby]\$/);
  });

  it("refuses to reuse the enrolment code to log in", async () => {
    // The code that switched MFA on is spent. Within its 30-second step the
    // authenticator app still displays it, and it must not work a second time.
    const setup = await request(app).post("/auth/mfa/setup").set(...asUser(user)).expect(200);
    const secret: string = setup.body.secret;
    const code = codeFor(secret, user.email);
    await request(app).post("/auth/mfa/enable").set(...asUser(user)).send({ code }).expect(200);

    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, code })
      .expect(401);
  });

  it("refuses to start setup twice", async () => {
    await enroll(user);
    await request(app).post("/auth/mfa/setup").set(...asUser(await reload(user))).expect(400);
  });
});

describe("login with MFA", () => {
  it("returns a challenge instead of a session", async () => {
    await enroll(user);
    const res = await request(app)
      .post("/auth/login").send({ username: user.email, password: PASSWORD }).expect(200);

    expect(res.body.mfa_required).toBe(true);
    expect(res.body.access_token).toBeUndefined();
    // No session cookie may be set at the halfway point.
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("refuses to accept the challenge token as a session", async () => {
    // The challenge is signed with the same key and carries the same claims;
    // if it were accepted as a session, MFA would be optional.
    await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app).get("/auth/me").set("Authorization", `Bearer ${login.body.mfa_token}`).expect(401);
    await request(app).get("/alerts").set("Authorization", `Bearer ${login.body.mfa_token}`).expect(401);
  });

  it("completes login with a valid code", async () => {
    const { secret } = await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    const res = await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, code: codeFor(secret, user.email) })
      .expect(200);
    expect(res.body.access_token).toBeDefined();
    await request(app).get("/auth/me").set("Authorization", `Bearer ${res.body.access_token}`).expect(200);
  });

  it("rejects a wrong code", async () => {
    await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, code: "000000" })
      .expect(401);
  });

  it("refuses to reuse a code that already worked", async () => {
    // A code stays valid for its whole step, so one observed in transit could
    // otherwise be replayed within that window.
    const { secret } = await enroll(user);
    const code = codeFor(secret, user.email);

    const first = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app).post("/auth/mfa/verify").send({ mfa_token: first.body.mfa_token, code }).expect(200);

    const second = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app).post("/auth/mfa/verify").send({ mfa_token: second.body.mfa_token, code }).expect(401);
  });

  it("accepts a code from the adjacent step for clock drift", async () => {
    const { secret } = await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, code: codeFor(secret, user.email, -1) })
      .expect(200);
  });

  it("rejects a code from far outside the window", async () => {
    const { secret } = await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, code: codeFor(secret, user.email, 10) })
      .expect(401);
  });

  it("invalidates the challenge when the password changes mid-flow", async () => {
    const { secret } = await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    // token_version moves, so a challenge minted beforehand is dead.
    await store.updateUser(user.id, { bump_token_version: true });
    await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, code: codeFor(secret, user.email) })
      .expect(401);
  });
});

describe("recovery codes", () => {
  it("logs in with a recovery code and reports how many remain", async () => {
    const { recoveryCodes } = await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    const res = await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, recovery_code: recoveryCodes[0] })
      .expect(200);
    expect(res.body.used_recovery_code).toBe(true);
    expect(res.body.recovery_codes_remaining).toBe(9);
  });

  it("burns a recovery code after one use", async () => {
    const { recoveryCodes } = await enroll(user);
    const first = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app).post("/auth/mfa/verify").send({ mfa_token: first.body.mfa_token, recovery_code: recoveryCodes[0] }).expect(200);

    const second = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app).post("/auth/mfa/verify").send({ mfa_token: second.body.mfa_token, recovery_code: recoveryCodes[0] }).expect(401);
  });

  it("spends a recovery code only once under concurrent use", async () => {
    const { recoveryCodes } = await enroll(user);
    const logins = await Promise.all([1, 2, 3].map(() =>
      request(app).post("/auth/login").send({ username: user.email, password: PASSWORD })
    ));
    const results = await Promise.all(logins.map((l) =>
      request(app).post("/auth/mfa/verify").send({ mfa_token: l.body.mfa_token, recovery_code: recoveryCodes[0] })
    ));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it("is case-insensitive about recovery codes", async () => {
    const { recoveryCodes } = await enroll(user);
    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app)
      .post("/auth/mfa/verify")
      .send({ mfa_token: login.body.mfa_token, recovery_code: recoveryCodes[0].toLowerCase() })
      .expect(200);
  });

  it("invalidates the old set when codes are regenerated", async () => {
    const { recoveryCodes } = await enroll(user);
    const res = await request(app)
      .post("/auth/mfa/recovery-codes")
      .set(...asUser(await reload(user)))
      .send({ password: PASSWORD })
      .expect(200);
    expect(res.body.recovery_codes).toHaveLength(10);

    const login = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD });
    await request(app).post("/auth/mfa/verify").send({ mfa_token: login.body.mfa_token, recovery_code: recoveryCodes[0] }).expect(401);
  });

  it("requires the password to regenerate", async () => {
    await enroll(user);
    await request(app)
      .post("/auth/mfa/recovery-codes")
      .set(...asUser(await reload(user)))
      .send({ password: "wrong-password" })
      .expect(400);
  });
});

describe("disabling MFA", () => {
  it("requires both the password and a valid code", async () => {
    const { secret } = await enroll(user);
    const current = await reload(user);

    await request(app).post("/auth/mfa/disable").set(...asUser(current))
      .send({ password: PASSWORD }).expect(400);                       // no code
    await request(app).post("/auth/mfa/disable").set(...asUser(current))
      .send({ password: "wrong", code: codeFor(secret, user.email) }).expect(400); // wrong password
    expect((await reload(user)).mfa_enabled).toBe(true);

    await request(app).post("/auth/mfa/disable").set(...asUser(current))
      .send({ password: PASSWORD, code: codeFor(secret, user.email) }).expect(200);

    const after = await reload(user);
    expect(after.mfa_enabled).toBe(false);
    expect(after.mfa_secret_enc).toBeNull();
    expect(after.mfa_secret_legacy).toBeNull();
  });

  it("clears the recovery codes as well", async () => {
    const { secret } = await enroll(user);
    await request(app).post("/auth/mfa/disable").set(...asUser(await reload(user)))
      .send({ password: PASSWORD, code: codeFor(secret, user.email) }).expect(200);

    const count = await queryOne<{ count: number }>(
      "SELECT count(*)::bigint AS count FROM mfa_recovery_codes WHERE user_id = $1", [user.id]
    );
    expect(Number(count!.count)).toBe(0);
  });

  it("returns to single-factor login once disabled", async () => {
    const { secret } = await enroll(user);
    await request(app).post("/auth/mfa/disable").set(...asUser(await reload(user)))
      .send({ password: PASSWORD, code: codeFor(secret, user.email) }).expect(200);

    const res = await request(app).post("/auth/login").send({ username: user.email, password: PASSWORD }).expect(200);
    expect(res.body.access_token).toBeDefined();
    expect(res.body.mfa_required).toBeUndefined();
  });
});
