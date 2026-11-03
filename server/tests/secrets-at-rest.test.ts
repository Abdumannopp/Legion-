/**
 * Authentication secrets at rest.
 *
 *  - one-time tokens (reset, invitation, e-mail verification) are stored only as
 *    SHA-256 hashes, expire, and work exactly once — also under concurrency;
 *  - TOTP seeds are AES-256-GCM encrypted under a dedicated, versioned keyring,
 *    bound to their user, and never readable from the database;
 *  - a ciphertext that cannot be opened fails CLOSED: MFA stays on, sign-in is
 *    refused, nothing is reset;
 *  - existing plaintext is converted without losing anyone's MFA or live links;
 *  - no secret reaches a log or a normal API response.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import pg from "pg";
import * as OTPAuth from "otpauth";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as mfa from "../src/mfa.js";
import { hashOneTimeToken, newOneTimeToken } from "../src/auth-tokens.js";
import { keyIdOf, keyringStatus, needsRotation, open, seal } from "../src/secret-box.js";
import { parseKeyring } from "../src/keyring-parse.js";
import { migrateSecretsAtRest, secretsStatus } from "../src/secrets-migration.js";
import type { User } from "../src/types.js";

const PASSWORD = "password123";
const K1 = `t1:${"0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0"}`; // the suite's key (vitest.config.ts)
const K2 = `t2:${"b51f1aea1251f1c247fa019607854984d20e1ebca028ad9d99e8aa5a6d78a12c"}`;
const saved = { keys: config.encryptionKeys, active: config.encryptionKeyActive, devLog: config.devLogAuthLinks };

let tenant: string;
let admin: User, member: User;
let passwordHash = "";

const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const reload = async (u: User) => (await store.findUserById(u.id))!;
/** Every column of a user row as one string: what a database dump would show. */
const rowText = async (id: string) => JSON.stringify((await query("SELECT * FROM users WHERE id = $1", [id])).rows[0]);
const dumpText = async () => JSON.stringify((await query("SELECT * FROM users")).rows);
const code = (secret: string, email: string, step = 0) => new OTPAuth.TOTP({ issuer: config.mfaIssuer, label: email, algorithm: "SHA1", digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secret) }).generate({ timestamp: Date.now() + step * 30_000 });

/** Captures console output, so tests can prove nothing secret was logged. */
let logged: string[] = [];
function captureLogs() {
  logged = [];
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, level).mockImplementation((...a: unknown[]) => { logged.push(a.map(String).join(" ")); });
  }
}

beforeAll(async () => { await migrate(); passwordHash = await bcrypt.hash(PASSWORD, 4); });
afterAll(async () => { Object.assign(config, { encryptionKeys: saved.keys, encryptionKeyActive: saved.active, devLogAuthLinks: saved.devLog }); await closePool(); });
beforeEach(async () => {
  await truncateAll();
  Object.assign(config, { encryptionKeys: saved.keys, encryptionKeyActive: "", devLogAuthLinks: false });
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'T', now() + interval '14 days')", [tenant]);
  admin = await store.insertUser({ email: "admin@t.io", password_hash: passwordHash, tenant_id: tenant, role: "admin", status: "active" });
  member = await store.insertUser({ email: "member@t.io", password_hash: passwordHash, tenant_id: tenant, role: "analyst", status: "active" });
  captureLogs();
});
afterEach(() => { vi.restoreAllMocks(); Object.assign(config, { encryptionKeys: saved.keys, encryptionKeyActive: "" }); });

/** Issues a reset link the way the server does, and returns the token that would be e-mailed. */
async function resetLinkFor(email: string): Promise<string> {
  config.devLogAuthLinks = true; // the only way a token leaves the server without SMTP
  await request(app).post("/auth/forgot-password").send({ email }).expect(202);
  config.devLogAuthLinks = false;
  const line = logged.find((l) => l.includes("reset-password?token="))!;
  logged = logged.filter((l) => l !== line);
  return new URL(line.slice(line.indexOf("http"))).searchParams.get("token")!;
}
async function inviteLink(email = "new@t.io"): Promise<string> {
  const res = await request(app).post("/users/invite").set(...bearer(admin)).send({ email, role: "viewer" }).expect(201);
  return new URL(res.body.invite_url).searchParams.get("token")!;
}

// =============================================================================
// Password reset tokens
// =============================================================================

describe("password reset tokens", () => {
  it("the plaintext token is never stored — only its SHA-256", async () => {
    const token = await resetLinkFor(member.email);
    const row = await reload(member);
    expect(row.reset_token_hash).toBe(hashOneTimeToken(token));
    expect(await rowText(member.id)).not.toContain(token);
    expect((await query("SELECT reset_token FROM users WHERE id = $1", [member.id])).rows[0].reset_token).toBeNull();
  });

  it("the database refuses a plaintext token, whoever tries to write one", async () => {
    await expect(query("UPDATE users SET reset_token = 'plain' WHERE id = $1", [member.id])).rejects.toThrow(/users_no_plaintext_tokens/);
    await expect(query("UPDATE users SET invite_token = 'plain' WHERE id = $1", [member.id])).rejects.toThrow(/users_no_plaintext_tokens/);
  });

  it("works once, with the right token", async () => {
    const token = await resetLinkFor(member.email);
    await request(app).post("/auth/reset-password").send({ token, new_password: "a-brand-new-password" }).expect(200);
    await request(app).post("/auth/login").send({ username: member.email, password: "a-brand-new-password" }).expect(200);
    expect((await reload(member)).reset_token_hash).toBeNull();
  });

  it("a used token fails", async () => {
    const token = await resetLinkFor(member.email);
    await request(app).post("/auth/reset-password").send({ token, new_password: "first-new-password" }).expect(200);
    await request(app).post("/auth/reset-password").send({ token, new_password: "second-new-password" }).expect(400);
    await request(app).post("/auth/login").send({ username: member.email, password: "first-new-password" }).expect(200);
  });

  it("a used token fails even when both uses race each other", async () => {
    const token = await resetLinkFor(member.email);
    const results = await Promise.all(Array.from({ length: 6 }, (_, i) =>
      request(app).post("/auth/reset-password").send({ token, new_password: `racing-password-${i}` })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 400)).toHaveLength(5);
  });

  it("an expired token fails and changes nothing", async () => {
    const token = await resetLinkFor(member.email);
    await query("UPDATE users SET reset_expires = now() - interval '1 second' WHERE id = $1", [member.id]);
    await request(app).post("/auth/reset-password").send({ token, new_password: "too-late-password" }).expect(400);
    await request(app).post("/auth/login").send({ username: member.email, password: PASSWORD }).expect(200);
  });

  it("expires one hour after it is issued", async () => {
    await resetLinkFor(member.email);
    const { expires_in } = (await query("SELECT extract(epoch FROM reset_expires - now()) AS expires_in FROM users WHERE id = $1", [member.id])).rows[0];
    expect(Number(expires_in)).toBeGreaterThan(3_500);
    expect(Number(expires_in)).toBeLessThanOrEqual(3_600);
  });

  it("a wrong token fails — a near miss, another user's, a garbage one", async () => {
    const token = await resetLinkFor(member.email);
    const other = await resetLinkFor(admin.email);
    for (const wrong of [token.slice(0, -1) + (token.endsWith("A") ? "B" : "A"), "x".repeat(43), hashOneTimeToken(token)]) {
      await request(app).post("/auth/reset-password").send({ token: wrong, new_password: "wrong-token-password" }).expect(400);
    }
    // Another user's valid token resets THAT user, never this one.
    await request(app).post("/auth/reset-password").send({ token: other, new_password: "admins-new-password" }).expect(200);
    await request(app).post("/auth/login").send({ username: member.email, password: PASSWORD }).expect(200);
    // …and this user's own token still works: failed attempts do not burn it.
    await request(app).post("/auth/reset-password").send({ token, new_password: "members-new-password" }).expect(200);
  });

  it("a new request replaces the previous link", async () => {
    const first = await resetLinkFor(member.email);
    const second = await resetLinkFor(member.email);
    await request(app).post("/auth/reset-password").send({ token: first, new_password: "old-link-password" }).expect(400);
    await request(app).post("/auth/reset-password").send({ token: second, new_password: "new-link-password" }).expect(200);
  });

  it("a deactivated account cannot be taken back with an outstanding link", async () => {
    const token = await resetLinkFor(member.email);
    await request(app).delete(`/users/${member.id}`).set(...bearer(admin)).expect(200);
    expect((await reload(member)).reset_token_hash).toBeNull();
    await request(app).post("/auth/reset-password").send({ token, new_password: "revived-password" }).expect(400);
  });

  it("using it ends every existing session", async () => {
    const before = (await reload(member)).token_version;
    const token = await resetLinkFor(member.email);
    await request(app).post("/auth/reset-password").send({ token, new_password: "session-ending-pw" }).expect(200);
    expect((await reload(member)).token_version).toBe(before + 1);
    await request(app).get("/auth/me").set(...bearer(member)).expect(401);
  });
});

// =============================================================================
// Invitation tokens
// =============================================================================

describe("invitation tokens", () => {
  it("the plaintext token is never stored — only its SHA-256", async () => {
    const token = await inviteLink();
    const invited = (await store.findUserByEmail("new@t.io"))!;
    expect(invited.invite_token_hash).toBe(hashOneTimeToken(token));
    expect(await rowText(invited.id)).not.toContain(token);
  });

  it("works once", async () => {
    const token = await inviteLink();
    await request(app).post("/auth/accept-invite").send({ token, password: "invited-password" }).expect(200);
    await request(app).post("/auth/accept-invite").send({ token, password: "second-password" }).expect(400);
    await request(app).post("/auth/invite/preview").send({ token }).expect(404);
    await request(app).post("/auth/login").send({ username: "new@t.io", password: "invited-password" }).expect(200);
  });

  it("works once even under concurrent accepts", async () => {
    const token = await inviteLink();
    const results = await Promise.all(Array.from({ length: 5 }, (_, i) => request(app).post("/auth/accept-invite").send({ token, password: `accept-password-${i}` })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it("an expired invitation fails, for preview and accept", async () => {
    const token = await inviteLink();
    await query("UPDATE users SET invite_expires = now() - interval '1 second' WHERE email = 'new@t.io'");
    await request(app).post("/auth/invite/preview").send({ token }).expect(404);
    await request(app).post("/auth/accept-invite").send({ token, password: "late-password" }).expect(400);
  });

  it("a wrong token fails", async () => {
    const token = await inviteLink();
    await request(app).post("/auth/invite/preview").send({ token: token.slice(0, -2) + "zz" }).expect(404);
    await request(app).post("/auth/accept-invite").send({ token: hashOneTimeToken(token), password: "hash-as-token" }).expect(400);
    await request(app).post("/auth/accept-invite").send({ token: "short", password: "short-token-pw" }).expect(422);
  });

  it("the token never travels in a URL: the preview is a POST, the old GET is gone", async () => {
    const token = await inviteLink();
    const res = await request(app).post("/auth/invite/preview").send({ token }).expect(200);
    expect(res.body).toEqual({ email: "new@t.io", role: "viewer", tenant_name: "T", existing_account: false });
    await request(app).get(`/auth/invite/${token}`).expect(404);
  });
});

describe("e-mail verification tokens", () => {
  it("are stored hashed and work exactly once, even concurrently", async () => {
    const { token, hash } = newOneTimeToken();
    await query("UPDATE users SET email_verified_at = NULL, verify_token_hash = $2, verify_expires = now() + interval '1 hour' WHERE id = $1", [member.id, hash]);
    expect(await rowText(member.id)).not.toContain(token);
    const results = await Promise.all(Array.from({ length: 4 }, () => request(app).post("/auth/verify-email").send({ token })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect((await query("SELECT verify_token_hash FROM users WHERE id = $1", [member.id])).rows[0].verify_token_hash).toBeNull();
  });

  it("an expired one fails", async () => {
    const { token, hash } = newOneTimeToken();
    await query("UPDATE users SET email_verified_at = NULL, verify_token_hash = $2, verify_expires = now() - interval '1 second' WHERE id = $1", [member.id, hash]);
    await request(app).post("/auth/verify-email").send({ token }).expect(400);
  });
});

// =============================================================================
// TOTP seeds
// =============================================================================

async function enroll(u: User): Promise<string> {
  const setup = await request(app).post("/auth/mfa/setup").set(...bearer(u)).expect(200);
  expect(setup.headers["cache-control"]).toBe("no-store");
  const secret = setup.body.secret as string;
  await request(app).post("/auth/mfa/enable").set(...bearer(u)).send({ code: code(secret, u.email) }).expect(200);
  await query("DELETE FROM mfa_used_counters WHERE user_id = $1", [u.id]);
  return secret;
}
async function mfaLogin(u: User, c: string) {
  const first = await request(app).post("/auth/login").send({ username: u.email, password: PASSWORD }).expect(200);
  expect(first.body.mfa_required).toBe(true);
  return request(app).post("/auth/mfa/verify").send({ mfa_token: first.body.mfa_token, code: c });
}

describe("the secret box (AES-256-GCM)", () => {
  it("encrypts and decrypts", () => {
    const sealed = seal("JBSWY3DPEHPK3PXP", "mfa-totp", "user-1");
    expect(open(sealed, "mfa-totp", "user-1")).toBe("JBSWY3DPEHPK3PXP");
    expect(sealed).not.toContain("JBSWY3DPEHPK3PXP");
    expect(sealed).toMatch(/^lsb1\.t1\.[\w-]{16}\.[\w-]{22}\.[\w-]+$/);
    expect(seal("JBSWY3DPEHPK3PXP", "mfa-totp", "user-1")).not.toBe(sealed); // a fresh IV every time
  });

  it("is bound to its owner and its purpose", () => {
    const sealed = seal("JBSWY3DPEHPK3PXP", "mfa-totp", "user-1");
    expect(open(sealed, "mfa-totp", "user-2")).toBeNull();
    expect(open(sealed, "webhook-secret", "user-1")).toBeNull();
  });

  it.each([
    ["a flipped ciphertext byte", (s: string) => { const p = s.split("."); const b = Buffer.from(p[4]!, "base64url"); b[0]! ^= 1; p[4] = b.toString("base64url"); return p.join("."); }],
    ["a flipped tag byte", (s: string) => { const p = s.split("."); const b = Buffer.from(p[3]!, "base64url"); b[5]! ^= 1; p[3] = b.toString("base64url"); return p.join("."); }],
    ["a different IV", (s: string) => { const p = s.split("."); p[2] = Buffer.alloc(12, 7).toString("base64url"); return p.join("."); }],
    ["a truncated ciphertext", (s: string) => s.slice(0, -4)],
    ["a truncated tag", (s: string) => { const p = s.split("."); p[3] = p[3]!.slice(0, 10); return p.join("."); }],
    ["an unknown key id", (s: string) => s.replace(".t1.", ".nope.")],
    ["another format", (s: string) => s.replace("lsb1.", "lsb9.")],
    ["missing parts", (s: string) => s.split(".").slice(0, 3).join(".")],
    ["not base64", (s: string) => { const p = s.split("."); p[4] = "!!!!"; return p.join("."); }],
    ["empty", () => ""],
    ["gigantic", () => `lsb1.t1.${"A".repeat(5000)}`],
    ["the plaintext itself", () => "JBSWY3DPEHPK3PXP"],
  ])("invalid ciphertext fails safely: %s → null, no exception", (_name, mutate) => {
    const sealed = seal("JBSWY3DPEHPK3PXP", "mfa-totp", "user-1");
    expect(() => open(mutate(sealed), "mfa-totp", "user-1")).not.toThrow();
    expect(open(mutate(sealed), "mfa-totp", "user-1")).toBeNull();
  });

  it("non-string input fails safely too", () => {
    for (const v of [null, undefined, 42, {}, [], Buffer.from("x")]) expect(open(v, "mfa-totp", "u")).toBeNull();
  });

  it("supports key versions: new seals use the active key, old ones still open, and are due for rotation", () => {
    const underK1 = seal("JBSWY3DPEHPK3PXP", "mfa-totp", "u");
    config.encryptionKeys = `${K2},${K1}`;
    expect(keyringStatus()).toMatchObject({ active: "t2", source: "configured" });
    const underK2 = seal("JBSWY3DPEHPK3PXP", "mfa-totp", "u");
    expect(keyIdOf(underK2)).toBe("t2");
    expect(open(underK1, "mfa-totp", "u")).toBe("JBSWY3DPEHPK3PXP");
    expect(needsRotation(underK1)).toBe(true);
    expect(needsRotation(underK2)).toBe(false);
    config.encryptionKeyActive = "t1"; // or pin the active key explicitly
    expect(keyIdOf(seal("x", "mfa-totp", "u"))).toBe("t1");
    config.encryptionKeys = K2; config.encryptionKeyActive = ""; // k1 removed
    expect(open(underK1, "mfa-totp", "u")).toBeNull();
  });

  it("keyring parsing refuses weak or malformed keys, without echoing them", () => {
    const secretish = "deadbeef".repeat(4);
    for (const [spec, active] of [
      ["", ""], ["k1", ""], [`k1:${secretish}`, ""], [`bad id!:${"ab".repeat(32)}`, ""], [`k1:${"00".repeat(32)}`, ""],
      [`k1:${"ab".repeat(32)},k1:${"cd".repeat(32)}`, ""], [`k1:${"ab".repeat(32)}`, "k2"],
    ] as const) {
      const r = parseKeyring(spec, active);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error).not.toContain(secretish);
    }
    expect(parseKeyring(`k1:${Buffer.alloc(32, 9).map((b, i) => b + i).toString("base64")}`).ok).toBe(true);
    expect(parseKeyring(`k1:${Buffer.alloc(32, 9).map((b, i) => b + i).toString("base64url")}`).ok).toBe(true);
  });
});

describe("TOTP seeds at rest", () => {
  it("are stored encrypted from the first moment of enrolment — no base32 seed anywhere in the row", async () => {
    const secret = await enroll(member);
    const row = await reload(member);
    expect(row.mfa_secret_legacy).toBeNull();
    expect(row.mfa_secret_enc).toMatch(/^lsb1\.t1\./);
    expect(await rowText(member.id)).not.toContain(secret);
    expect(open(row.mfa_secret_enc, "mfa-totp", member.id)).toBe(secret);
  });

  it("encryption and decryption work end to end: enrol, sign in, disable", async () => {
    const secret = await enroll(member);
    const ok = await mfaLogin(member, code(secret, member.email));
    expect(ok.status).toBe(200);
    await query("DELETE FROM mfa_used_counters WHERE user_id = $1", [member.id]);
    await request(app).post("/auth/mfa/disable").set(...bearer(await reload(member))).send({ password: PASSWORD, code: code(secret, member.email) }).expect(200);
    const after = await reload(member);
    expect([after.mfa_enabled, after.mfa_secret_enc, after.mfa_secret_legacy]).toEqual([false, null, null]);
  });

  it("a seed copied onto another user's row does not work there — and does not switch MFA off", async () => {
    const aSecret = await enroll(admin);
    await enroll(member);
    const adminEnc = (await reload(admin)).mfa_secret_enc;
    await query("UPDATE users SET mfa_secret_enc = $1 WHERE id = $2", [adminEnc, member.id]);
    const res = await mfaLogin(member, code(aSecret, member.email));
    expect(res.status).toBe(503);
    expect(res.body.code).toBe("mfa_unavailable");
    expect((await reload(member)).mfa_enabled).toBe(true);
  });

  it("an unreadable seed (key missing) fails closed: refused, MFA kept, nothing rewritten; restoring the key fixes it", async () => {
    const secret = await enroll(member);
    const before = await reload(member);
    config.encryptionKeys = K2; // t1 removed by mistake
    const res = await mfaLogin(member, code(secret, member.email));
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ code: "mfa_unavailable" });
    const during = await reload(member);
    expect(during.mfa_enabled).toBe(true);
    expect(during.mfa_secret_enc).toBe(before.mfa_secret_enc);
    // The boot migration leaves it alone too, and says so.
    const report = await migrateSecretsAtRest();
    expect(report.mfa.unreadable).toBe(1);
    expect((await reload(member)).mfa_secret_enc).toBe(before.mfa_secret_enc);
    // A disable attempt with a code cannot use the unreadable seed either.
    await request(app).post("/auth/mfa/disable").set(...bearer(during)).send({ password: PASSWORD, code: code(secret, member.email) }).expect(400);
    expect((await reload(member)).mfa_enabled).toBe(true);

    config.encryptionKeys = `${K2},${K1}`; // key restored
    const ok = await mfaLogin(member, code(secret, member.email));
    expect(ok.status).toBe(200);
  });

  it("recovery codes still work while the seed is unreadable (they are hashed, not encrypted)", async () => {
    await request(app).post("/auth/mfa/setup").set(...bearer(member)).expect(200);
    const secret = open((await reload(member)).mfa_secret_enc, "mfa-totp", member.id)!;
    const enabled = await request(app).post("/auth/mfa/enable").set(...bearer(member)).send({ code: code(secret, member.email) }).expect(200);
    config.encryptionKeys = K2;
    const first = await request(app).post("/auth/login").send({ username: member.email, password: PASSWORD }).expect(200);
    await request(app).post("/auth/mfa/verify").send({ mfa_token: first.body.mfa_token, recovery_code: enabled.body.recovery_codes[0] }).expect(200);
  });

  it("re-running setup while MFA is on never replaces the working seed", async () => {
    await enroll(member);
    const before = (await reload(member)).mfa_secret_enc;
    await request(app).post("/auth/mfa/setup").set(...bearer(await reload(member))).expect(400);
    expect(await mfa.beginEnrolment(member.id)).toBeNull();
    expect((await reload(member)).mfa_secret_enc).toBe(before);
  });

  it("key rotation: seeds move to the new key at boot and keep working; then the old key can go", async () => {
    const secret = await enroll(member);
    config.encryptionKeys = `${K2},${K1}`;
    const report = await migrateSecretsAtRest();
    expect(report.mfa).toMatchObject({ rotated: 1, unreadable: 0 });
    expect(keyIdOf((await reload(member)).mfa_secret_enc)).toBe("t2");
    expect((await secretsStatus()).mfa_by_key).toEqual([{ key: "t2", count: 1 }]);
    config.encryptionKeys = K2; // t1 retired
    expect((await mfaLogin(member, code(secret, member.email))).status).toBe(200);
  });

  it("a seed under an old key is also re-encrypted on first use, without waiting for a restart", async () => {
    const secret = await enroll(member);
    config.encryptionKeys = `${K2},${K1}`;
    expect((await mfaLogin(member, code(secret, member.email))).status).toBe(200);
    expect(keyIdOf((await reload(member)).mfa_secret_enc)).toBe("t2");
  });
});

// =============================================================================
// Migration of existing plaintext
// =============================================================================

describe("migrating existing plaintext secrets", () => {
  /** A user as the previous release left it: plaintext seed, MFA on. */
  async function legacyMfaUser(email: string, secret = new OTPAuth.Secret({ size: 20 }).base32) {
    const u = await store.insertUser({ email, password_hash: passwordHash, tenant_id: tenant, role: "analyst", status: "active" });
    await query("UPDATE users SET mfa_secret = $2, mfa_enabled = true, mfa_enrolled_at = now() WHERE id = $1", [u.id, secret]);
    return { user: (await reload(u))!, secret };
  }

  it("plaintext seeds are encrypted at boot; every user's MFA keeps working with their existing authenticator", async () => {
    const users = await Promise.all(["m1@t.io", "m2@t.io", "m3@t.io"].map((e) => legacyMfaUser(e)));
    const report = await migrateSecretsAtRest();
    expect(report.mfa).toMatchObject({ converted: 3, unreadable: 0, skipped: 0 });
    for (const { user, secret } of users) {
      const row = await reload(user);
      expect(row.mfa_enabled).toBe(true);
      expect(row.mfa_secret_legacy).toBeNull();
      expect(await rowText(user.id)).not.toContain(secret);
      expect((await mfaLogin(row, code(secret, row.email))).status).toBe(200);
    }
  });

  it("a plaintext seed not yet converted still works, and is encrypted on first use", async () => {
    const { user, secret } = await legacyMfaUser("lazy@t.io");
    expect((await mfaLogin(user, code(secret, user.email))).status).toBe(200);
    const row = await reload(user);
    expect(row.mfa_secret_legacy).toBeNull();
    expect(open(row.mfa_secret_enc, "mfa-totp", user.id)).toBe(secret);
  });

  it("is idempotent: a second run changes nothing", async () => {
    await legacyMfaUser("idem@t.io");
    await migrateSecretsAtRest();
    const snapshot = await dumpText();
    expect(await migrateSecretsAtRest()).toMatchObject({ mfa: { converted: 0, rotated: 0, unreadable: 0, skipped: 0 } });
    expect(await dumpText()).toBe(snapshot);
  });

  it("two instances migrating at once convert each seed once and lose none", async () => {
    const users = await Promise.all(Array.from({ length: 6 }, (_, i) => legacyMfaUser(`race${i}@t.io`)));
    const reports = await Promise.all([migrateSecretsAtRest(), migrateSecretsAtRest(), migrateSecretsAtRest()]);
    expect(reports.reduce((n, r) => n + r.mfa.converted, 0)).toBe(6);
    for (const { user, secret } of users) expect(open((await reload(user)).mfa_secret_enc, "mfa-totp", user.id)).toBe(secret);
  });

  it("a value that is not a seed is left for a human, not encrypted and not deleted", async () => {
    const { user } = await legacyMfaUser("odd@t.io", "not a base32 seed");
    const report = await migrateSecretsAtRest();
    expect(report.mfa.skipped).toBe(1);
    expect((await reload(user)).mfa_secret_legacy).toBe("not a base32 seed");
    expect((await reload(user)).mfa_enabled).toBe(true);
  });

  it("an older instance writing a plaintext seed during a rolling upgrade: the newer value wins and gets encrypted", async () => {
    await enroll(member);
    const fresh = new OTPAuth.Secret({ size: 20 }).base32;
    // What pre-upgrade code does on /auth/mfa/setup: write the plaintext column only.
    await query("UPDATE users SET mfa_secret = $2, mfa_enabled = false WHERE id = $1", [member.id, fresh]);
    await migrateSecretsAtRest();
    expect(open((await reload(member)).mfa_secret_enc, "mfa-totp", member.id)).toBe(fresh);
  });

  const schema = readFileSync(fileURLToPath(new URL("../src/db/schema.sql", import.meta.url)), "utf8");
  const previousRelease = schema.slice(0, schema.indexOf("-- Authentication secrets at rest."));
  const dbName = `legion_secrets_upgrade_${randomUUID().slice(0, 8)}`;
  const urlFor = (database: string) => { const u = new URL(config.databaseUrl); u.pathname = `/${database}`; return u.toString(); };

  it("upgrading a real database from the previous release: live links keep working, seeds are encrypted, nothing plaintext remains", async () => {
    expect(previousRelease).toMatch(/reset_token\s+text/); // sanity: that schema stored plaintext
    expect(previousRelease).not.toContain("reset_token_hash");
    const adminConn = new pg.Client({ connectionString: urlFor("postgres") });
    await adminConn.connect();
    await adminConn.query(`CREATE DATABASE ${dbName}`);
    const db = new pg.Client({ connectionString: urlFor(dbName) });
    try {
      await db.connect();
      await db.query(previousRelease);
      await db.query("CREATE TABLE IF NOT EXISTS webhook_credentials (key_id text PRIMARY KEY, secret_enc text NOT NULL)").catch(() => {});
      const t = randomUUID(), u1 = randomUUID(), u2 = randomUUID();
      const resetToken = newOneTimeToken().token, inviteToken = newOneTimeToken().token;
      const seed = new OTPAuth.Secret({ size: 20 }).base32;
      await db.query("INSERT INTO tenants (id, name) VALUES ($1, 'Old')", [t]);
      await db.query(
        `INSERT INTO users (id, email, password_hash, tenant_id, role, status, reset_token, reset_expires, mfa_secret, mfa_enabled)
         VALUES ($1, 'old@x.io', 'h', $2, 'admin', 'active', $3, now() + interval '1 hour', $4, true)`, [u1, t, resetToken, seed]);
      await db.query(
        `INSERT INTO users (id, email, password_hash, tenant_id, role, status, invite_token, invite_expires)
         VALUES ($1, 'inv@x.io', '', $2, 'viewer', 'invited', $3, now() + interval '7 days')`, [u2, t, inviteToken]);

      await db.query(schema); // the upgrade: SQL part
      const report = await migrateSecretsAtRest(db); // the upgrade: the part that needs the key
      expect(report.mfa.converted).toBe(1);

      const rows = (await db.query("SELECT * FROM users ORDER BY email")).rows;
      const dump = JSON.stringify(rows);
      for (const secret of [resetToken, inviteToken, seed]) expect(dump).not.toContain(secret);
      const old = rows.find((r) => r.email === "old@x.io")!;
      const inv = rows.find((r) => r.email === "inv@x.io")!;
      // The links in e-mails already sent still match.
      expect(old.reset_token_hash).toBe(hashOneTimeToken(resetToken));
      expect(inv.invite_token_hash).toBe(hashOneTimeToken(inviteToken));
      // MFA is intact: still enabled, same seed.
      expect(old.mfa_enabled).toBe(true);
      expect(open(old.mfa_secret_enc, "mfa-totp", old.id)).toBe(seed);

      // Running both again (every boot) is a no-op.
      await db.query(schema);
      expect((await migrateSecretsAtRest(db)).mfa).toMatchObject({ converted: 0, rotated: 0 });
      expect(JSON.stringify((await db.query("SELECT * FROM users ORDER BY email")).rows)).toBe(dump);
    } finally {
      await db.end().catch(() => {});
      await adminConn.query(`DROP DATABASE IF EXISTS ${dbName}`);
      await adminConn.end();
    }
  });
});

// =============================================================================
// Nothing secret in logs or normal responses
// =============================================================================

describe("secrets never leave through logs or ordinary responses", () => {
  it("a whole lifecycle — reset, invite, enrol, sign in, fail, rotate — logs no token, seed, hash or key", async () => {
    // The default: no DEV_LOG_AUTH_LINKS. Nothing the server generates is printed.
    await request(app).post("/auth/forgot-password").send({ email: member.email }).expect(202);
    const inviteRes = await request(app).post("/users/invite").set(...bearer(admin)).send({ email: "lc@t.io", role: "viewer" }).expect(201);
    const inviteToken = new URL(inviteRes.body.invite_url).searchParams.get("token")!;
    await request(app).post("/auth/invite/preview").send({ token: inviteToken }).expect(200);
    await request(app).post("/auth/accept-invite").send({ token: "wrong-" + inviteToken, password: "whatever-password" }).expect(400);
    const secret = await enroll(member);
    await mfaLogin(member, "000000");
    config.encryptionKeys = K2;
    await mfaLogin(member, code(secret, member.email)); // unreadable → logged for the operator
    config.encryptionKeys = `${K2},${K1}`;
    await migrateSecretsAtRest();

    const all = logged.join("\n");
    const resetHash = (await reload(member)).reset_token_hash!;
    const forbidden = [inviteToken, hashOneTimeToken(inviteToken), resetHash, secret, K1.split(":")[1]!, K2.split(":")[1]!, config.jwtSecret, "reset-password?token=", "accept-invite?token="];
    for (const f of forbidden) expect(all, `log leaked ${f.slice(0, 10)}…`).not.toContain(f);
    expect(all).toMatch(/cannot be decrypted \(key "t1"\)/); // the operator still learns what they need
    expect(all).toMatch(/link was generated but not e-mailed/);
  });

  it("DEV_LOG_AUTH_LINKS cannot turn on in production", async () => {
    vi.resetModules();
    const env = { ...process.env };
    Object.assign(process.env, { NODE_ENV: "production", DEV_LOG_AUTH_LINKS: "true", COOKIE_SECURE: "true", FRONTEND_URL: "https://x.example", SMTP_HOST: "smtp.example" });
    try {
      const { config: prodConfig } = await import("../src/config.js");
      expect(prodConfig.devLogAuthLinks).toBe(false);
    } catch (e) {
      // Production refuses other parts of the test environment; that is fine as long
      // as the refusal is not about this flag.
      expect(String(e)).not.toMatch(/DEV_LOG_AUTH_LINKS/);
    } finally {
      process.env = env;
      vi.resetModules();
    }
  });

  it("no ordinary API response carries a token, a hash, a seed or a ciphertext", async () => {
    await resetLinkFor(member.email);
    await inviteLink("x@t.io");
    await enroll(admin);
    const u = await reload(admin);
    const responses = await Promise.all([
      request(app).get("/auth/me").set(...bearer(u)),
      request(app).get("/users").set(...bearer(u)),
      request(app).get("/auth/mfa").set(...bearer(u)),
      request(app).patch(`/users/${member.id}/role`).set(...bearer(u)).send({ role: "viewer" }),
    ]);
    const rows = (await query("SELECT reset_token_hash, invite_token_hash, mfa_secret_enc FROM users")).rows;
    const secrets = rows.flatMap((r) => [r.reset_token_hash, r.invite_token_hash, r.mfa_secret_enc]).filter(Boolean) as string[];
    expect(secrets.length).toBeGreaterThanOrEqual(3);
    for (const res of responses) {
      expect(res.status).toBe(200);
      const text = JSON.stringify(res.body);
      for (const s of secrets) expect(text).not.toContain(s);
      expect(text).not.toMatch(/token_hash|mfa_secret|password_hash|lsb1\./);
    }
  });

  it("the only responses that carry a secret are the ones that create it, and they are not cacheable", async () => {
    const setup = await request(app).post("/auth/mfa/setup").set(...bearer(member)).expect(200);
    expect(setup.headers["cache-control"]).toBe("no-store");
    const secret = setup.body.secret;
    const enable = await request(app).post("/auth/mfa/enable").set(...bearer(member)).send({ code: code(secret, member.email) }).expect(200);
    expect(enable.headers["cache-control"]).toBe("no-store");
    const inv = await request(app).post("/users/invite").set(...bearer(admin)).send({ email: "nc@t.io", role: "viewer" }).expect(201);
    expect(inv.headers["cache-control"]).toBe("no-store");
    // After that, the seed is never shown again.
    const again = await request(app).get("/auth/mfa").set(...bearer(await reload(member))).expect(200);
    expect(JSON.stringify(again.body)).not.toContain(secret);
  });
});
