/**
 * Sensor webhook authentication (webhook-auth.ts / webhook-credentials.ts).
 *
 * What is being proven, in the order a forger would try things:
 *   - every credential is random and its own; the old global-secret scheme
 *     signs nothing;
 *   - the tenant comes from the credential, never from a header;
 *   - the signature covers the raw bytes, the timestamp and a nonce;
 *   - stale, replayed, forged, tampered, malformed and unauthenticated
 *     requests store nothing;
 *   - a credential can be rotated with an overlap and revoked instantly;
 *   - nothing secret reaches a log, a response, the audit trail or the
 *     database in the clear.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as creds from "../src/webhook-credentials.js";
import { computeSignature, decryptSecret, digestsEqual, encryptSecret, generateCredential, legacyEncryptForTests, signWebhook } from "../src/webhook-auth.js";
import { migrateSecretsAtRest } from "../src/secrets-migration.js";
import type { User } from "../src/types.js";
import { resetWebhookFailures } from "../src/webhook-guard.js";
import { freshNonce, issueCredential, nowSeconds, sendSigned, type TestCredential } from "./helpers/webhook.js";

let tenantA: string, tenantB: string;
let adminA: User, analystA: User, adminB: User;
let credA: TestCredential, credB: TestCredential;
const saved = { skew: config.webhookMaxSkewSeconds, key: config.webhookEncryptionKey, overlap: config.webhookRotationOverlapHours };

const event = (id: string, description = "Multiple authentication failures") => ({
  provider: "wazuh",
  event: {
    id,
    rule: { description, level: 10, mitre: { id: ["T1110"] } },
    agent: { name: "web-01", ip: "10.0.0.5" },
    full_log: "sshd: Failed password",
  },
});

const alertCount = async (tenant: string) =>
  Number((await query("SELECT count(*) FROM alerts WHERE tenant_id = $1", [tenant])).rows[0].count);
const nonceCount = async () => Number((await query("SELECT count(*) FROM webhook_nonces")).rows[0].count);
const bearer = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;

/** Every console line written during a test. */
let logged: string[] = [];
const captureLogs = () => {
  logged = [];
  for (const level of ["log", "info", "warn", "error"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      logged.push(args.map((a) => (typeof a === "string" ? a : a instanceof Error ? a.message : JSON.stringify(a))).join(" "));
    });
  }
};

beforeAll(async () => { await migrate(); });
afterAll(async () => {
  Object.assign(config, { webhookMaxSkewSeconds: saved.skew, webhookEncryptionKey: saved.key, webhookRotationOverlapHours: saved.overlap });
  await closePool();
});
beforeEach(async () => {
  await truncateAll();
  Object.assign(config, { webhookMaxSkewSeconds: 300, webhookEncryptionKey: saved.key, webhookRotationOverlapHours: 24 });
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenantA, tenantB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@a.io", password_hash: hash, tenant_id: tenantA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@a.io", password_hash: hash, tenant_id: tenantA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "admin@b.io", password_hash: hash, tenant_id: tenantB, role: "admin", status: "active" });
  credA = await issueCredential(tenantA);
  credB = await issueCredential(tenantB);
  captureLogs();
});
afterEach(() => { vi.restoreAllMocks(); });

// --- 1. a valid request ------------------------------------------------------

describe("a valid request", () => {
  it("is stored, in the tenant the credential belongs to", async () => {
    const res = await sendSigned(app, credA, event("good-1")).expect(202);
    expect(res.body.status).toBe("ingested");
    expect(await alertCount(tenantA)).toBe(1);
    expect(await alertCount(tenantB)).toBe(0);
  });

  it("works with no x-tenant-id header at all, and with a matching one", async () => {
    await sendSigned(app, credA, event("good-2")).expect(202);
    await sendSigned(app, credA, event("good-3"), { tenantHeader: tenantA }).expect(202);
    expect(await alertCount(tenantA)).toBe(2);
  });

  it("records when the credential was last used", async () => {
    expect((await creds.listCredentials(tenantA))[0]!.last_used_at).toBeNull();
    await sendSigned(app, credA, event("good-4")).expect(202);
    await vi.waitFor(async () => expect((await creds.listCredentials(tenantA))[0]!.last_used_at).not.toBeNull());
  });

  it("the same event sent again (fresh nonce) is a duplicate, not a second alert", async () => {
    await sendSigned(app, credA, event("good-5")).expect(202);
    const again = await sendSigned(app, credA, event("good-5")).expect(202);
    expect(again.body).toMatchObject({ status: "skipped", reason: "duplicate" });
    expect(await alertCount(tenantA)).toBe(1);
  });

  it("two credentials may use the same nonce value: nonces are per credential", async () => {
    const nonce = freshNonce();
    await sendSigned(app, credA, event("n-1"), { nonce }).expect(202);
    await sendSigned(app, credB, event("n-2"), { nonce }).expect(202);
  });
});

// --- credentials are random, per tenant, and not derived ---------------------

describe("credentials", () => {
  it("are random and unique — nothing is derived from the tenant or a server secret", async () => {
    const a = generateCredential(), b = generateCredential();
    expect(a.secret).not.toEqual(b.secret);
    expect(a.secret).toMatch(/^whs_[A-Za-z0-9_-]{43}$/); // 256 random bits
    expect(credA.secret).not.toEqual(credB.secret);
    const second = await creds.createCredential(tenantA);
    expect(second.secret).not.toEqual(credA.secret);
  });

  it("the old derived key, HMAC(global secret, tenant), signs nothing", async () => {
    const derived = createHmac("sha256", config.webhookSecret).update(tenantA).digest("hex");
    // As the previous scheme sent it…
    await request(app).post("/security-events/webhook").set("x-tenant-id", tenantA).set("x-security-event-secret", derived).send(event("old-1")).expect(401);
    // …as the previous scheme signed it…
    const raw = JSON.stringify(event("old-2")), ts = String(nowSeconds());
    const oldSig = "v1=" + createHmac("sha256", derived).update(`${ts}.`).update(raw).digest("hex");
    const res = await request(app).post("/security-events/webhook").set("content-type", "application/json")
      .set("x-tenant-id", tenantA).set("x-legion-timestamp", ts).set("x-legion-signature", oldSig).send(raw).expect(401);
    expect(res.body.detail).toMatch(/out of date/i);
    // …and used as the key of the new scheme against a real key id.
    await sendSigned(app, credA, event("old-3"), { signWithSecret: derived }).expect(401);
    await sendSigned(app, credA, event("old-4"), { signWithSecret: config.webhookSecret }).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("are stored encrypted, bound to their row, and fail closed if unreadable", async () => {
    const [row] = (await query("SELECT key_id, secret_enc FROM webhook_credentials WHERE tenant_id = $1", [tenantA])).rows;
    expect(row.secret_enc).not.toContain(credA.secret);
    expect(row.secret_enc).not.toContain(credA.secret.slice(4, 20));
    expect(decryptSecret(row.secret_enc, row.key_id)).toBe(credA.secret);
    expect(decryptSecret(row.secret_enc, credB.keyId)).toBeNull(); // bound to its own key id
    expect(decryptSecret(row.secret_enc.slice(0, -3) + "AAA", row.key_id)).toBeNull(); // tampered

    // A ciphertext copied onto another credential's row does not become a login.
    await query("UPDATE webhook_credentials SET secret_enc = $1 WHERE key_id = $2", [row.secret_enc, credB.keyId]);
    await sendSigned(app, credB, event("enc-1")).expect(401);
    expect(logged.join("\n")).toContain("secret-unreadable");

    // The key that encrypted them was replaced (or lost): closed, not open.
    const keys = config.encryptionKeys;
    config.encryptionKeys = `t9:${"ab".repeat(32)}`;
    try { await sendSigned(app, credA, event("enc-2")).expect(401); }
    finally { config.encryptionKeys = keys; }
    await sendSigned(app, credA, event("enc-3")).expect(202);
  });

  it("are on the versioned keyring, and one from before it still works and is re-encrypted", async () => {
    const [row] = (await query("SELECT secret_enc FROM webhook_credentials WHERE key_id = $1", [credA.keyId])).rows;
    expect(row.secret_enc).toMatch(/^lsb1\.t1\./); // format, then the id of the key that sealed it

    // A credential stored before the keyring existed ("v1." format).
    await query("UPDATE webhook_credentials SET secret_enc = $1 WHERE key_id = $2", [legacyEncryptForTests(credA.secret, credA.keyId), credA.keyId]);
    await sendSigned(app, credA, event("leg-1")).expect(202);
    const report = await migrateSecretsAtRest();
    expect(report.webhook.converted).toBe(1);
    const [after] = (await query("SELECT secret_enc FROM webhook_credentials WHERE key_id = $1", [credA.keyId])).rows;
    expect(after.secret_enc).toMatch(/^lsb1\.t1\./);
    await sendSigned(app, credA, event("leg-2")).expect(202);
    expect(encryptSecret("whs_x", "whk_" + "A".repeat(22))).not.toBe(encryptSecret("whs_x", "whk_" + "A".repeat(22))); // fresh IV each time
  });
});

// --- 2. forged signature -----------------------------------------------------

describe("a forged signature", () => {
  it("made without the secret is refused and stores nothing", async () => {
    await sendSigned(app, credA, event("f-1"), { signWithSecret: "whs_" + "A".repeat(43) }).expect(401);
    await sendSigned(app, credA, event("f-2"), { signWithSecret: credB.secret }).expect(401); // another tenant's real secret
    const raw = JSON.stringify(event("f-3")), ts = String(nowSeconds()), nonce = freshNonce();
    await request(app).post("/security-events/webhook").set("content-type", "application/json")
      .set("x-legion-key-id", credA.keyId).set("x-legion-timestamp", ts).set("x-legion-nonce", nonce)
      .set("x-legion-signature", "v2=" + "0".repeat(64)).send(raw).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("must be for THIS request: the timestamp, the nonce and the version are all covered", async () => {
    const raw = JSON.stringify(event("f-4")), ts = String(nowSeconds()), nonce = freshNonce();
    const good = signWebhook(credA.secret, ts, nonce, raw);
    const send = (over: { ts?: string; nonce?: string; sig?: string }) =>
      request(app).post("/security-events/webhook").set("content-type", "application/json")
        .set("x-legion-key-id", credA.keyId).set("x-legion-timestamp", over.ts ?? ts)
        .set("x-legion-nonce", over.nonce ?? nonce).set("x-legion-signature", over.sig ?? good).send(raw);
    await send({ ts: String(Number(ts) + 1) }).expect(401); // same signature, other timestamp
    await send({ nonce: freshNonce() }).expect(401); // same signature, other nonce
    // Same digest, presented as another version of the scheme.
    await send({ sig: "v1=" + good.slice(3) }).expect(401);
    expect(await nonceCount()).toBe(0); // none of that was remembered
    await send({}).expect(202); // and the untouched request is fine
  });

  it("is compared as fixed-length digests, in constant time", () => {
    const a = computeSignature("s", "1700000000", "n".repeat(16), "x");
    expect(digestsEqual(a, Buffer.from(a))).toBe(true);
    expect(digestsEqual(a, computeSignature("s", "1700000000", "n".repeat(16), "y"))).toBe(false);
    expect(digestsEqual(a, a.subarray(0, 31))).toBe(false); // a shorter value cannot throw or match
    // That the request path really goes through crypto.timingSafeEqual is
    // proven in webhook-constant-time.test.ts, which spies on it.
  });
});

// --- 3. modified body --------------------------------------------------------

describe("a modified body", () => {
  it("a single changed character is refused", async () => {
    const real = JSON.stringify(event("b-1"));
    await sendSigned(app, credA, real.replace('"level":10', '"level":1'), { signBody: real }).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("the raw bytes are signed: the same JSON with different whitespace is a different message", async () => {
    const real = JSON.stringify(event("b-2"));
    const reformatted = JSON.stringify(event("b-2"), null, 2);
    expect(JSON.parse(reformatted)).toEqual(JSON.parse(real));
    await sendSigned(app, credA, reformatted, { signBody: real }).expect(401);
    await sendSigned(app, credA, reformatted).expect(202); // signed as sent, it is fine
  });

  it("a real signature reused on a different message is refused", async () => {
    const real = JSON.stringify(event("b-3"));
    await sendSigned(app, credA, JSON.stringify(event("b-3", "Nothing to see here")), { signBody: real }).expect(401);
  });
});

// --- 4. replay ---------------------------------------------------------------

describe("replay", () => {
  it("an identical request, resent, is refused — even before the alert dedupe could absorb it", async () => {
    const opts = { timestamp: nowSeconds(), nonce: freshNonce() };
    await sendSigned(app, credA, event("r-1"), opts).expect(202);
    const replay = await sendSigned(app, credA, event("r-1"), opts).expect(401);
    expect(replay.body.detail).toMatch(/already received/i);
    expect(await alertCount(tenantA)).toBe(1);
  });

  it("a nonce cannot be reused for a different, correctly signed message", async () => {
    const nonce = freshNonce();
    await sendSigned(app, credA, event("r-2"), { nonce }).expect(202);
    await sendSigned(app, credA, event("r-3"), { nonce }).expect(401);
    expect(await alertCount(tenantA)).toBe(1);
  });

  it("holds when the same request arrives many times at once: exactly one is accepted", async () => {
    const opts = { timestamp: nowSeconds(), nonce: freshNonce() };
    const results = await Promise.all(Array.from({ length: 10 }, () => sendSigned(app, credA, event("r-4"), opts)));
    expect(results.filter((r) => r.status === 202)).toHaveLength(1);
    expect(results.filter((r) => r.status === 401)).toHaveLength(9);
    expect(await alertCount(tenantA)).toBe(1);
  });

  it("a nonce is remembered until its timestamp can no longer pass the freshness check", async () => {
    const ts = nowSeconds() - 200;
    await sendSigned(app, credA, event("r-5"), { timestamp: ts }).expect(202);
    const [row] = (await query("SELECT extract(epoch FROM expires_at) AS e FROM webhook_nonces")).rows;
    expect(Number(row.e)).toBeGreaterThanOrEqual(ts + config.webhookMaxSkewSeconds); // outlives the window
    // Housekeeping removes only what has expired.
    await query("UPDATE webhook_nonces SET expires_at = now() - interval '1 second'");
    await sendSigned(app, credA, event("r-6")).expect(202);
    expect(await creds.pruneExpiredNonces()).toBe(1);
    expect(await nonceCount()).toBe(1);
  });

  it("only requests that passed authentication are remembered, so junk cannot fill the table", async () => {
    for (let i = 0; i < 5; i++) {
      await sendSigned(app, credA, event(`junk-${i}`), { signWithSecret: "whs_" + "B".repeat(43) }).expect(401);
      await sendSigned(app, credA, event(`junk-${i}`), { keyId: "whk_" + "C".repeat(22) }).expect(401);
    }
    expect(await nonceCount()).toBe(0);
  });
});

// --- 5. expired timestamp ----------------------------------------------------

describe("the time window", () => {
  it("refuses old and future timestamps", async () => {
    await sendSigned(app, credA, event("t-1"), { timestamp: nowSeconds() - 301 }).expect(401);
    await sendSigned(app, credA, event("t-2"), { timestamp: nowSeconds() + 301 }).expect(401);
    await sendSigned(app, credA, event("t-3"), { timestamp: 1 }).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
    expect(await nonceCount()).toBe(0);
  });

  it("says why, so an operator can fix the clock", async () => {
    const res = await sendSigned(app, credA, event("t-4"), { timestamp: nowSeconds() - 3600 }).expect(401);
    expect(res.body.detail).toMatch(/too far from this server's clock/);
  });

  it("is configurable, and clamped to a sane range", async () => {
    config.webhookMaxSkewSeconds = 60;
    await sendSigned(app, credA, event("t-5"), { timestamp: nowSeconds() - 90 }).expect(401);
    await sendSigned(app, credA, event("t-6"), { timestamp: nowSeconds() - 45 }).expect(202);
    config.webhookMaxSkewSeconds = 900;
    await sendSigned(app, credA, event("t-7"), { timestamp: nowSeconds() - 600 }).expect(202);
    const reload = async (v: string) => { vi.resetModules(); process.env.WEBHOOK_MAX_SKEW_SECONDS = v; return (await import("../src/config.js")).config.webhookMaxSkewSeconds; };
    try {
      expect(await reload("5")).toBe(30);
      expect(await reload("99999")).toBe(900);
      expect(await reload("garbage")).toBe(300);
    } finally { delete process.env.WEBHOOK_MAX_SKEW_SECONDS; vi.resetModules(); }
  });
});

// --- 6. wrong tenant ---------------------------------------------------------

describe("the tenant comes from the credential, never from a header", () => {
  it("B's credential claiming to be A is refused, and nothing lands in either tenant", async () => {
    await sendSigned(app, credB, event("w-1"), { tenantHeader: tenantA }).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
    expect(await alertCount(tenantB)).toBe(0);
  });

  it("B's credential with no claim writes to B — A cannot be reached by any header", async () => {
    await sendSigned(app, credB, event("w-2")).expect(202);
    expect(await alertCount(tenantB)).toBe(1);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("naming a tenant without a credential achieves nothing", async () => {
    await request(app).post("/security-events/webhook").set("x-tenant-id", tenantA).send(event("w-3")).expect(401);
    await request(app).post("/security-events/webhook").set("x-tenant-id", randomUUID()).send(event("w-4")).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("a key id that does not exist is refused exactly like a wrong signature", async () => {
    const unknown = await sendSigned(app, credA, event("w-5"), { keyId: "whk_" + "Z".repeat(22) }).expect(401);
    const wrong = await sendSigned(app, credA, event("w-6"), { signWithSecret: "whs_" + "Z".repeat(43) }).expect(401);
    expect(unknown.body).toEqual(wrong.body); // nothing to enumerate
  });

  it("each request's tenant is the one its own credential names, under concurrency", async () => {
    await Promise.all(Array.from({ length: 6 }, (_, i) => sendSigned(app, i % 2 ? credA : credB, event(`cc-${i}`)).expect(202)));
    expect(await alertCount(tenantA)).toBe(3);
    expect(await alertCount(tenantB)).toBe(3);
  });
});

// --- 7. revocation -----------------------------------------------------------

describe("revocation", () => {
  it("takes effect at once: the very next request is refused", async () => {
    await sendSigned(app, credA, event("v-1")).expect(202);
    await request(app).delete(`/security-events/credentials/${credA.keyId}`).set("Authorization", bearer(adminA)).expect(200);
    const res = await sendSigned(app, credA, event("v-2")).expect(401);
    expect(res.body.detail).toBe("Invalid webhook credentials"); // no hint that it once worked
    expect(await alertCount(tenantA)).toBe(1);
  });

  it("only ends that credential; a second one keeps working", async () => {
    const other = await issueCredential(tenantA, "second sensor");
    await creds.revokeCredential(tenantA, credA.keyId);
    await sendSigned(app, credA, event("v-3")).expect(401);
    await sendSigned(app, other, event("v-4")).expect(202);
  });

  it("revoke-all ends every credential of the organisation and no one else's", async () => {
    await issueCredential(tenantA);
    expect(await creds.revokeAllCredentials(tenantA)).toBe(2);
    await sendSigned(app, credA, event("v-5")).expect(401);
    await sendSigned(app, credB, event("v-6")).expect(202);
  });

  it("an administrator cannot revoke another organisation's credential", async () => {
    await request(app).delete(`/security-events/credentials/${credA.keyId}`).set("Authorization", bearer(adminB)).expect(404);
    await sendSigned(app, credA, event("v-7")).expect(202);
  });

  it("is idempotent, and a malformed id is a 404 rather than a query", async () => {
    await creds.revokeCredential(tenantA, credA.keyId);
    await creds.revokeCredential(tenantA, credA.keyId);
    await request(app).delete("/security-events/credentials/not-a-key").set("Authorization", bearer(adminA)).expect(404);
    await request(app).delete(`/security-events/credentials/whk_${"Q".repeat(22)}`).set("Authorization", bearer(adminA)).expect(404);
  });

  it("a revoked credential's valid signature is not remembered as a nonce", async () => {
    await creds.revokeCredential(tenantA, credA.keyId);
    await sendSigned(app, credA, event("v-8")).expect(401);
    expect(await nonceCount()).toBe(0);
  });
});

// --- 8. rotation -------------------------------------------------------------

describe("rotation", () => {
  const rotate = (admin: User, keyId: string, body: object = {}) =>
    request(app).post(`/security-events/credentials/${keyId}/rotate`).set("Authorization", bearer(admin)).send(body);

  it("issues a new secret; old and new both work during the overlap", async () => {
    const res = await rotate(adminA, credA.keyId).expect(201);
    expect(res.headers["cache-control"]).toBe("no-store");
    const fresh: TestCredential = { keyId: res.body.id, secret: res.body.secret, apiKey: res.body.api_key };
    expect(fresh.keyId).not.toEqual(credA.keyId);
    expect(fresh.secret).not.toEqual(credA.secret);
    expect(res.body.api_key).toBe(`${fresh.keyId}:${fresh.secret}`);
    expect(res.body.previous.id).toBe(credA.keyId);

    await sendSigned(app, credA, event("x-old")).expect(202); // the sensor not yet reconfigured
    await sendSigned(app, fresh, event("x-new")).expect(202); // the sensor after it is
    expect(await alertCount(tenantA)).toBe(2);
    const [old] = (await creds.listCredentials(tenantA)).filter((c) => c.id === credA.keyId);
    expect(old).toMatchObject({ status: "rotating" });
    expect(new Date(old!.expires_at!).getTime()).toBeGreaterThan(Date.now() + 23 * 3_600_000); // the default 24 h
  });

  it("after the overlap only the new credential works", async () => {
    const res = await rotate(adminA, credA.keyId, { overlap_hours: 1 }).expect(201);
    const fresh = { keyId: res.body.id, secret: res.body.secret, apiKey: "" };
    await query("UPDATE webhook_credentials SET expires_at = now() - interval '1 second' WHERE key_id = $1", [credA.keyId]);
    await sendSigned(app, credA, event("x-late")).expect(401);
    await sendSigned(app, fresh, event("x-fresh")).expect(202);
    expect((await creds.listCredentials(tenantA)).find((c) => c.id === credA.keyId)!.status).toBe("expired");
  });

  it("an overlap of 0 ends the old credential immediately", async () => {
    await rotate(adminA, credA.keyId, { overlap_hours: 0 }).expect(201);
    await sendSigned(app, credA, event("x-zero")).expect(401);
  });

  it("the old credential can still be cut short during the overlap", async () => {
    await rotate(adminA, credA.keyId).expect(201);
    await creds.revokeCredential(tenantA, credA.keyId);
    await sendSigned(app, credA, event("x-cut")).expect(401);
  });

  it("refuses to rotate what is already rotating, revoked, unknown, or someone else's", async () => {
    await rotate(adminA, credA.keyId).expect(201);
    await rotate(adminA, credA.keyId).expect(409); // already rotating
    const spare = await issueCredential(tenantA);
    await creds.revokeCredential(tenantA, spare.keyId);
    await rotate(adminA, spare.keyId).expect(409); // revoked
    await rotate(adminA, `whk_${"Q".repeat(22)}`).expect(404);
    await rotate(adminB, credA.keyId).expect(404);
  });

  it("validates the overlap and needs an administrator", async () => {
    await rotate(adminA, credA.keyId, { overlap_hours: -1 }).expect(422);
    await rotate(adminA, credA.keyId, { overlap_hours: 1000 }).expect(422);
    await rotate(analystA, credA.keyId).expect(403);
  });

  it("rotating leaves the credential it replaced traceable", async () => {
    const res = await rotate(adminA, credA.keyId).expect(201);
    const list = await creds.listCredentials(tenantA);
    expect(list.find((c) => c.id === res.body.id)!.rotated_from).toBe(credA.keyId);
  });
});

// --- 9. malformed requests ---------------------------------------------------

describe("malformed requests", () => {
  const base = () => {
    const raw = JSON.stringify(event("m-1")), ts = String(nowSeconds()), nonce = freshNonce();
    return { raw, headers: {
      "x-legion-key-id": credA.keyId, "x-legion-timestamp": ts, "x-legion-nonce": nonce,
      "x-legion-signature": signWebhook(credA.secret, ts, nonce, raw),
    } as Record<string, string> };
  };
  const post = (headers: Record<string, string>, raw: string, type = "application/json") => {
    const r = request(app).post("/security-events/webhook").set("content-type", type);
    for (const [k, v] of Object.entries(headers)) r.set(k, v);
    return r.send(raw);
  };

  it.each([
    ["key id: wrong prefix", { "x-legion-key-id": "abc_" + "A".repeat(22) }],
    ["key id: too short", { "x-legion-key-id": "whk_short" }],
    ["key id: illegal characters", { "x-legion-key-id": "whk_" + "!".repeat(22) }],
    ["timestamp: not a number", { "x-legion-timestamp": "yesterday" }],
    ["timestamp: negative", { "x-legion-timestamp": "-100" }],
    ["timestamp: a decimal", { "x-legion-timestamp": "1700000000.5" }],
    ["timestamp: enormous", { "x-legion-timestamp": "9".repeat(40) }],
    ["nonce: too short", { "x-legion-nonce": "abc" }],
    ["nonce: illegal characters", { "x-legion-nonce": "a b c d e f g h i j k l" }],
    ["nonce: too long", { "x-legion-nonce": "a".repeat(200) }],
    ["signature: no version", { "x-legion-signature": "0".repeat(64) }],
    ["signature: not hex", { "x-legion-signature": "v2=" + "z".repeat(64) }],
    ["signature: too short", { "x-legion-signature": "v2=abcd" }],
    ["signature: upper-case hex", { "x-legion-signature": "v2=" + "A".repeat(64) }],
  ] as const)("%s → 401, nothing stored", async (_name, override) => {
    const { raw, headers } = base();
    const res = await post({ ...headers, ...override }, raw).expect(401);
    expect(res.body.detail).toMatch(/Malformed|clock/);
    expect(await alertCount(tenantA)).toBe(0);
    expect(await nonceCount()).toBe(0);
  });

  it("a body that is not JSON cannot be verified byte-for-byte and is refused", async () => {
    const { headers } = base();
    const res = await post(headers, "provider=wazuh", "application/x-www-form-urlencoded").expect(401);
    expect(res.body.detail).toMatch(/must be JSON/);
    await post(headers, "plain text", "text/plain").expect(401);
  });

  it("an UNSIGNED body is never parsed: broken JSON without a valid signature is a 401, not a 400", async () => {
    // Verification runs over the raw bytes before JSON.parse, so a parse error
    // can only ever be reached by the holder of the secret.
    const { headers } = base();
    const res = await post(headers, '{"provider":"wazuh","event":{').expect(401);
    expect(res.body.detail).toMatch(/Invalid webhook credentials/);
    expect(await nonceCount()).toBe(0);
  });

  it("broken JSON that IS correctly signed is a 400, not a server error and not a stack trace", async () => {
    const res = await sendSigned(app, credA, '{"provider":"wazuh","event":{').expect(400);
    expect(JSON.stringify(res.body)).not.toMatch(/at |\.ts|SyntaxError|node_modules/);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("an oversized body (over WEBHOOK_MAX_BODY_BYTES) is refused before anything is verified", async () => {
    const { headers } = base();
    await post(headers, JSON.stringify({ pad: "x".repeat(config.webhookMaxBodyBytes + 1) })).expect(413);
    expect(await nonceCount()).toBe(0);
  });

  it("a large, correctly signed Wazuh event (300 KB full_log) is accepted, not dropped", async () => {
    const big = event("big-1");
    big.event.full_log = "L".repeat(300_000);
    await sendSigned(app, credA, big).expect(202);
    expect(await alertCount(tenantA)).toBe(1);
  });

  it("a signed but empty or odd JSON document is harmless", async () => {
    await sendSigned(app, credA, {}).expect(202);
    await sendSigned(app, credA, []).expect(202);
    await sendSigned(app, credA, { event: "a string" }).expect(202);
    await sendSigned(app, credA, { event: { rule: null } }).expect(202);
    expect(await alertCount(tenantA)).toBe(0); // skipped: no rule description
  });

  it("repeating a header does not let one request carry two identities", async () => {
    const { raw, headers } = base();
    await post({ ...headers, "x-legion-key-id": `${credA.keyId}, ${credB.keyId}` }, raw).expect(401);
  });
});

// --- 9b. unauthenticated flood (audit P1-3) ---------------------------------

describe("unauthenticated traffic is throttled; signed traffic never is", () => {
  beforeEach(() => { process.env.LEGION_ENFORCE_RATE_LIMITS = "1"; resetWebhookFailures(); });
  afterEach(() => { delete process.env.LEGION_ENFORCE_RATE_LIMITS; resetWebhookFailures(); });
  const forged = (xff: string) =>
    sendSigned(app, credA, event(`f-${randomUUID()}`), { signWithSecret: "whs_" + "x".repeat(43) }).set("X-Forwarded-For", xff);

  it("after WEBHOOK_FAILED_AUTH_PER_MINUTE failures an address is refused with 429, before authentication", async () => {
    const limit = config.webhookFailedAuthPerMinute;
    for (let i = 0; i < limit; i++) await forged("203.0.113.7").expect(401);
    await forged("203.0.113.7").expect(429);
    // Refused before the credential is even looked at: a CORRECTLY signed
    // request from the same address is refused too, and leaves no nonce.
    const nonces = await nonceCount();
    const res = await sendSigned(app, credA, event("ok-1")).set("X-Forwarded-For", "203.0.113.7").expect(429);
    expect(res.headers["retry-after"]).toBe("60");
    expect(await nonceCount()).toBe(nonces);
    expect(await alertCount(tenantA)).toBe(0);
    // Other addresses are unaffected.
    await sendSigned(app, credA, event("ok-2")).set("X-Forwarded-For", "198.51.100.9").expect(202);
  });

  it("a sensor sending far more signed events than the failure limit is never throttled", async () => {
    const n = config.webhookFailedAuthPerMinute * 2;
    for (let i = 0; i < n; i++) {
      await sendSigned(app, credA, event(`bulk-${i}`)).set("X-Forwarded-For", "192.0.2.50").expect(202);
    }
    expect(await alertCount(tenantA)).toBe(n);
  });

  it("oversized and unparseable unauthenticated bodies count as failures too", async () => {
    const limit = config.webhookFailedAuthPerMinute;
    for (let i = 0; i < limit; i++) {
      await request(app).post("/security-events/webhook").set("X-Forwarded-For", "203.0.113.99")
        .set("content-type", "application/json").send("x".repeat(config.webhookMaxBodyBytes + 10)).expect(413);
    }
    await request(app).post("/security-events/webhook").set("X-Forwarded-For", "203.0.113.99")
      .set("content-type", "application/json").send("{}").expect(429);
  });
});

// --- 10. missing authentication ----------------------------------------------

describe("missing authentication", () => {
  it("no headers at all", async () => {
    const res = await request(app).post("/security-events/webhook").send(event("a-1")).expect(401);
    expect(res.body.detail).toMatch(/Missing x-legion-key-id/);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it.each(["x-legion-key-id", "x-legion-timestamp", "x-legion-nonce", "x-legion-signature"])("without %s", async (omit) => {
    const raw = JSON.stringify(event("a-2")), ts = String(nowSeconds()), nonce = freshNonce();
    const headers: Record<string, string> = {
      "x-legion-key-id": credA.keyId, "x-legion-timestamp": ts, "x-legion-nonce": nonce,
      "x-legion-signature": signWebhook(credA.secret, ts, nonce, raw),
    };
    delete headers[omit];
    const r = request(app).post("/security-events/webhook").set("content-type", "application/json");
    for (const [k, v] of Object.entries(headers)) r.set(k, v);
    await r.send(raw).expect(401);
    expect(await alertCount(tenantA)).toBe(0);
  });

  it("the previous integration script gets a clear message, never access", async () => {
    const res = await request(app).post("/security-events/webhook").set("x-tenant-id", tenantA).send(event("a-3")).expect(401);
    expect(res.body.detail).toMatch(/out of date/i);
  });

  it("there is no global switch that turns authentication off", async () => {
    const saved_ = config.webhookSecret;
    config.webhookSecret = "";
    try { await request(app).post("/security-events/webhook").send(event("a-4")).expect(401); }
    finally { config.webhookSecret = saved_; }
  });
});

// --- nothing secret leaks ----------------------------------------------------

describe("secrets stay secret", () => {
  it("never reach a log, whatever the request looks like", async () => {
    const raw = JSON.stringify(event("l-1")), ts = String(nowSeconds()), nonce = freshNonce();
    const sig = signWebhook(credA.secret, ts, nonce, raw);
    const attack = 'whk_\nlegion: ADMIN LOGGED IN\u0000';
    await sendSigned(app, credA, event("l-2"), { signWithSecret: credB.secret }).expect(401);
    await sendSigned(app, credA, event("l-3"), { timestamp: nowSeconds() - 9999 }).expect(401);
    await sendSigned(app, credB, event("l-4"), { tenantHeader: tenantA }).expect(401);
    await request(app).post("/security-events/webhook").set("content-type", "application/json")
      .set("x-legion-key-id", credA.keyId).set("x-legion-timestamp", ts).set("x-legion-nonce", nonce)
      .set("x-legion-signature", "v2=" + "1".repeat(64) + "extra").send(raw).expect(401);
    await request(app).post("/security-events/webhook").set("x-legion-key-id", encodeURIComponent(attack)).send(raw).expect(401);
    await sendSigned(app, credA, event("l-5"), { nonce }).expect(202);
    await sendSigned(app, credA, event("l-5"), { nonce }).expect(401); // replay
    await sendSigned(app, credA, '{"broken":', {}).expect(400);
    await request(app).get("/security-events/credentials").set("Authorization", bearer(adminA)).expect(200);
    await creds.revokeCredential(tenantA, credA.keyId);
    await sendSigned(app, credA, event("l-6")).expect(401);

    const all = logged.join("\n");
    expect(all).toContain("rejected webhook"); // it does log — just not secrets
    for (const secret of [credA.secret, credB.secret, credA.apiKey, credB.apiKey, config.webhookSecret, config.jwtSecret, sig, nonce, credA.keyId, credB.keyId, "ADMIN LOGGED IN", ts + "." + nonce]) {
      expect(all, `log leaked ${secret.slice(0, 12)}…`).not.toContain(secret);
    }
    expect(all).not.toMatch(/x-legion-signature|x-legion-nonce/i);
    expect(all).not.toMatch(/whs_/);
    // What is logged of a key id is a short prefix, only for well-formed ids.
    for (const line of logged.filter((l) => l.includes("rejected webhook"))) {
      expect(line).toMatch(/^Legion: rejected webhook \([a-z0-9() =\/_-]+\) key=(-|whk_\w{4}) ip=\S+$/);
    }
  });

  it("are shown once, when issued, and not by the list or the audit trail", async () => {
    const created = await request(app).post("/security-events/credentials").set("Authorization", bearer(adminA)).send({ label: "wazuh-1" }).expect(201);
    expect(created.headers["cache-control"]).toBe("no-store");
    expect(created.body.secret).toMatch(/^whs_/);
    expect(created.body.api_key).toBe(`${created.body.id}:${created.body.secret}`);

    const list = await request(app).get("/security-events/credentials").set("Authorization", bearer(adminA)).expect(200);
    expect(JSON.stringify(list.body)).not.toContain(created.body.secret);
    expect(JSON.stringify(list.body)).not.toContain("secret_enc");
    expect(list.body.credentials.map((c: { label: string }) => c.label)).toContain("wazuh-1");

    await request(app).post(`/security-events/credentials/${created.body.id}/rotate`).set("Authorization", bearer(adminA)).send({}).expect(201);
    const audit = JSON.stringify((await query("SELECT * FROM audit_log")).rows);
    for (const c of [created.body.secret, credA.secret, credB.secret]) expect(audit).not.toContain(c);
    expect(audit).toContain("webhook.credential_created");
    expect(audit).toContain("webhook.credential_rotated");
  });

  it("management is for administrators of the organisation, and is bounded", async () => {
    await request(app).get("/security-events/credentials").set("Authorization", bearer(analystA)).expect(403);
    await request(app).post("/security-events/credentials").set("Authorization", bearer(analystA)).send({}).expect(403);
    await request(app).get("/security-events/credentials").expect(401);
    const b = await request(app).get("/security-events/credentials").set("Authorization", bearer(adminB)).expect(200);
    expect(JSON.stringify(b.body)).not.toContain(credA.keyId);

    await request(app).post("/security-events/credentials").set("Authorization", bearer(adminA)).send({ label: "x".repeat(101) }).expect(422);
    for (let i = 0; i < creds.MAX_ACTIVE_CREDENTIALS - 1; i++) await creds.createCredential(tenantA);
    const over = await request(app).post("/security-events/credentials").set("Authorization", bearer(adminA)).send({}).expect(409);
    expect(over.body.detail).toMatch(/Too many active webhook credentials/);
  });

  it("the limit holds when several are created at once", async () => {
    const results = await Promise.allSettled(Array.from({ length: 8 }, () => creds.createCredential(tenantA)));
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(creds.MAX_ACTIVE_CREDENTIALS - 1); // one already exists
    expect((await creds.listCredentials(tenantA)).length).toBe(creds.MAX_ACTIVE_CREDENTIALS);
  });

  it("the providers view reflects whether this organisation has a working credential", async () => {
    const yes = await request(app).get("/security-events/providers").set("Authorization", bearer(adminA)).expect(200);
    expect(yes.body).toMatchObject({ webhook_configured: true, active: "webhook" });
    await creds.revokeAllCredentials(tenantA);
    const no = await request(app).get("/security-events/providers").set("Authorization", bearer(adminA)).expect(200);
    expect(no.body).toMatchObject({ webhook_configured: false, active: "mock" });
  });
});

// --- the real integration script ---------------------------------------------

describe("the real Wazuh integration script", () => {
  // Proves the Python the customer installs on the Wazuh manager and the
  // server agree on the signature byte-for-byte, not just two copies of the
  // same TypeScript.
  const python = ["python3", "python"].find((bin) => spawnSync(bin, ["--version"]).status === 0);
  const script = fileURLToPath(new URL("../../integrations/custom-legion.py", import.meta.url));

  async function runScript(apiKey: string, alertId: string) {
    const server = app.listen(0);
    try {
      const port = (server.address() as AddressInfo).port;
      const dir = mkdtempSync(join(tmpdir(), "legion-wazuh-"));
      const alertFile = join(dir, "alert.json");
      const logFile = join(dir, "integrations.log");
      writeFileSync(alertFile, JSON.stringify(event(alertId).event));
      const status = await new Promise<number | null>((resolve) => {
        const child = spawn(python!, [script, alertFile, apiKey, `http://127.0.0.1:${port}/security-events/webhook`], {
          env: { ...process.env, LEGION_INTEGRATION_LOG: logFile, LEGION_MAX_ATTEMPTS: "1" },
        });
        child.on("close", resolve);
      });
      return { status, log: existsSync(logFile) ? readFileSync(logFile, "utf8") : "" };
    } finally { server.close(); }
  }

  it.skipIf(!python || !existsSync(script))("delivers a signed alert the server accepts", async () => {
    const run = await runScript(credA.apiKey, "from-python");
    expect(run.log).toMatch(/OK .*status=202/);
    expect(run.status).toBe(0);
    expect((await store.listAlerts(tenantA, {})).map((a) => a.title)).toContain("Multiple authentication failures");
  });

  it.skipIf(!python || !existsSync(script))("survives a rotation: the old key still works in the overlap, the new one after", async () => {
    const { issued } = await creds.rotateCredential(tenantA, credA.keyId);
    expect((await runScript(credA.apiKey, "py-old")).status).toBe(0);
    expect((await runScript(issued.api_key, "py-new")).status).toBe(0);
    await creds.revokeCredential(tenantA, credA.keyId);
    const refused = await runScript(credA.apiKey, "py-revoked");
    expect(refused.status).toBe(1);
    expect(refused.log).toMatch(/status=401/);
    expect(refused.log).not.toContain(credA.secret);
  });

  it.skipIf(!python || !existsSync(script))("the old TENANT_ID:SECRET api_key is refused locally, with advice and without echoing the secret", async () => {
    const run = await runScript(`${tenantA}:${config.webhookSecret}`, "py-legacy");
    expect(run.status).toBe(1);
    expect(run.log).toMatch(/KEY_ID:SECRET/);
    expect(run.log).not.toContain(config.webhookSecret);
    expect(await alertCount(tenantA)).toBe(0);
  });
});
