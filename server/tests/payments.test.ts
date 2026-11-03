/**
 * Payment check: the payment software asks Legion before paying, and a
 * payment that looks like fraud is HELD until a person confirms it by phone.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { accountHint, ALERTS_PER_HOUR, beneficiaryHash, CHECKS_PER_MINUTE, HOLD_REASONS } from "../src/payments.js";
import { readFileSync } from "node:fs";
import type { User } from "../src/types.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

const savedMode = config.deploymentMode;
let tenantA: string, tenantB: string;
let adminA: User, analystA: User, adminB: User;
let credA: TestCredential, credB: TestCredential;

const IBAN = "DE89 3704 0044 0532 0130 00";
const bearer = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;
const pay = (o: Partial<{ account: string; amount: number; currency: string; requestedBy: string; name: string }> = {}) => ({
  action: "payment-check",
  beneficiary: { account: o.account ?? IBAN, name: o.name ?? "Acme Supplies Ltd" },
  amount: o.amount ?? 12500, currency: o.currency ?? "EUR",
  ...(o.requestedBy ? { requestedBy: o.requestedBy } : {}),
});
const check = (cred: TestCredential, body: unknown) => sendSigned(app, cred, body, { path: "/security-events/payment-check" });
const release = (u: User, id: string) => request(app).post(`/security/payments/${id}/release`).set("Authorization", bearer(u));
const reject = (u: User, id: string) => request(app).post(`/security/payments/${id}/reject`).set("Authorization", bearer(u));
const campaign = (tenant: string, rule: string, subject: string) =>
  query("INSERT INTO attack_campaigns (tenant_id, id, rule, subject) VALUES ($1, $2, $3, $4)", [tenant, `CMP-${randomUUID().slice(0, 8)}`, rule, subject]);

beforeAll(async () => { await migrate(); config.deploymentMode = "self-hosted"; });
afterAll(async () => { config.deploymentMode = savedMode; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenantA, tenantB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@a.io", password_hash: hash, tenant_id: tenantA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@a.io", password_hash: hash, tenant_id: tenantA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "admin@b.io", password_hash: hash, tenant_id: tenantB, role: "admin", status: "active" });
  credA = await issueCredential(tenantA);
  credB = await issueCredential(tenantB);
});

describe("a payment to an account never confirmed is held, then allowed once a person confirms it", () => {
  it("first payment: held, with the reason and how to verify; an alert is raised once", async () => {
    const r = await check(credA, pay()).expect(200);
    expect(r.body).toMatchObject({ decision: "hold", reasons: [{ code: "new_beneficiary" }] });
    expect(r.body.verify).toMatch(/number you already had/);
    expect(r.headers["cache-control"]).toBe("no-store");
    // The payment software retries: still held, still ONE alert.
    await check(credA, pay()).expect(200);
    const alerts = (await query("SELECT * FROM alerts WHERE tenant_id = $1 AND source = 'legion-payments'", [tenantA])).rows;
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ agent: "Executor", severity: "high", mitre_technique: "T1657" });
    expect(alerts[0].title).toBe("Payment held: 12,500.00 EUR to …3000 (Acme Supplies Ltd)");
  });

  it("an administrator releases it after calling; the same payment, and later ones to that account, are allowed", async () => {
    const held = (await check(credA, pay()).expect(200)).body;
    const r = await release(adminA, held.id).expect(200);
    expect(r.body.payment).toMatchObject({ resolution: "released", beneficiary_hint: "…3000" });
    expect((await check(credA, pay()).expect(200)).body).toMatchObject({ decision: "allow", reasons: [], verify: null });
    expect((await check(credA, pay({ amount: 900 })).expect(200)).body.decision).toBe("allow");
    // Spaces and dashes do not make it a different account.
    expect((await check(credA, pay({ account: "de89-3704-0044-0532-0130-00", amount: 50 })).expect(200)).body.decision).toBe("allow");
    const audit = (await query("SELECT action FROM audit_log WHERE tenant_id = $1 AND action LIKE 'security.payment_%' ORDER BY created_at", [tenantA])).rows.map((x) => x.action);
    expect(audit).toEqual(["security.payment_held", "security.payment_released", "security.payment_allowed", "security.payment_allowed", "security.payment_allowed"]);
  });

  it("a rejected payment stays held, and its alert is critical the next time", async () => {
    const held = (await check(credA, pay()).expect(200)).body;
    await reject(adminA, held.id).expect(200);
    const again = (await check(credA, pay()).expect(200)).body;
    expect(again.decision).toBe("hold");
    expect(again.reasons.map((x: { code: string }) => x.code)).toContain("rejected_before");
  });
});

describe("a payment requested during an attack is held even to a known account", () => {
  async function knownAccount() {
    const held = (await check(credA, pay()).expect(200)).body;
    await release(adminA, held.id).expect(200);
  }

  it("the person asking is the subject of an account takeover: held, critical", async () => {
    await knownAccount();
    await campaign(tenantA, "account_compromise", "dana");
    const r = (await check(credA, pay({ requestedBy: "dana@acme.example", amount: 7000 })).expect(200)).body;
    expect(r.decision).toBe("hold");
    expect(r.reasons.map((x: { code: string }) => x.code)).toEqual(["account_under_attack"]);
    const alert = (await query("SELECT severity FROM alerts WHERE tenant_id = $1 AND source = 'legion-payments' ORDER BY created_at DESC LIMIT 1", [tenantA])).rows[0];
    expect(alert.severity).toBe("critical");
  });

  it("any mailbox in the organisation is being taken over: held", async () => {
    await knownAccount();
    await campaign(tenantA, "mailbox_takeover", "erin@acme.example");
    const r = (await check(credA, pay({ amount: 300 })).expect(200)).body;
    expect(r.reasons.map((x: { code: string }) => x.code)).toEqual(["mailbox_takeover_active"]);
  });

  it("another organisation's attack does not hold this one's payments", async () => {
    await knownAccount();
    await campaign(tenantB, "mailbox_takeover", "x@b.example");
    await campaign(tenantB, "account_compromise", "dana");
    expect((await check(credA, pay({ requestedBy: "dana", amount: 1 })).expect(200)).body.decision).toBe("allow");
  });
});

describe("controls", () => {
  it("the account number is never stored, only a keyed hash and the last four characters", async () => {
    await check(credA, pay()).expect(200);
    const dump = JSON.stringify((await query("SELECT * FROM payment_checks")).rows) + JSON.stringify((await query("SELECT * FROM payment_beneficiaries")).rows)
      + JSON.stringify((await query("SELECT * FROM alerts")).rows) + JSON.stringify((await query("SELECT * FROM audit_log")).rows);
    expect(dump).not.toContain("370400440532");
    expect(dump).not.toContain("DE89370400440532013000");
    expect(dump).toContain(beneficiaryHash(tenantA, IBAN));
    expect(accountHint(IBAN)).toBe("…3000");
    // The same account in another organisation has a different hash.
    expect(beneficiaryHash(tenantB, IBAN)).not.toBe(beneficiaryHash(tenantA, IBAN));
  });

  it("must be signed, and must say what it is for", async () => {
    await request(app).post("/security-events/payment-check").set("content-type", "application/json").send(pay()).expect(401);
    await check(credA, { ...pay(), action: "sync-blocklist" }).expect(400);
    await check(credA, { ...pay(), execute: true }).expect(400);
    await check(credA, { ...pay(), amount: -5 }).expect(400);
    await check(credA, { ...pay(), currency: "E U R" }).expect(400);
    // A blocklist request body is not accepted as a payment check, and vice versa.
    await sendSigned(app, credA, pay(), { path: "/security-events/blocklist" }).expect(400);
  });

  it("only administrators release or reject; another organisation cannot touch this one's holds", async () => {
    const held = (await check(credA, pay()).expect(200)).body;
    await release(analystA, held.id).expect(403);
    await release(adminB, held.id).expect(404);
    await reject(adminB, held.id).expect(404);
    expect((await request(app).get("/security/payments?held=true").set("Authorization", bearer(adminB)).expect(200)).body.payments).toEqual([]);
    const mine = (await request(app).get("/security/payments?held=true").set("Authorization", bearer(analystA)).expect(200)).body.payments;
    expect(mine.map((p: { id: string }) => p.id)).toEqual([held.id]);
    // Still held for A.
    expect((await check(credA, pay()).expect(200)).body.decision).toBe("hold");
  });

  it("a hold is resolved once; unknown or malformed ids are 404", async () => {
    const held = (await check(credA, pay()).expect(200)).body;
    await release(adminA, held.id).expect(200);
    await release(adminA, held.id).expect(404);
    await reject(adminA, held.id).expect(404);
    await release(adminA, "PAY-0000000000000000").expect(404);
    await release(adminA, "../../etc").expect(404);
  });

  it("answers in English whatever Accept-Language says", async () => {
    const r = await request(app).post("/security/payments/PAY-0000000000000000/release").set("Authorization", bearer(adminA)).set("Accept-Language", "uz").expect(404);
    expect(r.body.detail).toBe("No such payment on hold");
  });
});

describe("one organisation cannot flood the payment check", () => {
  it("over the per-minute cap the answer is 429 (fail closed), and other organisations are unaffected", async () => {
    await query(
      `INSERT INTO payment_checks (tenant_id, id, beneficiary_hash, beneficiary_hint, amount, currency, decision, reasons)
       SELECT $1, 'PAY-' || lpad(g::text, 16, '0'), repeat('a', 64), '0000', 1, 'EUR', 'allow', '{}' FROM generate_series(1, $2) g`,
      [tenantA, CHECKS_PER_MINUTE],
    );
    const r = await check(credA, pay());
    expect(r.status).toBe(429);
    expect(r.headers["retry-after"]).toBe("60");
    expect((await check(credB, pay())).status).toBe(200);
  });
  it("past the hourly alert cap a payment is still held, but no new alert is raised", async () => {
    await query(
      `INSERT INTO payment_checks (tenant_id, id, beneficiary_hash, beneficiary_hint, amount, currency, decision, reasons, created_at)
       SELECT $1, 'PAY-' || lpad(g::text, 16, '0'), repeat('a', 64), '0000', 1, 'EUR', 'hold', '{new_beneficiary}', now() - interval '10 minutes' FROM generate_series(1, $2) g`,
      [tenantA, ALERTS_PER_HOUR],
    );
    const before = Number((await query("SELECT count(*) FROM alerts WHERE tenant_id = $1 AND source = 'legion-payments'", [tenantA])).rows[0].count);
    const r = await check(credA, pay({ account: "GB82 WEST 1234 5698 7654 32" }));
    expect(r.status).toBe(200);
    expect(r.body.decision).toBe("hold");
    const after = Number((await query("SELECT count(*) FROM alerts WHERE tenant_id = $1 AND source = 'legion-payments'", [tenantA])).rows[0].count);
    expect(after).toBe(before);
  });
});

describe("the dashboard explains every reason", () => {
  it("each hold reason has words on the Defense page, in English", () => {
    const text = readFileSync(new URL("../../frontend/lib/i18n/ns/defense.ts", import.meta.url), "utf8");
    for (const r of HOLD_REASONS) expect(text.split(`        ${r}: "`).length - 1, r).toBe(1);
  });
});

describe("Legion's own payment alerts are not evidence for coverage", () => {
  it("a held payment does not make Legion claim it can see phishing or BEC", async () => {
    await check(credA, pay()).expect(200);
    const c = (await request(app).get("/security/coverage").set("Authorization", bearer(analystA)).expect(200)).body;
    const by = Object.fromEntries(c.threats.map((t: { threat: string; status: string }) => [t.threat, t.status]));
    expect(by.phishing).toBe("blind");
    expect(by.bec).toBe("blind");
  });
});
