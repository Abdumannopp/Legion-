/**
 * The platform's mail server is not a relay for tenants.
 *
 * Regression for the finding that any administrator — in hosted mode anyone who
 * signs up — could point notification_email at any inbox and then, through a
 * sensor credential, have Legion send unlimited sensor-written email to it
 * from the platform's own domain.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import * as mailer from "../src/mailer.js";
import type { User } from "../src/types.js";

const FRONT = "http://localhost:3000";
let tenantId: string; let admin: User;
const as = (u: User) => ["Authorization", `Bearer ${jwt.sign({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, config.jwtSecret, { expiresIn: "1h" })}`] as const;

/** Captures every email the app sends (the mailer module is the only exit). */
const sent: Array<{ to: string; subject: string; text: string }> = [];
const saved = { host: config.smtpHost, min: config.alertEmailMinSeverity, cap: config.alertEmailHourlyCap };

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  sent.length = 0;
  config.smtpHost = "smtp.test.invalid";
  config.alertEmailMinSeverity = "high";
  vi.spyOn(mailer, "sendMail").mockImplementation(async (m) => { sent.push({ to: String(m.to), subject: String(m.subject), text: String(m.text) }); return { sent: true }; });
  tenantId = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'Acme', now() + interval '14 days')", [tenantId]);
  admin = await store.insertUser({ email: `admin-${randomUUID()}@acme.io`, password_hash: await bcrypt.hash("password123", 4), tenant_id: tenantId, role: "admin", status: "active" });
});
afterEach(() => { vi.restoreAllMocks(); Object.assign(config, { smtpHost: saved.host, alertEmailMinSeverity: saved.min, alertEmailHourlyCap: saved.cap }); });

const setEmail = (email: string | null) => request(app).patch("/notifications/settings").set(...as(admin)).send({ notification_email: email });
const tokenFrom = (text: string) => /confirm-notification-email\?token=([A-Za-z0-9_-]+)/.exec(text)?.[1] ?? "";
async function critical(id: string, title = "Wire the money to account 1234 now") {
  await outbox.insertAlertAndNotify({
    id, tenant_id: tenantId, title, severity: "critical", agent: "Sentinel", status: "open", summary: "click http://phish.example",
    confidence: 99, ai_explanation: null, explained_at: null, source_ip: null, target: "h", mitre_technique: null, source: "wazuh",
  });
}
const queuedEmails = async () => (await query("SELECT recipient FROM notification_outbox WHERE tenant_id = $1 AND kind = 'alert_email'", [tenantId])).rows.map((r) => r.recipient as string);

describe("a new notification address must be confirmed by its owner", () => {
  it("setting an address sends only a confirmation — and alerts are NOT emailed to it", async () => {
    const res = await setEmail("victim@elsewhere.example").expect(200);
    expect(res.body).toMatchObject({ notification_email: null, pending_notification_email: "victim@elsewhere.example", confirmation_sent: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe("victim@elsewhere.example");
    expect(sent[0]!.text).toMatch(/ignore this email/i);
    await critical("A-1");
    expect(await queuedEmails()).toEqual([]);
    // The test email goes nowhere either.
    expect((await request(app).post("/notifications/test").set(...as(admin))).status).toBe(400);
  });

  it("after the owner confirms, alerts go to it", async () => {
    await setEmail("soc@acme.io").expect(200);
    const token = tokenFrom(sent[0]!.text);
    expect(token.length).toBeGreaterThan(20);
    const ok = await request(app).post("/notifications/confirm").set("Origin", FRONT).send({ token });
    expect(ok.status).toBe(200);
    expect((await store.getTenant(tenantId))!.notification_email).toBe("soc@acme.io");
    await critical("A-2");
    expect(await queuedEmails()).toEqual(["soc@acme.io"]);
    // Single use.
    expect((await request(app).post("/notifications/confirm").set("Origin", FRONT).send({ token })).status).toBe(400);
  });

  it("while a change is pending, the confirmed address keeps receiving alerts", async () => {
    await query("UPDATE tenants SET notification_email = 'soc@acme.io' WHERE id = $1", [tenantId]);
    await setEmail("new@elsewhere.example").expect(200);
    await critical("A-3");
    expect(await queuedEmails()).toEqual(["soc@acme.io"]);
  });

  it("an expired or forged token confirms nothing; the token is stored hashed", async () => {
    await setEmail("x@elsewhere.example").expect(200);
    const token = tokenFrom(sent[0]!.text);
    const row = (await query("SELECT notification_email_token_hash FROM tenants WHERE id = $1", [tenantId])).rows[0];
    expect(row.notification_email_token_hash).not.toContain(token);
    expect((await request(app).post("/notifications/confirm").set("Origin", FRONT).send({ token: "x".repeat(43) })).status).toBe(400);
    await query("UPDATE tenants SET notification_email_token_expires = now() - interval '1 minute' WHERE id = $1", [tenantId]);
    expect((await request(app).post("/notifications/confirm").set("Origin", FRONT).send({ token })).status).toBe(400);
    expect((await store.getTenant(tenantId))!.notification_email).toBeNull();
  });

  it("clearing the address needs no confirmation and stops email at once", async () => {
    await query("UPDATE tenants SET notification_email = 'soc@acme.io' WHERE id = $1", [tenantId]);
    await setEmail(null).expect(200);
    expect((await store.getTenant(tenantId))!.notification_email).toBeNull();
    expect(sent).toEqual([]);
  });

  it("confirmation emails are capped per tenant", async () => {
    for (let i = 0; i < config.notificationConfirmHourlyCap; i++) await setEmail(`t${i}@elsewhere.example`).expect(200);
    expect((await setEmail("one-more@elsewhere.example")).status).toBe(429);
    expect(sent).toHaveLength(config.notificationConfirmHourlyCap);
  });
});

describe("caps on email sent on a tenant's behalf", () => {
  it("alert emails stop at the hourly cap; the alerts themselves are all stored", async () => {
    await query("UPDATE tenants SET notification_email = 'soc@acme.io' WHERE id = $1", [tenantId]);
    config.alertEmailHourlyCap = 3;
    for (let i = 0; i < 6; i++) await critical(`CAP-${i}`);
    expect(await queuedEmails()).toHaveLength(3);
    expect((await store.listAlerts(tenantId, { limit: 50 })).filter((a) => a.id.startsWith("CAP-"))).toHaveLength(6);
  });

  it("test emails are capped per tenant", async () => {
    await query("UPDATE tenants SET notification_email = 'soc@acme.io' WHERE id = $1", [tenantId]);
    vi.spyOn(mailer, "verifyMail").mockResolvedValue({ sent: true });
    const codes: number[] = [];
    for (let i = 0; i < config.notificationTestHourlyCap + 1; i++) codes.push((await request(app).post("/notifications/test").set(...as(admin))).status);
    expect(codes.slice(0, -1).every((c) => c === 200)).toBe(true);
    expect(codes.at(-1)).toBe(429);
  });

  it("SMTP errors never reach the tenant administrator", async () => {
    await query("UPDATE tenants SET notification_email = 'soc@acme.io' WHERE id = $1", [tenantId]);
    vi.spyOn(mailer, "verifyMail").mockResolvedValue({ sent: false, reason: "failed", detail: "535 auth failed for user platform-mailer@smtp.internal.corp password=hunter2" } as never);
    const res = await request(app).post("/notifications/test").set(...as(admin));
    expect(res.status).toBe(502);
    expect(JSON.stringify(res.body)).not.toMatch(/smtp\.internal|platform-mailer|hunter2|535/);
  });

  it("invitations are capped per tenant", async () => {
    config.inviteHourlyCap = 2;
    try {
      await request(app).post("/users/invite").set(...as(admin)).send({ email: "a1@elsewhere.example", role: "viewer" }).expect(201);
      await request(app).post("/users/invite").set(...as(admin)).send({ email: "a2@elsewhere.example", role: "viewer" }).expect(201);
      expect((await request(app).post("/users/invite").set(...as(admin)).send({ email: "a3@elsewhere.example", role: "viewer" })).status).toBe(429);
    } finally { config.inviteHourlyCap = 50; }
  });
});
