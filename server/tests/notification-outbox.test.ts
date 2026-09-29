/**
 * Reliable notification delivery (outbox.ts).
 *
 * Before: the alert email was sent fire-and-forget. One SMTP hiccup meant the
 * alert was stored and nobody was ever told. These tests cover the task's
 * list: success, failure, retry, repeated failure, eventual success — plus
 * no duplicates, no secrets in the stored error, and tenant isolation.
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
import * as outbox from "../src/outbox.js";
import type { Sender } from "../src/outbox.js";
import type { User } from "../src/types.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";

let tenantA: string, tenantB: string, adminA: User, adminB: User;
const saved = { host: config.smtpHost, user: config.smtpUser, pass: config.smtpPassword, max: config.notifyMaxAttempts };

/** A mail server we control: fails the first `failures` sends, records the rest. */
function fakeSmtp(failures = 0, detail = "421 service not available") {
  const delivered: Parameters<Sender>[0][] = [];
  let calls = 0;
  const send: Sender = async (m) => {
    calls++;
    if (calls <= failures) return { sent: false, reason: "send_failed", detail };
    delivered.push(m);
    return { sent: true };
  };
  return { send, delivered, calls: () => calls };
}

const rows = async () =>
  (await query("SELECT tenant_id, status, attempts, last_error, next_attempt_at FROM notification_outbox WHERE kind = 'alert_email' ORDER BY created_at")).rows;
/** Makes every waiting row due now — stands in for the backoff delay passing. */
const timePasses = () => query("UPDATE notification_outbox SET next_attempt_at = now() WHERE status = 'pending'");

const alert = (tenant: string, id: string, severity: "critical" | "low" = "critical") => ({
  id, tenant_id: tenant, title: `Brute force on web-01 (${id})`, severity, agent: "Sentinel" as const, status: "open" as const,
  summary: "sshd: many failures", confidence: 90, ai_explanation: null, explained_at: null,
  source_ip: "198.51.100.4", target: "web-01", mitre_technique: "T1110", source: "wazuh",
});

beforeAll(async () => { await migrate(); });
afterAll(async () => {
  Object.assign(config, { smtpHost: saved.host, smtpUser: saved.user, smtpPassword: saved.pass, notifyMaxAttempts: saved.max });
  await closePool();
});
beforeEach(async () => {
  await truncateAll();
  Object.assign(config, { smtpHost: "smtp.test.invalid", smtpUser: "legion-mailer", smtpPassword: "S3cr3t-SMTP-pass", notifyMaxAttempts: 4 });
  config.alertEmailMinSeverity = "high";
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, notification_email) VALUES ($1, 'A', 'soc@a.io'), ($2, 'B', 'soc@b.io')", [tenantA, tenantB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@a.io", password_hash: hash, tenant_id: tenantA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "admin@b.io", password_hash: hash, tenant_id: tenantB, role: "admin", status: "active" });
});

describe("the alert and its notification are stored together", () => {
  it("a severe alert queues exactly one email in the same transaction", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    expect(await rows()).toEqual([expect.objectContaining({ tenant_id: tenantA, status: "pending", attempts: 0 })]);
  });

  it("an alert below the email threshold queues nothing", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-low", "low"));
    expect(await rows()).toEqual([]);
  });

  it("if the alert cannot be stored, no orphan notification is left behind", async () => {
    await expect(outbox.insertAlertAndNotify({ ...alert(tenantA, "A-bad"), severity: "nonsense" as never })).rejects.toThrow();
    expect(await rows()).toEqual([]);
  });

  it("the same alert arriving twice queues one email, not two", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-dup"));
    expect(await outbox.insertAlertAndNotify(alert(tenantA, "A-dup"))).toBeNull();
    expect(await rows()).toHaveLength(1);
  });
});

describe("delivery", () => {
  it("successful delivery: sent once and marked sent", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const smtp = fakeSmtp();
    expect(await outbox.deliverDue({ send: smtp.send })).toEqual({ sent: 1, retrying: 0, dead: 0 });
    expect(smtp.delivered).toHaveLength(1);
    expect(smtp.delivered[0]).toMatchObject({ to: "soc@a.io", subject: expect.stringContaining("A-1") });
    expect((await rows())[0]).toMatchObject({ status: "sent", attempts: 1, last_error: null });
    // Nothing left to do.
    expect(await outbox.deliverDue({ send: smtp.send })).toEqual({ sent: 0, retrying: 0, dead: 0 });
  });

  it("failed delivery: kept, reason recorded, scheduled later — not lost", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const smtp = fakeSmtp(1);
    expect(await outbox.deliverDue({ send: smtp.send })).toEqual({ sent: 0, retrying: 1, dead: 0 });
    const [r] = await rows();
    expect(r).toMatchObject({ status: "pending", attempts: 1, last_error: "421 service not available" });
    expect(new Date(r.next_attempt_at).getTime()).toBeGreaterThan(Date.now() + 20_000); // backoff, not immediate
    // Not due yet, so a second pass does nothing.
    expect(await outbox.deliverDue({ send: smtp.send })).toEqual({ sent: 0, retrying: 0, dead: 0 });
  });

  it("retry → eventual success after the mail server recovers", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const smtp = fakeSmtp(2);
    await outbox.deliverDue({ send: smtp.send }); await timePasses();
    await outbox.deliverDue({ send: smtp.send }); await timePasses();
    expect(await outbox.deliverDue({ send: smtp.send })).toEqual({ sent: 1, retrying: 0, dead: 0 });
    expect(smtp.delivered).toHaveLength(1);
    expect((await rows())[0]).toMatchObject({ status: "sent", attempts: 3, last_error: null });
  });

  it("repeated failure: gives up after the maximum and stays visible as dead", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const smtp = fakeSmtp(99);
    for (let i = 0; i < 6; i++) { await outbox.deliverDue({ send: smtp.send }); await timePasses(); }
    expect(smtp.calls()).toBe(4); // notifyMaxAttempts, not forever
    expect((await rows())[0]).toMatchObject({ status: "dead", attempts: 4 });
  });

  it("every retry carries the same Message-ID, so a receiving system can drop a copy", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const ids: string[] = [];
    const send: Sender = async (m) => { ids.push(m.messageId!); return ids.length < 3 ? { sent: false, reason: "send_failed", detail: "x" } : { sent: true }; };
    for (let i = 0; i < 3; i++) { await outbox.deliverDue({ send }); await timePasses(); }
    expect(new Set(ids).size).toBe(1);
  });

  it("two workers running at once never send the same notification twice", async () => {
    for (let i = 0; i < 10; i++) await outbox.insertAlertAndNotify(alert(tenantA, `A-${i}`));
    const smtp = fakeSmtp();
    const slow: Sender = async (m) => { await new Promise((r) => setTimeout(r, 20)); return smtp.send(m); };
    await Promise.all([outbox.deliverDue({ send: slow }), outbox.deliverDue({ send: slow }), outbox.deliverDue({ send: slow })]);
    expect(smtp.delivered).toHaveLength(10);
    expect(new Set(smtp.delivered.map((m) => m.subject)).size).toBe(10);
  });

  it("a worker that died mid-send is picked up again once its lease runs out", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    await query("UPDATE notification_outbox SET status = 'sending', attempts = 1, locked_until = now() - interval '1 second'");
    const smtp = fakeSmtp();
    expect((await outbox.deliverDue({ send: smtp.send })).sent).toBe(1);
  });

  it("a sender that throws is treated as a failure, not a crash", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const send: Sender = async () => { throw new Error("socket hang up"); };
    expect(await outbox.deliverDue({ send })).toEqual({ sent: 0, retrying: 1, dead: 0 });
  });
});

describe("the stored failure reason never holds secrets", () => {
  it("redacts the SMTP login and password echoed back by a mail server", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    const smtp = fakeSmtp(1, "535 auth failed for legion-mailer with password S3cr3t-SMTP-pass via smtp://legion-mailer:S3cr3t-SMTP-pass@smtp.test.invalid");
    await outbox.deliverDue({ send: smtp.send });
    const { last_error } = (await rows())[0];
    expect(last_error).not.toContain("S3cr3t-SMTP-pass");
    expect(last_error).not.toContain("legion-mailer");
    expect(last_error).toContain("535 auth failed");
  });

  it("backoff doubles and is capped at one hour", () => {
    expect([1, 2, 3, 4].map((n) => outbox.backoffSeconds(n, 30))).toEqual([30, 60, 120, 240]);
    expect(outbox.backoffSeconds(20, 30)).toBe(3600);
  });
});

describe("tenant isolation", () => {
  it("each company's alert goes only to its own address", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    await outbox.insertAlertAndNotify(alert(tenantB, "B-1"));
    const smtp = fakeSmtp();
    await outbox.deliverDue({ send: smtp.send });
    const byTo = Object.fromEntries(smtp.delivered.map((m) => [m.to, m.subject]));
    expect(byTo["soc@a.io"]).toContain("A-1");
    expect(byTo["soc@b.io"]).toContain("B-1");
  });

  it("an administrator sees only their own organisation's deliveries", async () => {
    await outbox.insertAlertAndNotify(alert(tenantA, "A-1"));
    await outbox.insertAlertAndNotify(alert(tenantB, "B-1"));
    const tok = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;
    const a = await request(app).get("/notifications/deliveries").set("Authorization", tok(adminA)).expect(200);
    expect(a.body.deliveries.map((d: { subject_id: string }) => d.subject_id)).toEqual(["A-1"]);
    expect(JSON.stringify(a.body)).not.toContain("soc@b.io");
  });
});

describe("end to end through the Wazuh webhook", () => {
  it("an alert received while the mail server is down is emailed once it recovers", async () => {
    const cred = await issueCredential(tenantA);
    await sendSigned(app, cred, { provider: "wazuh", event: { id: "wz-1", rule: { description: "Root login from new country", level: 13 }, agent: { name: "db-01" } } }).expect(202);

    const down = fakeSmtp(99);
    await outbox.deliverDue({ send: down.send });
    expect((await rows())[0]).toMatchObject({ status: "pending", attempts: 1 });

    await timePasses();
    const up = fakeSmtp();
    await outbox.deliverDue({ send: up.send });
    expect(up.delivered.map((m) => m.subject).join()).toContain("Root login from new country");
    expect((await rows())[0].status).toBe("sent");
  });
});
