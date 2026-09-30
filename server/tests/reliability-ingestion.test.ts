/**
 * Reliability (2026-09) — ingestion and failed-job handling, in process.
 *
 *  - the sensor's own event time is kept (occurred_at), apart from ingestion time
 *  - a database outage is a 503 + Retry-After (retry/spool), never a bare 500
 *  - a silent sensor raises one alert per silence, on any number of instances,
 *    and resolves it when the sensor speaks again
 *  - dead-lettered notifications can be requeued by an administrator, exactly once,
 *    for their own organisation only
 *  - queue health reports the worker's liveness
 *
 * The real-process failure injection (DB restart, SIGKILL, Redis restart,
 * several instances) is in reliability-failover.test.ts.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app, databaseUnavailable, eventTime } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, pool, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import { checkSensors, silenceAlertId } from "../src/sensor-monitor.js";
import type { User } from "../src/types.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

let tenant: string; let other: string; let admin: User; let otherAdmin: User; let viewer: User; let cred: TestCredential;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const savedHost = config.smtpHost;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenant = randomUUID(); other = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at, notification_email) VALUES ($1, 'A', now() + interval '14 days', 'soc@a.example'), ($2, 'B', now() + interval '14 days', 'soc@b.example')", [tenant, other]);
  const hash = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "admin@a.example", password_hash: hash, tenant_id: tenant, role: "admin", status: "active" });
  viewer = await store.insertUser({ email: "viewer@a.example", password_hash: hash, tenant_id: tenant, role: "viewer", status: "active" });
  otherAdmin = await store.insertUser({ email: "admin@b.example", password_hash: hash, tenant_id: other, role: "admin", status: "active" });
  cred = await issueCredential(tenant, "wazuh-prod");
});
afterEach(() => { vi.restoreAllMocks(); config.smtpHost = savedHost; });

const event = (id: string, extra: Record<string, unknown> = {}) => ({
  provider: "wazuh",
  event: { id, rule: { description: `event ${id}`, level: 12 }, agent: { name: "web-01" }, full_log: "x", ...extra },
});

// --- event time ---------------------------------------------------------------------------------

describe("the sensor's own event time is kept", () => {
  it("a spooled event re-sent an hour late keeps when it happened; created_at is when it arrived", async () => {
    const hourAgo = new Date(Date.now() - 3_600_000);
    const wazuhStamp = hourAgo.toISOString().replace("Z", "+0000");
    await sendSigned(app, cred, event("late-1", { timestamp: wazuhStamp })).expect(202);
    const [alert] = await store.listAlerts(tenant);
    expect(Math.abs(new Date(alert!.occurred_at!).getTime() - hourAgo.getTime())).toBeLessThan(1000);
    expect(Date.now() - new Date(alert!.created_at).getTime()).toBeLessThan(10_000);
    const api = await request(app).get(`/alerts/${alert!.id}`).set(...as(admin)).expect(200);
    expect(api.body.occurred_at).toBe(alert!.occurred_at);
  });

  it("the Wazuh format with a +0000 offset, and ISO forms, are read; nonsense and a future clock are ignored", () => {
    expect(eventTime("2026-09-28T01:02:03.456+0000")).toBe("2026-09-28T01:02:03.456Z");
    expect(eventTime("2026-09-28T06:02:03+05:00")).toBe("2026-09-28T01:02:03.000Z");
    expect(eventTime("yesterday")).toBeNull();
    expect(eventTime(12345)).toBeNull();
    expect(eventTime("1970-01-01T00:00:00Z")).toBeNull();
    expect(eventTime(new Date(Date.now() + 3_600_000).toISOString())).toBeNull(); // sensor clock ahead
    expect(eventTime("x".repeat(500))).toBeNull();
  });

  it("an event without a timestamp still lands, with occurred_at null", async () => {
    await sendSigned(app, cred, event("no-time")).expect(202);
    expect((await store.listAlerts(tenant))[0]!.occurred_at).toBeNull();
  });
});

// --- database outage -------------------------------------------------------------------------------

describe("a database outage is a retryable 503, not a 500", () => {
  it.each([
    [{ code: "ECONNREFUSED", message: "connect ECONNREFUSED 127.0.0.1:5432" }],
    [{ code: "57P01", message: "terminating connection due to administrator command" }],
    [{ code: "57P03", message: "the database system is starting up" }],
    [{ message: "Connection terminated unexpectedly" }],
    [{ message: "timeout exceeded when trying to connect" }],
  ])("%j is recognised", (err) => {
    expect(databaseUnavailable(err)).toBe(true);
  });

  it("an ordinary error is not mistaken for an outage", () => {
    expect(databaseUnavailable({ code: "23505", message: "duplicate key" })).toBe(false);
    expect(databaseUnavailable(new Error("boom"))).toBe(false);
  });

  it("the sensor webhook answers 503 + Retry-After while the database is down, and nothing is half-stored", async () => {
    const down = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:5432"), { code: "ECONNREFUSED" });
    vi.spyOn(pool, "query").mockRejectedValue(down as never);
    vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await sendSigned(app, cred, event("during-outage"));
    expect(res.status).toBe(503);
    expect(res.headers["retry-after"]).toBe("5");
    expect(JSON.stringify(res.body)).not.toMatch(/ECONNREFUSED|5432/);
    vi.restoreAllMocks();
    // The sensor retries (or spools, then drains) after the outage: exactly one alert.
    await sendSigned(app, cred, event("during-outage")).expect(202);
    await sendSigned(app, cred, event("during-outage")).expect(202);
    expect(await store.listAlerts(tenant)).toHaveLength(1);
  });
});

// --- silent sensors ---------------------------------------------------------------------------------

describe("a silent sensor raises an alert", () => {
  const quiet = (minutes: number, keyId = cred.keyId) =>
    query("UPDATE webhook_credentials SET last_used_at = now() - make_interval(mins => $2) WHERE key_id = $1", [keyId, minutes]);
  const silenceAlerts = async (t = tenant) => (await store.listAlerts(t)).filter((a) => a.source === "legion-monitor");

  it("after SENSOR_SILENCE_MINUTES: one high alert, stored through the normal pipeline (versioned, emailed)", async () => {
    config.smtpHost = "smtp.test.invalid";
    await sendSigned(app, cred, event("before-silence")).expect(202);
    await quiet(180);
    expect((await checkSensors({ silenceMinutes: 120 })).raised).toBe(1);
    const [a] = await silenceAlerts();
    expect(a).toMatchObject({ severity: "high", status: "open", source: "legion-monitor" });
    expect(a!.title).toMatch(/Sensor silent: no events from "wazuh-prod" for 18\d minutes/);
    expect(a!.seq).toBeGreaterThan(0);
    const emails = await query("SELECT count(*)::int AS n FROM notification_outbox WHERE tenant_id = $1 AND kind = 'alert_email' AND dedupe_key = $2", [tenant, a!.id]);
    expect(emails.rows[0].n).toBe(1);
  });

  it("is raised once per silence, however many times — or instances — check", async () => {
    await quiet(180);
    const results = await Promise.all(Array.from({ length: 6 }, () => checkSensors({ silenceMinutes: 120 })));
    expect(results.reduce((n, r) => n + r.raised, 0)).toBe(1);
    await checkSensors({ silenceMinutes: 120 });
    expect(await silenceAlerts()).toHaveLength(1);
  });

  it("resolves itself when the sensor sends again; a later silence is a new alert", async () => {
    await quiet(180);
    await checkSensors({ silenceMinutes: 120 });
    await sendSigned(app, cred, event("back-again")).expect(202);
    // last_used_at is recorded without holding up the 202; wait for it.
    await expect.poll(async () => (await query("SELECT last_used_at > now() - interval '1 minute' AS fresh FROM webhook_credentials WHERE key_id = $1", [cred.keyId])).rows[0].fresh).toBe(true);
    expect((await checkSensors({ silenceMinutes: 120 })).resolved).toBe(1);
    expect((await silenceAlerts())[0]!.status).toBe("resolved");
    await quiet(200);
    expect((await checkSensors({ silenceMinutes: 120 })).raised).toBe(1);
    expect(await silenceAlerts()).toHaveLength(2);
  });

  it("ignores credentials never used, revoked, or unused for over a week, and never crosses organisations", async () => {
    const neverUsed = await issueCredential(tenant, "spare");
    const retired = await issueCredential(tenant, "retired");
    const revoked = await issueCredential(tenant, "revoked");
    await quiet(8 * 24 * 60, retired.keyId);
    await quiet(180, revoked.keyId);
    await query("UPDATE webhook_credentials SET revoked_at = now() WHERE key_id = $1", [revoked.keyId]);
    expect((await checkSensors({ silenceMinutes: 120 })).raised).toBe(0);
    void neverUsed;
    const b = await issueCredential(other, "b-sensor");
    await quiet(180, b.keyId);
    await checkSensors({ silenceMinutes: 120 });
    expect(await silenceAlerts(tenant)).toHaveLength(0);
    expect(await silenceAlerts(other)).toHaveLength(1);
  });

  it("the alert id is deterministic and hex-only after the prefix, whatever characters the key id has", () => {
    const t = new Date("2026-09-30T00:00:00Z");
    expect(silenceAlertId("whk_a-b_c-d_e-f_g-h_i-j_", t)).toMatch(/^SENSOR-SILENT-[0-9A-F]{12}-1790726400$/);
    expect(silenceAlertId("whk_a-b_c-d_e-f_g-h_i-j_", t)).toBe(silenceAlertId("whk_a-b_c-d_e-f_g-h_i-j_", t));
  });

  it("SENSOR_SILENCE_MINUTES=0 turns it off", async () => {
    await quiet(10_000);
    expect(await checkSensors({ silenceMinutes: 0 })).toEqual({ raised: 0, resolved: 0 });
  });
});

// --- dead letters ------------------------------------------------------------------------------------

describe("dead-lettered notifications can be requeued", () => {
  async function deadEmail(tenantId: string, id: string) {
    config.smtpHost = "smtp.test.invalid";
    await outbox.insertAlertAndNotify({
      id, tenant_id: tenantId, title: `t ${id}`, severity: "critical", agent: "Sentinel", status: "open", summary: "s",
      confidence: 90, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh",
    });
    const r = await query("UPDATE notification_outbox SET status = 'dead', attempts = max_attempts, last_error = 'SMTP 421 for hours' WHERE tenant_id = $1 AND dedupe_key = $2 AND kind = 'alert_email' RETURNING id", [tenantId, id]);
    return r.rows[0].id as string;
  }
  const row = async (id: string) => (await query("SELECT status, attempts, last_error FROM notification_outbox WHERE id = $1", [id])).rows[0];

  it("one job: back to pending with fresh attempts, then delivered exactly once", async () => {
    const id = await deadEmail(tenant, "D-1");
    const res = await request(app).post(`/notifications/deliveries/${id}/retry`).set(...as(admin)).expect(200);
    expect(res.body.requeued).toBe(1);
    expect(await row(id)).toMatchObject({ status: "pending", attempts: 0 });
    expect((await row(id)).last_error).toMatch(/requeued by an administrator after: SMTP 421/);
    const sent: string[] = [];
    await outbox.deliverDue({ kind: "alert_email", send: async (m) => { sent.push(m.to); return { sent: true }; } });
    await outbox.deliverDue({ kind: "alert_email", send: async (m) => { sent.push(m.to); return { sent: true }; } });
    expect(sent).toEqual(["soc@a.example"]);
    expect((await row(id)).status).toBe("sent");
    // Requeueing again is refused: it is no longer dead (no second email).
    await request(app).post(`/notifications/deliveries/${id}/retry`).set(...as(admin)).expect(404);
  });

  it("all of an organisation's dead jobs at once — never another organisation's", async () => {
    const a1 = await deadEmail(tenant, "D-2"); const a2 = await deadEmail(tenant, "D-3"); const b1 = await deadEmail(other, "D-4");
    const res = await request(app).post("/notifications/deliveries/retry-dead").set(...as(admin)).expect(200);
    expect(res.body.requeued).toBe(2);
    expect((await row(a1)).status).toBe("pending"); expect((await row(a2)).status).toBe("pending");
    expect((await row(b1)).status).toBe("dead");
  });

  it("another organisation's job is a 404, a pending job is not touched, and only administrators may do it", async () => {
    const b1 = await deadEmail(other, "D-5");
    await request(app).post(`/notifications/deliveries/${b1}/retry`).set(...as(admin)).expect(404);
    expect((await row(b1)).status).toBe("dead");
    await request(app).post(`/notifications/deliveries/${b1}/retry`).set(...as(otherAdmin)).expect(200);
    await request(app).post("/notifications/deliveries/retry-dead").set(...as(viewer)).expect(403);
    await request(app).post("/notifications/deliveries/not-a-uuid/retry").set(...as(admin)).expect(404);
  });
});

// --- the worker loses the database mid-batch ---------------------------------------------------------

describe("a worker that loses the database in the middle of a batch", () => {
  async function queueEmails(n: number) {
    config.smtpHost = "smtp.test.invalid";
    for (let i = 0; i < n; i++) {
      await outbox.insertAlertAndNotify({
        id: `W-${i}`, tenant_id: tenant, title: `t${i}`, severity: "critical", agent: "Sentinel", status: "open", summary: "s",
        confidence: 90, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh",
      });
    }
  }
  const statuses = async () => (await query("SELECT status, count(*)::int AS n FROM notification_outbox WHERE kind = 'alert_email' GROUP BY status")).rows
    .reduce((m, r) => ({ ...m, [r.status]: r.n }), {} as Record<string, number>);
  /** Makes the next statement matching `pattern` fail as if the database had gone away. */
  function failNext(pattern: RegExp) {
    const real = pool.query.bind(pool);
    let armed = true;
    return vi.spyOn(pool, "query").mockImplementation(((text: unknown, params?: unknown) => {
      if (armed && typeof text === "string" && pattern.test(text)) {
        armed = false;
        return Promise.reject(Object.assign(new Error("Connection terminated unexpectedly"), { code: "ECONNRESET" }));
      }
      return real(text as string, params as unknown[]);
    }) as never);
  }

  it("an email accepted by the mail server whose 'sent' could not be written is NOT sent again", async () => {
    await queueEmails(1);
    const sent: string[] = [];
    const sender = async (m: { messageId?: string }) => { sent.push(m.messageId ?? ""); return { sent: true as const }; };
    failNext(/SET status = 'sent'/);
    await expect(outbox.deliverDue({ kind: "alert_email", send: sender })).rejects.toThrow(/Connection terminated/);
    expect(sent).toHaveLength(1);
    expect(outbox.heldOutcomes().unrecorded).toBe(1);
    vi.restoreAllMocks();
    // The database is back: the known outcome is written, nothing is re-sent.
    await outbox.deliverDue({ kind: "alert_email", send: sender });
    await query("UPDATE notification_outbox SET locked_until = now() - interval '1 second', next_attempt_at = now()");
    await outbox.deliverDue({ kind: "alert_email", send: sender });
    expect(sent).toHaveLength(1);
    expect(await statuses()).toEqual({ sent: 1 });
    expect(outbox.heldOutcomes()).toEqual({ unrecorded: 0, untouched: 0 });
  });

  it("jobs claimed but never attempted are handed back at once — not after the 120 s lease — with the attempt not counted", async () => {
    await queueEmails(3);
    const sent: string[] = [];
    const sender = async (m: { to: string }) => { sent.push(m.to); return { sent: true as const }; };
    failNext(/SET locked_until = now\(\) \+ make_interval/); // the lease renewal before the first attempt
    await expect(outbox.deliverDue({ kind: "alert_email", send: sender })).rejects.toThrow();
    expect(await statuses()).toEqual({ sending: 3 });            // claimed, stranded under a lease
    expect(outbox.heldOutcomes().untouched).toBe(3);
    vi.restoreAllMocks();
    await outbox.deliverDue({ kind: "alert_email", send: sender }); // gives them back…
    await outbox.deliverDue({ kind: "alert_email", send: sender }); // …and delivers them, no lease wait
    expect(sent).toHaveLength(3);
    expect(await statuses()).toEqual({ sent: 3 });
    const attempts = (await query("SELECT max(attempts)::int AS a FROM notification_outbox")).rows[0].a;
    expect(attempts).toBe(1);
  });
});

// --- queue health --------------------------------------------------------------------------------------

describe("queue health includes the worker's liveness", () => {
  it("/health/outbox reports when this instance's worker last ran", async () => {
    const saved = config.healthMetricsToken;
    config.healthMetricsToken = "monitor-token-0123456789abcdef";
    try {
      const res = await request(app).get("/health/outbox").set("Authorization", "Bearer monitor-token-0123456789abcdef").expect(200);
      expect(res.body.worker).toHaveProperty("running");
      expect(res.body.worker).toHaveProperty("last_tick_seconds_ago");
      expect(res.body).toHaveProperty("dead");
      expect(res.body).toHaveProperty("oldest_pending_age_seconds");
    } finally { config.healthMetricsToken = saved; }
  });
});
