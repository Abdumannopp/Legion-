/**
 * Durable, loss-resistant alert delivery.
 *
 * The contract under test:
 *   - the Wazuh webhook answers 2xx only after the alert AND its follow-up
 *     jobs (email, realtime frame, asset upsert) are committed together;
 *   - SMTP and Redis are never on the ingestion path — their failure delays
 *     a notification, it never fails ingestion or loses the alert;
 *   - jobs retry with exponential backoff up to a maximum, then dead-letter;
 *   - duplicate events are idempotent, even when they arrive concurrently;
 *   - several workers can run at once without double delivery, and a worker
 *     that dies (or stalls past its lease) cannot overwrite a newer outcome;
 *   - nothing sensitive reaches the logs.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer, type AddressInfo } from "node:net";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import * as realtime from "../src/realtime.js";
import type { Publisher, Sender } from "../src/outbox.js";
import type { User } from "../src/types.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

// --- fixtures ----------------------------------------------------------------

const SMTP_PASSWORD = "Sm7p-Pa55-do-not-log";
const REDIS_PASSWORD = "r3dis-Pa55-do-not-log";
const SENSITIVE_LOG = "sshd: password for root is hunter2-do-not-log";

let tenant: string, otherTenant: string, admin: User;
const saved = { ...config };

const freePort = () => new Promise<number>((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => {
    const { port } = s.address() as AddressInfo;
    s.close(() => resolve(port));
  });
});

const wazuh = (id: string, extra: Record<string, unknown> = {}) => ({
  provider: "wazuh",
  event: {
    id, full_log: SENSITIVE_LOG,
    rule: { description: `Brute force (${id})`, level: 13, mitre: { id: ["T1110"] } },
    agent: { name: "web-01", ip: "10.0.0.5", os: { name: "Ubuntu" } },
    data: { srcip: "198.51.100.7" },
    ...extra,
  },
});

let creds: Record<string, TestCredential> = {};
function post(body: unknown, tenantId = tenant) {
  return sendSigned(app, creds[tenantId]!, body);
}

const jobs = async (kind?: string) =>
  (await query(
    `SELECT id, kind, status, attempts, max_attempts, last_error, next_attempt_at, locked_until
       FROM notification_outbox WHERE ($1::text IS NULL OR kind = $1) ORDER BY kind, created_at`,
    [kind ?? null]
  )).rows;
const alertCount = async () => Number((await query("SELECT count(*) FROM alerts")).rows[0].count);
const timePasses = () => query("UPDATE notification_outbox SET next_attempt_at = now() WHERE status = 'pending'");

function recordingSmtp(failures = 0, detail = "421 4.3.2 service not available") {
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

function recordingRedis(failures = 0, message = "connect ECONNREFUSED 127.0.0.1:6379") {
  const published: { tenantId: string; payload: unknown }[] = [];
  let calls = 0;
  const publish: Publisher = async (tenantId, payload) => {
    calls++;
    if (calls <= failures) throw new Error(message);
    published.push({ tenantId, payload });
  };
  return { publish, published, calls: () => calls };
}

/** Every console line written during a test, to prove secrets stay out. */
let logged: string[] = [];
const captureLogs = () => {
  logged = [];
  for (const level of ["log", "info", "warn", "error"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      logged.push(args.map((a) => (a instanceof Error ? `${a.message} ${JSON.stringify(a)}` : typeof a === "string" ? a : JSON.stringify(a))).join(" "));
    });
  }
};
const expectNoSecretsLogged = () => {
  const all = logged.join("\n");
  for (const secret of [SMTP_PASSWORD, REDIS_PASSWORD, SENSITIVE_LOG, "hunter2", config.webhookSecret, config.jwtSecret]) {
    expect(all).not.toContain(secret);
  }
};

beforeAll(async () => { await migrate(); });
afterAll(async () => {
  Object.assign(config, saved);
  await closePool();
});
beforeEach(async () => {
  await truncateAll();
  await query("DROP TRIGGER IF EXISTS fail_outbox ON notification_outbox; DROP TRIGGER IF EXISTS fail_assets ON assets");
  // An SMTP server that refuses connections: a real failure, not a stub.
  Object.assign(config, {
    smtpHost: "127.0.0.1", smtpPort: await freePort(), smtpUser: "legion-mailer", smtpPassword: SMTP_PASSWORD,
    notifyMaxAttempts: 4, notifyRetryBaseSeconds: 30, realtimeMaxAttempts: 3, realtimeRetryBaseSeconds: 5,
    alertEmailMinSeverity: "high", redisUrl: "", healthMetricsToken: "",
  });
  tenant = randomUUID(); otherTenant = randomUUID();
  await query("INSERT INTO tenants (id, name, notification_email) VALUES ($1, 'A', 'soc@a.io'), ($2, 'B', 'soc@b.io')", [tenant, otherTenant]);
  creds = { [tenant]: await issueCredential(tenant), [otherTenant]: await issueCredential(otherTenant) };
  admin = await store.insertUser({ email: "admin@a.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenant, role: "admin", status: "active" });
  captureLogs();
});
afterEach(async () => {
  vi.restoreAllMocks();
  await query("DROP TRIGGER IF EXISTS fail_outbox ON notification_outbox; DROP TRIGGER IF EXISTS fail_assets ON assets");
});

// --- ingestion ---------------------------------------------------------------

describe("ingestion persists before it answers", () => {
  it("a 202 means the alert, its asset, its email job and its realtime job are all committed", async () => {
    const res = await post(wazuh("wz-1")).expect(202);
    expect(res.body.status).toBe("ingested");
    expect(await store.getAlert(tenant, res.body.alert_id)).toMatchObject({ severity: "critical", target: "web-01" });
    expect((await query("SELECT name, os, ip_address FROM assets WHERE tenant_id = $1", [tenant])).rows)
      .toEqual([{ name: "web-01", os: "Ubuntu", ip_address: "10.0.0.5" }]);
    expect((await jobs()).map((j) => [j.kind, j.status])).toEqual([["alert_email", "pending"], ["realtime_alert", "pending"]]);
  });

  it("does not touch SMTP or Redis: both unreachable, ingestion still succeeds at once", async () => {
    // A blackhole address would hang a connect for the full SMTP timeout,
    // and this Redis URL points nowhere — neither may be on the request path.
    Object.assign(config, { smtpHost: "10.255.255.1", smtpPort: 25, redisUrl: `redis://:${REDIS_PASSWORD}@127.0.0.1:1` });
    const started = Date.now();
    await post(wazuh("wz-fast")).expect(202);
    expect(Date.now() - started).toBeLessThan(1500);
    expect(await alertCount()).toBe(1);
    expectNoSecretsLogged();
  });
});

describe("duplicate Wazuh events are idempotent", () => {
  it("the same event twice: one alert, one email, one frame; the retry is told it was a duplicate", async () => {
    const first = await post(wazuh("wz-dup")).expect(202);
    const second = await post(wazuh("wz-dup")).expect(202);
    expect(second.body).toMatchObject({ status: "skipped", reason: "duplicate", alert_id: first.body.alert_id });
    expect(await alertCount()).toBe(1);
    expect(await jobs()).toHaveLength(2);
  });

  it("the same event delivered 10 times concurrently still yields exactly one of everything", async () => {
    const results = await Promise.all(Array.from({ length: 10 }, () => post(wazuh("wz-race"))));
    expect(results.every((r) => r.status === 202)).toBe(true);
    expect(results.filter((r) => r.body.status === "ingested")).toHaveLength(1);
    expect(await alertCount()).toBe(1);
    expect((await jobs()).map((j) => j.kind)).toEqual(["alert_email", "realtime_alert"]);
  });

  it("an event without an id is de-duplicated by its content; a different event is not", async () => {
    const noId = { provider: "wazuh", event: { rule: { description: "No id here", level: 10 }, agent: { name: "h" } } };
    await post(noId).expect(202);
    expect((await post(noId).expect(202)).body.status).toBe("skipped");
    await post({ ...noId, event: { ...noId.event, rule: { description: "Something else", level: 10 } } }).expect(202);
    expect(await alertCount()).toBe(2);
  });

  it("the same event id from two tenants is two alerts — idempotency is per tenant", async () => {
    await post(wazuh("shared-id"), tenant).expect(202);
    expect((await post(wazuh("shared-id"), otherTenant).expect(202)).body.status).toBe("ingested");
    expect(await alertCount()).toBe(2);
  });
});

describe("database rollback", () => {
  it("if a follow-up job cannot be stored, the alert is rolled back and the sender is told to retry", async () => {
    await query(`CREATE OR REPLACE FUNCTION legion_test_fail() RETURNS trigger LANGUAGE plpgsql AS
                 $$ BEGIN RAISE EXCEPTION 'simulated outbox failure'; END $$`);
    await query(`CREATE TRIGGER fail_outbox BEFORE INSERT ON notification_outbox
                 FOR EACH ROW WHEN (NEW.kind = 'realtime_alert') EXECUTE FUNCTION legion_test_fail()`);

    await post(wazuh("wz-rb")).expect(500);
    // Nothing half-written: no alert, no asset, no email job (it was inserted
    // before the failing statement, in the same transaction).
    expect(await alertCount()).toBe(0);
    expect(Number((await query("SELECT count(*) FROM assets")).rows[0].count)).toBe(0);
    expect(await jobs()).toEqual([]);

    // The database recovers; the sensor's retry is a first delivery, not a duplicate.
    await query("DROP TRIGGER fail_outbox ON notification_outbox");
    expect((await post(wazuh("wz-rb")).expect(202)).body.status).toBe("ingested");
    expect(await alertCount()).toBe(1);
    expect(await jobs()).toHaveLength(2);
    // The Postgres error (whose detail can hold the failing row) was not dumped to the log.
    expectNoSecretsLogged();
  });

  it("an asset upsert failure also rolls back the alert rather than answering 202 for half the work", async () => {
    await query(`CREATE OR REPLACE FUNCTION legion_test_fail() RETURNS trigger LANGUAGE plpgsql AS
                 $$ BEGIN RAISE EXCEPTION 'simulated asset failure'; END $$`);
    await query("CREATE TRIGGER fail_assets BEFORE INSERT ON assets FOR EACH ROW EXECUTE FUNCTION legion_test_fail()");
    await post(wazuh("wz-asset")).expect(500);
    expect(await alertCount()).toBe(0);
    expect(await jobs()).toEqual([]);
  });

  it("a rejected alert row leaves no orphan jobs", async () => {
    await expect(outbox.insertAlertAndNotify(
      { id: "bad", tenant_id: tenant, title: "t", severity: "nonsense" as never, agent: "Sentinel", status: "open", summary: SENSITIVE_LOG, confidence: 1, ai_explanation: null, explained_at: null, source_ip: null, target: "web-01", mitre_technique: null, source: "wazuh" },
      { asset: { name: "web-01", ip: null, os: null }, realtime: (a) => a }
    )).rejects.toThrow();
    expect(await jobs()).toEqual([]);
    expect(Number((await query("SELECT count(*) FROM assets")).rows[0].count)).toBe(0);
  });
});

// --- delivery failures -------------------------------------------------------

describe("SMTP failure", () => {
  it("a real connection refusal is retried later; the alert and the job are kept", async () => {
    await post(wazuh("wz-smtp")).expect(202);
    // Default sender: nodemailer against a port nobody listens on.
    const report = await outbox.deliverDue({ kind: "alert_email" });
    expect(report).toEqual({ sent: 0, retrying: 1, dead: 0 });
    const [job] = await jobs("alert_email");
    expect(job).toMatchObject({ status: "pending", attempts: 1 });
    expect(job.last_error).toMatch(/ECONNREFUSED|connect/i);
    expect(new Date(job.next_attempt_at).getTime()).toBeGreaterThan(Date.now() + 20_000);
    expect(await alertCount()).toBe(1);
    expectNoSecretsLogged();
  });

  it("the stored reason never contains the SMTP login or password", async () => {
    await post(wazuh("wz-smtp2")).expect(202);
    const smtp = recordingSmtp(1, `535 auth failed for legion-mailer / ${SMTP_PASSWORD} at smtp://legion-mailer:${SMTP_PASSWORD}@mx`);
    await outbox.deliverDue({ kind: "alert_email", send: smtp.send });
    const [job] = await jobs("alert_email");
    expect(job.last_error).toContain("535 auth failed");
    expect(job.last_error).not.toContain(SMTP_PASSWORD);
    expect(job.last_error).not.toContain("legion-mailer");
    expectNoSecretsLogged();
  });

  it("an email outage does not hold back the realtime frame", async () => {
    await post(wazuh("wz-split")).expect(202);
    const redis = recordingRedis();
    await outbox.deliverDue({ send: recordingSmtp(99).send, publish: redis.publish });
    expect(redis.published).toHaveLength(1);
    expect((await jobs()).map((j) => [j.kind, j.status])).toEqual([["alert_email", "pending"], ["realtime_alert", "sent"]]);
  });

  it("a hung mail server is cut off by the attempt timeout and retried, not left holding the lease", async () => {
    await post(wazuh("wz-hang")).expect(202);
    const hang: Sender = () => new Promise(() => {});
    expect(await outbox.deliverDue({ kind: "alert_email", send: hang, attemptTimeoutMs: 50 })).toEqual({ sent: 0, retrying: 1, dead: 0 });
    expect((await jobs("alert_email"))[0]).toMatchObject({ status: "pending", locked_until: null, last_error: expect.stringContaining("timed out") });
  });
});

describe("Redis failure", () => {
  it("a publish failure keeps the frame queued; it is delivered once Redis is back", async () => {
    await post(wazuh("wz-redis")).expect(202);
    const redis = recordingRedis(2, `Redis publish failed: connect ECONNREFUSED redis://:${REDIS_PASSWORD}@10.0.0.9:6379`);
    config.redisUrl = `redis://:${REDIS_PASSWORD}@10.0.0.9:6379`;

    expect(await outbox.deliverDue({ kind: "realtime_alert", publish: redis.publish })).toEqual({ sent: 0, retrying: 1, dead: 0 });
    let [job] = await jobs("realtime_alert");
    expect(job).toMatchObject({ status: "pending", attempts: 1 });
    expect(job.last_error).toContain("ECONNREFUSED");
    expect(job.last_error).not.toContain(REDIS_PASSWORD);
    // Realtime backs off on its own, shorter schedule (base 5 s).
    const wait = new Date(job.next_attempt_at).getTime() - Date.now();
    expect(wait).toBeGreaterThan(2_000);
    expect(wait).toBeLessThan(10_000);

    await timePasses();
    await outbox.deliverDue({ kind: "realtime_alert", publish: redis.publish });
    await timePasses();
    expect(await outbox.deliverDue({ kind: "realtime_alert", publish: redis.publish })).toEqual({ sent: 1, retrying: 0, dead: 0 });
    [job] = await jobs("realtime_alert");
    expect(job).toMatchObject({ status: "sent", attempts: 3, last_error: null });
    expect(redis.published[0]).toMatchObject({ tenantId: tenant, payload: { type: "new_alert", alert: { title: "Brute force (wz-redis)" } } });
    expect(await alertCount()).toBe(1);
    expectNoSecretsLogged();
  });

  it("with REDIS_URL set but no connection, the real publisher reports failure instead of pretending", async () => {
    config.redisUrl = `redis://:${REDIS_PASSWORD}@127.0.0.1:1`;
    await expect(realtime.publishOrThrow(tenant, { type: "x" })).rejects.toThrow("Redis is not connected");
    await post(wazuh("wz-nored")).expect(202);
    expect(await outbox.deliverDue({ kind: "realtime_alert" })).toEqual({ sent: 0, retrying: 1, dead: 0 });
    expect(await alertCount()).toBe(1);
  });

  it("without REDIS_URL (single instance) local delivery is complete delivery", async () => {
    await post(wazuh("wz-single")).expect(202);
    expect(await outbox.deliverDue({ kind: "realtime_alert" })).toEqual({ sent: 1, retrying: 0, dead: 0 });
  });

  const hasRedis = spawnSync("redis-server", ["--version"]).status === 0;
  describe.skipIf(!hasRedis)("against a real Redis that goes down and comes back", () => {
    let proc: ChildProcess | null = null;
    let port = 0;
    const startRedis = async () => {
      proc = spawn("redis-server", ["--port", String(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--requirepass", REDIS_PASSWORD], { stdio: "ignore" });
      await new Promise((r) => setTimeout(r, 300));
    };
    const stopRedis = async () => {
      if (!proc) return;
      const p = proc; proc = null;
      await new Promise<void>((resolve) => { p.once("exit", () => resolve()); p.kill("SIGKILL"); });
    };
    const until = async (cond: () => boolean, ms = 8_000) => {
      const end = Date.now() + ms;
      while (!cond()) { if (Date.now() > end) throw new Error("timed out waiting"); await new Promise((r) => setTimeout(r, 50)); }
    };

    afterEach(async () => { await realtime.closeRealtime(); await stopRedis(); });

    it("Redis dies after ingestion: the frame waits in Postgres and goes out when Redis returns", async () => {
      port = await freePort();
      config.redisUrl = `redis://:${REDIS_PASSWORD}@127.0.0.1:${port}`;
      await startRedis();
      await realtime.initRealtime();
      expect(realtime.realtimeConnected()).toBe(true);

      await stopRedis();
      await until(() => !realtime.realtimeConnected());

      await post(wazuh("wz-real-redis")).expect(202);
      expect(await outbox.deliverDue({ kind: "realtime_alert" })).toEqual({ sent: 0, retrying: 1, dead: 0 });
      expect(await alertCount()).toBe(1);

      await startRedis();
      await until(() => realtime.realtimeConnected());
      await timePasses();
      expect(await outbox.deliverDue({ kind: "realtime_alert" })).toEqual({ sent: 1, retrying: 0, dead: 0 });
      expectNoSecretsLogged();
    }, 30_000);
  });
});

// --- retry & dead letter -----------------------------------------------------

describe("retry and dead-letter", () => {
  it("backoff doubles per failure and is capped", () => {
    expect([1, 2, 3, 4, 5].map((n) => outbox.backoffSeconds(n, 5))).toEqual([5, 10, 20, 40, 80]);
    expect(outbox.backoffSeconds(30, 30)).toBe(3600);
  });

  it("retry → success: delivered exactly once after the server recovers", async () => {
    await post(wazuh("wz-retry")).expect(202);
    const smtp = recordingSmtp(2);
    for (let i = 0; i < 3; i++) { await outbox.deliverDue({ kind: "alert_email", send: smtp.send }); await timePasses(); }
    expect(smtp.delivered).toHaveLength(1);
    expect((await jobs("alert_email"))[0]).toMatchObject({ status: "sent", attempts: 3 });
    // Nothing further happens to a sent job.
    await outbox.deliverDue({ kind: "alert_email", send: smtp.send });
    expect(smtp.calls()).toBe(3);
  });

  it("permanent failure: stops at max attempts, marked dead, alert untouched, never retried again", async () => {
    await post(wazuh("wz-dead")).expect(202);
    const smtp = recordingSmtp(99);
    const redis = recordingRedis(99);
    for (let i = 0; i < 8; i++) { await outbox.deliverDue({ send: smtp.send, publish: redis.publish }); await timePasses(); }
    expect(smtp.calls()).toBe(4); // notifyMaxAttempts
    expect(redis.calls()).toBe(3); // realtimeMaxAttempts
    expect((await jobs()).map((j) => [j.kind, j.status, j.attempts])).toEqual([["alert_email", "dead", 4], ["realtime_alert", "dead", 3]]);
    expect(await alertCount()).toBe(1);

    // Dead letters are visible to the organisation's administrator…
    const tok = `Bearer ${jwt.sign({ sub: admin.id, tenant_id: tenant, token_version: admin.token_version }, config.jwtSecret, { expiresIn: "1h" })}`;
    const list = await request(app).get("/notifications/deliveries").set("Authorization", tok).expect(200);
    expect(list.body.deliveries.filter((d: { status: string }) => d.status === "dead")).toHaveLength(2);
    // …and the payload is not in that listing.
    expect(JSON.stringify(list.body)).not.toContain(SENSITIVE_LOG);
  });

  it("a worker that dies during the final attempt dead-letters the job instead of looping", async () => {
    await post(wazuh("wz-poison")).expect(202);
    await query("UPDATE notification_outbox SET status = 'sending', attempts = max_attempts, locked_until = now() - interval '1 second' WHERE kind = 'alert_email'");
    const smtp = recordingSmtp();
    const report = await outbox.deliverDue({ kind: "alert_email", send: smtp.send });
    expect(report).toEqual({ sent: 0, retrying: 0, dead: 1 });
    expect(smtp.calls()).toBe(0);
    expect((await jobs("alert_email"))[0]).toMatchObject({ status: "dead", last_error: expect.stringContaining("final attempt") });
  });
});

// --- workers -----------------------------------------------------------------

describe("worker restart", () => {
  it("jobs queued while no worker runs are delivered when one starts", async () => {
    Object.assign(config, { smtpHost: "" }); // no email jobs; realtime only, delivered locally
    outbox.stopOutboxWorker();
    for (let i = 0; i < 5; i++) await post(wazuh(`wz-offline-${i}`)).expect(202);
    expect((await outbox.queueMetrics()).pending).toBe(5);

    outbox.startOutboxWorker();
    try {
      const end = Date.now() + 5_000;
      const undelivered = async () => { const m = await outbox.queueMetrics(); return m.pending + m.in_flight; };
      while ((await undelivered()) > 0 && Date.now() < end) await new Promise((r) => setTimeout(r, 50));
      expect((await jobs()).every((j) => j.status === "sent")).toBe(true);
      expect(await jobs()).toHaveLength(5);
    } finally {
      outbox.stopOutboxWorker();
    }
  });

  it("a job whose worker crashed mid-send is reclaimed after its lease and delivered once", async () => {
    await post(wazuh("wz-crash")).expect(202);
    await query("UPDATE notification_outbox SET status = 'sending', attempts = 1, locked_until = now() - interval '1 second' WHERE kind = 'alert_email'");
    const smtp = recordingSmtp();
    expect(await outbox.deliverDue({ kind: "alert_email", send: smtp.send })).toEqual({ sent: 1, retrying: 0, dead: 0 });
    expect((await jobs("alert_email"))[0]).toMatchObject({ status: "sent", attempts: 2 });
  });

  it("a stalled worker that lost its lease cannot overwrite the outcome of the worker that took over", async () => {
    await post(wazuh("wz-stall")).expect(202);
    let release!: (r: { sent: false; reason: "send_failed"; detail: string }) => void;
    const stalled: Sender = () => new Promise((r) => { release = r; });
    const first = outbox.deliverDue({ kind: "alert_email", send: stalled, attemptTimeoutMs: 60_000 });
    // Wait until the first worker is inside its send.
    const end = Date.now() + 3_000;
    while (!release && Date.now() < end) await new Promise((r) => setTimeout(r, 10));
    expect(release).toBeTypeOf("function");

    // Its lease runs out; a second worker takes the job over and succeeds.
    await query("UPDATE notification_outbox SET locked_until = now() - interval '1 second' WHERE kind = 'alert_email'");
    const smtp = recordingSmtp();
    expect(await outbox.deliverDue({ kind: "alert_email", send: smtp.send })).toEqual({ sent: 1, retrying: 0, dead: 0 });

    // The first worker finally returns a failure. It must not flip 'sent' back.
    release({ sent: false, reason: "send_failed", detail: "late failure" });
    expect(await first).toEqual({ sent: 0, retrying: 0, dead: 0 });
    expect((await jobs("alert_email"))[0]).toMatchObject({ status: "sent", attempts: 2, last_error: null });
  });
});

describe("concurrent workers", () => {
  it("four workers over 25 alerts: every job delivered exactly once, all marked sent", async () => {
    for (let i = 0; i < 25; i++) await post(wazuh(`wz-c-${i}`)).expect(202);
    const smtp = recordingSmtp();
    const redis = recordingRedis();
    const slowSend: Sender = async (m) => { await new Promise((r) => setTimeout(r, 5)); return smtp.send(m); };
    const slowPublish: Publisher = async (t, p) => { await new Promise((r) => setTimeout(r, 5)); return redis.publish(t, p); };

    const reports = await Promise.all(Array.from({ length: 4 }, () => outbox.deliverDue({ send: slowSend, publish: slowPublish, limit: 10 })))
      .then(async (first) => [...first, ...(await Promise.all(Array.from({ length: 4 }, () => outbox.deliverDue({ send: slowSend, publish: slowPublish, limit: 10 }))))]);

    expect(smtp.delivered).toHaveLength(25);
    expect(new Set(smtp.delivered.map((m) => m.messageId)).size).toBe(25);
    expect(redis.published).toHaveLength(25);
    expect(new Set(redis.published.map((p) => (p.payload as { alert: { id: string } }).alert.id)).size).toBe(25);
    expect(reports.reduce((n, r) => n + r.sent, 0)).toBe(50);
    expect((await jobs()).every((j) => j.status === "sent" && j.attempts === 1)).toBe(true);
  });
});

// --- health metrics ----------------------------------------------------------

describe("queue health metrics", () => {
  it("reports pending, retrying, dead and the age of the oldest undelivered job", async () => {
    await post(wazuh("m-1")).expect(202);
    await post(wazuh("m-2")).expect(202);
    await query("UPDATE notification_outbox SET created_at = now() - interval '10 minutes' WHERE dedupe_key IN (SELECT id FROM alerts WHERE title LIKE '%m-1%')");
    await outbox.deliverDue({ kind: "realtime_alert", publish: recordingRedis(99).publish });

    const m = await outbox.queueMetrics(tenant);
    expect(m).toMatchObject({ pending: 4, retrying: 2, in_flight: 0, dead: 0 });
    expect(m.oldest_pending_age_seconds).toBeGreaterThanOrEqual(599);
    expect(m.by_kind.realtime_alert).toMatchObject({ pending: 2, retrying: 2 });
    expect(m.by_kind.alert_email).toMatchObject({ pending: 2, retrying: 0 });

    await query("UPDATE notification_outbox SET status = 'dead' WHERE kind = 'realtime_alert'");
    await query("UPDATE notification_outbox SET status = 'sent' WHERE kind = 'alert_email'");
    expect(await outbox.queueMetrics(tenant)).toMatchObject({ pending: 0, dead: 2, oldest_pending_age_seconds: null });
  });

  it("an administrator sees only their own organisation's queue", async () => {
    await post(wazuh("iso-1"), otherTenant).expect(202);
    const tok = `Bearer ${jwt.sign({ sub: admin.id, tenant_id: tenant, token_version: admin.token_version }, config.jwtSecret, { expiresIn: "1h" })}`;
    const res = await request(app).get("/notifications/health").set("Authorization", tok).expect(200);
    expect(res.body).toMatchObject({ pending: 0, dead: 0 });
    expect((await outbox.queueMetrics()).pending).toBe(2);
  });

  it("the platform-wide endpoint exists only with a token, and requires it", async () => {
    await post(wazuh("h-1")).expect(202);
    await request(app).get("/health/outbox").expect(404);
    config.healthMetricsToken = "metrics-token-long-enough";
    await request(app).get("/health/outbox").expect(401);
    await request(app).get("/health/outbox").set("Authorization", "Bearer wrong").expect(401);
    const res = await request(app).get("/health/outbox").set("Authorization", "Bearer metrics-token-long-enough").expect(200);
    expect(res.body).toMatchObject({ pending: 2, dead: 0, by_kind: { alert_email: { pending: 1 }, realtime_alert: { pending: 1 } } });
    // Counts only: no tenant ids, recipients or alert content.
    expect(JSON.stringify(res.body)).not.toMatch(new RegExp(`${tenant}|soc@a\\.io|Brute force`));
  });
});
