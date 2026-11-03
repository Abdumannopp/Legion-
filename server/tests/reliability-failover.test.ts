/**
 * Reliability (2026-09) — failure injection against REAL processes.
 *
 * Every scenario runs the actual server (src/index.ts) as child processes,
 * the actual Wazuh integration script (integrations/custom-legion.py), a real
 * Redis where it matters, and the dashboard's own sync client
 * (frontend/lib/realtime/alert-sync.ts) as the "browser tab". Faults are
 * injected from outside, the way they happen in production:
 *
 *   DB restart ............. a TCP proxy in front of Postgres drops every
 *                            connection and refuses new ones, then comes back
 *   app / worker crash ..... SIGKILL (no shutdown handler runs)
 *   Redis restart .......... redis-server killed and started again
 *   SMTP failure ........... a fake mail server that refuses (421) or hangs
 *
 * and the invariant checked every time is the same: every event the sensor
 * produced is stored exactly once, every notification is sent exactly once
 * (counted by Message-ID at the mail server), and the dashboard converges on
 * exactly what PostgreSQL holds.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";
import { AlertSyncClient, type FeedEvent, type SocketLike, type SyncResponse, type SyncedAlert } from "../../frontend/lib/realtime/alert-sync.js";
import { upsertAlert, sortAlerts } from "../../frontend/lib/realtime/alert-feed.js";
import { mint } from "./helpers/tokens.js";
import { issueCredential, type TestCredential } from "./helpers/webhook.js";
import { FakeSmtp, FaultProxy, freePort, killApi, sleep, startApi, stopApi, until, type ApiProcess } from "./helpers/faults.js";

const DB_URL = new URL(process.env.TEST_DATABASE_URL || "postgresql://legion@127.0.0.1:5433/legion_test");
const SCRIPT = join(__dirname, "..", "..", "integrations", "custom-legion.py");
const HAS_PYTHON = spawnSync("python3", ["--version"]).status === 0;
const HAS_REDIS = spawnSync("redis-server", ["--version"]).status === 0;
// CI sets this: there, a missing tool must fail the run, not skip the scenarios.
if (process.env.LEGION_REQUIRE_FAILURE_INJECTION === "1" && (!HAS_PYTHON || !HAS_REDIS)) {
  throw new Error(`failure-injection tests require python3 and redis-server (python3: ${HAS_PYTHON}, redis-server: ${HAS_REDIS})`);
}

let work: string;
let tenant: string; let user: User; let cred: TestCredential;
let smtp: FakeSmtp; let proxy: FaultProxy;
const apis: ApiProcess[] = [];
let redis: ChildProcess | null = null; let redisPort = 0;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  work = mkdtempSync(join(tmpdir(), "legion-failover-"));
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name, notification_email) VALUES ($1, 'SOC', 'soc@acme.example')", [tenant]);
  user = await store.insertUser({ email: "analyst@acme.example", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenant, role: "admin", status: "active" });
  cred = await issueCredential(tenant, "wazuh-prod");
  smtp = await new FakeSmtp().start();
  proxy = await new FaultProxy(DB_URL.hostname, Number(DB_URL.port || 5432)).start();
});
afterEach(async () => {
  for (const t of tabs.splice(0)) { t.client.stop(); for (const s of t.sockets) s.terminate(); }
  for (const a of apis.splice(0)) await stopApi(a).catch(() => {});
  stopRedis();
  await smtp.stop(); await proxy.stop();
  rmSync(work, { recursive: true, force: true });
});

// --- the pieces ----------------------------------------------------------------------------

function dbThroughProxy(): string {
  const u = new URL(DB_URL.toString()); u.hostname = "127.0.0.1"; u.port = String(proxy.port); return u.toString();
}
async function api(env: Record<string, string> = {}): Promise<ApiProcess> {
  const a = await startApi({
    DEPLOYMENT_MODE: "self-hosted", FRONTEND_URL: "http://localhost:3000",
    JWT_SECRET: config.jwtSecret, LEGION_ENCRYPTION_KEYS: config.encryptionKeys,
    DATABASE_URL: dbThroughProxy(), DB_POOL_MAX: "5",
    SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtp.port), SMTP_FROM: "Legion <legion@test.example>",
    ALERT_EMAIL_MIN_SEVERITY: "high",
    // Fast schedules so each scenario runs in seconds; the logic is the production logic.
    NOTIFY_POLL_SECONDS: "1", NOTIFY_RETRY_BASE_SECONDS: "1", REALTIME_RETRY_BASE_SECONDS: "1", WS_HEARTBEAT_SECONDS: "5",
    SETUP_TOKEN_FILE: join(work, "setup-token"), SENSOR_SILENCE_MINUTES: "0",
    ...(redis ? { REDIS_URL: `redis://127.0.0.1:${redisPort}` } : {}),
    ...env,
  });
  apis.push(a);
  return a;
}
const token = () => mint({ sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version }, { expiresIn: "1h" });
const get = (a: ApiProcess, path: string) => fetch(`${a.url}${path}`, { headers: { authorization: `Bearer ${token()}` } });

async function startRedis(): Promise<void> {
  redisPort = redisPort || await freePort();
  redis = spawn("redis-server", ["--port", String(redisPort), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"], { stdio: "ignore" });
  await until(() => spawnSync("redis-cli", ["-p", String(redisPort), "ping"]).stdout?.toString().includes("PONG") ?? false, 5_000, "redis");
}
function stopRedis(): void { redis?.kill("SIGKILL"); redis = null; }

/** One Wazuh alert through the REAL integration script (async: the proxy and
 *  fake SMTP run in this process and must keep serving meanwhile). */
function sensor(a: ApiProcess, id: string, opts: { timestamp?: string; level?: number } = {}): Promise<number> {
  const file = join(work, `alert-${id}.json`);
  writeFileSync(file, JSON.stringify({
    id, timestamp: opts.timestamp, rule: { id: "5712", level: opts.level ?? 12, description: `Brute force ${id}` },
    agent: { name: "web-01", ip: "10.0.0.5" }, full_log: `sshd: failure ${id}`,
  }));
  return runScript([file, cred.apiKey, `${a.url}/security-events/webhook`]);
}
function drain(a: ApiProcess): Promise<number> {
  return runScript(["--drain", cred.apiKey, `${a.url}/security-events/webhook`]);
}
function runScript(args: string[]): Promise<number> {
  return new Promise((resolve) => {
    const p = spawn("python3", [SCRIPT, ...args], {
      env: { ...process.env, LEGION_SPOOL_DIR: join(work, "spool"), LEGION_INTEGRATION_LOG: join(work, "integration.log"),
        LEGION_MAX_ATTEMPTS: "2", LEGION_BACKOFF_SECONDS: "0.2" },
      stdio: "ignore",
    });
    p.on("exit", (code) => resolve(code ?? -1));
  });
}
const integrationLog = () => { try { return readFileSync(join(work, "integration.log"), "utf8"); } catch { return ""; } };

const alertIds = async () => (await query("SELECT id FROM alerts WHERE tenant_id = $1 ORDER BY id", [tenant])).rows.map((r) => r.id as string);
const jobs = async (kind: string) =>
  (await query("SELECT status, count(*)::int AS n FROM notification_outbox WHERE tenant_id = $1 AND kind = $2 GROUP BY status", [tenant, kind])).rows
    .reduce((m, r) => ({ ...m, [r.status as string]: r.n as number }), {} as Record<string, number>);
const dupes = (xs: string[]) => xs.filter((x, i) => xs.indexOf(x) !== i);

// --- a dashboard tab, using the dashboard's own sync logic -------------------------------------

type A = SyncedAlert & { status: string };
interface Tab { client: AlertSyncClient<A>; sockets: WebSocket[]; events: FeedEvent<A>[]; view: () => A[]; target: ApiProcess; load: () => Promise<void> }
const tabs: Tab[] = [];
async function openTab(target: ApiProcess): Promise<Tab> {
  let view: A[] = [];
  const tab = { sockets: [] as WebSocket[], events: [] as FeedEvent<A>[], view: () => view, target } as Tab;
  tab.load = async () => {
    const body = await (await get(tab.target, "/alerts/feed?limit=500")).json() as { alerts: A[]; cursor: number };
    view = sortAlerts(body.alerts); tab.client.setBaseline(body.cursor);
  };
  tab.client = new AlertSyncClient<A>({
    connect: () => {
      const ws = new WebSocket(`ws://127.0.0.1:${tab.target.port}/ws/alerts`, { headers: { cookie: `legion_token=${token()}`, origin: "http://localhost:3000" } });
      ws.on("error", () => {});
      tab.sockets.push(ws);
      return ws as unknown as SocketLike;
    },
    fetchSync: async (after, signal): Promise<SyncResponse<A>> => {
      const r = await fetch(`${tab.target.url}/alerts/sync?after=${after}&limit=200`, { headers: { authorization: `Bearer ${token()}` }, signal });
      if (!r.ok) throw new Error(`sync ${r.status}`);
      return (await r.json()) as SyncResponse<A>;
    },
    onEvent: (e) => { tab.events.push(e); view = upsertAlert(view, e.alert, { insert: e.type === "new_alert" }); },
    onReset: async () => { await tab.load(); },
    reconcileMs: 1_000, offlinePollMs: 300, watchdogMs: 12_000, backoffBaseMs: 100, backoffMaxMs: 500, gapGraceMs: 200,
  });
  tabs.push(tab);
  tab.client.start();
  await until(() => tab.sockets.some((s) => s.readyState === WebSocket.OPEN), 10_000, "the tab's socket");
  await tab.load();
  return tab;
}
async function converged(tab: Tab): Promise<boolean> {
  const db = (await query("SELECT id, seq, status FROM alerts WHERE tenant_id = $1", [tenant])).rows;
  const want = db.map((r) => `${r.id}@${r.seq}:${r.status}`).sort();
  const have = tab.view().map((a) => `${a.id}@${a.seq}:${a.status}`).sort();
  return JSON.stringify(want) === JSON.stringify(have);
}

// --- scenarios ------------------------------------------------------------------------------------

describe.skipIf(!HAS_PYTHON)("database restart during ingestion", () => {
  it("events sent while Postgres is down are spooled by the sensor and land exactly once when it returns", async () => {
    const a = await api();
    for (let i = 0; i < 3; i++) expect(await sensor(a, `before-${i}`)).toBe(0);

    await proxy.cut();                                     // Postgres "restarts"
    const during = new Date(Date.now() - 1000).toISOString();
    for (let i = 0; i < 4; i++) expect(await sensor(a, `during-${i}`, { timestamp: during })).toBe(1);
    expect(integrationLog()).toMatch(/status=503/);        // retryable, not a 500
    expect(integrationLog()).toMatch(/SPOOLED/);
    expect((await fetch(`${a.url}/health`)).status).toBe(503);
    // The API process itself survived the outage.
    expect(a.proc.exitCode).toBeNull();

    await proxy.heal();                                    // back
    await until(async () => (await fetch(`${a.url}/health`)).status === 200, 20_000, "the API to see the database again");
    expect(await sensor(a, "after-0")).toBe(0);            // drains the backlog first, then this one

    const ids = await alertIds();
    expect(ids).toHaveLength(8);
    expect(dupes(ids)).toEqual([]);
    // The spooled events keep when they happened, not when they finally arrived.
    const late = await store.listAlerts(tenant, { q: "during-0" });
    expect(Math.abs(new Date(late[0]!.occurred_at!).getTime() - new Date(during).getTime())).toBeLessThan(1500);

    // Every one of them is emailed exactly once.
    await until(async () => (await jobs("alert_email")).sent === 8, 30_000, "all emails sent").catch(async (e) => { console.log("outbox rows:", JSON.stringify((await query("SELECT dedupe_key, status, attempts, locked_until > now() AS leased, left(last_error, 80) AS err FROM notification_outbox WHERE kind = $1", ["alert_email"])).rows)); throw e; });
    expect(smtp.accepted).toHaveLength(8);
    expect(dupes(smtp.accepted)).toEqual([]);
  }, 120_000);

  it("a database blip in the middle of a burst loses nothing and duplicates nothing", async () => {
    const a = await api();
    const burst = Array.from({ length: 12 }, (_, i) => sensor(a, `burst-${i}`));
    await sleep(150);
    await proxy.cut(); await sleep(1500); await proxy.heal();
    await Promise.all(burst);
    await until(async () => (await fetch(`${a.url}/health`)).status === 200, 20_000, "recovery");
    expect(await drain(a)).toBe(0);
    const ids = await alertIds();
    expect(ids.filter((x) => x.startsWith("SEC-"))).toHaveLength(12);
    expect(dupes(ids)).toEqual([]);
  }, 120_000);
});

describe.skipIf(!HAS_PYTHON)("application crash (SIGKILL) and restart", () => {
  it("work queued when the process dies is delivered by the next process, exactly once", async () => {
    smtp.mode = "failing";                                // mail is down: jobs pile up and retry
    const a = await api();
    for (let i = 0; i < 5; i++) expect(await sensor(a, `crash-${i}`)).toBe(0);
    await until(async () => ((await jobs("alert_email")).pending ?? 0) === 5, 15_000, "5 pending emails");
    await killApi(a);                                      // crash: no shutdown handler, nothing flushed

    smtp.mode = "up";
    const b = await api();                                 // a new process picks up where the old one died
    await until(async () => (await jobs("alert_email")).sent === 5, 30_000, "emails delivered after restart");
    expect(smtp.accepted).toHaveLength(5);
    expect(dupes(smtp.accepted)).toEqual([]);
    expect(await alertIds()).toHaveLength(5);
    void b;
  }, 120_000);

  it("a worker killed in the middle of sending: the job is reclaimed after its lease and sent once", async () => {
    smtp.mode = "hung";                                   // the send starts and never finishes
    const a = await api();
    expect(await sensor(a, "mid-send")).toBe(0);
    await until(async () => ((await jobs("alert_email")).sending ?? 0) === 1, 15_000, "the job to be in flight");
    await killApi(a);                                      // dies holding the lease
    // Fast-forward the lease (120 s in production) instead of waiting it out.
    await query("UPDATE notification_outbox SET locked_until = now() - interval '1 second' WHERE status = 'sending'");
    smtp.resetConnections(); smtp.mode = "up";
    await api();
    await until(async () => (await jobs("alert_email")).sent === 1, 30_000, "the reclaimed job to be sent");
    expect(smtp.accepted).toHaveLength(1);
  }, 120_000);

  it("a SIGKILL in the middle of a burst of webhooks: no partial alert, and the sensor's retries fill every gap", async () => {
    const a = await api();
    const burst = Array.from({ length: 10 }, (_, i) => sensor(a, `k-${i}`));
    await sleep(200);
    await killApi(a);
    await Promise.all(burst);
    const b = await api();
    expect(await drain(b)).toBe(0);
    const ids = await alertIds();
    expect(ids).toHaveLength(10);
    expect(dupes(ids)).toEqual([]);
    // Every stored alert is complete: its asset and its jobs were committed with it.
    const orphans = await query(
      `SELECT count(*)::int AS n FROM alerts a WHERE tenant_id = $1 AND NOT EXISTS
         (SELECT 1 FROM notification_outbox o WHERE o.tenant_id = a.tenant_id AND o.dedupe_key = a.id AND o.kind = 'realtime_alert')`, [tenant]);
    expect(orphans.rows[0].n).toBe(0);
  }, 120_000);
});

describe.skipIf(!HAS_REDIS)("several instances, Redis restart and reconnect", () => {
  it("fan-out across instances; a Redis outage delays frames but the tab never misses or duplicates an alert", async () => {
    await startRedis();
    const a = await api(); const b = await api();
    const tab = await openTab(b);                          // the browser is on B

    // Ingested on A, pushed to the tab on B through Redis.
    const ingestOnA = (id: string) => fetch(`${a.url}/alerts`, {
      method: "POST", headers: { authorization: `Bearer ${token()}`, "content-type": "application/json", origin: "http://localhost:3000" },
      body: JSON.stringify({ id, title: `alert ${id}`, severity: "high", agent: "Sentinel", summary: "s" }),
    }).then((r) => expect(r.status).toBe(201));
    await ingestOnA("R-1");
    await until(() => tab.view().some((x) => x.id === "R-1"), 10_000, "the frame from A to reach the tab on B");

    stopRedis();                                           // Redis goes down
    for (const id of ["R-2", "R-3", "R-4"]) await ingestOnA(id);
    // No Redis: frames cannot fan out, but the tab catches up from Postgres (heartbeat cursor + /alerts/sync).
    await until(() => converged(tab), 20_000, "the tab to converge without Redis");
    await until(async () => ((await jobs("realtime_alert")).pending ?? 0) > 0, 10_000, "frames waiting for Redis");

    await startRedis();                                    // Redis returns: queued frames go out
    await until(async () => ((await jobs("realtime_alert")).pending ?? 0) === 0, 30_000, "queued frames published");
    await sleep(1000);
    expect(await converged(tab)).toBe(true);
    const seen = tab.events.map((e) => `${e.alert.id}@${e.alert.seq}`);
    expect(dupes(seen)).toEqual([]);                       // re-published frames are not shown twice

    // The instance the tab is on crashes; the tab reconnects to the other one and recovers what happened meanwhile.
    await killApi(b);
    await ingestOnA("R-5");
    tab.target = a;
    await until(() => tab.view().some((x) => x.id === "R-5"), 20_000, "the tab to recover R-5 on the other instance");
    expect(await converged(tab)).toBe(true);
  }, 180_000);

  it("the same Wazuh event hitting two instances at once is stored, emailed and pushed exactly once", async () => {
    await startRedis();
    const a = await api(); const b = await api();
    const sends: Promise<number>[] = [];
    for (let i = 0; i < 6; i++) sends.push(sensor(i % 2 ? a : b, "dup-1"));
    const codes = await Promise.all(sends);
    expect(codes.every((c) => c === 0)).toBe(true);        // all accepted: the retries were told "duplicate"
    expect(await alertIds()).toHaveLength(1);
    await until(async () => (await jobs("alert_email")).sent === 1, 20_000, "one email");
    await sleep(1500);
    expect(smtp.accepted).toHaveLength(1);
    expect((await jobs("realtime_alert"))).toEqual({ sent: 1 });
  }, 120_000);
});

describe.skipIf(!HAS_PYTHON)("notification failure and retry exhaustion", () => {
  it("a mail server that stays down exhausts the retries: dead, visible, and requeued after the fix — sent once", async () => {
    smtp.mode = "failing";
    const a = await api({ NOTIFY_MAX_ATTEMPTS: "3" });
    expect(await sensor(a, "exhaust-1")).toBe(0);
    await until(async () => (await jobs("alert_email")).dead === 1, 30_000, "the job to be dead-lettered");
    expect(smtp.accepted).toHaveLength(0);
    const deliveries = await (await get(a, "/notifications/deliveries")).json() as { deliveries: Array<{ status: string; attempts: number; last_error: string }> };
    const dead = deliveries.deliveries.find((d) => d.status === "dead")!;
    expect(dead.attempts).toBe(3);
    expect(dead.last_error).toMatch(/421|not available/i);
    const health = await (await get(a, "/notifications/health")).json() as { dead: number };
    expect(health.dead).toBe(1);
    // The alert itself was never affected.
    expect(await alertIds()).toHaveLength(1);

    smtp.mode = "up";
    const r = await fetch(`${a.url}/notifications/deliveries/retry-dead`, { method: "POST", headers: { authorization: `Bearer ${token()}`, origin: "http://localhost:3000" } });
    expect((await r.json() as { requeued: number }).requeued).toBe(1);
    await until(async () => (await jobs("alert_email")).sent === 1, 20_000, "the requeued job to be sent");
    expect(smtp.accepted).toHaveLength(1);
  }, 120_000);
});

describe.skipIf(!HAS_PYTHON || !HAS_REDIS)("recovery after a total outage", () => {
  it("database, Redis and mail all down while the sensor keeps producing: everything arrives exactly once afterwards", async () => {
    await startRedis();
    const a = await api();
    const tab = await openTab(a);
    expect(await sensor(a, "calm-1")).toBe(0);

    await proxy.cut(); stopRedis(); smtp.mode = "failing";   // everything downstream fails at once
    for (let i = 0; i < 5; i++) expect(await sensor(a, `storm-${i}`)).toBe(1);   // spooled at the sensor
    expect(a.proc.exitCode).toBeNull();

    await proxy.heal(); await startRedis(); smtp.mode = "up";
    await until(async () => (await fetch(`${a.url}/health`)).status === 200, 20_000, "database back");
    expect(await drain(a)).toBe(0);

    expect(await alertIds()).toHaveLength(6);
    await until(async () => (await jobs("alert_email")).sent === 6, 60_000, "all six emails");
    expect(dupes(smtp.accepted)).toEqual([]);
    expect(smtp.accepted).toHaveLength(6);
    await until(() => converged(tab), 30_000, "the dashboard to show exactly what Postgres holds");
    expect(dupes(tab.events.map((e) => `${e.alert.id}@${e.alert.seq}`))).toEqual([]);
  }, 180_000);
});
