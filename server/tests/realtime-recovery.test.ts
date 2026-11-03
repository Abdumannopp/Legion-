/**
 * Realtime alerts survive Redis, socket and server failures — end to end.
 *
 * This runs the REAL client (frontend/lib/realtime/alert-sync.ts, unmodified)
 * against the REAL server: real Postgres, real WebSockets, real HTTP, a real
 * Redis that is killed and restarted, and a server that is taken down and
 * brought back on the same port. Nothing about the socket is assumed to be
 * complete; the assertion is always the same — the client's view ends up
 * identical to what the database holds, each change delivered once.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import request from "supertest";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createServer, type AddressInfo, type Socket } from "node:net";
import { randomUUID } from "node:crypto";
import { app, httpServer } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import * as realtime from "../src/realtime.js";
import type { Alert, User } from "../src/types.js";
import { AlertSyncClient, type FeedEvent, type SocketLike, type SyncResponse, type SyncedAlert } from "../../frontend/lib/realtime/alert-sync.js";
import { upsertAlert, sortAlerts } from "../../frontend/lib/realtime/alert-feed.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

type A = Alert & SyncedAlert;

let tenant: string, otherTenant: string;
let user: User;
let cred: TestCredential;
let port = 0;
let baseUrl = "";
const connections = new Set<Socket>();
const saved = { redisUrl: config.redisUrl, wsHeartbeatSeconds: config.wsHeartbeatSeconds };

const token = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const until = async (cond: () => boolean | Promise<boolean>, ms = 10_000, what = "condition") => {
  const end = Date.now() + ms;
  while (!(await cond())) { if (Date.now() > end) throw new Error(`timed out waiting for ${what}`); await sleep(25); }
};
const freePort = () => new Promise<number>((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => { const { port: p } = s.address() as AddressInfo; s.close(() => resolve(p)); });
});

const wazuh = (id: string, level = 10) => ({ provider: "wazuh", event: { id, rule: { description: `Event ${id}`, level }, agent: { name: "web-01" } } });
/** What the server's own webhook does, then the outbox worker publishing the frame. */
const ingest = async (id: string, publish = true) => {
  const res = await sendSigned(app, cred, wazuh(id)).expect(202);
  if (publish) await outbox.deliverDue({ kind: "realtime_alert" });
  return res.body.alert_id as string;
};
const dbAlerts = async (): Promise<A[]> => sortAlerts((await store.listAlerts(tenant, { limit: 500 })) as A[]);
const cursorNow = () => store.alertCursor(tenant);

// --- a browser tab, as the real client sees it ------------------------------------

interface Tab {
  client: AlertSyncClient<A>;
  view: () => A[];
  events: FeedEvent<A>[];
  frames: string[];
  sockets: WebSocket[];
  resets: number;
  /** While true, nothing gets through: no WebSocket, no HTTP (a network outage). */
  offline: boolean;
  /** While true only the WebSocket is blocked (a proxy that breaks upgrades); HTTP works. */
  wsBlocked: boolean;
  load: () => Promise<void>;
  stop: () => void;
  delivered: () => string[];
  converged: () => Promise<boolean>;
}
const tabs: Tab[] = [];

function openTab(over: { reconcileMs?: number; offlinePollMs?: number; gapGraceMs?: number; watchdogMs?: number } = {}): Tab {
  let view: A[] = [];
  const events: FeedEvent<A>[] = [];
  const frames: string[] = [];
  const sockets: WebSocket[] = [];
  const headers = { Authorization: `Bearer ${token(user)}` };
  const tab: Tab = {
    events, frames, sockets, resets: 0, offline: false, wsBlocked: false,
    view: () => view,
    delivered: () => events.map((e) => `${e.alert.id}@${e.alert.seq}`),
    stop: () => client.stop(),
    load: async () => {
      if (tab.offline) throw new Error("network down");
      const r = await fetch(`${baseUrl}/alerts/feed?limit=500`, { headers });
      const body = (await r.json()) as { alerts: A[]; cursor: number };
      view = sortAlerts(body.alerts);
      client.setBaseline(body.cursor);
    },
    converged: async () => JSON.stringify(view.map((a) => [a.id, a.seq, a.status])) === JSON.stringify((await dbAlerts()).map((a) => [a.id, a.seq, a.status])),
    client: undefined as unknown as AlertSyncClient<A>,
  };
  const client = new AlertSyncClient<A>({
    connect: () => {
      // Port 1 refuses connections: what the browser sees when the network is down.
      const ws = new WebSocket(`ws://127.0.0.1:${tab.offline || tab.wsBlocked ? 1 : port}/ws/alerts`, { headers: { cookie: `legion_token=${token(user)}`, origin: "http://localhost:3000" } });
      ws.on("message", (m) => frames.push(String(m)));
      ws.on("error", () => {}); // a refused connection is an expected part of these tests
      sockets.push(ws);
      return ws as unknown as SocketLike;
    },
    fetchSync: async (after, signal): Promise<SyncResponse<A>> => {
      if (tab.offline) throw new Error("network down");
      const r = await fetch(`${baseUrl}/alerts/sync?after=${after}&limit=200`, { headers, signal });
      if (!r.ok) throw new Error(`sync ${r.status}`);
      return (await r.json()) as SyncResponse<A>;
    },
    onEvent: (e) => { events.push(e); view = upsertAlert(view, e.alert, { insert: e.type === "new_alert" }); },
    onReset: async () => { tab.resets++; await tab.load(); },
    // Short timers so the tests run in seconds; the logic is the same.
    reconcileMs: over.reconcileMs ?? 400, offlinePollMs: over.offlinePollMs ?? 150,
    watchdogMs: over.watchdogMs ?? 5_000, backoffBaseMs: 40, backoffMaxMs: 250, gapGraceMs: over.gapGraceMs ?? 80,
  });
  tab.client = client;
  tabs.push(tab);
  return tab;
}
async function startTab(over: Parameters<typeof openTab>[0] = {}): Promise<Tab> {
  const t = openTab(over);
  t.client.start();
  await until(() => t.sockets[0]?.readyState === WebSocket.OPEN, 5_000, "the socket to open");
  await t.load();
  return t;
}

// --- server lifecycle ---------------------------------------------------------------

async function listen(p = 0): Promise<void> {
  await new Promise<void>((resolve) => httpServer.listen(p, "127.0.0.1", () => resolve()));
  port = (httpServer.address() as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;
}
/** A server restart as its clients experience it: every connection is cut, the port goes quiet. */
async function stopServer(): Promise<void> {
  for (const c of connections) c.destroy();
  connections.clear();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
}

beforeAll(async () => {
  await migrate();
  httpServer.on("connection", (s: Socket) => { connections.add(s); s.on("close", () => connections.delete(s)); });
  await listen();
});
afterAll(async () => {
  realtime.stopHeartbeat();
  await stopServer().catch(() => {});
  await sleep(250); // let requests that were already running finish before the pool goes
  Object.assign(config, saved);
  await closePool();
});
beforeEach(async () => {
  await truncateAll();
  Object.assign(config, { redisUrl: "", notifyMaxAttempts: 4, alertEmailMinSeverity: "off" });
  tenant = randomUUID(); otherTenant = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenant, otherTenant]);
  user = await store.insertUser({ email: "analyst@a.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenant, role: "analyst", status: "active" });
  cred = await issueCredential(tenant);
  realtime.stopHeartbeat();
});
afterEach(async () => {
  for (const t of tabs.splice(0)) { t.stop(); for (const s of t.sockets) s.terminate(); }
  realtime.stopHeartbeat();
  await sleep(100);
  if (!httpServer.listening) await listen(port);
});

// --- the protocol itself --------------------------------------------------------------

describe("what the server sends", () => {
  const raw = async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/alerts`, { headers: { cookie: `legion_token=${token(user)}`, origin: "http://localhost:3000" } });
    const frames: Array<Record<string, unknown>> = [];
    ws.on("message", (m) => frames.push(JSON.parse(String(m))));
    await new Promise((resolve, reject) => { ws.once("open", resolve); ws.once("error", reject); });
    return { ws, frames };
  };

  it("says hello with the current cursor as soon as a socket connects", async () => {
    await ingest("h1", false); await ingest("h2", false);
    const { ws, frames } = await raw();
    await until(() => frames.length > 0, 3_000, "hello");
    expect(frames[0]).toEqual({ type: "hello", cursor: 2 });
    ws.close();
  });

  it("alert frames carry the alert's version", async () => {
    const { ws, frames } = await raw();
    await ingest("v1");
    await until(() => frames.some((f) => f.type === "new_alert"), 3_000, "the alert frame");
    const f = frames.find((x) => x.type === "new_alert") as { alert: { seq: number; created_seq: number; id: string } };
    expect(f.alert).toMatchObject({ seq: 1, created_seq: 1 });
    ws.close();
  });

  it("a heartbeat carries the cursor from Postgres, to that tenant's sockets only", async () => {
    const mine = await raw();
    await ingest("p1", false);
    await realtime.heartbeatOnce(store.listTenantCursors);
    await until(() => mine.frames.some((f) => f.type === "ping"), 3_000, "a ping");
    expect(mine.frames.find((f) => f.type === "ping")).toEqual({ type: "ping", cursor: 1 });
    mine.ws.close();
  });

  it("the heartbeat repeats on its interval and stops when told to", async () => {
    const { ws, frames } = await raw();
    realtime.startHeartbeat(store.listTenantCursors, 60);
    await until(() => frames.filter((f) => f.type === "ping").length >= 3, 3_000, "three pings");
    realtime.stopHeartbeat();
    const n = frames.filter((f) => f.type === "ping").length;
    await sleep(200);
    expect(frames.filter((f) => f.type === "ping").length).toBe(n);
    ws.close();
  });

  it("another organisation's socket hears nothing about this one's alerts or cursor", async () => {
    const other = await store.insertUser({ email: "x@b.io", password_hash: "x", tenant_id: otherTenant, role: "analyst", status: "active" });
    const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/alerts`, { headers: { cookie: `legion_token=${token(other)}`, origin: "http://localhost:3000" } });
    const frames: string[] = [];
    ws.on("message", (m) => frames.push(String(m)));
    await new Promise((resolve) => ws.once("open", resolve));
    await ingest("mine-only");
    await realtime.heartbeatOnce(store.listTenantCursors);
    await sleep(300);
    expect(frames.join("")).not.toContain("mine-only");
    expect(frames.map((f) => JSON.parse(f).type)).not.toContain("new_alert");
    ws.close();
  });
});

// --- the scenarios ----------------------------------------------------------------------

describe("normal connection", () => {
  it("live alerts arrive once, marked new, and the view matches the database", async () => {
    await ingest("before", false);
    const tab = await startTab();
    expect(tab.view().map((a) => a.id)).toEqual((await dbAlerts()).map((a) => a.id));
    await ingest("live-1"); await ingest("live-2");
    await until(() => tab.delivered().length === 2, 5_000, "two live events");
    expect(tab.events.map((e) => [e.alert.title, e.type, e.source])).toEqual([["Event live-1", "new_alert", "live"], ["Event live-2", "new_alert", "live"]]);
    await until(() => tab.converged(), 3_000, "convergence");
  });

  it("a status change made through the API reaches the tab as an update", async () => {
    const id = await ingest("s1");
    const tab = await startTab();
    await request(app).patch(`/alerts/${id}/status`).set("Authorization", `Bearer ${token(user)}`).send({ status: "resolved" }).expect(200);
    await until(() => tab.view()[0]?.status === "resolved", 5_000, "the update");
    expect(tab.events.at(-1)).toMatchObject({ type: "alert.status_updated" });
  });
});

describe("disconnect and reconnect", () => {
  it("alerts that arrive while a tab is disconnected appear when it reconnects, with nothing repeated", async () => {
    await ingest("a0");
    const tab = await startTab();
    await ingest("a1");
    await until(() => tab.delivered().length === 1, 5_000, "the first live alert");

    tab.offline = true;
    for (const s of tab.sockets) s.terminate(); // the network drops
    await until(() => !tab.client.state.connected, 3_000, "the drop to be noticed");
    await ingest("gap-1"); await ingest("gap-2"); // frames published to nobody
    await request(app).patch(`/alerts/${(await dbAlerts()).find((a) => a.title === "Event a0")!.id}/status`).set("Authorization", `Bearer ${token(user)}`).send({ status: "investigating" }).expect(200);
    await sleep(300); // still offline: nothing can have arrived
    expect(tab.delivered()).toHaveLength(1);

    tab.offline = false; // the network is back
    await until(() => tab.converged(), 8_000, "the tab to catch up");
    expect(new Set(tab.delivered()).size).toBe(tab.delivered().length);
    expect(tab.events.filter((e) => e.source === "sync").map((e) => e.alert.title)).toEqual(expect.arrayContaining(["Event gap-1", "Event gap-2", "Event a0"]));
    expect(tab.sockets.length).toBeGreaterThan(1);
    expect(tab.client.state.cursor).toBe(await cursorNow());
  });

  it("with the WebSocket blocked (a proxy that breaks upgrades) but HTTP working, polling still delivers everything", async () => {
    const tab = await startTab({ offlinePollMs: 120 });
    tab.wsBlocked = true;
    for (const s of tab.sockets) s.terminate();
    await until(() => !tab.client.state.connected, 3_000, "the drop");
    await ingest("polled-1"); await ingest("polled-2");
    await until(() => tab.converged(), 8_000, "polling to deliver");
    expect(tab.client.state.connected).toBe(false); // never came back — and it did not need to
    expect(tab.events.every((e) => e.source === "sync")).toBe(true);
    expect(tab.delivered()).toHaveLength(2);
  });

  it("keeps recovering across repeated disconnects", async () => {
    const tab = await startTab();
    for (let i = 0; i < 4; i++) {
      tab.offline = true;
      for (const s of tab.sockets) s.terminate();
      await ingest(`round-${i}`, false);
      tab.offline = false;
      await until(() => tab.converged(), 8_000, `round ${i}`);
    }
    expect(new Set(tab.delivered()).size).toBe(tab.delivered().length);
  });
});

describe("missed alerts (no frame ever sent)", () => {
  it("the heartbeat brings back an alert whose frame was never published", async () => {
    const tab = await startTab({ reconcileMs: 60_000, offlinePollMs: 60_000 }); // only the heartbeat can help
    await ingest("silent", false); // committed; the frame job is still queued
    expect(tab.events).toEqual([]);
    realtime.startHeartbeat(store.listTenantCursors, 100);
    await until(() => tab.delivered().length === 1, 5_000, "the heartbeat to trigger a sync");
    expect(tab.events[0]).toMatchObject({ type: "new_alert", source: "sync" });
    expect(await tab.converged()).toBe(true);
  });

  it("with no heartbeat and no socket, the periodic reconciliation still finds it", async () => {
    const tab = await startTab({ reconcileMs: 200, offlinePollMs: 200 });
    await ingest("quiet", false);
    await until(() => tab.delivered().length === 1, 5_000, "the reconciliation");
  });
});

describe("Redis failure", () => {
  const hasRedis = spawnSync("redis-server", ["--version"]).status === 0;
  let proc: ChildProcess | null = null;
  let redisPort = 0;
  const startRedis = async () => {
    proc = spawn("redis-server", ["--port", String(redisPort), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no"], { stdio: "ignore" });
    await sleep(300);
  };
  const stopRedis = async () => {
    if (!proc) return;
    const p = proc; proc = null;
    await new Promise<void>((resolve) => { p.once("exit", () => resolve()); p.kill("SIGKILL"); });
  };
  afterEach(async () => { await realtime.closeRealtime(); await stopRedis(); });

  it.skipIf(!hasRedis)("Redis dies: alerts are still stored and reach the tab; when Redis returns, sockets are told to reconcile", async () => {
    redisPort = await freePort();
    config.redisUrl = `redis://127.0.0.1:${redisPort}`;
    await startRedis();
    await realtime.initRealtime();
    await until(() => realtime.realtimeConnected(), 5_000, "Redis to connect");

    const tab = await startTab();
    await ingest("with-redis");
    await until(() => tab.delivered().length === 1, 5_000, "a frame through Redis");

    await stopRedis(); // Redis is gone
    await until(() => !realtime.realtimeConnected(), 5_000, "the outage to be noticed");

    // This instance still serves its own sockets directly, so this tab hears it live…
    const during = await ingest("during-outage");
    expect((await store.getAlert(tenant, during))!.seq).toBe(2); // stored and versioned regardless
    await until(() => tab.delivered().length === 2, 5_000, "local delivery during the outage");
    expect(tab.events.at(-1)).toMatchObject({ source: "live" });
    // …but a frame that never reaches this tab (it was on another instance, or the
    // frame was lost) has to come from Postgres. Nothing is published for this one.
    await ingest("lost-frame", false);
    expect(tab.delivered()).toHaveLength(2);

    realtime.startHeartbeat(store.listTenantCursors, 100); // Postgres-fed, independent of Redis
    await until(() => tab.delivered().length === 3, 8_000, "recovery without Redis");
    expect(tab.events.at(-1)).toMatchObject({ source: "sync" });
    expect(tab.events.at(-1)!.alert.title).toBe("Event lost-frame");

    await startRedis(); // Redis returns
    await until(() => realtime.realtimeConnected(), 10_000, "Redis to reconnect");
    await until(() => tab.frames.some((f) => JSON.parse(f).type === "resync"), 5_000, "the resync signal");
    // The frame job that failed while Redis was down is retried and arrives late.
    await query("UPDATE notification_outbox SET next_attempt_at = now() WHERE status = 'pending'");
    await outbox.deliverDue({ kind: "realtime_alert" });
    await sleep(300);
    expect(new Set(tab.delivered()).size).toBe(tab.delivered().length); // and is recognised as already handled
    expect(await tab.converged()).toBe(true);
  }, 40_000);

  it.skipIf(!hasRedis)("Redis restarting again and again never loses an alert", async () => {
    redisPort = await freePort();
    config.redisUrl = `redis://127.0.0.1:${redisPort}`;
    await startRedis();
    await realtime.initRealtime();
    const tab = await startTab();
    realtime.startHeartbeat(store.listTenantCursors, 150);
    for (let i = 0; i < 3; i++) {
      await stopRedis();
      await ingest(`flap-${i}-a`);
      await startRedis();
      await ingest(`flap-${i}-b`);
    }
    await until(() => tab.converged(), 12_000, "convergence after the flapping");
    expect((await dbAlerts()).length).toBe(6);
    expect(new Set(tab.delivered()).size).toBe(tab.delivered().length);
  }, 60_000);
});

describe("backend restart", () => {
  it("clients reconnect on their own after the server comes back and recover what happened while it was down", async () => {
    await ingest("before");
    // Fast polling while disconnected; the relaxed cadence once connected, so the
    // live frame after the restart is not beaten to it by a periodic sync.
    const tab = await startTab({ reconcileMs: 60_000, offlinePollMs: 150 });
    const socketsBefore = tab.sockets.length;

    await stopServer();
    await until(() => !tab.client.state.connected, 5_000, "the outage to be noticed");
    // While it is down, alerts still land in Postgres (another instance, the sensor's retry, a worker).
    await query(`INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary, confidence, source)
                 VALUES ($1, 'while-down-1', 'Down 1', 'high', 'Sentinel', 'open', 's', 1, 'test'),
                        ($1, 'while-down-2', 'Down 2', 'high', 'Sentinel', 'open', 's', 1, 'test')`, [tenant]);
    await sleep(400); // the client keeps trying and failing

    await listen(port); // the server is back on the same address
    await until(async () => (await tab.converged()) && tab.client.state.connected, 10_000, "the tab to recover and reconnect");
    expect(tab.sockets.length).toBeGreaterThan(socketsBefore);
    expect(tab.events.map((e) => e.alert.id).sort()).toEqual(["while-down-1", "while-down-2"]);
    expect(tab.client.state.cursor).toBe(await cursorNow());

    // Live delivery is back too, from a clean in-memory state on the server: the
    // frame reaches the new socket. (A leftover sync retry may legitimately fetch the
    // alert first; either way it is shown exactly once.)
    const framesBefore = tab.frames.length;
    await ingest("after");
    await until(() => tab.frames.slice(framesBefore).some((f) => f.includes("Event after")), 5_000, "the live frame after the restart");
    await until(() => tab.delivered().length === 3, 5_000, "the alert after the restart");
    expect(tab.events.filter((e) => e.alert.title === "Event after")).toHaveLength(1);
  });

  it("versions are in Postgres, so a restarted server continues the sequence instead of starting over", async () => {
    await ingest("one"); await ingest("two");
    await stopServer();
    await listen(port);
    await ingest("three", false);
    expect((await dbAlerts()).map((a) => a.seq).sort()).toEqual([1, 2, 3]);
  });

  it("many tabs recover from the same restart, each on its own", async () => {
    const many = await Promise.all([startTab(), startTab(), startTab(), startTab(), startTab()]);
    await stopServer();
    await ingest("during", false);
    await sleep(200);
    await listen(port);
    await until(async () => (await Promise.all(many.map((t) => t.converged()))).every(Boolean), 12_000, "every tab to converge");
    for (const t of many) expect(t.delivered()).toEqual([`${(await dbAlerts())[0]!.id}@1`]);
  });
});

describe("duplicate events", () => {
  it("the outbox publishing the same frame again does not show the alert twice", async () => {
    const tab = await startTab();
    await ingest("once");
    await until(() => tab.delivered().length === 1, 5_000, "the alert");
    for (let i = 0; i < 3; i++) {
      await query("UPDATE notification_outbox SET status = 'pending', next_attempt_at = now() WHERE kind = 'realtime_alert'");
      await outbox.deliverDue({ kind: "realtime_alert" });
    }
    await sleep(300);
    expect(tab.delivered()).toHaveLength(1);
    expect(tab.view()).toHaveLength(1);
    expect(tab.frames.filter((f) => JSON.parse(f).type === "new_alert").length).toBeGreaterThan(1); // the duplicates really were sent
  });

  it("a sensor retrying the same event creates one alert and one version", async () => {
    const tab = await startTab();
    for (let i = 0; i < 4; i++) await sendSigned(app, cred, wazuh("retry")).expect(202);
    await outbox.deliverDue({ kind: "realtime_alert" });
    await until(() => tab.delivered().length === 1, 5_000, "the alert");
    expect(await cursorNow()).toBe(1);
  });
});

describe("out-of-order events", () => {
  it("frames published newest-first still leave the list in the right order and complete", async () => {
    const tab = await startTab();
    const ids: string[] = [];
    for (const n of ["o1", "o2", "o3", "o4"]) ids.push(await ingest(n, false));
    const all = await dbAlerts();
    // Publish in reverse, by hand.
    for (const a of [...all].reverse()) await realtime.publish(tenant, { type: "new_alert", alert: a });
    await until(() => tab.delivered().length === 4, 5_000, "all four");
    expect(tab.view().map((a) => a.title)).toEqual(all.map((a) => a.title));
    expect(await tab.converged()).toBe(true);
  });

  it("an older version of an alert delivered after a newer one never wins", async () => {
    const id = await ingest("v", false);
    const tab = await startTab();
    const v1 = (await store.updateAlertStatus(tenant, id, "investigating"))!;
    const v2 = (await store.updateAlertStatus(tenant, id, "resolved"))!;
    await realtime.publish(tenant, { type: "alert.status_updated", alert: v2 });
    await realtime.publish(tenant, { type: "alert.status_updated", alert: v1 }); // arrives late
    await until(() => tab.delivered().includes(`${id}@${v2.seq}`), 5_000, "the newest version");
    await sleep(300);
    expect(tab.view()[0]!.status).toBe("resolved");
    // A periodic sync may legitimately have shown v1 first — but never after v2.
    const d = tab.delivered();
    expect(d.filter((x) => x === `${id}@${v2.seq}`)).toHaveLength(1);
    if (d.includes(`${id}@${v1.seq}`)) expect(d.indexOf(`${id}@${v1.seq}`)).toBeLessThan(d.indexOf(`${id}@${v2.seq}`));
    expect(d.at(-1)).toBe(`${id}@${v2.seq}`);
  });
});

describe("multiple browser tabs", () => {
  it("three tabs each converge; killing one does not disturb the others; none shows a duplicate", async () => {
    const [t1, t2, t3] = await Promise.all([startTab(), startTab(), startTab()]);
    await ingest("m1");
    await until(() => [t1, t2, t3].every((t) => t.delivered().length === 1), 5_000, "all tabs to see m1");

    for (const s of t2.sockets) s.terminate();
    await ingest("m2"); await ingest("m3");
    await until(async () => (await Promise.all([t1, t2, t3].map((t) => t.converged()))).every(Boolean), 10_000, "all tabs to converge");
    for (const t of [t1, t2, t3]) expect(new Set(t.delivered()).size).toBe(t.delivered().length);
    expect(t1.events.every((e) => e.source === "live")).toBe(true); // the undisturbed tabs never needed a catch-up
    expect(t3.events.every((e) => e.source === "live")).toBe(true);
    expect(t2.events.some((e) => e.source === "sync")).toBe(true);
  });

  it("a tab opened late starts from the database, not from a frame it never saw", async () => {
    for (const n of ["e1", "e2", "e3"]) await ingest(n);
    const late = await startTab();
    expect(late.view()).toHaveLength(3);
    expect(late.events).toEqual([]);
    await ingest("e4");
    await until(() => late.delivered().length === 1, 5_000, "the next alert");
    expect(await late.converged()).toBe(true);
  });
});

describe("falling too far behind", () => {
  it("reloads the list instead of paging through everything", async () => {
    const savedMax = config.alertSyncMaxCatchup;
    config.alertSyncMaxCatchup = 5;
    try {
      const tab = await startTab();
      for (const s of tab.sockets) s.terminate();
      // One statement, so the client sees either none of it or all of it.
      await query(`INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary, confidence, source)
                   SELECT $1, 'big-' || n, 'Big ' || n, 'high', 'Sentinel', 'open', 's', 1, 'test' FROM generate_series(1, 12) n`, [tenant]);
      await until(() => tab.resets >= 1 && tab.view().length === 12, 10_000, "a reload");
      expect(tab.events).toEqual([]);
      expect(await tab.converged()).toBe(true);
    } finally {
      config.alertSyncMaxCatchup = savedMax;
    }
  });
});
