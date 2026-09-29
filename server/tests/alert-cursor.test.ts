/**
 * The alert change cursor (alerts.seq) — the property the whole realtime
 * recovery design rests on: a client that remembers "the newest change I have"
 * and asks for everything after it can never miss one.
 *
 * What has to hold, and is proven below against real Postgres:
 *   - numbers are per tenant, gapless, and assigned in COMMIT order (a plain
 *     sequence hands them out in START order, which would let a slow
 *     transaction commit "behind" a client that had already moved past it);
 *   - a duplicate or a rolled-back insert does not use up a number;
 *   - every change (insert OR update) gets a new number; created_seq is fixed;
 *   - a poller running while many writers commit misses nothing;
 *   - the list and its cursor come from one snapshot;
 *   - a database from before this existed is numbered correctly on upgrade.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import pg from "pg";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { app } from "../src/index.js";
import { closePool, migrate, pool, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import type { User } from "../src/types.js";

let tenantA: string, tenantB: string;
let adminA: User, adminB: User, analystA: User;
const savedCatchup = config.alertSyncMaxCatchup;

const auth = (u: User) => ["Authorization", `Bearer ${jwt.sign({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, config.jwtSecret, { expiresIn: "1h" })}`] as const;
const newAlert = (tenant: string, id: string, over: Partial<Parameters<typeof store.insertAlert>[0]> = {}) => ({
  id, tenant_id: tenant, title: `Alert ${id}`, severity: "high" as const, agent: "Sentinel" as const, status: "open" as const,
  summary: "s", confidence: 50, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "test", ...over,
});
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const seqs = async (tenant: string) => (await query("SELECT seq FROM alerts WHERE tenant_id = $1 ORDER BY seq", [tenant])).rows.map((r) => Number(r.seq));

beforeAll(async () => { await migrate(); });
afterAll(async () => { config.alertSyncMaxCatchup = savedCatchup; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  config.alertSyncMaxCatchup = savedCatchup;
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenantA, tenantB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@a.io", password_hash: hash, tenant_id: tenantA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@a.io", password_hash: hash, tenant_id: tenantA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "admin@b.io", password_hash: hash, tenant_id: tenantB, role: "admin", status: "active" });
});

describe("versions are assigned per tenant, gapless, in commit order", () => {
  it("numbers each tenant's alerts 1, 2, 3… independently", async () => {
    const a1 = await store.insertAlert(newAlert(tenantA, "a1"));
    const a2 = await store.insertAlert(newAlert(tenantA, "a2"));
    const b1 = await store.insertAlert(newAlert(tenantB, "b1"));
    expect([a1!.seq, a2!.seq, b1!.seq]).toEqual([1, 2, 1]);
    expect([a1!.created_seq, a2!.created_seq]).toEqual([1, 2]);
    expect(await store.alertCursor(tenantA)).toBe(2);
    expect(await store.alertCursor(tenantB)).toBe(1);
  });

  it("every change is a new version; the creation version never moves", async () => {
    const a = (await store.insertAlert(newAlert(tenantA, "a")))!;
    await store.insertAlert(newAlert(tenantA, "other"));
    const resolved = (await store.updateAlertStatus(tenantA, "a", "resolved"))!;
    const explained = (await store.setAlertExplanation(tenantA, "a", "text", "en", "local"))!;
    expect(resolved.seq).toBe(3);
    expect(explained.seq).toBe(4);
    expect([resolved.created_seq, explained.created_seq]).toEqual([a.created_seq, a.created_seq]);
    expect(await store.alertCursor(tenantA)).toBe(4);
  });

  it("a duplicate does not use up a version, and tells the caller it was a duplicate", async () => {
    await store.insertAlert(newAlert(tenantA, "dup"));
    expect(await store.insertAlert(newAlert(tenantA, "dup"))).toBeNull();
    expect(await store.insertAlert(newAlert(tenantA, "dup"))).toBeNull();
    expect(await store.alertCursor(tenantA)).toBe(1);
    expect((await store.insertAlert(newAlert(tenantA, "next")))!.seq).toBe(2);
  });

  it("identical inserts racing each other create one alert and burn nothing beyond it", async () => {
    const results = await Promise.all(Array.from({ length: 12 }, () => store.insertAlert(newAlert(tenantA, "race"))));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await seqs(tenantA)).toEqual([1]);
    expect((await store.insertAlert(newAlert(tenantA, "after")))!.seq).toBe(await store.alertCursor(tenantA));
  });

  it("a rolled-back alert takes its version with it: no gap, and the next one reuses the number", async () => {
    await store.insertAlert(newAlert(tenantA, "kept"));
    await query(`CREATE OR REPLACE FUNCTION legion_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated failure'; END $$`);
    await query("CREATE TRIGGER fail_outbox BEFORE INSERT ON notification_outbox FOR EACH ROW EXECUTE FUNCTION legion_test_fail()");
    try {
      await expect(outbox.insertAlertAndNotify(newAlert(tenantA, "doomed"), { realtime: (a) => a })).rejects.toThrow();
    } finally {
      await query("DROP TRIGGER fail_outbox ON notification_outbox");
    }
    expect(await store.alertCursor(tenantA)).toBe(1);
    expect((await store.insertAlert(newAlert(tenantA, "next")))!.seq).toBe(2);
    expect(await seqs(tenantA)).toEqual([1, 2]);
  });

  it("versions become visible in the order they were assigned, even when a slow transaction is still open", async () => {
    // Transaction A gets version 1 and stays open. B starts later and must wait
    // for A: it cannot commit version 2 "in front of" A's version 1.
    const a = await pool.connect();
    try {
      await a.query("BEGIN");
      await a.query(
        `INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary, confidence, source)
         VALUES ($1, 'slow', 't', 'high', 'Sentinel', 'open', 's', 1, 'test')`, [tenantA]
      );
      let bDone = false;
      const b = store.insertAlert(newAlert(tenantA, "fast")).then((x) => { bDone = true; return x; });
      await sleep(250);
      expect(bDone).toBe(false); // waiting for A's commit
      expect(await store.alertCursor(tenantA)).toBe(0); // nothing committed: nothing to be told about
      expect((await store.syncAlerts(tenantA, 0, 100)).alerts).toEqual([]);

      await a.query("COMMIT");
      const inserted = (await b)!;
      expect(inserted.seq).toBe(2);
      expect((await store.syncAlerts(tenantA, 0, 100)).alerts.map((x) => [x.id, x.seq])).toEqual([["slow", 1], ["fast", 2]]);
    } finally {
      a.release();
    }
  });
});

describe("a poller never misses a change, however many writers are running", () => {
  it("40 concurrent inserts and 20 concurrent updates: every version seen exactly once, none skipped", async () => {
    let cursor = 0;
    const seen = new Map<string, number>(); // id -> newest version seen
    const versionsSeen: number[] = [];
    let stop = false;
    const poller = (async () => {
      while (!stop) {
        const res = await store.syncAlerts(tenantA, cursor, 25);
        for (const a of res.alerts) { versionsSeen.push(a.seq); seen.set(a.id, a.seq); }
        cursor = res.cursor;
        if (!res.has_more) await sleep(2);
      }
    })();

    const ids = Array.from({ length: 40 }, (_, i) => `c${i}`);
    await Promise.all(ids.map((id) => store.insertAlert(newAlert(tenantA, id))));
    await Promise.all(ids.slice(0, 20).map((id) => store.updateAlertStatus(tenantA, id, "resolved")));

    // Let the poller drain, then stop it.
    const final = await store.alertCursor(tenantA);
    const deadline = Date.now() + 8_000;
    while (cursor < final && Date.now() < deadline) await sleep(10);
    stop = true;
    await poller;

    expect(final).toBe(60);
    expect(cursor).toBe(60);
    // The poller's picture of the world is the database's, alert by alert.
    const db = new Map((await query("SELECT id, seq FROM alerts WHERE tenant_id = $1", [tenantA])).rows.map((r) => [r.id as string, Number(r.seq)]));
    expect(seen).toEqual(db);
    // Versions arrive in increasing order and never repeat.
    expect(versionsSeen).toEqual([...versionsSeen].sort((x, y) => x - y));
    expect(new Set(versionsSeen).size).toBe(versionsSeen.length);
  });

  it("the versions handed out are exactly 1..n with no holes", async () => {
    await Promise.all(Array.from({ length: 50 }, (_, i) => store.insertAlert(newAlert(tenantA, `d${i}`))));
    expect(await seqs(tenantA)).toEqual(Array.from({ length: 50 }, (_, i) => i + 1));
  });

  it("the list and its cursor come from one snapshot: nothing at or below the cursor is ever absent", async () => {
    const writers = Promise.all(Array.from({ length: 40 }, (_, i) => store.insertAlert(newAlert(tenantA, `w${i}`))));
    const readers = await Promise.all(Array.from({ length: 30 }, () => store.listAlertsWithCursor(tenantA, { limit: 500 })));
    await writers;
    for (const { alerts, cursor } of readers) {
      const have = new Set(alerts.map((a) => a.seq));
      for (let s = 1; s <= cursor; s++) expect(have.has(s), `seq ${s} missing from a snapshot at cursor ${cursor}`).toBe(true);
      expect(Math.max(0, ...have)).toBeLessThanOrEqual(cursor);
    }
  });
});

describe("GET /alerts/sync", () => {
  beforeEach(async () => {
    for (const id of ["s1", "s2", "s3", "s4", "s5"]) await store.insertAlert(newAlert(tenantA, id));
    await store.insertAlert(newAlert(tenantB, "b-secret", { title: "TENANT B SECRET" }));
  });

  it("requires a signed-in user", async () => {
    await request(app).get("/alerts/sync?after=0").expect(401);
    await request(app).get("/alerts/feed").expect(401);
  });

  it("returns changes after the cursor, oldest first, with the new cursor — and is never cacheable", async () => {
    const res = await request(app).get("/alerts/sync?after=2").set(...auth(adminA)).expect(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.body.alerts.map((a: { id: string; seq: number }) => [a.id, a.seq])).toEqual([["s3", 3], ["s4", 4], ["s5", 5]]);
    expect(res.body).toMatchObject({ cursor: 5, has_more: false, reset: false });
    expect(res.body.alerts[0]).toMatchObject({ created_seq: 3, suggested_actions: expect.any(Array) });
  });

  it("nothing new is an empty page at the same cursor", async () => {
    const res = await request(app).get("/alerts/sync?after=5").set(...auth(adminA)).expect(200);
    expect(res.body).toEqual({ alerts: [], cursor: 5, has_more: false, reset: false });
  });

  it("pages: the cursor reported is the last version in the page until the end", async () => {
    const first = await request(app).get("/alerts/sync?after=0&limit=2").set(...auth(adminA)).expect(200);
    expect(first.body).toMatchObject({ cursor: 2, has_more: true });
    const second = await request(app).get(`/alerts/sync?after=${first.body.cursor}&limit=2`).set(...auth(adminA)).expect(200);
    expect(second.body).toMatchObject({ cursor: 4, has_more: true });
    const third = await request(app).get(`/alerts/sync?after=${second.body.cursor}&limit=2`).set(...auth(adminA)).expect(200);
    expect(third.body).toMatchObject({ cursor: 5, has_more: false });
    expect([...first.body.alerts, ...second.body.alerts, ...third.body.alerts].map((a: { id: string }) => a.id)).toEqual(["s1", "s2", "s3", "s4", "s5"]);
  });

  it("an updated alert appears once, as its latest version", async () => {
    await store.updateAlertStatus(tenantA, "s2", "resolved");
    await store.updateAlertStatus(tenantA, "s2", "investigating");
    const res = await request(app).get("/alerts/sync?after=1").set(...auth(adminA)).expect(200);
    const s2 = res.body.alerts.filter((a: { id: string }) => a.id === "s2");
    expect(s2).toHaveLength(1);
    expect(s2[0]).toMatchObject({ status: "investigating", seq: 7, created_seq: 2 });
  });

  it("tells a client that is too far behind to reload instead of paging", async () => {
    config.alertSyncMaxCatchup = 3;
    const res = await request(app).get("/alerts/sync?after=0").set(...auth(adminA)).expect(200);
    expect(res.body).toEqual({ alerts: [], cursor: 5, has_more: false, reset: true });
    config.alertSyncMaxCatchup = savedCatchup;
    await request(app).get("/alerts/sync?after=3").set(...auth(adminA)).expect(200);
  });

  it("tells a client whose cursor is from the future (a restored database) to reload", async () => {
    const res = await request(app).get("/alerts/sync?after=999").set(...auth(adminA)).expect(200);
    expect(res.body).toMatchObject({ reset: true, cursor: 5 });
  });

  it("never returns another organisation's alerts, whatever cursor is asked for", async () => {
    for (const after of [0, 1, 5]) {
      const res = await request(app).get(`/alerts/sync?after=${after}`).set(...auth(adminA)).expect(200);
      expect(JSON.stringify(res.body)).not.toContain("SECRET");
    }
    const b = await request(app).get("/alerts/sync?after=0").set(...auth(adminB)).expect(200);
    expect(b.body.alerts.map((a: { id: string }) => a.id)).toEqual(["b-secret"]);
    expect(b.body.cursor).toBe(1);
  });

  it.each(["", "?after=-1", "?after=abc", "?after=1.5", "?after=0&limit=0", "?after=0&limit=501", "?after=99999999999999999999"])("refuses malformed parameters %j", async (qs) => {
    const res = await request(app).get(`/alerts/sync${qs}`).set(...auth(adminA));
    expect(res.status).toBe(422);
  });
});

describe("GET /alerts/feed", () => {
  it("returns the list and the cursor it corresponds to, filtered like /alerts, newest first", async () => {
    await store.insertAlert(newAlert(tenantA, "low1", { severity: "low" }));
    await store.insertAlert(newAlert(tenantA, "high1", { severity: "high" }));
    await store.insertAlert(newAlert(tenantA, "high2", { severity: "high" }));
    const feed = await request(app).get("/alerts/feed?severity=high").set(...auth(adminA)).expect(200);
    expect(feed.headers["cache-control"]).toBe("no-store");
    expect(feed.body.cursor).toBe(3);
    expect(feed.body.alerts.map((a: { id: string }) => a.id)).toEqual(["high2", "high1"]);
    // The plain list is unchanged: still an array, still the same order.
    const list = await request(app).get("/alerts").set(...auth(adminA)).expect(200);
    expect(Array.isArray(list.body)).toBe(true);
    expect(list.body.map((a: { id: string }) => a.id)).toEqual(["high2", "high1", "low1"]);
  });

  it("an empty organisation has cursor 0", async () => {
    const feed = await request(app).get("/alerts/feed").set(...auth(adminB)).expect(200);
    expect(feed.body).toEqual({ alerts: [], cursor: 0 });
  });

  it("changes made through the API by another user show up as new versions", async () => {
    await store.insertAlert(newAlert(tenantA, "x"));
    const before = (await request(app).get("/alerts/feed").set(...auth(adminA))).body.cursor;
    await request(app).patch("/alerts/x/status").set(...auth(analystA)).send({ status: "resolved" }).expect(200);
    const sync = await request(app).get(`/alerts/sync?after=${before}`).set(...auth(adminA)).expect(200);
    expect(sync.body.alerts).toHaveLength(1);
    expect(sync.body.alerts[0]).toMatchObject({ id: "x", status: "resolved", seq: before + 1, created_seq: 1 });
  });
});

describe("upgrading a database that has alerts but no versions", () => {
  const schemaPath = fileURLToPath(new URL("../src/db/schema.sql", import.meta.url));
  const fullSchema = readFileSync(schemaPath, "utf8");
  // Everything before the change-cursor block: the schema as it was.
  const oldSchema = fullSchema.slice(0, fullSchema.indexOf("-- Alert change cursor (realtime reliability)."));
  const dbName = `legion_upgrade_${randomUUID().slice(0, 8)}`;

  function urlFor(database: string): string {
    const u = new URL(config.databaseUrl);
    u.pathname = `/${database}`;
    return u.toString();
  }

  it("numbers existing alerts in creation order, keeps counters right, and is safe to run again", async () => {
    const admin = new pg.Client({ connectionString: urlFor("postgres") });
    await admin.connect();
    await admin.query(`CREATE DATABASE ${dbName}`);
    const db = new pg.Client({ connectionString: urlFor(dbName) });
    try {
      await db.connect();
      await db.query(oldSchema);
      expect(oldSchema).not.toContain("alert_seq");

      const t1 = randomUUID(), t2 = randomUUID();
      await db.query("INSERT INTO tenants (id, name) VALUES ($1, 'one'), ($2, 'two')", [t1, t2]);
      // Inserted out of creation order, with ties on created_at.
      const rows: Array<[string, string, string]> = [
        [t1, "late", "2026-09-29T10:00:03Z"], [t1, "early", "2026-09-29T10:00:01Z"], [t1, "tie-b", "2026-09-29T10:00:02Z"],
        [t1, "tie-a", "2026-09-29T10:00:02Z"], [t2, "solo", "2026-09-29T09:00:00Z"],
      ];
      for (const [t, id, at] of rows) {
        await db.query(
          `INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary, confidence, source, created_at)
           VALUES ($1, $2, 't', 'high', 'Sentinel', 'open', 's', 1, 'test', $3)`, [t, id, at]
        );
      }

      await db.query(fullSchema); // the upgrade
      const numbered = async () => (await db.query("SELECT tenant_id, id, seq, created_seq FROM alerts ORDER BY tenant_id, seq")).rows;
      const first = await numbered();
      const byTenant = (t: string) => first.filter((r) => r.tenant_id === t).map((r) => [r.id, Number(r.seq), Number(r.created_seq)]);
      expect(byTenant(t1)).toEqual([["early", 1, 1], ["tie-a", 2, 2], ["tie-b", 3, 3], ["late", 4, 4]]);
      expect(byTenant(t2)).toEqual([["solo", 1, 1]]);
      const counters = (await db.query("SELECT id, alert_seq FROM tenants")).rows.map((r) => [r.id, Number(r.alert_seq)]);
      expect(new Map(counters as Array<[string, number]>)).toEqual(new Map([[t1, 4], [t2, 1]]));

      // Running the schema again (every boot of every instance does) changes nothing.
      await db.query(fullSchema);
      expect(await numbered()).toEqual(first);

      // New writes continue from the counter, and updates bump it.
      await db.query(
        `INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary, confidence, source)
         VALUES ($1, 'new', 't', 'high', 'Sentinel', 'open', 's', 1, 'test')`, [t1]
      );
      await db.query("UPDATE alerts SET status = 'resolved' WHERE tenant_id = $1 AND id = 'early'", [t1]);
      const after = (await db.query("SELECT id, seq, created_seq FROM alerts WHERE tenant_id = $1 AND id IN ('new', 'early') ORDER BY id", [t1])).rows;
      expect(after.map((r) => [r.id, Number(r.seq), Number(r.created_seq)])).toEqual([["early", 6, 1], ["new", 5, 5]]);
      expect(Number((await db.query("SELECT alert_seq FROM tenants WHERE id = $1", [t1])).rows[0].alert_seq)).toBe(6);
    } finally {
      await db.end().catch(() => {});
      await admin.query(`DROP DATABASE IF EXISTS ${dbName}`);
      await admin.end();
    }
  });
});
