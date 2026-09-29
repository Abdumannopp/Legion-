/**
 * The live alert feed under failure (alert-sync.ts).
 *
 * Every test replays a way the realtime path can go wrong and asserts the same
 * thing in the end: the view equals what the database would show, each change
 * was delivered once, and nothing older replaced something newer. The socket is
 * never assumed to be complete — the database is the source of truth.
 */
import { describe, expect, it } from "vitest";
import { FakeDb, Harness, flush, type TestAlert } from "./alert-sync.harness";

const fresh = (seed?: (db: FakeDb) => void, over: ConstructorParameters<typeof Harness>[1] = {}) => {
  const db = new FakeDb();
  seed?.(db);
  return { db, h: new Harness(db, over) };
};

describe("normal connection", () => {
  it("shows the list, then delivers live alerts once, marked new, and moves the cursor", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    expect(h.events).toEqual([]); // the snapshot already has a1
    expect(h.client.state.ready).toBe(true);

    const a2 = db.insert("a2");
    h.frame(a2);
    expect(h.delivered).toEqual(["a2@2"]);
    expect(h.events[0]).toMatchObject({ type: "new_alert", source: "live" });
    expect(h.client.state.cursor).toBe(2);
    expect(h.converged()).toBe(true);
  });

  it("an update to an alert the list already has is an update, not a new alert", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    h.frame(db.update("a1", { status: "resolved" }), "alert.status_updated");
    expect(h.events[0]).toMatchObject({ type: "alert.status_updated" });
    expect(h.view[0]!.status).toBe("resolved");
    expect(h.converged()).toBe(true);
  });

  it("asks the database as soon as it connects, and on the baseline, even with no frames", async () => {
    const { db, h } = fresh((d) => { d.insert("a1"); });
    await h.up();
    expect(db.syncCalls).toEqual([1]); // the baseline sync; nothing to fetch
    db.insert("a2"); // committed, but no frame ever reaches the client
    h.socket.push({ type: "hello", cursor: db.cursor });
    await flush();
    expect(h.delivered).toEqual(["a2@2"]);
    expect(h.events[0]).toMatchObject({ source: "sync" });
  });

  it("a heartbeat that is not ahead costs nothing", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    const calls = db.syncCalls.length;
    h.socket.push({ type: "ping", cursor: db.cursor });
    h.socket.push({ type: "ping", cursor: 0 });
    await flush();
    expect(db.syncCalls.length).toBe(calls);
  });
});

describe("disconnect and reconnect", () => {
  it("when the server ends the socket because the session expired (4401), it syncs over HTTP at once — which refreshes the session — before reconnecting", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    const before = db.syncCalls.length;
    db.insert("a2");
    h.socket.drop(4401);
    await flush();
    expect(db.syncCalls.length).toBe(before + 1); // immediately, not after the backoff
    expect(h.sockets).toHaveLength(1);            // the reconnect still waits for its backoff
    await h.clock.advance(1_000);
    expect(h.sockets).toHaveLength(2);
    h.socket.open();
    await flush();
    expect(h.delivered).toContain("a2@2");
    expect(h.converged()).toBe(true);
  });

  it("an ordinary drop does not trigger that extra request", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    const before = db.syncCalls.length;
    h.socket.drop();
    await flush();
    expect(db.syncCalls.length).toBe(before);
  });

  it("recovers everything committed while the socket was down — new alerts and changes — in order", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    h.socket.drop();
    expect(h.client.state.connected).toBe(false);
    db.insert("a2"); db.insert("a3"); db.update("a1", { status: "resolved" }); // no frames: nobody is listening

    await h.clock.advance(1_000); // backoff elapses, a new socket is created
    expect(h.sockets).toHaveLength(2);
    h.socket.open();
    await flush();

    expect(h.delivered).toEqual(["a2@2", "a3@3", "a1@4"]); // by version, oldest first
    expect(h.events.map((e) => [e.type, e.source])).toEqual([["new_alert", "sync"], ["new_alert", "sync"], ["alert.status_updated", "sync"]]);
    expect(h.converged()).toBe(true);
    expect(h.client.state.cursor).toBe(4);
  });

  it("a frame from the connection that just died is ignored", async () => {
    const { db, h } = fresh();
    await h.up();
    const old = h.socket;
    old.drop();
    db.insert("x");
    old.push({ type: "new_alert", alert: db.alerts.get("x") });
    expect(h.events).toEqual([]);
    await h.clock.advance(1_000);
    h.socket.open();
    await flush();
    expect(h.delivered).toEqual(["x@1"]); // delivered once, from the database
  });

  it("recovers repeatedly across many disconnects", async () => {
    const { db, h } = fresh((d) => d.insert("a0"));
    await h.up();
    for (let i = 1; i <= 5; i++) {
      h.socket.drop();
      db.insert(`m${i}`);
      db.update(`m${i}`, { status: "investigating" });
      await h.clock.advance(31_000);
      h.socket.open();
      await flush();
      expect(h.converged()).toBe(true);
    }
    expect(h.events.every((e) => e.source === "sync")).toBe(true);
  });

  it("backs off exponentially with jitter, up to a cap, and starts over after a successful connection", async () => {
    const { h } = fresh();
    h.clock.rnd = 0.5; // delay = 0.75 × the ceiling
    h.client.start();
    const gaps: number[] = [];
    for (let i = 0; i < 8; i++) {
      const before = h.clock.time;
      h.socket.drop(); // never got as far as opening
      const n = h.sockets.length;
      let waited = 0;
      while (h.sockets.length === n && waited < 60_000) { await h.clock.advance(50); waited += 50; }
      gaps.push(h.clock.time - before);
    }
    expect(gaps.slice(0, 6)).toEqual([750, 1_500, 3_000, 6_000, 12_000, 22_500]);
    expect(gaps[6]).toBe(22_500); // capped at 30 s × 0.75
    // A real connection resets the ladder.
    h.socket.open();
    await flush();
    h.socket.drop();
    const before = h.clock.time;
    const n = h.sockets.length;
    while (h.sockets.length === n) await h.clock.advance(50);
    expect(h.clock.time - before).toBe(750);
  });

  it("many tabs reconnecting after a server restart spread out instead of arriving together", async () => {
    const times: number[] = [];
    for (let i = 0; i < 20; i++) {
      const { h } = fresh();
      h.clock.rnd = i / 19; // each tab draws a different jitter
      h.client.start();
      h.socket.drop();
      const start = h.clock.time;
      while (h.sockets.length === 1) await h.clock.advance(10);
      times.push(h.clock.time - start);
    }
    expect(new Set(times).size).toBeGreaterThanOrEqual(15);
    expect(Math.min(...times)).toBeGreaterThanOrEqual(500);
    expect(Math.max(...times)).toBeLessThanOrEqual(1_000);
  });
});

describe("missed alerts", () => {
  it("a gap in versions is noticed: the later alert shows at once, the cursor does not skip the hole, and the database fills it", async () => {
    const { db, h } = fresh();
    await h.up();
    const [a, b, c] = [db.insert("a"), db.insert("b"), db.insert("c")];
    h.frame(a);
    h.frame(c); // b's frame was lost
    expect(h.delivered).toEqual(["a@1", "c@3"]);
    expect(h.client.state.cursor).toBe(1); // NOT 3: seq 2 is still owed
    void b;

    await h.clock.advance(500); // the grace period passes; the database is asked
    expect(h.delivered).toEqual(["a@1", "c@3", "b@2"]); // c is not delivered twice
    expect(h.client.state.cursor).toBe(3);
    expect(h.converged()).toBe(true);
  });

  it("frames that are merely reordered do not cost a request", async () => {
    const { db, h } = fresh();
    await h.up();
    const [a, b, c] = [db.insert("a"), db.insert("b"), db.insert("c")];
    const calls = db.syncCalls.length;
    h.frame(c); h.frame(b); h.frame(a); // arrive newest first
    await h.clock.advance(2_000);
    expect(db.syncCalls.length).toBe(calls);
    expect(h.client.state.cursor).toBe(3);
    expect(h.delivered.sort()).toEqual(["a@1", "b@2", "c@3"]);
    expect(h.converged()).toBe(true); // and the list is in the right order regardless
  });

  it("with the WebSocket blocked entirely, polling still finds new alerts", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    h.client.start(); // the socket never opens
    h.load();
    await flush();
    db.insert("a2");
    await h.clock.advance(10_000);
    expect(h.delivered).toEqual(["a2@2"]);
    expect(h.client.state.connected).toBe(false);
    db.insert("a3");
    await h.clock.advance(10_000);
    expect(h.delivered).toEqual(["a2@2", "a3@3"]);
  });

  it("while connected, a periodic reconciliation still catches what no frame or heartbeat announced", async () => {
    const { db, h } = fresh();
    await h.up();
    db.insert("quiet"); // e.g. published on another instance while Redis was down
    await h.clock.advance(59_000);
    expect(h.delivered).toEqual([]);
    await h.clock.advance(2_000);
    expect(h.delivered).toEqual(["quiet@1"]);
  });

  it("pages through a long absence without dropping or repeating anything", async () => {
    const { db, h } = fresh(undefined, {});
    const pages: number[] = [];
    const paged = new Harness(db, { fetchSync: async (after) => { pages.push(after); return db.sync(after, 2); } });
    await paged.up();
    for (let i = 1; i <= 5; i++) db.insert(`p${i}`);
    paged.socket.push({ type: "ping", cursor: db.cursor });
    await flush();
    expect(pages).toEqual([0, 0, 2, 4]); // baseline, then three pages
    expect(paged.delivered).toEqual(["p1@1", "p2@2", "p3@3", "p4@4", "p5@5"]);
    expect(paged.client.state.cursor).toBe(5);
    void h;
  });

  it("a returning tab catches up the moment it becomes visible", async () => {
    const { db, h } = fresh((d) => d.insert("a1"));
    await h.up();
    h.setVisible(false);
    const calls = db.syncCalls.length;
    db.insert("a2");
    await h.clock.advance(120_000);
    expect(db.syncCalls.length).toBe(calls); // a hidden tab does not poll
    h.setVisible(true);
    await flush();
    expect(h.delivered).toEqual(["a2@2"]);
  });

  it("a returning tab whose socket died reconnects at once instead of waiting out the backoff", async () => {
    const { db, h } = fresh();
    await h.up();
    h.setVisible(false);
    h.socket.drop();
    db.insert("late");
    h.setVisible(true);
    expect(h.sockets).toHaveLength(2);
    h.socket.open();
    await flush();
    expect(h.delivered).toEqual(["late@1"]);
  });

  it("regaining the network reconnects and catches up", async () => {
    const { db, h } = fresh();
    await h.up();
    h.socket.drop();
    db.insert("offline");
    h.onlineListeners.forEach((l) => l());
    expect(h.sockets).toHaveLength(2);
    h.socket.open();
    await flush();
    expect(h.delivered).toEqual(["offline@1"]);
  });
});

describe("duplicate events", () => {
  it("the same frame twice is one event", async () => {
    const { db, h } = fresh();
    await h.up();
    const a = db.insert("a");
    h.frame(a); h.frame(a);
    expect(h.delivered).toEqual(["a@1"]);
  });

  it("a frame replayed after a reconnect is not delivered again", async () => {
    const { db, h } = fresh();
    await h.up();
    const a = db.insert("a");
    h.frame(a);
    h.socket.drop();
    await h.clock.advance(1_000);
    h.socket.open();
    await flush();
    h.frame(a); // the server's outbox re-publishes it
    expect(h.delivered).toEqual(["a@1"]);
  });

  it("what a sync returns is not delivered twice when a live frame already showed it", async () => {
    const { db, h } = fresh();
    await h.up();
    const [, , c] = [db.insert("a"), db.insert("b"), db.insert("c")];
    h.frame(c); // seen live, ahead of a hole
    await h.clock.advance(500);
    expect(h.delivered.filter((d) => d === "c@3")).toHaveLength(1);
  });

  it("an alert in the snapshot, whose frame arrives late, is not shown again", async () => {
    const { db, h } = fresh();
    const a = db.insert("a");
    await h.up(); // the list already contains a
    h.frame(a);
    expect(h.events).toEqual([]);
  });
});

describe("out-of-order events", () => {
  it("an older version of an alert arriving after a newer one never replaces it", async () => {
    const { db, h } = fresh((d) => d.insert("x"));
    await h.up();
    const v1 = db.update("x", { status: "investigating" }); // seq 2
    const v2 = db.update("x", { status: "resolved" }); // seq 3
    h.frame(v2, "alert.status_updated");
    h.frame(v1, "alert.status_updated"); // late
    expect(h.delivered).toEqual(["x@3"]);
    expect(h.view[0]!.status).toBe("resolved");
  });

  it("alerts arriving newest-first still end up in the right order on screen", async () => {
    const { db, h } = fresh();
    await h.up();
    const all = ["a", "b", "c", "d"].map((id) => db.insert(id));
    [...all].reverse().forEach((a) => h.frame(a));
    expect(h.view.map((a) => a.id)).toEqual(["d", "c", "b", "a"]);
    expect(h.converged()).toBe(true);
  });

  it("the cursor never moves past a version that has not arrived, however frames are ordered", async () => {
    const { db, h } = fresh();
    await h.up();
    const all = Array.from({ length: 10 }, (_, i) => db.insert(`n${i}`));
    h.frame(all[9]!);
    expect(h.client.state.cursor).toBe(0);
    h.frame(all[5]!);
    h.frame(all[0]!);
    expect(h.client.state.cursor).toBe(1);
    for (const i of [1, 2, 3, 4, 6, 7, 8]) h.frame(all[i]!);
    expect(h.client.state.cursor).toBe(10);
  });

  it("a stale copy of an alert the snapshot already supersedes is dropped", async () => {
    const { db, h } = fresh((d) => d.insert("x"));
    const old = { ...db.alerts.get("x")! };
    db.update("x", { status: "resolved" });
    await h.up(); // snapshot at seq 2 shows resolved
    h.frame(old, "alert.status_updated");
    expect(h.events).toEqual([]);
    expect(h.view[0]!.status).toBe("resolved");
  });
});

describe("the list snapshot and the cursor", () => {
  it("frames before the first snapshot are ignored, and whatever they announced is fetched after it", async () => {
    const { db, h } = fresh();
    h.client.start();
    h.socket.open();
    const early = db.insert("early");
    h.socket.push({ type: "new_alert", alert: early }); // no baseline yet
    expect(h.events).toEqual([]);
    h.view = []; // the snapshot was taken before "early" existed...
    h.client.setBaseline(0);
    await flush();
    expect(h.delivered).toEqual(["early@1"]); // ...so the sync after it delivers it
  });

  it("reloading with a new filter installs the new cursor with the new list", async () => {
    const { db, h } = fresh((d) => { d.insert("a"); d.insert("b"); });
    await h.up();
    const c = db.insert("c");
    h.frame(c);
    db.insert("d"); // committed before the reload below
    h.load(); // filter changed: list and cursor re-read together
    await flush();
    expect(h.client.state.cursor).toBe(4);
    expect(h.converged()).toBe(true);
    expect(h.delivered).toEqual(["c@3"]); // d is in the new snapshot, not re-announced
  });

  it("an alert created after the snapshot is new; a change to one in it is an update", async () => {
    const { db, h } = fresh((d) => d.insert("old"));
    await h.up();
    const n = db.insert("newer");
    const u = db.update("old", { status: "resolved" });
    h.frame(n); h.frame(u, "alert.status_updated");
    expect(h.events.map((e) => [e.alert.id, e.type])).toEqual([["newer", "new_alert"], ["old", "alert.status_updated"]]);
  });
});

describe("falling too far behind (reset)", () => {
  it("asks the owner to reload the list rather than paging through everything, and delivers no partial events", async () => {
    const { db, h } = fresh();
    db.maxCatchup = 3;
    await h.up();
    h.socket.drop();
    for (let i = 0; i < 10; i++) db.insert(`bulk${i}`);
    await h.clock.advance(1_000);
    h.socket.open();
    await flush();
    expect(h.resets).toBe(1);
    expect(h.events).toEqual([]);
    expect(h.converged()).toBe(true);
    expect(h.client.state.cursor).toBe(10);
  });

  it("does not adopt the server's cursor without a matching list — it keeps asking until the owner reloads", async () => {
    const { db, h } = fresh();
    db.maxCatchup = 3;
    h.reloadOnReset = false; // the reload fails this time
    await h.up();
    for (let i = 0; i < 10; i++) db.insert(`bulk${i}`);
    h.socket.push({ type: "ping", cursor: db.cursor });
    await flush();
    expect(h.resets).toBe(1);
    expect(h.client.state.ready).toBe(false);
    await h.clock.advance(70_000);
    expect(h.resets).toBeGreaterThan(1); // asked again on a later reconciliation
    expect(h.client.state.cursor).toBe(0); // and never skipped ahead

    h.reloadOnReset = true;
    await h.clock.advance(70_000);
    expect(h.converged()).toBe(true);
    expect(h.client.state.ready).toBe(true);
  });

  it("a cursor from the future (the database was restored from a backup) is a reset too", async () => {
    const { db, h } = fresh((d) => { d.insert("a"); d.insert("b"); });
    await h.up();
    db.cursor = 0; db.alerts.clear(); db.insert("only"); // restored to an earlier state: the database is now BEHIND this client
    h.socket.push({ type: "resync" });
    await flush();
    expect(h.resets).toBe(1);
    expect(h.converged()).toBe(true);
  });
});

describe("backend restart", () => {
  it("clients reconnect, ask the database, and pick up what happened during the outage", async () => {
    const { db, h } = fresh((d) => d.insert("before"));
    await h.up();
    h.socket.drop(); // server goes away
    db.insert("during-1");
    await h.clock.advance(3_000); // reconnect attempts fail while it is down
    h.socket.drop();
    db.insert("during-2");
    await h.clock.advance(31_000);
    h.socket.open(); // it is back
    await flush();
    h.socket.push({ type: "hello", cursor: db.cursor });
    await flush();
    expect(h.delivered).toEqual(["during-1@2", "during-2@3"]);
    expect(h.converged()).toBe(true);
    h.frame(db.insert("after")); // and live delivery works again
    expect(h.delivered.at(-1)).toBe("after@4");
  });

  it("while the API itself is failing, sync retries with backoff and loses nothing when it recovers", async () => {
    const { db, h } = fresh();
    await h.up();
    h.failSync = true;
    db.insert("a"); db.insert("b");
    h.socket.push({ type: "ping", cursor: db.cursor });
    await flush();
    expect(h.client.state.lastError).toBe("sync unavailable");
    await h.clock.advance(20_000);
    expect(h.events).toEqual([]);
    h.failSync = false;
    await h.clock.advance(40_000);
    expect(h.delivered).toEqual(["a@1", "b@2"]);
    expect(h.client.state.lastError).toBeNull();
    expect(h.converged()).toBe(true);
  });
});

describe("Redis failure", () => {
  it("a Redis outage drops frames but not alerts: the heartbeat, taken from the database, brings them back", async () => {
    const { db, h } = fresh();
    await h.up();
    db.insert("lost-1"); db.insert("lost-2"); // Redis was down: the frames never reached any socket
    expect(h.events).toEqual([]);
    h.socket.push({ type: "ping", cursor: db.cursor }); // the server's next heartbeat
    await flush();
    expect(h.delivered).toEqual(["lost-1@1", "lost-2@2"]);
  });

  it("when Redis comes back, the server says so and the client reconciles at once", async () => {
    const { db, h } = fresh();
    await h.up();
    db.insert("missed");
    h.socket.push({ type: "resync" });
    await flush();
    expect(h.delivered).toEqual(["missed@1"]);
  });

  it("frames the outbox re-publishes late are recognised as already handled", async () => {
    const { db, h } = fresh();
    await h.up();
    const a = db.insert("a");
    h.socket.push({ type: "ping", cursor: db.cursor });
    await flush(); // delivered by sync
    h.frame(a); // the retried Redis publish arrives later
    expect(h.delivered).toEqual(["a@1"]);
  });
});

describe("a stalled or hostile stream", () => {
  it("a connection that goes silent without closing is replaced", async () => {
    const { db, h } = fresh((d) => d.insert("a"));
    await h.up();
    const stalled = h.socket;
    await h.clock.advance(46_000); // no frame at all
    expect(stalled.closed).toBe(true);
    await h.clock.advance(1_000);
    expect(h.sockets).toHaveLength(2);
    db.insert("b");
    h.socket.open();
    await flush();
    expect(h.delivered).toEqual(["b@2"]);
  });

  it("heartbeats keep a quiet but healthy connection open", async () => {
    const { db, h } = fresh();
    await h.up();
    for (let i = 0; i < 20; i++) {
      await h.clock.advance(20_000);
      h.socket.push({ type: "ping", cursor: db.cursor });
    }
    expect(h.sockets).toHaveLength(1);
  });

  it("malformed frames are ignored without breaking the stream", async () => {
    const { db, h } = fresh();
    await h.up();
    for (const junk of ["not json", "{}", '{"type":1}', "null", "[]", '{"type":"new_alert"}', '{"type":"nonsense","cursor":5}']) h.socket.push(junk);
    await flush();
    expect(h.events).toEqual([]);
    h.frame(db.insert("still-works"));
    expect(h.delivered).toEqual(["still-works@1"]);
  });

  it("a frame without a version is not trusted or shown — the database is asked instead", async () => {
    const { db, h } = fresh();
    await h.up();
    db.insert("real");
    const calls = db.syncCalls.length;
    h.socket.push({ type: "new_alert", alert: { id: "real", title: "FORGED", created_at: "x" } });
    await flush();
    expect(db.syncCalls.length).toBe(calls + 1);
    expect(h.delivered).toEqual(["real@1"]);
    expect(h.events[0]!.alert.title).toBe("alert real"); // the database's copy, not the frame's
  });

  it("a burst of hints is one request at a time, and at most one follow-up", async () => {
    let inFlight = 0, maxInFlight = 0, calls = 0;
    const { db, h } = fresh(undefined, {
      fetchSync: async (after) => {
        calls++; inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
        await flush(5);
        inFlight--;
        return db.sync(after);
      },
    });
    await h.up();
    calls = 0;
    db.insert("a");
    for (let i = 0; i < 30; i++) { h.socket.push({ type: "resync" }); h.socket.push({ type: "ping", cursor: db.cursor }); }
    await flush(100);
    expect(maxInFlight).toBe(1);
    expect(calls).toBeLessThanOrEqual(2);
    expect(h.delivered).toEqual(["a@1"]);
  });
});

describe("multiple browser tabs", () => {
  it("each tab converges on the database by itself, whatever the others miss", async () => {
    const db = new FakeDb();
    db.insert("seed");
    const tabs = [new Harness(db), new Harness(db), new Harness(db)];
    for (const t of tabs) await t.up();

    const a = db.insert("a");
    tabs[0]!.frame(a); // only tab 1 gets the frame
    tabs[1]!.socket.drop(); // tab 2 loses its connection
    const b = db.insert("b");
    tabs[0]!.frame(b);
    tabs[2]!.frame(b); // tab 3 missed a, saw b (ahead of a hole)
    tabs[2]!.socket.push({ type: "ping", cursor: db.cursor });
    await tabs[1]!.clock.advance(1_000);
    tabs[1]!.socket.open();
    await flush();
    await tabs[2]!.clock.advance(500);

    for (const t of tabs) {
      expect(t.converged()).toBe(true);
      expect(new Set(t.delivered).size).toBe(t.delivered.length); // once each
    }
  });

  it("cursors are private to a tab: one tab's progress never moves another's", async () => {
    const db = new FakeDb();
    const [t1, t2] = [new Harness(db), new Harness(db)];
    await t1.up();
    await t2.up();
    t1.frame(db.insert("a"));
    expect(t1.client.state.cursor).toBe(1);
    expect(t2.client.state.cursor).toBe(0);
    expect(t2.events).toEqual([]);
  });

  it("closing one tab leaves the others running", async () => {
    const db = new FakeDb();
    const [t1, t2] = [new Harness(db), new Harness(db)];
    await t1.up();
    await t2.up();
    t1.client.stop();
    t2.frame(db.insert("a"));
    expect(t2.delivered).toEqual(["a@1"]);
    expect(t1.events).toEqual([]);
  });
});

describe("stopping", () => {
  it("cancels everything: no timers, no reconnect, no events, and an in-flight sync is aborted", async () => {
    let signal: AbortSignal | undefined;
    const { db, h } = fresh(undefined, {
      fetchSync: (_after, s) => { signal = s; return new Promise(() => {}); },
    });
    await h.up();
    db.insert("a");
    h.socket.push({ type: "resync" });
    await flush();
    h.client.stop();
    expect(signal?.aborted).toBe(true);
    expect(h.socket.closed).toBe(true);
    expect(h.clock.pending).toBe(0);
    await h.clock.advance(300_000);
    expect(h.sockets).toHaveLength(1);
    expect(h.events).toEqual([]);
  });
});

// --- a random storm ------------------------------------------------------------

function prng(seed: number) {
  let s = seed >>> 0;
  return () => ((s = (Math.imul(s, 1664525) + 1013904223) >>> 0) / 4294967296);
}

describe("under a random storm of drops, duplicates, reordering, restarts and hidden tabs", () => {
  it.each(Array.from({ length: 60 }, (_, i) => i + 1))("seed %i: converges on the database, once each, never going backwards", async (seed) => {
    const rnd = prng(seed);
    const db = new FakeDb();
    for (let i = 0; i < 3; i++) db.insert(`seed${i}`);
    const h = new Harness(db);
    h.clock.rnd = rnd();
    await h.up();

    const inflight: Array<{ alert: TestAlert; type: "new_alert" | "alert.status_updated" }> = [];
    let n = 0;
    const open = () => { if (h.socket.readyState === 0) h.socket.open(); };

    for (let step = 0; step < 120; step++) {
      const r = rnd();
      if (r < 0.28) {
        const a = db.insert(`s${seed}-${n++}`);
        inflight.push({ alert: a, type: "new_alert" });
      } else if (r < 0.46 && db.alerts.size) {
        const ids = [...db.alerts.keys()];
        const a = db.update(ids[Math.floor(rnd() * ids.length)]!, { status: (["open", "investigating", "resolved"] as const)[Math.floor(rnd() * 3)]! });
        inflight.push({ alert: a, type: "alert.status_updated" });
      } else if (r < 0.66 && inflight.length) {
        const i = Math.floor(rnd() * inflight.length); // any of them: reordering
        const f = inflight[i]!;
        if (h.socket.readyState === 1) {
          h.socket.push({ type: f.type, alert: f.alert });
          if (rnd() < 0.3) h.socket.push({ type: f.type, alert: f.alert }); // duplicate
        }
        if (rnd() < 0.7) inflight.splice(i, 1); // otherwise it may be replayed later
        else if (rnd() < 0.5) inflight.splice(i, 1); // dropped
      } else if (r < 0.73) {
        if (h.socket.readyState === 1) h.socket.drop();
        await h.clock.advance(Math.floor(rnd() * 5_000));
        open();
      } else if (r < 0.79) {
        if (h.socket.readyState === 1) h.socket.push({ type: "ping", cursor: db.cursor });
      } else if (r < 0.82) {
        if (h.socket.readyState === 1) h.socket.push({ type: "resync" });
      } else if (r < 0.86) {
        h.setVisible(rnd() < 0.5);
      } else if (r < 0.88) {
        h.failSync = rnd() < 0.5;
      } else {
        await h.clock.advance(Math.floor(rnd() * 3_000));
        open();
      }
    }

    // Peace returns: the API works, the tab is visible, a connection is open.
    h.failSync = false;
    h.setVisible(true);
    await h.clock.advance(40_000);
    open();
    await flush();
    if (h.socket.readyState === 1) h.socket.push({ type: "ping", cursor: db.cursor });
    await h.clock.advance(70_000);
    await flush();

    expect(h.converged()).toBe(true);
    expect(new Set(h.delivered).size).toBe(h.delivered.length); // each (alert, version) at most once
    const last = new Map<string, number>();
    for (const e of h.events) {
      expect(e.alert.seq, `${e.alert.id} went backwards`).toBeGreaterThan(last.get(e.alert.id) ?? 0);
      last.set(e.alert.id, e.alert.seq);
    }
    expect(h.client.state.cursor).toBe(db.cursor);
  });
});
