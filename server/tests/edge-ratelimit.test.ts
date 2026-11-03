/**
 * The limiter's promises: bounded memory, and a brute-force cap that does not
 * depend on Redis being healthy, fast, or present.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Options, Store } from "express-rate-limit";
import { BoundedCounter, OVERFLOW_KEY } from "../src/bounded-counter.js";
import { ResilientStore, makeLimiter } from "../src/ratelimit.js";

beforeAll(() => { process.env.LEGION_ENFORCE_RATE_LIMITS = "1"; });
afterAll(() => { delete process.env.LEGION_ENFORCE_RATE_LIMITS; });

describe("BoundedCounter", () => {
  it("never holds more than maxKeys counters, however many keys are thrown at it", () => {
    const c = new BoundedCounter(60_000, 100);
    for (let i = 0; i < 10_000; i++) c.increment(`attacker-${i}`);
    expect(c.size).toBeLessThanOrEqual(100);
  });

  it("does not let a flood of new keys erase the count of one already being tracked", () => {
    const c = new BoundedCounter(60_000, 50);
    for (let i = 0; i < 5; i++) c.increment("victim");
    for (let i = 0; i < 5_000; i++) c.increment(`noise-${i}`);
    expect(c.increment("victim").totalHits).toBe(6);
  });

  it("still counts every fresh key once full — nothing is let through uncounted (fails safe, not open)", () => {
    const c = new BoundedCounter(60_000, 10);
    for (let i = 0; i < 9; i++) c.increment(`k${i}`);
    const hits = Array.from({ length: 50 }, (_, i) => c.increment(`new-${i}`).totalHits);
    expect(hits.every((h) => h >= 1)).toBe(true);
    // 8 keys fit; the 9th and the 50 fresh ones are all accounted for in the overflow.
    expect(c.overflowTotal).toBe(51);
    expect(OVERFLOW_KEY).toBeTruthy();
  });

  it("a flood of fresh keys does not throttle every other fresh key (the blast radius is a share, not everyone)", () => {
    // Before: all fresh keys shared one counter, so a flood from more than
    // maxKeys addresses put EVERY new legitimate address at the shared limit.
    const c = new BoundedCounter(60_000, 10_000);
    for (let i = 0; i < 9_744; i++) c.increment(`tracked-${i}`);          // table full
    for (let i = 0; i < 5_000; i++) c.increment(`botnet-${i}`);            // 5,000 distinct fresh keys
    const legit = c.increment("a-real-user-on-a-new-address").totalHits;
    expect(c.overflowTotal).toBe(5_001);                                    // all counted…
    expect(legit).toBeLessThan(100);                                        // …but the user shares with ~1/256 of them, not all 5,000
  });

  it("a saturated table costs O(1) per call, not a sweep of every entry (the flood must not pin a CPU)", () => {
    // Measured before the fix: ~600 µs per call once full (1 µs when not).
    const c = new BoundedCounter(60_000, 50_000);
    for (let i = 0; i < 50_000; i++) c.increment(`fill-${i}`);
    const t0 = performance.now();
    for (let i = 0; i < 20_000; i++) c.increment(`flood-${i}`);
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(1_000);                                          // was ~12,000 ms
  });

  it("keeps entries in expiry order, so a sweep can stop at the first live one", () => {
    let now = 0;
    const c = new BoundedCounter(1_000, 100, () => now);
    c.increment("a"); c.increment("b");                                      // expire at 1000
    now = 500; c.increment("c");                                             // expires at 1500
    now = 1_100; c.increment("a");                                           // a, b expired and are dropped; c is live, so the sweep stops there; a is created again at the back
    expect(c.size).toBe(2);                                                  // c, a
    expect(c.peek("c")).toBe(1);
    expect(c.peek("a")).toBe(1);
    now = 2_200; c.increment("b");                                           // c (1500) and a (2100) have expired by now, in that order
    expect(c.size).toBe(1);                                                  // b
    expect(c.peek("c")).toBe(0);
    expect(c.peek("a")).toBe(0);
  });

  it("decrement finds a fresh key's overflow counter again", () => {
    const c = new BoundedCounter(60_000, 8);
    for (let i = 0; i < 6; i++) c.increment(`k${i}`);
    c.increment("late"); c.increment("late");
    const before = c.overflowTotal;
    c.decrement("late");
    expect(c.overflowTotal).toBe(before - 1);
  });

  it("frees expired entries so the table recovers", () => {
    let now = 0;
    const c = new BoundedCounter(1_000, 10, () => now);
    for (let i = 0; i < 9; i++) c.increment(`k${i}`);
    now = 5_000;
    expect(c.increment("fresh").totalHits).toBe(1);
    expect(c.size).toBeLessThanOrEqual(2);
  });
});

// --- A shared backend that misbehaves ------------------------------------------

type Mode = "ok" | "throw" | "hang" | "slow";
function fakeRemote(mode: () => Mode): Store & { calls: number } {
  const counts = new Map<string, number>();
  const self = {
    calls: 0,
    init(_o: Options) {},
    async increment(key: string) {
      self.calls++;
      if (mode() === "throw") throw new Error("ECONNREFUSED");
      if (mode() === "hang") return new Promise<never>(() => {});
      if (mode() === "slow") await new Promise((r) => setTimeout(r, 150));
      const n = (counts.get(key) ?? 0) + 1; counts.set(key, n);
      return { totalHits: n, resetTime: new Date(Date.now() + 60_000) };
    },
    async decrement(key: string) { counts.set(key, Math.max(0, (counts.get(key) ?? 0) - 1)); },
    async resetKey(key: string) { counts.delete(key); },
  };
  return self as unknown as Store & { calls: number };
}

async function serve(store: ResilientStore, limit: number): Promise<{ port: number; close: () => void }> {
  const app = express();
  app.set("trust proxy", "loopback");
  app.use(express.json());
  app.post("/login", makeLimiter({
    windowMs: 60_000, limit, prefix: "t", store,
    failuresOnly: true,
    key: (req) => `acct:${req.body?.user}`,
  }), (req, res) => res.status(req.body?.pass === "right" ? 200 : 401).json({}));
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as AddressInfo).port, close: () => server.close() };
}

async function post(port: number, body: object): Promise<number> {
  const res = await fetch(`http://127.0.0.1:${port}/login`, {
    method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": `198.51.100.${Math.floor(Math.random() * 250)}` },
    body: JSON.stringify(body),
  });
  return res.status;
}

describe("brute force is capped whatever Redis does", () => {
  for (const mode of ["ok", "throw", "hang"] as const) {
    it(`redis ${mode}: the 4th wrong password for one account is refused, from any address`, async () => {
      const store = new ResilientStore(`bf-${mode}`, { redisTimeoutMs: 50, cooldownMs: 60_000 });
      const { port, close } = await serve(store, 3);
      store.attachRemote(fakeRemote(() => mode));
      try {
        const statuses: number[] = [];
        for (let i = 0; i < 6; i++) statuses.push(await post(port, { user: "victim", pass: "guess" + i }));
        expect(statuses).toEqual([401, 401, 401, 429, 429, 429]);
        // Another account is unaffected.
        expect(await post(port, { user: "someone-else", pass: "x" })).toBe(401);
      } finally { close(); }
    });
  }

  it("a hanging Redis costs one timeout, then is skipped for the cooldown — login is not stalled", async () => {
    const store = new ResilientStore("hang-cost", { redisTimeoutMs: 100, cooldownMs: 60_000 });
    const { port, close } = await serve(store, 1000);
    const remote = fakeRemote(() => "hang");
    store.attachRemote(remote);
    try {
      const t0 = Date.now();
      await post(port, { user: "a", pass: "x" });        // pays the timeout once
      const first = Date.now() - t0;
      const t1 = Date.now();
      for (let i = 0; i < 20; i++) await post(port, { user: "a", pass: "x" });
      const rest = Date.now() - t1;
      expect(first).toBeGreaterThanOrEqual(90);
      expect(rest).toBeLessThan(1_000);                  // 20 requests, no per-request stall
      expect(remote.calls).toBe(1);                      // and Redis was not hammered
    } finally { close(); }
  });

  it("recovers to the shared count after the cooldown, without a restart", async () => {
    let mode: Mode = "throw";
    const store = new ResilientStore("recover", { redisTimeoutMs: 50, cooldownMs: 50 });
    const { port, close } = await serve(store, 100);
    const remote = fakeRemote(() => mode);
    store.attachRemote(remote);
    try {
      await post(port, { user: "z", pass: "x" });
      mode = "ok";
      await new Promise((r) => setTimeout(r, 80));
      await post(port, { user: "z", pass: "x" });
      expect(remote.calls).toBeGreaterThanOrEqual(2);
    } finally { close(); }
  });

  it("a reply that was only late puts the shared count back at once, not after the cooldown", async () => {
    // Validation 2026-10-01 (RED-1): a busy process made healthy Redis replies
    // miss the timeout, and every instance then counted on its own for the
    // whole cooldown — tripling the per-account limit across three instances.
    let mode: Mode = "slow";
    const store = new ResilientStore("late", { redisTimeoutMs: 50, cooldownMs: 60_000 });
    const { port, close } = await serve(store, 1000);
    const remote = fakeRemote(() => mode);
    store.attachRemote(remote);
    try {
      await post(port, { user: "late", pass: "x" });     // times out at 50 ms; the reply lands at 150 ms
      mode = "ok";
      await new Promise((r) => setTimeout(r, 200));
      await post(port, { user: "late", pass: "x" });
      expect(remote.calls).toBe(2);                      // consulted again despite a 60 s cooldown
    } finally { close(); }
  });

  it("a Redis that never answers still gets the cooldown (no stall per request)", async () => {
    const store = new ResilientStore("late-hang", { redisTimeoutMs: 50, cooldownMs: 60_000 });
    const { port, close } = await serve(store, 1000);
    const remote = fakeRemote(() => "hang");
    store.attachRemote(remote);
    try {
      for (let i = 0; i < 5; i++) await post(port, { user: "h", pass: "x" });
      expect(remote.calls).toBe(1);
    } finally { close(); }
  });

  it("'busy, retry shortly' (503) does not count as a failed sign-in", async () => {
    const store = new ResilientStore("busy", { redisTimeoutMs: 50 });
    const app = express();
    app.use(express.json());
    app.post("/login", makeLimiter({ windowMs: 60_000, limit: 2, prefix: "busy", store, failuresOnly: true, key: (req) => `acct:${req.body?.user}` }),
      (req, res) => res.status(req.body?.pass === "busy" ? 503 : 401).json({}));
    const server = http.createServer(app);
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as AddressInfo).port;
    try {
      for (let i = 0; i < 5; i++) expect(await post(port, { user: "b", pass: "busy" })).toBe(503);
      expect(await post(port, { user: "b", pass: "wrong" })).toBe(401);
      expect(await post(port, { user: "b", pass: "wrong" })).toBe(401);
      expect(await post(port, { user: "b", pass: "wrong" })).toBe(429);
    } finally { server.close(); }
  });

  it("a successful login does not count against the account", async () => {
    const store = new ResilientStore("success", { redisTimeoutMs: 50 });
    const { port, close } = await serve(store, 2);
    try {
      for (let i = 0; i < 10; i++) expect(await post(port, { user: "ok", pass: "right" })).toBe(200);
      expect(await post(port, { user: "ok", pass: "wrong" })).toBe(401);
    } finally { close(); }
  });
});
