/**
 * Password hashing off the event loop (passwords.ts) — the fix for RED-1 in
 * PRODUCTION-VALIDATION-2026-10-01.md: concurrent sign-ins froze the whole
 * instance because bcryptjs ran on the main thread.
 */
import { afterAll, describe, expect, it } from "vitest";
import bcrypt from "bcryptjs";
import { HashPool, HashingBusyError } from "../src/passwords.js";

const pools: HashPool[] = [];
const make = (o: ConstructorParameters<typeof HashPool>[0]) => { const p = new HashPool(o); pools.push(p); return p; };
afterAll(async () => { await Promise.all(pools.map((p) => p.close())); });

describe("the worker pool hashes like bcryptjs did", () => {
  it("hash and compare round-trip", async () => {
    const pool = make({ workers: 1 });
    const h = await pool.hash("correct horse", 10);
    expect(h).toMatch(/^\$2[aby]\$10\$/);
    expect(await pool.compare("correct horse", h)).toBe(true);
    expect(await pool.compare("wrong horse", h)).toBe(false);
  });

  it("every existing hash keeps working, and new hashes verify on the main thread too", async () => {
    const pool = make({ workers: 1 });
    const stored = bcrypt.hashSync("legacy-password", 12);
    expect(await pool.compare("legacy-password", stored)).toBe(true);
    expect(bcrypt.compareSync("new-password", await pool.hash("new-password", 12))).toBe(true);
  });

  it("an invalid hash is an error, not a match", async () => {
    const pool = make({ workers: 1 });
    expect(await pool.compare("x", "not-a-bcrypt-hash")).toBe(false);
  });
});

describe("the event loop stays free while hashing", () => {
  it("eight cost-12 comparisons in flight: timers still fire on time", async () => {
    const pool = make({ workers: 2, maxPending: 16 });
    const stored = bcrypt.hashSync("p", 12);
    let worstLag = 0;
    let last = performance.now();
    const ticker = setInterval(() => {
      const now = performance.now();
      worstLag = Math.max(worstLag, now - last - 10);
      last = now;
    }, 10);
    await Promise.all(Array.from({ length: 8 }, () => pool.compare("p", stored)));
    clearInterval(ticker);
    // On the main thread this was ~8 × 200 ms of blocking; off it, the loop
    // only ever waits for message passing.
    expect(worstLag).toBeLessThan(100);
  });
});

describe("saturation is refused, not queued without limit", () => {
  it("past maxPending a call fails at once with HashingBusyError (→ 503 + Retry-After)", async () => {
    const pool = make({ workers: 1, maxPending: 2 });
    const stored = bcrypt.hashSync("p", 12);
    const a = pool.compare("p", stored), b = pool.compare("p", stored);
    const t0 = performance.now();
    await expect(pool.compare("p", stored)).rejects.toBeInstanceOf(HashingBusyError);
    expect(performance.now() - t0).toBeLessThan(50);
    expect(await a).toBe(true);
    expect(await b).toBe(true);
    // Room again once the queue drains.
    expect(await pool.compare("p", stored)).toBe(true);
  });

  it("a stopped worker fails only its own jobs; the next call gets a fresh one", async () => {
    const pool = make({ workers: 1 });
    await pool.close();
    expect(await pool.compare("p", bcrypt.hashSync("p", 4))).toBe(true);
  });
});

describe("the priority lane (known devices, signed-in users)", () => {
  it("a priority job overtakes every normal job that is still waiting", async () => {
    const pool = make({ workers: 1, maxPending: 8, maxPriority: 2 });
    const stored = bcrypt.hashSync("p", 10);
    const order: string[] = [];
    const normal = Array.from({ length: 5 }, (_, i) => pool.compare("p", stored).then(() => order.push(`n${i}`)));
    const prio = pool.compare("p", stored, { priority: true }).then(() => order.push("P"));
    await Promise.all([...normal, prio]);
    // n0 was already running on the only worker; P is next, ahead of n1..n4.
    expect(order.slice(0, 2)).toEqual(["n0", "P"]);
  });

  it("a full normal lane refuses normal jobs but still accepts priority ones", async () => {
    const pool = make({ workers: 1, maxPending: 2, maxPriority: 1 });
    const stored = bcrypt.hashSync("p", 10);
    const a = pool.compare("p", stored), b = pool.compare("p", stored);
    await expect(pool.compare("p", stored)).rejects.toBeInstanceOf(HashingBusyError);
    const p = pool.compare("p", stored, { priority: true });
    // ...and the priority lane has its own bound.
    await expect(pool.compare("p", stored, { priority: true })).rejects.toBeInstanceOf(HashingBusyError);
    expect(pool.pendingPriority).toBe(1);
    expect(await Promise.all([a, b, p])).toEqual([true, true, true]);
    expect(pool.pending + pool.pendingPriority).toBe(0);
  });

  it("a worker that dies mid-job fails that job only; the queue keeps moving", async () => {
    const pool = make({ workers: 1, maxPending: 4 });
    const stored = bcrypt.hashSync("p", 10);
    const first = pool.compare("p", stored);
    const second = pool.compare("p", stored);
    await pool.close();
    await expect(first).rejects.toThrow(/password worker/);
    expect(await second).toBe(true);
    expect(pool.pending).toBe(0);
  });
});
