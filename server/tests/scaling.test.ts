/**
 * Horizontal scaling: state that must hold across every instance lives in
 * Postgres (or Redis), never in one process. These tests exercise the shared
 * paths directly; the database is the only thing instances have in common,
 * so concurrent calls here are what concurrent instances do.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { closePool, migrate, query, withLeaderLock } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import { consumeAiQuota, resetAiQuota } from "../src/ai-policy.js";

let tA: string, tB: string;
const saved = config.aiRateLimitPerMinute;

beforeAll(async () => { await migrate(); });
afterAll(async () => { (config as { aiRateLimitPerMinute: number }).aiRateLimitPerMinute = saved; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  await resetAiQuota();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  (config as { aiRateLimitPerMinute: number }).aiRateLimitPerMinute = 5;
});

describe("the AI quota is per workspace across all instances", () => {
  it("20 simultaneous requests (any instances) get exactly the allowance", async () => {
    const now = Date.UTC(2026, 8, 30, 12, 0, 10);
    const results = await Promise.all(Array.from({ length: 20 }, () => consumeAiQuota(tA, now)));
    expect(results.filter((r) => r.ok)).toHaveLength(5);
    expect(results.find((r) => !r.ok)!.retryAfterSeconds).toBe(50);
    // Another workspace has its own allowance; the next minute starts afresh.
    expect((await consumeAiQuota(tB, now)).ok).toBe(true);
    expect((await consumeAiQuota(tA, now + 60_000)).ok).toBe(true);
  });

  it("if the shared counter cannot be written, the limit still holds per instance", async () => {
    const orphan = randomUUID(); // no such workspace: the insert fails, the fallback counts
    const results = [];
    for (let i = 0; i < 8; i++) results.push(await consumeAiQuota(orphan));
    expect(results.filter((r) => r.ok)).toHaveLength(5);
  });
});

describe("periodic jobs run on one instance at a time", () => {
  it("a second leader waits for nothing and does nothing; the lock is free afterwards", async () => {
    let running = 0; let maxConcurrent = 0; let ran = 0;
    const job = async () => {
      running++; ran++; maxConcurrent = Math.max(maxConcurrent, running);
      await new Promise((r) => setTimeout(r, 100));
      running--;
      return "done";
    };
    const results = await Promise.all([withLeaderLock(424242, job), withLeaderLock(424242, job), withLeaderLock(424242, job)]);
    expect(results.filter((r) => r.ran)).toHaveLength(1);
    expect(maxConcurrent).toBe(1);
    expect((await withLeaderLock(424242, job)).ran).toBe(true);
    expect(ran).toBe(2);
  });

  it("a leader that throws releases the lock", async () => {
    await expect(withLeaderLock(434343, async () => { throw new Error("boom"); })).rejects.toThrow("boom");
    expect((await withLeaderLock(434343, async () => 1)).ran).toBe(true);
  });
});
