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

  it("audit P1-7: a daily budget per workspace caps what it can spend even under the per-minute rate", async () => {
    const savedDaily = config.aiDailyLimit;
    (config as { aiDailyLimit: number }).aiDailyLimit = 7;
    try {
      const day = Date.UTC(2026, 8, 30, 0, 0, 0);
      let allowed = 0;
      // 20 minutes, 5 calls each: the per-minute rate allows 100, the day allows 7.
      for (let m = 0; m < 20; m++) for (let i = 0; i < 5; i++) if ((await consumeAiQuota(tA, day + m * 60_000 + 1000)).ok) allowed++;
      expect(allowed).toBe(7);
      const refused = await consumeAiQuota(tA, day + 30 * 60_000);
      expect(refused).toMatchObject({ ok: false, limit: "day" });
      expect(refused.retryAfterSeconds).toBeGreaterThan(22 * 3600); // until 00:00 UTC
      // Another workspace has its own budget; the next UTC day starts afresh.
      expect((await consumeAiQuota(tB, day + 30 * 60_000)).ok).toBe(true);
      expect((await consumeAiQuota(tA, day + 86_400_000 + 1000)).ok).toBe(true);
      // Calls refused by the per-minute rate do not spend the daily budget.
      const rows = await query("SELECT count FROM usage_counters WHERE tenant_id = $1 AND meter = 'ai.requests.day' ORDER BY window_start", [tA]);
      expect(rows.rows.map((r) => r.count)).toEqual([7, 1]);
    } finally {
      (config as { aiDailyLimit: number }).aiDailyLimit = savedDaily;
    }
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
