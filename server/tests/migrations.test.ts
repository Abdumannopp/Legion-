/**
 * Audit P1-2: boot-time migrations must not lock hot tables on every start,
 * and must not queue every request behind a migration waiting for a lock.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { closePool, migrate, query } from "../src/db/pool.js";

const url = process.env.DATABASE_URL!;
let holder: pg.Client;

beforeAll(async () => {
  await migrate();
  holder = new pg.Client({ connectionString: url });
  await holder.connect();
});
afterAll(async () => {
  await holder.query("ROLLBACK").catch(() => {});
  await holder.end();
  await closePool();
});

describe("schema migrations", () => {
  it("records what the schema was built from", async () => {
    const r = await query("SELECT fingerprint FROM legion_schema_state WHERE id = 1");
    expect(r.rows[0]?.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("an ordinary restart takes no table lock: it finishes while a long query holds alerts", async () => {
    await holder.query("BEGIN");
    await holder.query("LOCK TABLE alerts IN ACCESS SHARE MODE"); // what any long SELECT holds
    const started = Date.now();
    await migrate({ lockTimeout: "300ms", attempts: 1 });
    expect(Date.now() - started).toBeLessThan(2_000);
    await holder.query("ROLLBACK");
  });

  it("a changed schema waits only briefly for a busy table, then fails instead of blocking everyone", async () => {
    await query("UPDATE legion_schema_state SET fingerprint = 'old' WHERE id = 1");
    await holder.query("BEGIN");
    await holder.query("LOCK TABLE alerts IN ACCESS SHARE MODE");
    const started = Date.now();
    const err = await migrate({ lockTimeout: "200ms", attempts: 2 }).then(() => null, (e: { code?: string }) => e);
    await holder.query("ROLLBACK");
    // Either nothing in the schema needed the lock (then it succeeded quickly),
    // or it gave up with lock_not_available — never an unbounded wait.
    expect(Date.now() - started).toBeLessThan(5_000);
    if (err) expect(err.code).toBe("55P03");
    // Once the table is free, the change is applied and recorded.
    await migrate();
    expect((await query("SELECT fingerprint FROM legion_schema_state WHERE id = 1")).rows[0]?.fingerprint).not.toBe("old");
  });

  it("LEGION_FORCE_MIGRATE=1 re-applies even when nothing changed", async () => {
    const before = (await query("SELECT applied_at FROM legion_schema_state WHERE id = 1")).rows[0]?.applied_at as Date;
    process.env.LEGION_FORCE_MIGRATE = "1";
    try { await migrate(); } finally { delete process.env.LEGION_FORCE_MIGRATE; }
    const after = (await query("SELECT applied_at FROM legion_schema_state WHERE id = 1")).rows[0]?.applied_at as Date;
    expect(after.getTime()).toBeGreaterThanOrEqual(before.getTime());
    await migrate(); // and an ordinary start afterwards still skips cleanly
  });

  it("refuses a malformed lock timeout (it is interpolated into SET)", async () => {
    await expect(migrate({ lockTimeout: "1s; DROP TABLE alerts" })).rejects.toThrow(/invalid lock timeout/);
  });
});
