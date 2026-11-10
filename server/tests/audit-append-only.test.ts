/**
 * Audit P2-12: the audit log cannot be changed or deleted through ordinary
 * SQL — not by a bug, not by SQL injection reaching DML.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { closePool, migrate, query, pool } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";

let tenant: string;
beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'T')", [tenant]);
  await store.audit({ tenant_id: tenant, user_id: null, user_email: "a@b.io", action: "user.login", resource_type: null, resource_id: null, detail: "x", ip_address: null });
});

describe("the audit log is append-only", () => {
  it("new entries are still written", async () => {
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1", [tenant])).rows[0].n).toBe(1);
  });

  it("an UPDATE is refused", async () => {
    await expect(query("UPDATE audit_log SET action = 'nothing.happened' WHERE tenant_id = $1", [tenant])).rejects.toThrow(/append-only/);
  });

  it("a DELETE is refused", async () => {
    await expect(query("DELETE FROM audit_log WHERE tenant_id = $1", [tenant])).rejects.toThrow(/append-only/);
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1", [tenant])).rows[0].n).toBe(1);
  });

  it("deleting the workspace cannot quietly cascade the log away either", async () => {
    await expect(query("DELETE FROM tenants WHERE id = $1", [tenant])).rejects.toThrow(/append-only/);
  });

  it("only an explicit erasure, in its own transaction, can remove entries", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('legion.audit_erasure', 'on', true)");
      await client.query("UPDATE audit_log SET user_email = NULL WHERE tenant_id = $1", [tenant]);
      await client.query("COMMIT");
    } finally { client.release(); }
    expect((await query("SELECT user_email FROM audit_log WHERE tenant_id = $1", [tenant])).rows[0].user_email).toBeNull();
    // The setting was local to that transaction: the next statement is refused again.
    await expect(query("DELETE FROM audit_log WHERE tenant_id = $1", [tenant])).rejects.toThrow(/append-only/);
  });
});
