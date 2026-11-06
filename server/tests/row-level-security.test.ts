/**
 * F-04 (PR-3a): row-level security on the tables Legion reaches workspace-first, against a real
 * PostgreSQL, as the API's role under the owner/runtime split. The point: a query that FORGETS its
 * `tenant_id` predicate still only sees and changes the declared workspace's rows; with no declared
 * workspace it sees nothing and can write nothing; with DB_RLS off nothing changes.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { grantRuntimePrivileges, provisionAppRole } from "../src/db/provision.js";
import { runMigrations } from "../src/db/migrator.js";
import { currentTenant, inTenant, RLS_TABLES, touchesRlsTable, withTenant } from "../src/db/rls.js";
import { config } from "../src/config.js";
import { query, closePool, transaction } from "../src/db/pool.js";

const ADMIN_URL = process.env.DATABASE_URL!;
const suffix = randomBytes(3).toString("hex");
const APP = `legion_app_r${suffix}`;
const OWNER = `legion_owner_r${suffix}`;
const PASSWORD = `app-${randomBytes(16).toString("hex")}`;
const DB = `legion_rls_${suffix}`;
const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const urlFor = (db: string, user?: string) => {
  const u = new URL(ADMIN_URL);
  u.pathname = `/${db}`;
  if (user) { u.username = user; u.password = PASSWORD; }
  return u.toString();
};
async function withClient<T>(url: string, fn: (c: pg.Client) => Promise<T>): Promise<T> {
  const c = new pg.Client({ connectionString: url });
  await c.connect();
  try { return await fn(c); } finally { await c.end(); }
}
/** The API's role, the way pool.ts runs it with DB_RLS=enforce: enforcement on, a workspace (or none) declared. */
const asApp = <T>(tenant: string | null, fn: (c: pg.Client) => Promise<T>, rls: "enforce" | "off" = "enforce") =>
  withClient(urlFor(DB, APP), async (c) => {
    await c.query("SELECT set_config('legion.rls', $1, false)", [rls]);
    if (tenant) await c.query("SELECT set_config('legion.tenant_id', $1, false)", [tenant]);
    return fn(c);
  });
const n = async (c: pg.Client, sql: string, p: unknown[] = []) => (await c.query(sql, p)).rows[0].n as number;

beforeAll(async () => {
  await withClient(ADMIN_URL, async (c) => {
    await c.query(`DROP DATABASE IF EXISTS "${DB}"`);
    await c.query(`CREATE DATABASE "${DB}"`);
  });
  await withClient(urlFor(DB), (c) => provisionAppRole(c, { appUser: APP, appPassword: PASSWORD, split: true, ownerRole: OWNER }));
  const ownerPool = new pg.Pool({ connectionString: urlFor(DB), max: 2, options: `-c role=${OWNER}` });
  try { await runMigrations(ownerPool); } finally { await ownerPool.end(); }
  await withClient(urlFor(DB), (c) => grantRuntimePrivileges(c, { appUser: APP, ownerRole: OWNER }));
  await asApp(null, async (c) => {
    await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [A, B]);
  }, "off");
  for (const [t, ids] of [[A, ["A1", "A2"]], [B, ["B1"]]] as const) {
    await asApp(t, async (c) => {
      for (const id of ids) await c.query("INSERT INTO alerts (tenant_id, id, title, severity, agent, summary) VALUES ($1, $2, $3, 'high', 'Sentinel', 's')", [t, id, `secret of ${t.slice(0, 1)}`]);
    });
  }
}, 120_000);

afterAll(async () => {
  await withClient(ADMIN_URL, async (c) => {
    await c.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", [DB]);
    await c.query(`DROP DATABASE IF EXISTS "${DB}"`);
    await c.query(`DROP ROLE IF EXISTS "${APP}"`);
    await c.query(`DROP ROLE IF EXISTS "${OWNER}"`);
  });
  await closePool();
});

describe("a query that forgets tenant_id is still confined to the declared workspace", () => {
  it("reads: only the declared workspace's rows, whatever the WHERE clause says", async () => {
    expect(await asApp(A, (c) => n(c, "SELECT count(*)::int AS n FROM alerts"))).toBe(2);
    expect(await asApp(B, (c) => n(c, "SELECT count(*)::int AS n FROM alerts"))).toBe(1);
    // Even asking for the other workspace by name returns nothing.
    expect(await asApp(A, (c) => n(c, "SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1", [B]))).toBe(0);
  });

  it("writes: an unscoped UPDATE or DELETE touches only the declared workspace", async () => {
    await asApp(A, async (c) => {
      const r = await c.query("UPDATE alerts SET summary = 'changed by A'");
      expect(r.rowCount).toBe(2);
    });
    expect(await asApp(B, (c) => n(c, "SELECT count(*)::int AS n FROM alerts WHERE summary = 's'"))).toBe(1);
  });

  it("an insert for another workspace is refused", async () => {
    await asApp(A, async (c) => {
      await expect(c.query("INSERT INTO alerts (tenant_id, id, title, severity, agent, summary) VALUES ($1, 'X1', 't', 'low', 'x', 's')", [B]))
        .rejects.toThrow(/row-level security/);
    });
  });

  it("moving a row into another workspace is refused", async () => {
    await asApp(A, async (c) => {
      await expect(c.query("UPDATE alerts SET tenant_id = $1 WHERE id = 'A1'", [B])).rejects.toThrow(/row-level security/);
    });
  });
});

describe("fail closed, and nothing changes when it is off", () => {
  it("with enforcement on and no workspace declared: nothing is visible and nothing can be written", async () => {
    await asApp(null, async (c) => {
      expect(await n(c, "SELECT count(*)::int AS n FROM alerts")).toBe(0);
      expect(await n(c, "SELECT count(*)::int AS n FROM audit_log")).toBe(0);
      await expect(c.query("INSERT INTO audit_log (id, tenant_id, action) VALUES ($1, $2, 'x')", [randomUUID(), A])).rejects.toThrow(/row-level security/);
    });
  });

  it("with DB_RLS off the API sees what it always saw (the application predicates remain the control)", async () => {
    expect(await asApp(null, (c) => n(c, "SELECT count(*)::int AS n FROM alerts"), "off")).toBe(3);
  });

  it("the bounded erasure functions (run as the owner) still work across workspaces under enforcement", async () => {
    await asApp(A, async (c) => {
      const t = randomUUID();
      await c.query("SELECT set_config('legion.rls', 'off', false)");
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Leaving')", [t]);
      await c.query("SELECT set_config('legion.rls', 'enforce', false)");
      await c.query("SELECT legion_erase_tenant($1, 'test', null, '{}', false)", [t]);
      expect(await n(c, "SELECT count(*)::int AS n FROM tenant_deletions WHERE tenant_id = $1", [t])).toBe(1);
    });
  });

  it("every table of the group has row-level security and the policy, and the list matches db/rls.ts", async () => {
    const rows = (await withClient(urlFor(DB), (c) => c.query(
      `SELECT c.relname, c.relrowsecurity, EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'legion_tenant_isolation') AS has_policy
         FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'public' AND c.relrowsecurity ORDER BY c.relname`))).rows;
    expect(rows.map((r) => r.relname).sort()).toEqual([...RLS_TABLES].sort());
    expect(rows.every((r) => r.has_policy)).toBe(true);
    const migration = readFileSync(join(__dirname, "..", "src", "db", "migrations", "0009_row_level_security.sql"), "utf8");
    for (const t of RLS_TABLES) expect(migration).toContain(`'${t}'`);
  });

  it.skipIf(spawnSync("pg_dump", ["--version"]).status !== 0)("the backup (pg_dump --enable-row-security as the API's role, ops/backup.sh) still contains every workspace", () => {
    const r = spawnSync("pg_dump", [urlFor(DB, APP), "--enable-row-security", "--data-only", "-t", "alerts"], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("A1");
    expect(r.stdout).toContain("B1");
  });
});

describe("the API side (db/rls.ts, pool.ts)", () => {
  it("recognises the statements that reach a protected table", () => {
    expect(touchesRlsTable("SELECT * FROM alerts WHERE tenant_id = $1")).toBe("alerts");
    expect(touchesRlsTable("UPDATE soc_audit_events SET x = 1")).toBe("soc_audit_events");
    expect(touchesRlsTable('SELECT count(*) FROM "audit_log" WHERE tenant_id::text = $1')).toBe("audit_log");   // a name from a table list
    expect(touchesRlsTable("SELECT 1 FROM tenants")).toBeNull();
    expect(touchesRlsTable("SELECT legion_prune_soc($1, $2)")).toBeNull();
  });

  it("withTenant refuses anything but a workspace id; inTenant never widens a context that exists", async () => {
    expect(() => withTenant("'; DROP TABLE alerts; --", () => 1)).toThrow(/not a workspace id/);
    await withTenant(A, async () => {
      expect(inTenant(B, () => currentTenant())).toBe(A);       // the request's workspace wins over an argument
      expect(withTenant(B, () => currentTenant())).toBe(B);     // only an explicit, visible withTenant changes it
    });
    expect(inTenant(B, () => currentTenant())).toBe(B);
    expect(currentTenant()).toBeNull();
  });

  it("with DB_RLS=enforce, a query on a protected table without a workspace context is refused before it reaches the database", async () => {
    const before = config.dbRls;
    config.dbRls = "enforce";
    try {
      await expect(query("SELECT count(*) FROM alerts")).rejects.toThrow(/without a workspace context/);
      await expect(withTenant(A, () => query("SELECT count(*) FROM alerts WHERE tenant_id = $1", [A]))).resolves.toBeTruthy();
      await expect(query("SELECT 1 FROM tenants LIMIT 1")).resolves.toBeTruthy();   // not a protected table
      // …and inside a transaction started without one, too.
      await expect(transaction((c) => c.query("SELECT count(*) FROM audit_log"))).rejects.toThrow(/without a workspace context/);
      await expect(withTenant(A, () => transaction((c) => c.query("SELECT count(*) FROM audit_log WHERE tenant_id = $1", [A])))).resolves.toBeTruthy();
    } finally {
      config.dbRls = before;
    }
  });
});
