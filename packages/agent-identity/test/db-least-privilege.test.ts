/**
 * Database-level least privilege for agent SQL (src/database/least-privilege.ts).
 *
 * tools/sql.ts (tested elsewhere) refuses dangerous SQL text before a query
 * ever reaches Postgres. These tests assume that layer does not exist —
 * every query here is sent directly, exactly as a caller who bypassed the
 * analyzer (a bug, a bad executor, a future maintainer wiring the wrong
 * pool) would send it — and prove Postgres itself, under the least-privilege
 * role, refuses what it should refuse regardless.
 */
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AGENT_TENANT_SETTING, applyLeastPrivilegeRole, assertIdentifier, DENIED_ROLE_MEMBERSHIPS, withAgentTenant } from "../src/database/least-privilege.js";
import { PROTECTED_TABLES } from "../src/firewall/policy.js";
import { DATABASE_URL } from "./helpers.js";

const ROLE = "lp_test_agent_role";
const OTHER_ROLE = "lp_test_agent_role_2";
const PASSWORD = "lp-test-password-1";

function poolAs(user: string, password: string): pg.Pool {
  const url = new URL(DATABASE_URL);
  url.username = user;
  url.password = password;
  return new pg.Pool({ connectionString: url.toString(), max: 3 });
}

const admin = new pg.Pool({ connectionString: DATABASE_URL, max: 5 });

async function dropTestRole(name: string) {
  // A role that still owns objects or holds live grants can't be dropped;
  // this is only ever used on our own disposable test roles.
  await admin.query(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "${name}"`).catch(() => {});
  await admin.query(`DROP OWNED BY "${name}"`).catch(() => {});
  await admin.query(`DROP ROLE IF EXISTS "${name}"`).catch(() => {});
}

beforeAll(async () => {
  await admin.query(`
    DROP TABLE IF EXISTS lp_notes, lp_secret_table CASCADE;
    CREATE TABLE lp_notes (
      id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id  text NOT NULL,
      body       text NOT NULL
    );
    CREATE TABLE lp_secret_table (
      id         serial PRIMARY KEY,
      tenant_id  text NOT NULL,
      body       text NOT NULL
    );
  `);
  for (const r of [ROLE, OTHER_ROLE]) await dropTestRole(r);
});

afterAll(async () => {
  for (const r of [ROLE, OTHER_ROLE]) await dropTestRole(r);
  await admin.query(`DROP TABLE IF EXISTS lp_notes, lp_secret_table CASCADE;`);
  await admin.end();
});

describe("assertIdentifier", () => {
  it("accepts a plain lowercase identifier and rejects everything that could break out of DDL text", () => {
    expect(assertIdentifier("legion_agent_sql")).toBe("legion_agent_sql");
    for (const bad of ['legion"; DROP TABLE users; --', "Legion", "1role", "a b", "", "a".repeat(64)]) {
      expect(() => assertIdentifier(bad)).toThrow();
    }
  });
});

describe("provisioning the role", () => {
  it("refuses to grant a protected table, and touches nothing when it does", async () => {
    const protectedName = [...PROTECTED_TABLES][0]!;
    await expect(
      applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { [protectedName]: ["select"] } }),
    ).rejects.toThrow(/holds identities, secrets or audit history/);
    // Nothing was attempted: the role was never even created.
    const exists = await admin.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [ROLE]);
    expect(exists.rowCount).toBe(0);
  });

  it("is idempotent: applying twice does not error", async () => {
    const apply = () => applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { lp_notes: ["select", "insert", "update", "delete"] } });
    await expect(apply()).resolves.toBeUndefined();
    await expect(apply()).resolves.toBeUndefined();
  });

  it("creates a role with none of the superuser-adjacent attributes", async () => {
    const r = await admin.query(
      `SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls FROM pg_roles WHERE rolname = $1`,
      [ROLE],
    );
    expect(r.rows[0]).toEqual({ rolsuper: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolbypassrls: false });
  });

  it("joins none of the predefined roles that unlock files, programs, signals or settings", async () => {
    const r = await admin.query(
      `SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid
       JOIN pg_roles member ON member.oid = m.member WHERE member.rolname = $1`,
      [ROLE],
    );
    expect(r.rows.map((row) => row.rolname)).toEqual([]);
  });

  it("self-heals: a privilege granted by hand outside this function is stripped on the next apply", async () => {
    await admin.query(`GRANT SELECT ON lp_secret_table TO "${ROLE}"`);
    const probe = poolAs(ROLE, PASSWORD);
    const before = await probe.query("SELECT 1 FROM lp_secret_table LIMIT 1").catch((e) => e);
    await probe.end();
    expect(before).not.toBeInstanceOf(Error); // the manual grant works, for now

    await applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { lp_notes: ["select", "insert", "update", "delete"] } });

    const pool = poolAs(ROLE, PASSWORD);
    await expect(pool.query("SELECT 1 FROM lp_secret_table LIMIT 1")).rejects.toThrow(/permission denied/);
    await pool.end();
  });

  it("self-heals: a dangerous role membership granted by hand is revoked on the next apply", async () => {
    await admin.query(`GRANT pg_read_server_files TO "${ROLE}"`);
    await applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { lp_notes: ["select", "insert", "update", "delete"] } });
    const r = await admin.query(
      `SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = $1`,
      [ROLE],
    );
    expect(r.rows).toEqual([]);
    for (const denied of DENIED_ROLE_MEMBERSHIPS) expect(r.rows.map((x) => x.rolname)).not.toContain(denied);
    const pool = poolAs(ROLE, PASSWORD);
    await expect(pool.query("SELECT pg_read_file('/etc/passwd')")).rejects.toThrow(/permission denied/);
    await pool.end();
  });

  it("does not change what other database roles see on the same tables", async () => {
    const REPORTING = "lp_test_reporting";
    await dropTestRole(REPORTING);
    await admin.query(`CREATE ROLE "${REPORTING}" LOGIN PASSWORD 'lp-reporting'`);
    await admin.query(`GRANT SELECT ON lp_notes TO "${REPORTING}"`);
    await admin.query("DELETE FROM lp_notes");
    await admin.query("INSERT INTO lp_notes (tenant_id, body) VALUES ('t1', 'one'), ('t2', 'two')");
    const other = poolAs(REPORTING, "lp-reporting");
    try {
      // RLS is on for lp_notes now, but only the agent role is confined by it.
      const r = await other.query("SELECT body FROM lp_notes ORDER BY body");
      expect(r.rows.map((x) => x.body)).toEqual(["one", "two"]);
    } finally {
      await other.end();
      await admin.query("DELETE FROM lp_notes");
      await dropTestRole(REPORTING);
    }
  });
});

describe("denied at the database level, whatever tools/sql.ts would have said", () => {
  let pool: pg.Pool;
  beforeAll(async () => {
    await applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { lp_notes: ["select", "insert", "update", "delete"] } });
    pool = poolAs(ROLE, PASSWORD);
  });
  afterAll(async () => pool.end());

  it("cannot read a table that was never granted", async () => {
    await expect(pool.query("SELECT * FROM lp_secret_table")).rejects.toThrow(/permission denied/);
    await expect(pool.query("INSERT INTO lp_secret_table (tenant_id, body) VALUES ('t', 'x')")).rejects.toThrow(/permission denied/);
  });

  it("cannot create or drop tables", async () => {
    await expect(pool.query("CREATE TABLE lp_should_not_exist (id int)")).rejects.toThrow(/permission denied/);
    await expect(pool.query("DROP TABLE lp_notes")).rejects.toThrow(/must be owner/);
  });

  it("cannot read files from the server", async () => {
    await expect(pool.query("SELECT pg_read_file('/etc/passwd')")).rejects.toThrow(/permission denied/);
  });

  it("cannot reload or change server configuration", async () => {
    await expect(pool.query("SELECT pg_reload_conf()")).rejects.toThrow(/permission denied/);
  });

  it("cannot terminate or cancel another session's backend", async () => {
    const admin2 = await admin.connect();
    try {
      const pid = (await admin2.query("SELECT pg_backend_pid() AS pid")).rows[0].pid as number;
      await expect(pool.query("SELECT pg_terminate_backend($1)", [pid])).rejects.toThrow(/permission denied|must be a member/);
    } finally {
      admin2.release();
    }
  });

  it("cannot grant itself superuser or create roles", async () => {
    await expect(pool.query(`ALTER ROLE "${ROLE}" WITH SUPERUSER`)).rejects.toThrow(/permission denied/);
    await expect(pool.query(`CREATE ROLE lp_should_not_exist`)).rejects.toThrow(/permission denied/);
  });
});

describe("row-level tenant isolation, enforced independently of the query text", () => {
  let pool: pg.Pool;
  const TENANT_A = "lp-tenant-a";
  const TENANT_B = "lp-tenant-b";
  let rowA: string;
  let rowB: string;

  beforeAll(async () => {
    await applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { lp_notes: ["select", "insert", "update", "delete"] } });
    pool = poolAs(ROLE, PASSWORD);
    await admin.query("DELETE FROM lp_notes");
    const a = await admin.query("INSERT INTO lp_notes (tenant_id, body) VALUES ($1, 'a-note') RETURNING id", [TENANT_A]);
    const b = await admin.query("INSERT INTO lp_notes (tenant_id, body) VALUES ($1, 'b-note') RETURNING id", [TENANT_B]);
    rowA = a.rows[0].id;
    rowB = b.rows[0].id;
  });
  afterAll(async () => pool.end());

  it("a SELECT with no WHERE at all still only returns the bound tenant's rows", async () => {
    const rows = await withAgentTenant(pool, TENANT_A, (c) => c.query("SELECT tenant_id, body FROM lp_notes"));
    expect(rows.rows).toEqual([{ tenant_id: TENANT_A, body: "a-note" }]);
  });

  it("a SELECT that explicitly asks for the other tenant's id still comes back empty", async () => {
    const rows = await withAgentTenant(pool, TENANT_A, (c) => c.query("SELECT * FROM lp_notes WHERE tenant_id = $1", [TENANT_B]));
    expect(rows.rows).toEqual([]);
  });

  it("cannot UPDATE a row belonging to another tenant, even naming it by id", async () => {
    const r = await withAgentTenant(pool, TENANT_A, (c) => c.query("UPDATE lp_notes SET body = 'tampered' WHERE id = $1", [rowB]));
    expect(r.rowCount).toBe(0);
    const check = await admin.query("SELECT body FROM lp_notes WHERE id = $1", [rowB]);
    expect(check.rows[0].body).toBe("b-note");
  });

  it("cannot DELETE a row belonging to another tenant", async () => {
    const r = await withAgentTenant(pool, TENANT_A, (c) => c.query("DELETE FROM lp_notes WHERE id = $1", [rowB]));
    expect(r.rowCount).toBe(0);
    const check = await admin.query("SELECT 1 FROM lp_notes WHERE id = $1", [rowB]);
    expect(check.rowCount).toBe(1);
  });

  it("cannot INSERT a row claiming another tenant's id", async () => {
    await expect(
      withAgentTenant(pool, TENANT_A, (c) => c.query("INSERT INTO lp_notes (tenant_id, body) VALUES ($1, 'sneaky')", [TENANT_B])),
    ).rejects.toThrow(/row-level security/);
  });

  it("can read, insert, update and delete freely within its own tenant", async () => {
    await withAgentTenant(pool, TENANT_A, async (c) => {
      const ins = await c.query("INSERT INTO lp_notes (tenant_id, body) VALUES ($1, 'own') RETURNING id", [TENANT_A]);
      const id = ins.rows[0].id;
      await c.query("UPDATE lp_notes SET body = 'own-updated' WHERE id = $1", [id]);
      const sel = await c.query("SELECT body FROM lp_notes WHERE id = $1", [id]);
      expect(sel.rows[0].body).toBe("own-updated");
      const del = await c.query("DELETE FROM lp_notes WHERE id = $1", [id]);
      expect(del.rowCount).toBe(1);
    });
  });

  it("a session that never bound a tenant sees nothing (current_setting comes back unset, not a wildcard)", async () => {
    const bare = await pool.query("SELECT * FROM lp_notes");
    expect(bare.rows).toEqual([]);
  });

  it("two tenants drawing from the same pool concurrently never see each other's rows", async () => {
    const [a, b] = await Promise.all([
      withAgentTenant(pool, TENANT_A, (c) => c.query("SELECT body FROM lp_notes")),
      withAgentTenant(pool, TENANT_B, (c) => c.query("SELECT body FROM lp_notes")),
    ]);
    expect(a.rows.map((r) => r.body)).toEqual(["a-note"]);
    expect(b.rows.map((r) => r.body)).toEqual(["b-note"]);
  });
});

describe("tables shaped like Legion's own (uuid tenant_id)", () => {
  const A = "11111111-1111-4111-8111-111111111111";
  const B = "22222222-2222-4222-8222-222222222222";
  let pool: pg.Pool;

  beforeAll(async () => {
    await admin.query(`
      DROP TABLE IF EXISTS lp_uuid_alerts, lp_no_tenant CASCADE;
      CREATE TABLE lp_uuid_alerts (tenant_id uuid NOT NULL, id text NOT NULL, title text NOT NULL, PRIMARY KEY (tenant_id, id));
      CREATE TABLE lp_no_tenant (id int PRIMARY KEY, body text);
    `);
    await admin.query("INSERT INTO lp_uuid_alerts VALUES ($1, 'x', 'mine'), ($2, 'x', 'theirs')", [A, B]);
    await applyLeastPrivilegeRole(admin, { roleName: OTHER_ROLE, password: PASSWORD, tables: { lp_uuid_alerts: ["select", "update"] } });
    pool = poolAs(OTHER_ROLE, PASSWORD);
  });
  afterAll(async () => {
    await pool.end();
    await admin.query("DROP TABLE IF EXISTS lp_uuid_alerts, lp_no_tenant CASCADE");
  });

  it("isolates tenants on a uuid tenant column, same as on text", async () => {
    const r = await withAgentTenant(pool, A, (c) => c.query("SELECT title FROM lp_uuid_alerts"));
    expect(r.rows).toEqual([{ title: "mine" }]);
    const u = await withAgentTenant(pool, A, (c) => c.query("UPDATE lp_uuid_alerts SET title = 'hit' WHERE tenant_id = $1", [B]));
    expect(u.rowCount).toBe(0);
  });

  it("a tenant value that is not a valid id errors instead of matching anything", async () => {
    await expect(withAgentTenant(pool, "' OR 1=1 --", (c) => c.query("SELECT * FROM lp_uuid_alerts"))).rejects.toThrow(/invalid input syntax for type uuid/);
  });

  it("refuses to grant a table that has no tenant column", async () => {
    await expect(
      applyLeastPrivilegeRole(admin, { roleName: OTHER_ROLE, password: PASSWORD, tables: { lp_no_tenant: ["select"] } }),
    ).rejects.toThrow(/no "tenant_id" column/);
  });
});

describe("AGENT_TENANT_SETTING", () => {
  it("is namespaced so it cannot collide with an ordinary Postgres setting", () => {
    expect(AGENT_TENANT_SETTING).toMatch(/^legion\./);
  });
});
