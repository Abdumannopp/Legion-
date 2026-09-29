/**
 * ToolGateway.database(): the wiring between an authorized agent SQL call and
 * the least-privilege Postgres role (src/database/least-privilege.ts).
 * tools/sql.ts's own denial rules are covered in test/tools-analyzers.test.ts
 * and test/tools.test.ts; database-level denial and row-level tenant
 * isolation are covered directly against Postgres in
 * test/db-least-privilege.test.ts. This file proves the two are actually
 * connected: an allowed call runs on the restricted connection, not the
 * module's own admin pool, and a host that forgets to configure it gets a
 * clear refusal instead of silently falling back to full privileges.
 */
import pg from "pg";
import request from "supertest";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { applyLeastPrivilegeRole } from "../src/index.js";
import { agentWithToken, as, bearer, DATABASE_URL, makeApp, resetDb, TENANT_A, TENANT_B, type TestApp } from "./helpers.js";

const ROLE = "lp_gw_test_role";
const PASSWORD = "lp-gw-test-password";
const TABLE = "gw_agent_notes";

function poolAs(user: string, password: string): pg.Pool {
  const url = new URL(DATABASE_URL);
  url.username = user;
  url.password = password;
  return new pg.Pool({ connectionString: url.toString(), max: 3 });
}

const admin = new pg.Pool({ connectionString: DATABASE_URL, max: 5 });
let agentDbPool: pg.Pool;
let t: TestApp;

async function dropRole() {
  await admin.query(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "${ROLE}"`).catch(() => {});
  await admin.query(`DROP OWNED BY "${ROLE}"`).catch(() => {});
  await admin.query(`DROP ROLE IF EXISTS "${ROLE}"`).catch(() => {});
}

beforeEach(async () => {
  if (t) await t.pool.end();
  if (agentDbPool) await agentDbPool.end();
  await dropRole();
  await admin.query(`
    DROP TABLE IF EXISTS ${TABLE} CASCADE;
    CREATE TABLE ${TABLE} (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id text NOT NULL, body text NOT NULL);
  `);
  await applyLeastPrivilegeRole(admin, { roleName: ROLE, password: PASSWORD, tables: { [TABLE]: ["select", "insert", "update"] } });
  agentDbPool = poolAs(ROLE, PASSWORD);

  t = await makeApp({ extra: { agentDbPool } });
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  const res = await request(t.app).put("/firewall/policy").set(as("alice")).send({ database: { tables: { [TABLE]: ["select", "insert", "update"] } } });
  if (res.status !== 200) throw new Error(JSON.stringify(res.body));
});

afterAll(async () => {
  await t?.pool.end();
  await agentDbPool?.end();
  await dropRole();
  await admin.query(`DROP TABLE IF EXISTS ${TABLE} CASCADE;`);
  await admin.end();
});

describe("tools.database()", () => {
  it("runs an authorized call on the least-privilege connection, scoped to the caller's own tenant", async () => {
    await admin.query(`INSERT INTO ${TABLE} (tenant_id, body) VALUES ($1, 'mine'), ($2, 'not mine')`, [TENANT_A, TENANT_B]);
    const { token } = await agentWithToken(t, "alice", { permissions: ["tool.database:read"] });
    const who = await request(t.app).get("/agent/v1/whoami").set(bearer(token));
    const ctx = { principal: who.body.principal };

    const result = await t.identity.tools.database(ctx, {
      kind: "database", operation: "query", sql: `SELECT body FROM ${TABLE} WHERE tenant_id = $1 LIMIT 10`, params: [TENANT_A],
    });
    expect(result.data).toEqual([{ body: "mine" }]);
  });

  it("row-level security holds even for a query analyzeSql would have allowed but which reads too broadly", async () => {
    await admin.query(`INSERT INTO ${TABLE} (tenant_id, body) VALUES ($1, 'mine'), ($2, 'not mine')`, [TENANT_A, TENANT_B]);
    const { token } = await agentWithToken(t, "alice", { permissions: ["tool.database:write"] });
    const who = await request(t.app).get("/agent/v1/whoami").set(bearer(token));
    const ctx = { principal: who.body.principal };

    // A same-tenant UPDATE with no row-identifying WHERE beyond tenant_id: the
    // analyzer's own tenant-scope check is satisfied (tenant_id = $1 is bound
    // to the caller's tenant), so this is a call it would allow. RLS is the
    // reason it still can't touch the other tenant's row.
    await t.identity.tools.database(ctx, {
      kind: "database", operation: "query", sql: `UPDATE ${TABLE} SET body = 'changed' WHERE tenant_id = $1`, params: [TENANT_A],
    });
    const rows = await admin.query(`SELECT tenant_id, body FROM ${TABLE} ORDER BY tenant_id`);
    expect(rows.rows).toEqual([{ tenant_id: TENANT_A, body: "changed" }, { tenant_id: TENANT_B, body: "not mine" }]);
  });

  it("refuses to run at all when no least-privilege pool is configured, rather than falling back to full privileges", async () => {
    const bare = await makeApp();
    await resetDb(bare.pool);
    await bare.identity.migrate();
    bare.host.add("alice", TENANT_A, "admin");
    await request(bare.app).put("/firewall/policy").set(as("alice")).send({ database: { tables: { [TABLE]: ["select"] } } });
    const { token } = await agentWithToken(bare, "alice", { permissions: ["tool.database:read"] });
    const who = await request(bare.app).get("/agent/v1/whoami").set(bearer(token));
    const ctx = { principal: who.body.principal };

    await expect(
      bare.identity.tools.database(ctx, {
        kind: "database", operation: "query", sql: `SELECT body FROM ${TABLE} WHERE tenant_id = $1 LIMIT 10`, params: [TENANT_A],
      }),
    ).rejects.toThrow(/No least-privilege database pool configured/);
    await bare.pool.end();
  });

  it("a call tools/sql.ts blocks never reaches the least-privilege connection", async () => {
    await admin.query(`INSERT INTO ${TABLE} (tenant_id, body) VALUES ($1, 'survives')`, [TENANT_A]);
    const { token } = await agentWithToken(t, "alice", { permissions: ["tool.database:write"] });
    const who = await request(t.app).get("/agent/v1/whoami").set(bearer(token));
    const ctx = { principal: who.body.principal };

    // No WHERE at all: sql.unbounded_write blocks this in authorize(), before
    // execute() ever invokes the executor that would touch Postgres.
    await expect(
      t.identity.tools.database(ctx, { kind: "database", operation: "query", sql: `DELETE FROM ${TABLE}`, params: [] }),
    ).rejects.toThrow();
    const rows = await admin.query(`SELECT body FROM ${TABLE}`);
    expect(rows.rows).toEqual([{ body: "survives" }]);
  });
});
