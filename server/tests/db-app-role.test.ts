/**
 * The API's own database role (src/db/provision.ts), against a real
 * PostgreSQL: fresh install, upgrade of an install whose tables the
 * superuser owns, what the role cannot do, idempotence and self-healing,
 * and the boot decision.
 */
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { databaseRoleDecision, privilegedRoleProblems, provisionAppRole } from "../src/db/provision.js";

const ADMIN_URL = process.env.DATABASE_URL!;
const SCHEMA = readFileSync(join(__dirname, "..", "src", "db", "schema.sql"), "utf8");
const suffix = randomBytes(3).toString("hex");
const ROLE = `legion_app_t${suffix}`;
const PASSWORD = `app-${randomBytes(16).toString("hex")}`;
const DBS = { fresh: `legion_role_fresh_${suffix}`, upgrade: `legion_role_upg_${suffix}` };

const urlFor = (db: string, user?: string, password?: string) => {
  const u = new URL(ADMIN_URL);
  u.pathname = `/${db}`;
  if (user) { u.username = user; u.password = password ?? ""; }
  return u.toString();
};
async function withClient<T>(url: string, fn: (c: pg.Client) => Promise<T>): Promise<T> {
  const c = new pg.Client({ connectionString: url });
  await c.connect();
  try { return await fn(c); } finally { await c.end(); }
}
const asAdmin = <T>(db: string, fn: (c: pg.Client) => Promise<T>) => withClient(urlFor(db), fn);
const asApp = <T>(db: string, fn: (c: pg.Client) => Promise<T>, password = PASSWORD) => withClient(urlFor(db, ROLE, password), fn);

beforeAll(async () => {
  await withClient(ADMIN_URL, async (c) => {
    for (const db of Object.values(DBS)) {
      await c.query(`DROP DATABASE IF EXISTS "${db}"`);
      await c.query(`CREATE DATABASE "${db}"`);
    }
  });
});

afterAll(async () => {
  await withClient(ADMIN_URL, async (c) => {
    for (const db of Object.values(DBS)) {
      await c.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", [db]);
      await c.query(`DROP DATABASE IF EXISTS "${db}"`);
    }
    await c.query(`DROP ROLE IF EXISTS "${ROLE}"`);
  });
});

describe("fresh install", () => {
  it("creates a role that is not a superuser and can run Legion's migrations and queries", async () => {
    const r = await asAdmin(DBS.fresh, (c) => provisionAppRole(c, { appUser: ROLE, appPassword: PASSWORD }));
    expect(r.created).toBe(true);
    await asApp(DBS.fresh, async (c) => {
      await c.query(SCHEMA);
      await c.query(SCHEMA); // idempotent, as on every boot
      const t = "11111111-1111-4111-8111-111111111111";
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Acme')", [t]);
      await c.query("INSERT INTO alerts (tenant_id, id, title, severity, agent, summary) VALUES ($1, 'A1', 't', 'high', 'x', 's')", [t]);
      expect((await c.query("SELECT count(*)::int AS n FROM alerts")).rows[0].n).toBe(1);
      const me = (await c.query("SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication FROM pg_roles WHERE rolname = current_user")).rows[0];
      expect(me).toEqual({ rolsuper: false, rolcreaterole: false, rolcreatedb: false, rolbypassrls: false, rolreplication: false });
    });
  });

  it.each([
    ["read a server file", "SELECT pg_read_file('/etc/passwd')", /permission denied/],
    ["run a program on the server", "COPY (SELECT 1) TO PROGRAM 'id'", /permission denied|must be superuser|pg_execute_server_program/],
    ["write a server file", "COPY (SELECT 1) TO '/tmp/legion-pwned'", /permission denied|must be superuser|pg_write_server_files/],
    ["create a role", "CREATE ROLE legion_evil LOGIN SUPERUSER", /permission denied/],
    ["make itself superuser", `ALTER ROLE "${ROLE}" SUPERUSER`, /permission denied/],
    ["create a database", "CREATE DATABASE legion_evil", /permission denied/],
    ["change server settings", "ALTER SYSTEM SET log_statement = 'none'", /permission denied|must be superuser/],
    ["reload the server configuration", "SELECT pg_reload_conf()", /permission denied/],
    ["read password hashes", "SELECT rolpassword FROM pg_authid LIMIT 1", /permission denied/],
    ["become the superuser", `SET ROLE "${new URL(ADMIN_URL).username}"`, /permission denied/],
  ])("the API role cannot %s", async (_what, sql, err) => {
    await asApp(DBS.fresh, async (c) => {
      await expect(c.query(sql)).rejects.toThrow(err);
    });
  });

  it("cannot terminate the administrator's sessions", async () => {
    await asAdmin(DBS.fresh, async (admin) => {
      const pid = (await admin.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
      await asApp(DBS.fresh, async (c) => {
        await expect(c.query("SELECT pg_terminate_backend($1)", [pid])).rejects.toThrow(/permission denied|must be a member/);
      });
    });
  });
});

describe("upgrading an install whose tables the superuser owns", () => {
  it("moves ownership to the API role so boot-time migrations keep working, with the data intact", async () => {
    const t = "22222222-2222-4222-8222-222222222222";
    await asAdmin(DBS.upgrade, async (c) => {
      await c.query(SCHEMA);
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Old')", [t]);
      await c.query("CREATE FUNCTION old_helper() RETURNS int LANGUAGE sql AS 'SELECT 1'");
      await c.query("CREATE SEQUENCE old_counter");
    });
    // Before provisioning, the app role could not even migrate.
    const r = await asAdmin(DBS.upgrade, (c) => provisionAppRole(c, { appUser: ROLE, appPassword: PASSWORD }));
    expect(r.transferred).toEqual(expect.arrayContaining(["table tenants", "table alerts", "table users", "function old_helper", "sequence old_counter"]));
    await asApp(DBS.upgrade, async (c) => {
      await c.query(SCHEMA);
      await c.query("ALTER TABLE tenants ADD COLUMN IF NOT EXISTS upgrade_probe text");
      expect((await c.query("SELECT name FROM tenants WHERE id = $1", [t])).rows[0].name).toBe("Old");
    });
    const owners = await asAdmin(DBS.upgrade, (c) => c.query(
      "SELECT DISTINCT pg_get_userbyid(relowner) AS owner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND relkind IN ('r','S','v')",
    ));
    expect(owners.rows).toEqual([{ owner: ROLE }]);
  });
});

describe("every run reasserts the role", () => {
  it("is idempotent and rotates the password", async () => {
    const next = `app-${randomBytes(16).toString("hex")}`;
    const r = await asAdmin(DBS.fresh, (c) => provisionAppRole(c, { appUser: ROLE, appPassword: next }));
    expect(r.created).toBe(false);
    expect(r.transferred).toEqual([]);
    await expect(asApp(DBS.fresh, async () => {}, PASSWORD)).rejects.toThrow(/password authentication failed/);
    await asApp(DBS.fresh, async (c) => { await c.query("SELECT 1"); }, next);
    await asAdmin(DBS.fresh, (c) => provisionAppRole(c, { appUser: ROLE, appPassword: PASSWORD }));
  });

  it("undoes privileges someone added by hand", async () => {
    await asAdmin(DBS.fresh, async (c) => {
      await c.query(`ALTER ROLE "${ROLE}" SUPERUSER CREATEROLE BYPASSRLS`);
      await c.query(`GRANT pg_read_server_files TO "${ROLE}"`);
    });
    const r = await asAdmin(DBS.fresh, (c) => provisionAppRole(c, { appUser: ROLE, appPassword: PASSWORD }));
    expect(r.revokedMemberships).toEqual(["pg_read_server_files"]);
    await asApp(DBS.fresh, async (c) => {
      await expect(c.query("SELECT pg_read_file('/etc/passwd')")).rejects.toThrow(/permission denied/);
      const me = (await c.query("SELECT rolsuper, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = current_user")).rows[0];
      expect(me).toEqual({ rolsuper: false, rolcreaterole: false, rolbypassrls: false });
    });
  });

  it("refuses a weak password, an unsafe name, or being run by the app role itself", async () => {
    await asAdmin(DBS.fresh, async (c) => {
      await expect(provisionAppRole(c, { appUser: ROLE, appPassword: "short" })).rejects.toThrow(/16 characters/);
      await expect(provisionAppRole(c, { appUser: 'x"; DROP ROLE postgres; --', appPassword: PASSWORD })).rejects.toThrow(/unsafe role name/);
    });
    await asApp(DBS.fresh, async (c) => {
      await expect(provisionAppRole(c, { appUser: ROLE, appPassword: PASSWORD })).rejects.toThrow(/administrator/);
      await expect(provisionAppRole(c, { appUser: "other_role", appPassword: PASSWORD })).rejects.toThrow(/superuser/);
    });
  });
});

describe("boot decision", () => {
  const app = { rolname: "legion_app", rolsuper: false, rolcreaterole: false, rolcreatedb: false, rolbypassrls: false, rolreplication: false };
  const su = { ...app, rolname: "legion", rolsuper: true, rolcreaterole: true, rolcreatedb: true, rolbypassrls: true, rolreplication: true };

  it("the app role is fine everywhere", () => {
    expect(databaseRoleDecision(app, { production: true, allowPrivileged: false }).action).toBe("ok");
  });
  it("a superuser is refused in production, with the reason and the fix", () => {
    const d = databaseRoleDecision(su, { production: true, allowPrivileged: false });
    expect(d.action).toBe("refuse");
    expect(d.message).toMatch(/superuser/);
    expect(d.message).toMatch(/provision-cli/);
  });
  it("outside production it is a loud warning; in production only an explicit override lets it through", () => {
    expect(databaseRoleDecision(su, { production: false, allowPrivileged: false }).action).toBe("warn");
    expect(databaseRoleDecision(su, { production: true, allowPrivileged: true }).action).toBe("warn");
  });
  it("names each dangerous attribute", () => {
    expect(privilegedRoleProblems(su)).toHaveLength(5);
    expect(privilegedRoleProblems({ ...app, rolbypassrls: true })[0]).toMatch(/BYPASSRLS/);
  });
});
