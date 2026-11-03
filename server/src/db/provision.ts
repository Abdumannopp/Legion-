import { randomBytes } from "node:crypto";
import type pg from "pg";

/*
 * Legion's API should not talk to Postgres as the superuser.
 *
 * The official Postgres image makes POSTGRES_USER the bootstrap superuser,
 * and until now the API connected as that user. A superuser can read and
 * write files on the database server (pg_read_file, COPY … TO PROGRAM),
 * create roles, change server settings and reach every database — so one
 * SQL injection or one leaked DATABASE_URL was the whole machine.
 *
 * provisionAppRole() gives the API its own role instead: it owns Legion's
 * tables (so boot-time migrations keep working) and nothing more. It is run
 * by a one-shot step that holds the superuser password — `node
 * dist/db/provision-cli.js`, run once by hand or from a deploy script; the
 * API itself only ever sees the app role's password. It is idempotent and
 * also upgrades existing installs, whose tables were created by the
 * superuser, by transferring ownership.
 */

export const DEFAULT_APP_ROLE = "legion_app";
const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

/** A string literal Postgres will accept where a bind parameter is not allowed (ALTER ROLE … PASSWORD). */
function literal(value: string): string {
  for (let i = 0; i < 10; i++) {
    const tag = `p${randomBytes(12).toString("hex")}`;
    if (!value.includes(tag)) return `$${tag}$${value}$${tag}$`;
  }
  throw new Error("could not build a safe literal");
}

const q = (ident: string) => `"${ident.replace(/"/g, '""')}"`;

export interface ProvisionResult {
  role: string;
  created: boolean;
  /** Objects whose ownership moved to the app role (existing installs). */
  transferred: string[];
  /** Role memberships that were removed from the app role. */
  revokedMemberships: string[];
}

export async function provisionAppRole(
  admin: pg.ClientBase,
  opts: { appUser?: string; appPassword: string; schema?: string },
): Promise<ProvisionResult> {
  const role = opts.appUser ?? DEFAULT_APP_ROLE;
  const schema = opts.schema ?? "public";
  if (!IDENTIFIER.test(role)) throw new Error(`Refusing unsafe role name ${JSON.stringify(role)}`);
  if (!IDENTIFIER.test(schema)) throw new Error(`Refusing unsafe schema name ${JSON.stringify(schema)}`);
  if (typeof opts.appPassword !== "string" || opts.appPassword.length < 16) {
    throw new Error("APP_DB_PASSWORD must be at least 16 characters (openssl rand -hex 24 generates one).");
  }

  const me = (await admin.query<{ user: string; super: boolean; createrole: boolean }>(
    "SELECT current_user AS user, rolsuper AS super, rolcreaterole AS createrole FROM pg_roles WHERE rolname = current_user",
  )).rows[0]!;
  if (me.user === role) throw new Error(`Provisioning must run as an administrator, not as ${role} itself.`);
  if (!me.super) throw new Error(`Provisioning needs the database superuser (connected as ${me.user}).`);

  await admin.query("BEGIN");
  try {
    const exists = (await admin.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [role])).rowCount! > 0;
    if (!exists) await admin.query(`CREATE ROLE ${q(role)}`);
    // Reasserted every run: a privilege added by hand does not survive the next start.
    await admin.query(
      `ALTER ROLE ${q(role)} WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT PASSWORD ${literal(opts.appPassword)}`,
    );
    const memberships = (await admin.query<{ rolname: string }>(
      `SELECT g.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = $1`,
      [role],
    )).rows.map((r) => r.rolname);
    for (const g of memberships) await admin.query(`REVOKE ${q(g)} FROM ${q(role)}`);

    const db = (await admin.query<{ db: string }>("SELECT current_database() AS db")).rows[0]!.db;
    await admin.query(`GRANT CONNECT, TEMPORARY ON DATABASE ${q(db)} TO ${q(role)}`);
    await admin.query(`GRANT USAGE, CREATE ON SCHEMA ${q(schema)} TO ${q(role)}`);

    // Existing installs: tables, views, sequences, functions and types the
    // superuser created. Extension members are left alone. A sequence owned
    // by a table column moves with its table.
    const transferred: string[] = [];
    const relations = (await admin.query<{ name: string; kind: string }>(
      `SELECT c.relname AS name, c.relkind AS kind
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relkind IN ('r','p','v','m','f','S')
          AND pg_get_userbyid(c.relowner) <> $2
          AND NOT (c.relkind = 'r' AND c.relispartition)
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.classid = 'pg_class'::regclass AND d.deptype IN ('e', 'a', 'i'))
        ORDER BY c.relkind, c.relname`,
      [schema, role],
    )).rows;
    const verb: Record<string, string> = { r: "TABLE", p: "TABLE", f: "FOREIGN TABLE", v: "VIEW", m: "MATERIALIZED VIEW", S: "SEQUENCE" };
    for (const r of relations) {
      await admin.query(`ALTER ${verb[r.kind]} ${q(schema)}.${q(r.name)} OWNER TO ${q(role)}`);
      transferred.push(`${verb[r.kind]!.toLowerCase()} ${r.name}`);
    }
    const routines = (await admin.query<{ name: string; args: string }>(
      `SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = $1 AND pg_get_userbyid(p.proowner) <> $2
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.classid = 'pg_proc'::regclass AND d.deptype = 'e')`,
      [schema, role],
    )).rows;
    for (const r of routines) {
      await admin.query(`ALTER ROUTINE ${q(schema)}.${q(r.name)}(${r.args}) OWNER TO ${q(role)}`);
      transferred.push(`function ${r.name}`);
    }
    const types = (await admin.query<{ name: string }>(
      `SELECT t.typname AS name FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = $1 AND t.typtype IN ('e', 'd', 'c') AND (t.typrelid = 0 OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c')
          AND pg_get_userbyid(t.typowner) <> $2
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = t.oid AND d.classid = 'pg_type'::regclass AND d.deptype = 'e')`,
      [schema, role],
    )).rows;
    for (const t of types) {
      await admin.query(`ALTER TYPE ${q(schema)}.${q(t.name)} OWNER TO ${q(role)}`);
      transferred.push(`type ${t.name}`);
    }

    await admin.query("COMMIT");
    return { role, created: !exists, transferred, revokedMemberships: memberships };
  } catch (err) {
    await admin.query("ROLLBACK").catch(() => {});
    throw err;
  }
}

/** Role attributes the API should never hold. Pure, for the boot check and its tests. */
export function privilegedRoleProblems(attrs: {
  rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolbypassrls: boolean; rolreplication: boolean;
}): string[] {
  const p: string[] = [];
  if (attrs.rolsuper) p.push("superuser (can read server files, run programs and reach every database)");
  if (attrs.rolcreaterole) p.push("CREATEROLE (can create and grant roles)");
  if (attrs.rolcreatedb) p.push("CREATEDB");
  if (attrs.rolbypassrls) p.push("BYPASSRLS (ignores row-level security)");
  if (attrs.rolreplication) p.push("REPLICATION (can stream the whole cluster)");
  return p;
}

/** What the API does at boot, given the role it connected as. Refuses in production unless explicitly overridden. */
export function databaseRoleDecision(
  role: { rolname: string; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolbypassrls: boolean; rolreplication: boolean },
  env: { production: boolean; allowPrivileged: boolean },
): { action: "ok" | "warn" | "refuse"; message: string } {
  const problems = privilegedRoleProblems(role);
  if (!problems.length) return { action: "ok", message: "" };
  const message = `the API is connected to Postgres as "${role.rolname}", which has: ${problems.join("; ")}. ` +
    "Run the API as the app role created by `node dist/db/provision-cli.js` (see provision-cli.ts).";
  if (env.production && !env.allowPrivileged) return { action: "refuse", message: `${message} (DB_ALLOW_PRIVILEGED_ROLE=true overrides this.)` };
  return { action: "warn", message };
}
