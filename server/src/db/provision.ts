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
/** F-02: the role that owns the schema when the owner/runtime split is on. It cannot log in. */
export const DEFAULT_OWNER_ROLE = "legion_owner";
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
  /** The role that now owns the schema: the app role itself, or the separate owner role (split). */
  owner: string;
}

export async function provisionAppRole(
  admin: pg.ClientBase,
  opts: { appUser?: string; appPassword: string; schema?: string; split?: boolean; ownerRole?: string },
): Promise<ProvisionResult> {
  const role = opts.appUser ?? DEFAULT_APP_ROLE;
  const schema = opts.schema ?? "public";
  const split = opts.split === true;
  const owner = split ? (opts.ownerRole ?? DEFAULT_OWNER_ROLE) : role;
  if (!IDENTIFIER.test(role)) throw new Error(`Refusing unsafe role name ${JSON.stringify(role)}`);
  if (!IDENTIFIER.test(owner)) throw new Error(`Refusing unsafe role name ${JSON.stringify(owner)}`);
  if (split && owner === role) throw new Error("The owner role must differ from the app role.");
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
    if (split) {
      // The owner: holds the schema, cannot log in, and nobody (the app role least of all) is a member.
      const ownerExists = (await admin.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [owner])).rowCount! > 0;
      if (!ownerExists) await admin.query(`CREATE ROLE ${q(owner)}`);
      await admin.query(`ALTER ROLE ${q(owner)} WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`);
      const members = (await admin.query<{ rolname: string }>(
        "SELECT u.rolname FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE g.rolname = $1 AND NOT u.rolsuper",
        [owner],
      )).rows.map((r) => r.rolname);
      for (const m of members) await admin.query(`REVOKE ${q(owner)} FROM ${q(m)}`);
      await admin.query(`GRANT USAGE, CREATE ON SCHEMA ${q(schema)} TO ${q(owner)}`);
      // The runtime may use the schema, not add to it.
      await admin.query(`GRANT USAGE ON SCHEMA ${q(schema)} TO ${q(role)}`);
      await admin.query(`REVOKE CREATE ON SCHEMA ${q(schema)} FROM ${q(role)}`);
      await admin.query(`REVOKE CREATE ON SCHEMA ${q(schema)} FROM PUBLIC`);
    } else {
      await admin.query(`GRANT USAGE, CREATE ON SCHEMA ${q(schema)} TO ${q(role)}`);
    }

    // Existing installs: tables, views, sequences, functions and types the
    // superuser created. Extension members are left alone. A sequence owned
    // by a table column moves with its table.
    // Postgres builds each statement itself (format %I and the reg* casts quote every name), so no
    // catalog name is ever spliced into SQL here.
    const relations = (await admin.query<{ label: string; stmt: string }>(
      `SELECT lower(v.verb) || ' ' || c.relname AS label,
              format('ALTER %s %s OWNER TO %I', v.verb, c.oid::regclass, $2::text) AS stmt
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN (VALUES ('r', 'TABLE'), ('p', 'TABLE'), ('f', 'FOREIGN TABLE'), ('v', 'VIEW'), ('m', 'MATERIALIZED VIEW'), ('S', 'SEQUENCE')) AS v(kind, verb)
           ON v.kind = c.relkind::text
        WHERE n.nspname = $1
          AND pg_get_userbyid(c.relowner) <> $2
          AND NOT (c.relkind = 'r' AND c.relispartition)
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.classid = 'pg_class'::regclass AND d.deptype IN ('e', 'a', 'i'))
        ORDER BY c.relkind, c.relname`,
      [schema, owner],
    )).rows;
    const routines = (await admin.query<{ label: string; stmt: string }>(
      `SELECT 'function ' || p.proname AS label, format('ALTER ROUTINE %s OWNER TO %I', p.oid::regprocedure, $2::text) AS stmt
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = $1 AND pg_get_userbyid(p.proowner) <> $2
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.classid = 'pg_proc'::regclass AND d.deptype = 'e')`,
      [schema, owner],
    )).rows;
    const types = (await admin.query<{ label: string; stmt: string }>(
      `SELECT 'type ' || t.typname AS label, format('ALTER TYPE %s OWNER TO %I', t.oid::regtype, $2::text) AS stmt
         FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = $1 AND t.typtype IN ('e', 'd', 'c') AND (t.typrelid = 0 OR (SELECT relkind FROM pg_class WHERE oid = t.typrelid) = 'c')
          AND pg_get_userbyid(t.typowner) <> $2
          AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = t.oid AND d.classid = 'pg_type'::regclass AND d.deptype = 'e')`,
      [schema, owner],
    )).rows;
    const transferred: string[] = [];
    for (const o of [...relations, ...routines, ...types]) {
      await admin.query(o.stmt);
      transferred.push(o.label);
    }

    await admin.query("COMMIT");
    return { role, created: !exists, transferred, revokedMemberships: memberships, owner };
  } catch (err) {
    await admin.query("ROLLBACK").catch(() => {});
    throw err;
  }
}

/**
 * Tables the runtime may read but never write with the split: the schema bookkeeping, the
 * erasure context, and what the bounded erasure functions record (anchors, tombstones).
 * Readable, so the backup (pg_dump as the API's role, ops/backup.sh) still covers them.
 */
export const RUNTIME_READ_ONLY_TABLES = ["legion_schema_state", "legion_migrations", "legion_erasure_context", "chain_prune_anchors", "tenant_deletions"] as const;
/** Functions only the bounded erasure functions (running as the owner) may call. */
export const OWNER_ONLY_FUNCTIONS = ["legion_erasure_begin(text)", "legion_erasure_end()"] as const;

/**
 * F-02, after the owner has migrated the schema: what the runtime role may do with it. Data
 * (SELECT/INSERT/UPDATE/DELETE — the append-only triggers still refuse changes to audit rows),
 * sequences, and EXECUTE on functions (the bounded erasure functions among them). Never
 * TRUNCATE, REFERENCES or TRIGGER, and no ownership, so no ALTER, DROP or DISABLE TRIGGER.
 * Re-run after every migration; it also strips privileges added by hand.
 */
export async function grantRuntimePrivileges(admin: pg.ClientBase, opts: { appUser?: string; ownerRole?: string; schema?: string } = {}): Promise<void> {
  const role = opts.appUser ?? DEFAULT_APP_ROLE;
  const owner = opts.ownerRole ?? DEFAULT_OWNER_ROLE;
  const schema = opts.schema ?? "public";
  for (const r of [role, owner, schema]) if (!IDENTIFIER.test(r)) throw new Error(`Refusing unsafe name ${JSON.stringify(r)}`);
  const s = q(schema);
  await admin.query("BEGIN");
  try {
    await admin.query(`REVOKE ALL ON ALL TABLES IN SCHEMA ${s} FROM ${q(role)}`);
    await admin.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ${s} TO ${q(role)}`);
    for (const t of RUNTIME_READ_ONLY_TABLES) {
      if ((await admin.query("SELECT to_regclass($1) AS r", [`${schema}.${t}`])).rows[0].r) {
        await admin.query(`REVOKE INSERT, UPDATE, DELETE ON ${s}.${q(t)} FROM ${q(role)}`);
      }
    }
    await admin.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${s} FROM ${q(role)}`);
    await admin.query(`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA ${s} TO ${q(role)}`);
    await admin.query(`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ${s} TO ${q(role)}`);
    for (const f of OWNER_ONLY_FUNCTIONS) {
      if ((await admin.query("SELECT to_regprocedure($1) AS p", [`${schema}.${f}`])).rows[0].p) {
        await admin.query(`REVOKE ALL ON FUNCTION ${s}.${f} FROM PUBLIC, ${q(role)}`);
      }
    }
    // Objects a later migration creates get the same data privileges until this runs again.
    await admin.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${q(owner)} IN SCHEMA ${s} GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${q(role)}`);
    await admin.query(`ALTER DEFAULT PRIVILEGES FOR ROLE ${q(owner)} IN SCHEMA ${s} GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ${q(role)}`);
    await admin.query("COMMIT");
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

/**
 * F-01: when the boot check refuses a privileged role. Everywhere except an explicit
 * NODE_ENV=development (a developer's laptop): the default Docker install sets no NODE_ENV, and
 * treating "unset" as "development" is how it ran as the database superuser.
 */
export function refusePrivilegedRole(nodeEnv: string | undefined): boolean {
  return nodeEnv !== "development";
}
