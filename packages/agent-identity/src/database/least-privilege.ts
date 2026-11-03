import { randomBytes } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { PROTECTED_TABLES } from "../firewall/policy.js";

/*
 * Database-level least privilege for agent SQL (tools/sql.ts's `database`
 * tool kind).
 *
 * Everything in tools/sql.ts is static analysis: it reads the SQL text and
 * refuses what it doesn't like, but the query still runs — if it runs at
 * all — over whatever Postgres connection the host handed the tool gateway.
 * Until now that was always the same connection Legion's own backend code
 * uses, which owns every table and can do anything a superuser can. A bug in
 * the analyzer, a caller that builds its own executor and skips it, or a
 * future maintainer wiring the `database` tool kind to the wrong pool would
 * have nothing left standing between an agent and the whole database.
 *
 * `applyLeastPrivilegeRole` provisions a dedicated Postgres role that makes
 * that bypass survivable: deny-by-default grants covering only the exact
 * tables the policy opens to agents, and row-level security that scopes
 * every row to the caller's own tenant no matter what the query's WHERE
 * clause says. tools/sql.ts keeps running first, unchanged — this is what
 * catches a call that gets past it anyway.
 */

export type DbOp = "select" | "insert" | "update" | "delete";

/** Session setting RLS policies check. Set with set_config(), never string-built into SQL. */
export const AGENT_TENANT_SETTING = "legion.agent_tenant_id";

/** Name the tenant-isolation policy is created under, so re-runs can find and replace it. */
const POLICY_NAME = "legion_agent_tenant_isolation";
/** Keeps every role other than the agent role unaffected by enabling RLS. */
const PASSTHROUGH_POLICY = "legion_agent_others_unchanged";

/**
 * Predefined Postgres roles that unlock file access, running server-side
 * programs, signalling other backends, or reading all settings/data. A
 * fresh role starts in none of them; applyLeastPrivilegeRole() revokes every
 * membership the agent role has (these included) on each run, so one granted
 * by hand does not survive. Exported for documentation and tests.
 */
export const DENIED_ROLE_MEMBERSHIPS = [
  "pg_read_server_files", "pg_write_server_files", "pg_execute_server_program",
  "pg_signal_backend", "pg_monitor", "pg_read_all_settings", "pg_read_all_stats",
  "pg_write_all_data", "pg_read_all_data", "pg_checkpoint", "pg_use_reserved_connections",
  "pg_create_subscription",
] as const;

const IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;

/** A conservative, lowercase-only identifier check. Postgres identifiers built into DDL text must pass this. */
export function assertIdentifier(name: string, what = "identifier"): string {
  if (typeof name !== "string" || !IDENTIFIER.test(name)) {
    throw new Error(`Refusing unsafe ${what}: ${JSON.stringify(name)}`);
  }
  return name;
}

/**
 * A safe SQL string literal for a value that cannot be a bind parameter
 * (Postgres's grammar for CREATE/ALTER ROLE ... PASSWORD takes a literal,
 * not an expression). Dollar-quoted with a random tag, so no escaping of
 * quotes or backslashes is needed — and the tag is rejected and regenerated
 * if it happens to already appear in the value.
 */
function sqlLiteral(value: string): string {
  for (let i = 0; i < 10; i++) {
    const tag = `lp_${randomBytes(12).toString("hex")}`;
    if (!value.includes(tag)) return `$${tag}$${value}$${tag}$`;
  }
  throw new Error("could not construct a safe SQL literal");
}

export interface LeastPrivilegeOptions {
  /** The restricted role's name (lowercase, e.g. "legion_agent_sql"). */
  roleName: string;
  /** Login password for the role. Reasserted on every apply, so rotation is just calling this again. */
  password: string;
  /** Exactly the tables the agent role may reach, and which operations on each — normally `policy.database.tables`. */
  tables: Record<string, readonly DbOp[]>;
  /** Column that scopes every row to a tenant. Same name on every table. Default "tenant_id". */
  tenantColumn?: string;
  /** Tables that must never be granted, whatever `tables` says. Defaults to the firewall's own protected set. */
  protectedTables?: ReadonlySet<string>;
  /** Schema the tables live in. Default "public". */
  schema?: string;
}

const OP_SQL: Record<DbOp, string> = { select: "SELECT", insert: "INSERT", update: "UPDATE", delete: "DELETE" };

/** Tenant column types the RLS policy can cast the session setting to. Read from the catalog, then checked against this list. */
const TENANT_COLUMN_TYPES = new Set(["text", "uuid", "character varying", "integer", "bigint"]);

/**
 * Provisions, or re-tightens, the least-privilege role for agent SQL.
 * Idempotent and meant to be run on every boot next to the host's own
 * migration: it resets the role to exactly this allowlist each time, so a
 * grant added by hand, or left behind after a table is removed from the
 * policy, does not survive the next run. Requires a connection able to
 * CREATE ROLE and GRANT/REVOKE on the target tables (the host's own admin
 * pool — the one that already runs schema migrations).
 */
export async function applyLeastPrivilegeRole(admin: Pool, opts: LeastPrivilegeOptions): Promise<void> {
  const role = assertIdentifier(opts.roleName, "role name");
  const schema = assertIdentifier(opts.schema ?? "public", "schema name");
  const tenantColumn = assertIdentifier(opts.tenantColumn ?? "tenant_id", "tenant column name");
  const protectedTables = opts.protectedTables ?? PROTECTED_TABLES;
  const tables = Object.entries(opts.tables).map(([t, ops]) => [assertIdentifier(t, "table name"), ops] as const);

  for (const [table] of tables) {
    if (protectedTables.has(table)) {
      throw new Error(`Refusing to grant the agent database role access to "${table}": it holds identities, secrets or audit history.`);
    }
  }

  const client = await admin.connect();
  try {
    await client.query("BEGIN");

    const existing = await client.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [role]);
    if (!existing.rowCount) {
      await client.query(`CREATE ROLE "${role}"`);
    }
    // Reasserted every run: NOSUPERUSER/NOBYPASSRLS etc. undo any manual
    // escalation, and the password is rotated to whatever was supplied.
    await client.query(
      `ALTER ROLE "${role}" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 20 PASSWORD ${sqlLiteral(opts.password)}`,
    );
    // No role memberships at all: not the predefined ones that unlock files,
    // programs or signals, and not any other role it could SET ROLE into.
    const memberships = await client.query<{ rolname: string }>(
      `SELECT g.rolname FROM pg_auth_members m
         JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member
        WHERE u.rolname = $1`,
      [role],
    );
    for (const { rolname } of memberships.rows) {
      await client.query(`REVOKE "${rolname.replace(/"/g, '""')}" FROM "${role}"`);
    }

    const { rows } = await client.query<{ db: string }>("SELECT current_database() AS db");
    const db = assertIdentifier(rows[0]!.db, "database name");
    await client.query(`REVOKE ALL ON DATABASE "${db}" FROM "${role}"`);
    await client.query(`GRANT CONNECT, TEMP ON DATABASE "${db}" TO "${role}"`);

    // Deny-by-default: strip whatever this role could reach before, then
    // grant back exactly the allowlist below. A table dropped from `tables`
    // between runs loses its grant here, not by being remembered to revoke.
    await client.query(`REVOKE CREATE ON SCHEMA "${schema}" FROM "${role}"`);
    await client.query(`GRANT USAGE ON SCHEMA "${schema}" TO "${role}"`);
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA "${schema}" FROM "${role}"`);
    await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA "${schema}" FROM "${role}"`);
    await client.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA "${schema}" FROM "${role}"`);

    for (const [table, ops] of tables) {
      const grantOps = [...new Set(ops)].map((o) => OP_SQL[o]);
      if (!grantOps.length) continue;

      // A table without the tenant column cannot be tenant-isolated, so it is
      // refused rather than granted unscoped. The setting is cast to the
      // column's own type (not the column to text) so the tenant index is
      // still usable.
      const col = await client.query<{ type: string }>(
        `SELECT format_type(a.atttypid, NULL) AS type
           FROM pg_attribute a
          WHERE a.attrelid = to_regclass($1) AND a.attname = $2 AND a.attnum > 0 AND NOT a.attisdropped`,
        [`"${schema}"."${table}"`, tenantColumn],
      );
      const colType = col.rows[0]?.type;
      if (!colType) {
        throw new Error(`Refusing to grant "${table}": it has no "${tenantColumn}" column, so rows could not be confined to one tenant.`);
      }
      if (!TENANT_COLUMN_TYPES.has(colType)) {
        throw new Error(`Refusing to grant "${table}": "${tenantColumn}" has unsupported type ${colType}.`);
      }

      await client.query(`GRANT ${grantOps.join(", ")} ON TABLE "${schema}"."${table}" TO "${role}"`);

      // Row-level security ties every row this role can see or change to the
      // tenant bound on the connection — independent of what the query's own
      // WHERE clause says, and independent of tools/sql.ts's own (separate)
      // textual tenant-scope check.
      //
      // Enabling RLS is table-wide: every other non-owner role would then see
      // nothing unless a policy lets it through. The passthrough policy keeps
      // those roles exactly as they were; it is keyed on session_user (the
      // login role), which SET ROLE and SECURITY DEFINER functions cannot
      // change, so the agent role never matches it. FORCE is deliberately not
      // used: the agent role is not the owner, and forcing RLS on the owner
      // would break a host that runs as a non-superuser owner.
      await client.query(`ALTER TABLE "${schema}"."${table}" ENABLE ROW LEVEL SECURITY`);
      await client.query(`DROP POLICY IF EXISTS ${PASSTHROUGH_POLICY} ON "${schema}"."${table}"`);
      await client.query(
        `CREATE POLICY ${PASSTHROUGH_POLICY} ON "${schema}"."${table}"
           FOR ALL TO PUBLIC USING (session_user <> '${role}') WITH CHECK (session_user <> '${role}')`,
      );
      await client.query(`DROP POLICY IF EXISTS ${POLICY_NAME} ON "${schema}"."${table}"`);
      await client.query(
        `CREATE POLICY ${POLICY_NAME} ON "${schema}"."${table}"
           FOR ALL TO "${role}"
           USING ("${tenantColumn}" = current_setting('${AGENT_TENANT_SETTING}', true)::${colType})
           WITH CHECK ("${tenantColumn}" = current_setting('${AGENT_TENANT_SETTING}', true)::${colType})`,
      );

      if (grantOps.includes("INSERT")) {
        // A column backed by a sequence (serial/identity/bigserial) needs its
        // own USAGE grant, or an otherwise-permitted INSERT fails on the
        // default expression. Anything the table's columns don't use is
        // never touched.
        const cols = await client.query<{ column_name: string }>(
          `SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2`,
          [schema, table],
        );
        for (const { column_name } of cols.rows) {
          const seq = await client.query<{ seq: string | null }>(
            `SELECT pg_get_serial_sequence($1, $2) AS seq`,
            [`${schema}.${table}`, column_name],
          );
          const name = seq.rows[0]?.seq;
          if (name) await client.query(`GRANT USAGE, SELECT ON SEQUENCE ${name} TO "${role}"`);
        }
      }
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Runs `fn` on a connection from the least-privilege pool with the caller's
 * tenant bound for row-level security, inside one transaction. `set_config`
 * (not a string-built SET LOCAL) is what keeps the tenant id a bound
 * parameter rather than text spliced into SQL.
 */
export async function withAgentTenant<T>(pool: Pool, tenantId: string, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config($1, $2, true)", [AGENT_TENANT_SETTING, tenantId]);
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
