import { readFileSync } from "node:fs";
import type { ConnectionOptions } from "node:tls";
import pg from "pg";
import { ownsSchema, runMigrations, schemaProblems } from "./migrator.js";
import { currentTenant, RlsContextError, touchesRlsTable } from "./rls.js";
import { config } from "../config.js";

export { currentTenant, inTenant, withTenant } from "./rls.js";

export { MIGRATION_LOCK_TIMEOUT, MIGRATIONS_DIR, migrationFiles, schemaFingerprint, type MigrationFile } from "./migrator.js";

const { Pool, types } = pg;

// Return NUMERIC as a JS number. Legion only stores small values in numeric
// columns (confidence, counts); without this, node-postgres hands back strings
// to avoid precision loss on big decimals.
types.setTypeParser(1700, (value) => Number(value));
// COUNT(*) comes back as bigint; the same reasoning applies.
types.setTypeParser(20, (value) => Number(value));

/**
 * TLS settings for the database connection.
 *
 * Certificates ARE verified. An earlier version passed
 * `rejectUnauthorized: false` so that managed providers "just worked" — which
 * silently accepted any certificate, including an attacker's. Encryption
 * without verification protects against nothing but a passive listener.
 *
 * Providers whose chain Node cannot verify supply a CA bundle; point DB_SSL_CA
 * at it. DB_SSL_INSECURE exists for local experiments only and config.ts
 * refuses to start with it in production.
 */
function sslOptions(): ConnectionOptions | undefined {
  if (!config.dbSsl) return undefined;

  if (config.dbSslInsecure) {
    console.warn(
      "WARNING: DB_SSL_INSECURE=true — the database certificate is NOT verified. " +
      "Never use this outside local development."
    );
    return { rejectUnauthorized: false };
  }

  const options: ConnectionOptions = { rejectUnauthorized: true };
  if (config.dbSslCa) {
    // Accept the PEM inline (handy for secret managers and container envs) or
    // as a path on disk.
    options.ca = config.dbSslCa.includes("-----BEGIN")
      ? config.dbSslCa
      : readFileSync(config.dbSslCa, "utf8");
  }
  return options;
}

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: config.dbPoolMax,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ssl: sslOptions(),
});

// A pool error on an idle client is normal (the server closed it); an
// unhandled 'error' event would take the process down.
pool.on("error", (error) => {
  console.error("Postgres idle client error:", error.message);
});

// …and the same is true of a client that is CHECKED OUT when its connection
// dies — mid-transaction during a database restart or failover. The pool only
// listens for errors on idle clients, so that 'error' event had no listener
// and crashed the whole API on every database restart (found by the
// failure-injection tests). Every connection gets a permanent listener: the
// query in flight still fails (and the caller answers 503), and the pool
// discards the dead client when it is released.
pool.on("connect", (client) => {
  client.on("error", (error) => {
    console.error("Postgres connection lost:", error.message);
  });
});

export type QueryParams = ReadonlyArray<unknown>;

/*
 * F-04 (db/rls.ts): with DB_RLS=enforce every connection says so (legion.rls), and every query
 * carries the workspace of the current request or job (legion.tenant_id) — session-level for a
 * single query, set and reset around it so a pooled connection never keeps one workspace's id;
 * transaction-local inside transaction().
 */
export const rlsEnforced = (): boolean => config.dbRls === "enforce";

if (rlsEnforced()) {
  pool.on("connect", (client) => {
    // Queued before anything else on this connection (a client runs its queries in order).
    client.query("SELECT set_config('legion.rls', 'enforce', false)").catch(() => {});
  });
}

function rlsGuard(text: string): string | null {
  const tenant = currentTenant();
  if (!tenant) {
    const table = touchesRlsTable(text);
    if (table) throw new RlsContextError(table);
  }
  return tenant;
}

async function rlsQuery<T extends pg.QueryResultRow>(text: string, params: QueryParams): Promise<pg.QueryResult<T>> {
  const tenant = rlsGuard(text);
  if (!tenant) return pool.query<T>(text, params as unknown[]);
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query("SELECT set_config('legion.tenant_id', $1, false)", [tenant]);
    return await client.query<T>(text, params as unknown[]);
  } finally {
    await client.query("SELECT set_config('legion.tenant_id', '', false)").catch(() => { broken = true; });
    client.release(broken || undefined);
  }
}

function guardedClient(client: pg.PoolClient): pg.PoolClient {
  return new Proxy(client, {
    get(target, prop, receiver) {
      if (prop !== "query") return Reflect.get(target, prop, receiver);
      return (text: unknown, ...rest: unknown[]) => {
        const sql = typeof text === "string" ? text : (text as { text?: unknown } | null)?.text;
        if (typeof sql === "string") rlsGuard(sql);
        return (target.query as (...a: unknown[]) => unknown).call(target, text, ...rest);
      };
    },
  });
}

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: QueryParams = []
): Promise<pg.QueryResult<T>> {
  if (rlsEnforced()) return rlsQuery<T>(text, params);
  return pool.query<T>(text, params as unknown[]);
}

/** First row, or null. The overwhelmingly common shape in this codebase. */
export async function queryOne<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: QueryParams = []
): Promise<T | null> {
  const result = await query<T>(text, params);
  return result.rows[0] ?? null;
}

export async function queryAll<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: QueryParams = []
): Promise<T[]> {
  const result = await query<T>(text, params);
  return result.rows;
}

/**
 * Runs `fn` inside a transaction on a single dedicated client.
 *
 * Callers must use the passed client for every statement in the unit of work —
 * using the pool directly would take a different connection and land outside
 * the transaction.
 */
export async function transaction<T>(
  fn: (client: pg.PoolClient) => Promise<T>,
  /** Set in BEGIN itself: SET TRANSACTION would have to come before any other statement. */
  opts: { isolation?: "REPEATABLE READ READ ONLY" } = {},
): Promise<T> {
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query(opts.isolation ? `BEGIN ISOLATION LEVEL ${opts.isolation}` : "BEGIN");
    // F-04: the workspace of this unit of work, for the transaction only. Statements inside go
    // straight to the client, so the context is checked when the transaction starts.
    const tenant = rlsEnforced() ? currentTenant() : null;
    if (tenant) await client.query("SELECT set_config('legion.tenant_id', $1, true)", [tenant]);
    // Without a workspace, a statement inside that reaches a protected table is refused as loudly as
    // query() refuses it (the database would otherwise just return nothing).
    const result = await fn(rlsEnforced() && !tenant ? guardedClient(client) : client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {
      // The connection is broken: make sure it is not handed out again.
      broken = true;
    });
    throw error;
  } finally {
    client.release(broken || undefined);
  }
}

/** Postgres error code for a unique-constraint violation. */
export const UNIQUE_VIOLATION = "23505";

export function isUniqueViolation(error: unknown, constraint?: string): boolean {
  const code = (error as { code?: string })?.code;
  if (code !== UNIQUE_VIOLATION) return false;
  if (!constraint) return true;
  return (error as { constraint?: string })?.constraint === constraint;
}

/**
 * At boot. A role that owns the schema (single-role installs, development, tests) applies it as
 * before. With the owner/runtime split (DB_ROLE_SPLIT, F-02) the API's role owns nothing and cannot
 * change the schema: the provisioning step (provision-cli.ts, db-provision in Docker) migrates as
 * legion_owner, and the API only checks that it did — and refuses to start against a schema that
 * is not the one this build expects.
 */
export async function migrate(opts: { lockTimeout?: string; attempts?: number } = {}): Promise<void> {
  const client = await pool.connect();
  let owns: boolean | null;
  try {
    owns = await ownsSchema(client);
    if (owns === false) {
      const problems = await schemaProblems(client);
      if (problems.length) {
        throw new Error(`The database schema is not current (${problems.join("; ")}), and this API's role does not own it ` +
          "(owner/runtime split). Run the migration step first: node dist/db/provision-cli.js (Docker: the db-provision service).");
      }
      return;
    }
  } finally {
    client.release();
  }
  await runMigrations(pool, opts);
}

/** The attributes of the role this API is connected as (see db/provision.ts). */
export async function currentRoleAttributes() {
  const r = await pool.query<{ rolname: string; rolsuper: boolean; rolcreaterole: boolean; rolcreatedb: boolean; rolbypassrls: boolean; rolreplication: boolean }>(
    "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication FROM pg_roles WHERE rolname = current_user",
  );
  return r.rows[0]!;
}

export async function closePool(): Promise<void> {
  await pool.end();
}

/**
 * Runs `fn` on at most one instance at a time, cluster-wide: a session-level
 * advisory lock held on a dedicated connection for the duration. Another
 * instance that tries meanwhile skips (it does not wait). If this process
 * dies, Postgres drops the connection and the lock with it — no stuck leader.
 * For periodic jobs that are correct but wasteful when several instances run
 * them at once (sensor-silence checks, behaviour sweeps).
 */
export async function withLeaderLock<T>(key: number, fn: () => Promise<T>): Promise<{ ran: true; value: T } | { ran: false }> {
  const client = await pool.connect();
  try {
    const got = (await client.query<{ ok: boolean }>("SELECT pg_try_advisory_lock($1) AS ok", [key])).rows[0]?.ok;
    if (!got) return { ran: false };
    try {
      return { ran: true, value: await fn() };
    } finally {
      await client.query("SELECT pg_advisory_unlock($1)", [key]).catch(() => {});
    }
  } finally {
    client.release();
  }
}
