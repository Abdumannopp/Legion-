import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import type { ConnectionOptions } from "node:tls";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { migrateAgentSchema } from "@legion/agent-identity";
import { config } from "../config.js";

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

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: QueryParams = []
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params as unknown[]);
}

/** First row, or null. The overwhelmingly common shape in this codebase. */
export async function queryOne<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: QueryParams = []
): Promise<T | null> {
  const result = await pool.query<T>(text, params as unknown[]);
  return result.rows[0] ?? null;
}

export async function queryAll<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: QueryParams = []
): Promise<T[]> {
  const result = await pool.query<T>(text, params as unknown[]);
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
  fn: (client: pg.PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query("BEGIN");
    const result = await fn(client);
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

const here = dirname(fileURLToPath(import.meta.url));

/** Stable arbitrary key identifying the schema-migration advisory lock. */
const MIGRATION_LOCK_KEY = 728_401_337;

/**
 * Applies the schema. Every statement is IF NOT EXISTS, so this runs safely on
 * every boot.
 *
 * The advisory lock serialises instances that start at the same moment:
 * concurrent CREATE INDEX statements on the same table can otherwise deadlock
 * against each other, which would crash a deploy that rolls several pods at
 * once.
 */
export async function migrate(): Promise<void> {
  // The .sql file sits next to the compiled output; tsc doesn't copy it, so the
  // build script does (see package.json).
  const sql = await readFile(join(here, "schema.sql"), "utf8");
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
    await client.query(sql);
    // The AI-agent tables (identities, firewall, audit, skills…), from
    // packages/agent-identity. Idempotent like schema.sql.
    await migrateAgentSchema(pool);
  } finally {
    await client
      .query("SELECT pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY])
      .catch(() => {
        // Losing the unlock only matters if the connection survives, and it is
        // released (and reset) immediately below.
      });
    client.release();
  }
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
