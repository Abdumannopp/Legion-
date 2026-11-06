/**
 * Applying Legion's schema: the base schema files (schema.sql + the agent schema) and the
 * versioned migrations in db/migrations. Separate from pool.ts so that the provisioning step
 * (provision-cli.ts) can run it as the schema owner without loading config.ts and the API's
 * secrets. The API calls it through pool.ts migrate(), which only migrates when its own role
 * owns the schema; with the owner/runtime split (F-02) it checks the schema is current instead.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import type pg from "pg";
import { AGENT_SCHEMA_SQL, migrateAgentSchema } from "@legion/agent-identity";

const here = dirname(fileURLToPath(import.meta.url));

/** Stable arbitrary key identifying the schema-migration advisory lock. */
const MIGRATION_LOCK_KEY = 728_401_337;

/**
 * How long a schema statement may wait for a table lock before giving up. A
 * migration that queues behind a long query would otherwise make every request
 * touching that table queue behind IT — a full outage on every restart.
 */
export const MIGRATION_LOCK_TIMEOUT = "5s";
const MIGRATION_ATTEMPTS = 5;

/** What the database's schema was last built from: both schema files. */
export function schemaFingerprint(sql: string): string {
  return createHash("sha256").update(sql).update("\0").update(AGENT_SCHEMA_SQL).digest("hex");
}

/**
 * Applies the schema. Every statement is IF NOT EXISTS, so it is safe to run
 * again — but some statements (constraint re-creation, triggers) take
 * ACCESS EXCLUSIVE locks on hot tables. So:
 *
 *  - The fingerprint of the schema files is recorded in legion_schema_state.
 *    When it matches (an ordinary restart, every replica of a rolling deploy
 *    after the first), nothing is run and no table is locked.
 *  - When it differs, the schema is applied with a lock timeout and retried a
 *    few times, instead of queueing every request behind a waiting ALTER.
 *
 * The advisory lock serialises instances that start at the same moment:
 * concurrent CREATE INDEX statements on the same table can otherwise deadlock.
 */
export async function runMigrations(pool: pg.Pool, opts: { lockTimeout?: string; attempts?: number } = {}): Promise<void> {
  const lockTimeout = opts.lockTimeout ?? MIGRATION_LOCK_TIMEOUT;
  const attempts = opts.attempts ?? MIGRATION_ATTEMPTS;
  if (!/^\d+(ms|s)$/.test(lockTimeout)) throw new Error("invalid lock timeout");
  // The .sql file sits next to the compiled output; tsc doesn't copy it, so the
  // build script does (see package.json).
  const sql = await readFile(join(here, "schema.sql"), "utf8");
  const fingerprint = schemaFingerprint(sql);
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
    await client.query(
      `CREATE TABLE IF NOT EXISTS legion_schema_state (
         id          int         PRIMARY KEY CHECK (id = 1),
         fingerprint text        NOT NULL,
         applied_at  timestamptz NOT NULL DEFAULT now()
       )`,
    );
    const current = await client.query<{ fingerprint: string; intact: boolean }>(
      `SELECT fingerprint,
              to_regclass('public.tenants') IS NOT NULL AND to_regclass('public.alerts') IS NOT NULL AS intact
         FROM legion_schema_state WHERE id = 1`,
    );
    const row = current.rows[0];
    // LEGION_FORCE_MIGRATE=1 re-applies anyway (e.g. after repairing a damaged schema by hand).
    if (row && row.fingerprint === fingerprint && row.intact && process.env.LEGION_FORCE_MIGRATE !== "1") {
      await applyVersionedMigrations(client, lockTimeout);
      return;
    }

    for (let attempt = 1; ; attempt++) {
      try {
        await client.query(`SET lock_timeout = '${lockTimeout}'`);
        await client.query(sql);
        break;
      } catch (err) {
        const code = (err as { code?: string }).code;
        // 55P03 lock_not_available, 40P01 deadlock_detected: a busy table. The
        // whole file ran as one implicit transaction, so nothing was applied.
        if (attempt >= attempts || (code !== "55P03" && code !== "40P01")) throw err;
        await new Promise((r) => setTimeout(r, 500 * attempt));
      } finally {
        await client.query("RESET lock_timeout").catch(() => {});
      }
    }
    // The AI-agent tables (identities, firewall, audit, skills…), from
    // packages/agent-identity. Idempotent, with its own lock timeout.
    await migrateAgentSchema(pool);
    await client.query(
      `INSERT INTO legion_schema_state (id, fingerprint) VALUES (1, $1)
       ON CONFLICT (id) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, applied_at = now()`,
      [fingerprint],
    );
    await applyVersionedMigrations(client, lockTimeout);
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

/**
 * Versioned migrations: `db/migrations/NNNN_name.sql`, applied once each, in
 * order, after the base schema. Each runs in its own transaction together with
 * the row that records it, so a failed migration leaves nothing half-applied.
 *
 * An applied migration is immutable: if its file changes afterwards (checksum
 * mismatch) the server refuses to start instead of silently running a schema
 * that differs from what the database holds. Fix forward with a new file.
 * Numbers must be contiguous from 0001, so a missing or misnamed file is caught.
 */
export const MIGRATIONS_DIR = join(here, "migrations");

export interface MigrationFile { version: number; name: string; sql: string; checksum: string }

export function migrationFiles(dir = MIGRATIONS_DIR): MigrationFile[] {
  if (!existsSync(dir)) return [];
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  return files.map((file, i) => {
    const m = /^(\d{4})_([a-z0-9_]+)\.sql$/.exec(file);
    if (!m) throw new Error(`migration file name not allowed: ${file}`);
    const version = Number(m[1]);
    if (version !== i + 1) throw new Error(`migrations must be numbered contiguously from 0001: expected ${String(i + 1).padStart(4, "0")}, found ${file}`);
    const sql = readFileSync(join(dir, file), "utf8");
    return { version, name: m[2]!, sql, checksum: createHash("sha256").update(sql).digest("hex") };
  });
}

async function applyVersionedMigrations(client: pg.PoolClient, lockTimeout: string, dir = MIGRATIONS_DIR): Promise<void> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS legion_migrations (
       version    int         PRIMARY KEY CHECK (version > 0),
       name       text        NOT NULL,
       checksum   text        NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
       applied_at timestamptz NOT NULL DEFAULT now()
     )`,
  );
  const applied = new Map((await client.query<{ version: number; checksum: string }>("SELECT version, checksum FROM legion_migrations")).rows.map((r) => [r.version, r.checksum]));
  for (const m of migrationFiles(dir)) {
    const done = applied.get(m.version);
    if (done !== undefined) {
      if (done !== m.checksum) throw new Error(`migration ${String(m.version).padStart(4, "0")}_${m.name} was changed after it was applied; add a new migration instead`);
      continue;
    }
    await client.query("BEGIN");
    try {
      await client.query(`SET LOCAL lock_timeout = '${lockTimeout}'`);
      await client.query(m.sql);
      await client.query("INSERT INTO legion_migrations (version, name, checksum) VALUES ($1, $2, $3)", [m.version, m.name, m.checksum]);
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    }
  }
}


/**
 * For an API whose role does not own the schema (owner/runtime split): the schema must already be
 * exactly what this build expects, because this role cannot change it. Returns the problems; empty
 * means current.
 */
export async function schemaProblems(client: pg.ClientBase, dir = MIGRATIONS_DIR): Promise<string[]> {
  const sql = await readFile(join(here, "schema.sql"), "utf8");
  const problems: string[] = [];
  const state = (await client.query<{ fingerprint: string | null }>(
    "SELECT CASE WHEN to_regclass('public.legion_schema_state') IS NULL THEN NULL ELSE (SELECT fingerprint FROM legion_schema_state WHERE id = 1) END AS fingerprint",
  )).rows[0]?.fingerprint;
  if (state !== schemaFingerprint(sql)) problems.push("the base schema differs from this version's schema.sql");
  const applied = new Map((await client.query<{ version: number; checksum: string }>(
    "SELECT version, checksum FROM legion_migrations",
  ).catch(() => ({ rows: [] as Array<{ version: number; checksum: string }> }))).rows.map((r) => [r.version, r.checksum]));
  for (const m of migrationFiles(dir)) {
    const c = applied.get(m.version);
    if (c === undefined) problems.push(`migration ${String(m.version).padStart(4, "0")}_${m.name} is not applied`);
    else if (c !== m.checksum) problems.push(`migration ${String(m.version).padStart(4, "0")}_${m.name} was changed after it was applied`);
  }
  return problems;
}

/** Whether this session's role may change the schema: true/false, or null on an empty database. */
export async function ownsSchema(client: pg.ClientBase): Promise<boolean | null> {
  const r = await client.query<{ mine: boolean | null }>(
    `SELECT CASE WHEN to_regclass('public.tenants') IS NULL THEN NULL
            ELSE pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = to_regclass('public.tenants')), 'USAGE') END AS mine`,
  );
  return r.rows[0]?.mine ?? null;
}
