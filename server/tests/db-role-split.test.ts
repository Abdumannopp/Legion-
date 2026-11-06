/**
 * F-02 (PR-2): the owner/runtime split, against a real PostgreSQL. The schema belongs to a role
 * that cannot log in; the API's role gets data privileges only. These tests prove what the API's
 * role can no longer do (alter, drop, truncate, disable a trigger, flip the erasure switch, delete
 * recent audit evidence) and that what it legitimately needs still works through the bounded
 * erasure functions (retention with a 30-day floor, workspace deletion with a tombstone).
 */
import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { grantRuntimePrivileges, provisionAppRole } from "../src/db/provision.js";
import { ownsSchema, runMigrations, schemaProblems } from "../src/db/migrator.js";

const ADMIN_URL = process.env.DATABASE_URL!;
const suffix = randomBytes(3).toString("hex");
const APP = `legion_app_s${suffix}`;
const OWNER = `legion_owner_s${suffix}`;
const PASSWORD = `app-${randomBytes(16).toString("hex")}`;
const DBS = { split: `legion_split_${suffix}`, upgrade: `legion_split_upg_${suffix}` };

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
const asAdmin = <T>(db: string, fn: (c: pg.Client) => Promise<T>) => withClient(urlFor(db), fn);
const asApp = <T>(db: string, fn: (c: pg.Client) => Promise<T>) => withClient(urlFor(db, APP), fn);

/** What provision-cli does with DB_ROLE_SPLIT=on. */
async function provisionSplit(db: string) {
  const r = await asAdmin(db, (c) => provisionAppRole(c, { appUser: APP, appPassword: PASSWORD, split: true, ownerRole: OWNER }));
  const ownerPool = new pg.Pool({ connectionString: urlFor(db), max: 2, options: `-c role=${OWNER}` });
  try { await runMigrations(ownerPool); } finally { await ownerPool.end(); }
  await asAdmin(db, (c) => grantRuntimePrivileges(c, { appUser: APP, ownerRole: OWNER }));
  return r;
}

const T = "22222222-2222-4222-8222-222222222222";
const T2 = "33333333-3333-4333-8333-333333333333";
const hex = (n: number) => n.toString(16).padStart(64, "0");
/** A SOC audit event `daysAgo` old (the chain's hash values only need the right shape here). */
const socEvent = (c: pg.Client, tenant: string, seq: number, daysAgo: number) => c.query(
  `INSERT INTO soc_audit_events (tenant_id, seq, id, at, category, event, actor, key_id, prev_hash, hash)
   VALUES ($1, $2, $3, now() - make_interval(days => $4), 'controls', 'split.test', '{"kind":"system"}', 'k1', $5, $6)`,
  [tenant, seq, randomUUID(), daysAgo, hex(seq - 1), hex(seq)]);
const auditEntry = (c: pg.Client, tenant: string, daysAgo: number) => c.query(
  `INSERT INTO audit_log (id, tenant_id, user_email, action, detail, ip_address, created_at)
   VALUES ($1, $2, 'soc@a.io', 'login', 'by soc@a.io', '203.0.113.9', now() - make_interval(days => $3))`,
  [randomUUID(), tenant, daysAgo]);

beforeAll(async () => {
  await withClient(ADMIN_URL, async (c) => {
    for (const db of Object.values(DBS)) {
      await c.query(`DROP DATABASE IF EXISTS "${db}"`);
      await c.query(`CREATE DATABASE "${db}"`);
    }
  });
  await provisionSplit(DBS.split);
  await asApp(DBS.split, async (c) => {
    await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Acme'), ($2, 'Other')", [T, T2]);
  });
}, 120_000);

afterAll(async () => {
  await withClient(ADMIN_URL, async (c) => {
    for (const db of Object.values(DBS)) {
      await c.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()", [db]);
      await c.query(`DROP DATABASE IF EXISTS "${db}"`);
    }
    await c.query(`DROP ROLE IF EXISTS "${APP}"`);
    await c.query(`DROP ROLE IF EXISTS "${OWNER}"`);
  });
});

describe("the schema belongs to a role nobody can log in as", () => {
  it("every table, sequence and function is owned by the owner role; the owner cannot log in; the app role is not a member", async () => {
    await asAdmin(DBS.split, async (c) => {
      const notOwner = (await c.query(
        `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relkind IN ('r','S','v') AND pg_get_userbyid(c.relowner) <> $1`, [OWNER])).rows;
      expect(notOwner).toEqual([]);
      const fnNotOwner = (await c.query(
        `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'public' AND pg_get_userbyid(p.proowner) <> $1`, [OWNER])).rows;
      expect(fnNotOwner).toEqual([]);
      const o = (await c.query("SELECT rolcanlogin, rolsuper FROM pg_roles WHERE rolname = $1", [OWNER])).rows[0];
      expect(o).toEqual({ rolcanlogin: false, rolsuper: false });
      expect((await c.query("SELECT pg_has_role($1, $2, 'MEMBER') AS m", [APP, OWNER])).rows[0].m).toBe(false);
    });
    await expect(withClient(urlFor(DBS.split, OWNER), async () => {})).rejects.toThrow();
  });

  it("the app role sees the schema as current and not its own (the API checks instead of migrating)", async () => {
    await asApp(DBS.split, async (c) => {
      expect(await ownsSchema(c)).toBe(false);
      expect(await schemaProblems(c)).toEqual([]);
    });
  });

  it("a schema the provisioning step did not finish is reported, so the API refuses to start against it", async () => {
    await asAdmin(DBS.split, (c) => c.query("UPDATE legion_schema_state SET fingerprint = 'stale' WHERE id = 1"));
    try {
      await asApp(DBS.split, async (c) => expect((await schemaProblems(c)).join()).toMatch(/base schema differs/));
    } finally {
      await provisionSplit(DBS.split);   // re-running provisioning repairs it
    }
    await asApp(DBS.split, async (c) => expect(await schemaProblems(c)).toEqual([]));
  });
});

describe("what the API's role can no longer do", () => {
  it.each([
    ["alter a table", "ALTER TABLE alerts ADD COLUMN pwned int"],
    ["drop a table", "DROP TABLE alerts"],
    ["truncate the audit log", "TRUNCATE audit_log"],
    ["truncate the SOC audit chain", "TRUNCATE soc_audit_events"],
    ["disable the append-only trigger", "ALTER TABLE soc_audit_events DISABLE TRIGGER soc_audit_events_append_only"],
    ["drop the append-only trigger", "DROP TRIGGER audit_log_append_only ON audit_log"],
    ["replace the guard function", "CREATE OR REPLACE FUNCTION legion_erasure_allowed(rel oid) RETURNS boolean LANGUAGE sql AS 'SELECT true'"],
    ["create a table", "CREATE TABLE evil (x int)"],
    ["become the owner", `SET ROLE "${OWNER}"`],
    ["open an erasure context", "SELECT legion_erasure_begin('mine')"],
    ["write the erasure context directly", "INSERT INTO legion_erasure_context (txid, purpose) VALUES (txid_current(), 'mine')"],
    ["forge a prune anchor", "INSERT INTO chain_prune_anchors (table_name, tenant_id, anchor_hash, pruned_through_seq, pruned_rows) VALUES ('soc_audit_events', 'x', 'h', 1, 1)"],
    ["erase a tombstone", "DELETE FROM tenant_deletions"],
    ["rewrite the migration record", "DELETE FROM legion_migrations"],
  ])("cannot %s", async (_what, sql) => {
    await asApp(DBS.split, async (c) => {
      await expect(c.query(sql)).rejects.toThrow(/permission denied|must be owner|must be member/);
    });
  });

  it("flipping the old erasure switch no longer lets it delete or rewrite audit rows — directly or through a cascade", async () => {
    await asApp(DBS.split, async (c) => {
      await auditEntry(c, T, 1);
      await socEvent(c, T, 1, 1);
      for (const sql of [
        "DELETE FROM audit_log WHERE tenant_id = $1",
        "UPDATE audit_log SET detail = 'rewritten' WHERE tenant_id = $1",
        "DELETE FROM soc_audit_events WHERE tenant_id = $1",
        "DELETE FROM tenants WHERE id = $1",           // ON DELETE CASCADE runs as the owner: still refused
      ]) {
        await c.query("BEGIN");
        await c.query("SELECT set_config('legion.audit_erasure', 'on', true)");
        await expect(c.query(sql, [T])).rejects.toThrow(/append-only/);
        await c.query("ROLLBACK");
      }
      expect((await c.query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1", [T])).rows[0].n).toBe(1);
      expect((await c.query("SELECT count(*)::int AS n FROM soc_audit_events WHERE tenant_id = $1", [T])).rows[0].n).toBe(1);
    });
  });

  it("ordinary work still runs: reads, inserts, updates and deletes of non-audit rows", async () => {
    await asApp(DBS.split, async (c) => {
      await c.query("INSERT INTO alerts (tenant_id, id, title, severity, agent, summary) VALUES ($1, 'A1', 't', 'high', 'x', 's')", [T]);
      await c.query("UPDATE alerts SET status = 'resolved' WHERE tenant_id = $1 AND id = 'A1'", [T]);
      await c.query("DELETE FROM alerts WHERE tenant_id = $1 AND id = 'A1'", [T]);
    });
  });
});

describe("the bounded erasure functions", () => {
  it("SOC retention never removes an audit event younger than 30 days, even when asked for 1 day", async () => {
    await asApp(DBS.split, async (c) => {
      const t = randomUUID();
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Floor')", [t]);
      await socEvent(c, t, 1, 90);
      await socEvent(c, t, 2, 60);
      await socEvent(c, t, 3, 10);
      await socEvent(c, t, 4, 2);
      const r = (await c.query("SELECT legion_prune_soc($1, 1) AS c", [t])).rows[0].c;
      expect(r.soc_audit_events).toBe(2);                        // 90 and 60 days old; 10 and 2 stay
      const left = (await c.query("SELECT seq FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq", [t])).rows.map((x) => Number(x.seq));
      expect(left).toEqual([3, 4]);
      const anchor = (await c.query("SELECT pruned_through_seq::int AS pruned_through_seq, anchor_hash FROM chain_prune_anchors WHERE table_name = 'soc_audit_events' AND tenant_id = $1", [t])).rows[0];
      expect(anchor).toEqual({ pruned_through_seq: 2, anchor_hash: hex(2) });
    });
  });

  it("refuses a non-positive period and an unknown chain", async () => {
    await asApp(DBS.split, async (c) => {
      await expect(c.query("SELECT legion_prune_soc($1, 0)", [T])).rejects.toThrow(/must be positive/);
      await expect(c.query("SELECT legion_pseudonymise_audit($1, -1)", [T])).rejects.toThrow(/must be positive/);
      await expect(c.query("SELECT legion_prune_chain('audit_log', $1, 24)", [T])).rejects.toThrow(/not a prunable chain/);
    });
  });

  it("pseudonymising the audit log leaves entries younger than 30 days untouched", async () => {
    await asApp(DBS.split, async (c) => {
      const t = randomUUID();
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Pseudo')", [t]);
      await auditEntry(c, t, 45);
      await auditEntry(c, t, 5);
      expect((await c.query("SELECT legion_pseudonymise_audit($1, 1) AS n", [t])).rows[0].n).toBe(1);
      const rows = (await c.query("SELECT user_email, ip_address, detail FROM audit_log WHERE tenant_id = $1 ORDER BY created_at", [t])).rows;
      expect(rows[0]).toEqual({ user_email: null, ip_address: null, detail: "by [removed]" });
      expect(rows[1]).toEqual({ user_email: "soc@a.io", ip_address: "203.0.113.9", detail: "by soc@a.io" });
    });
  });

  it("a workspace on a legal hold is skipped by retention and refused by deletion unless forced", async () => {
    await asApp(DBS.split, async (c) => {
      const t = randomUUID();
      await c.query("INSERT INTO tenants (id, name, legal_hold) VALUES ($1, 'Held', true)", [t]);
      await socEvent(c, t, 1, 90);
      await socEvent(c, t, 2, 80);
      expect((await c.query("SELECT legion_prune_soc($1, 1) AS c", [t])).rows[0].c.soc_audit_events).toBe(0);
      await expect(c.query("SELECT legion_erase_tenant($1, 'test', null, '{}', false)", [t])).rejects.toThrow(/legal hold/);
      expect((await c.query("SELECT count(*)::int AS n FROM soc_audit_events WHERE tenant_id = $1", [t])).rows[0].n).toBe(2);
    });
  });

  it("deleting a workspace removes its append-only history and always leaves a tombstone the API cannot remove", async () => {
    await asApp(DBS.split, async (c) => {
      const t = randomUUID();
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Leaving')", [t]);
      await auditEntry(c, t, 1);
      await socEvent(c, t, 1, 1);
      await c.query("SELECT legion_erase_tenant($1, 'operator', 'offboarding', '{\"audit_log\":1}', false)", [t]);
      expect((await c.query("SELECT count(*)::int AS n FROM soc_audit_events WHERE tenant_id = $1", [t])).rows[0].n).toBe(0);
      expect((await c.query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1", [t])).rows[0].n).toBe(0);
      expect((await c.query("SELECT deleted_by, reason FROM tenant_deletions WHERE tenant_id = $1", [t])).rows).toEqual([{ deleted_by: "operator", reason: "offboarding" }]);
      // The context the function opened is closed again: nothing in this session can erase now.
      expect((await c.query("SELECT legion_erasure_allowed('audit_log'::regclass) AS ok")).rows[0].ok).toBe(false);
    });
  });
});

describe("upgrading a single-role install", () => {
  it("moves ownership from the app role to the owner role; the data stays and the app role stops owning anything", async () => {
    const db = DBS.upgrade;
    await asAdmin(db, (c) => provisionAppRole(c, { appUser: APP, appPassword: PASSWORD }));
    const appPool = new pg.Pool({ connectionString: urlFor(db, APP), max: 2 });
    try {
      await runMigrations(appPool);   // the old way: the API migrates at boot as its own role
      await appPool.query("INSERT INTO tenants (id, name) VALUES ($1, 'Kept')", [T]);
    } finally { await appPool.end(); }
    await asApp(db, async (c) => expect(await ownsSchema(c)).toBe(true));

    const r = await provisionSplit(db);
    expect(r.transferred.length).toBeGreaterThan(20);
    expect(r.owner).toBe(OWNER);
    await asApp(db, async (c) => {
      expect(await ownsSchema(c)).toBe(false);
      expect(await schemaProblems(c)).toEqual([]);
      expect((await c.query("SELECT name FROM tenants WHERE id = $1", [T])).rows).toEqual([{ name: "Kept" }]);
      await expect(c.query("ALTER TABLE tenants ADD COLUMN x int")).rejects.toThrow(/must be owner/);
    });
    // Idempotent: a second run changes nothing and moves nothing.
    expect((await provisionSplit(db)).transferred).toEqual([]);
  }, 120_000);
});
