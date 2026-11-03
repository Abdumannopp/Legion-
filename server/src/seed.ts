import { randomUUID } from "node:crypto";
import bcrypt from "bcryptjs";
import { config, loopbackBind } from "./config.js";
import { query, queryOne, transaction } from "./db/pool.js";
import { trialEnd } from "./store.js";

/**
 * Populates a demo workspace on an empty database.
 *
 * Never runs in production (`config.seedDemoData` is forced false there): a
 * well-known login shipped to every install is a standing invitation, and the
 * first real account is created through POST /auth/register instead.
 */
/** Stable key for the seed advisory lock, distinct from the migration lock. */
const SEED_LOCK_KEY = 728_401_338;

export async function seedDemoIfEmpty(): Promise<void> {
  // Cheap pre-check outside the lock: on every boot after the first, this
  // returns immediately without taking a lock at all.
  const existing = await queryOne<{ count: number }>("SELECT count(*)::bigint AS count FROM tenants");
  if (Number(existing?.count ?? 0) > 0) return;

  if (!config.seedDemoData) {
    console.info("Legion: empty database (demo seed disabled).");
    return;
  }
  // The demo login (admin@legion.demo / legion123) is published. It is created
  // only on a server nobody else can reach.
  if (!loopbackBind) {
    console.warn(`Legion: SEED_DEMO_DATA=true ignored — the API listens on ${config.bindAddress}, and the demo login is public.`);
    return;
  }

  const tenantId = randomUUID();
  const passwordHash = await bcrypt.hash("legion123", 12);

  const seeded = await transaction(async (client) => {
    // Instances that boot together all see an empty database and all try to
    // seed it; without this the losers crash on the unique email constraint
    // and the pod restart-loops on every fresh deploy.
    //
    // pg_advisory_xact_lock is released automatically when the transaction
    // ends, so a crash mid-seed cannot strand the lock.
    await client.query("SELECT pg_advisory_xact_lock($1)", [SEED_LOCK_KEY]);

    // Re-check inside the lock: by the time we got it, another instance may
    // already have finished seeding.
    const recheck = await client.query<{ count: string }>("SELECT count(*) AS count FROM tenants");
    if (Number(recheck.rows[0]?.count ?? 0) > 0) return false;

    await client.query(
      "INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, $3)",
      [tenantId, "Legion Demo", trialEnd()]
    );
    await client.query(
      // Verified: in hosted mode an unconfirmed address cannot sign in, and
      // nobody can click a confirmation link for a demo account.
      `INSERT INTO users (id, email, password_hash, tenant_id, role, status, email_verified_at)
       VALUES ($1, $2, $3, $4, 'admin', 'active', now())`,
      [randomUUID(), "admin@legion.demo", passwordHash, tenantId]
    );

    const alerts: Array<[string, string, string, string, string, string, number, string]> = [
      ["LGN-DEMO-1001", "Suspicious PowerShell execution", "critical", "Sentinel", "10.20.1.44", "WIN-ACCT-07", 96, "T1059"],
      ["LGN-DEMO-1002", "Repeated authentication failures", "high", "Hunter", "203.0.113.18", "vpn-gateway", 88, "T1110"],
      ["LGN-DEMO-1003", "Unusual outbound connection", "medium", "Guardian", "10.20.2.12", "api-server", 72, "T1110"],
    ];
    for (const [id, title, severity, agent, sourceIp, target, confidence, mitre] of alerts) {
      await client.query(
        `INSERT INTO alerts (tenant_id, id, title, severity, agent, summary, confidence,
                             source_ip, target, mitre_technique, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'demo')`,
        [tenantId, id, title, severity, agent,
         `${title}. Automated local demo telemetry requires investigation.`,
         confidence, sourceIp, target, mitre]
      );
    }

    const assets: Array<[string, string, string, string, string]> = [
      ["WIN-ACCT-07", "Windows 11", "10.20.1.44", "critical", "AST-1001"],
      ["api-server", "Ubuntu 24.04", "10.20.2.12", "medium", "AST-1002"],
      ["vpn-gateway", "Linux", "10.20.0.1", "high", "AST-1003"],
    ];
    for (const [name, os, ip, risk, id] of assets) {
      await client.query(
        `INSERT INTO assets (id, tenant_id, name, os, ip_address, risk, online)
         VALUES ($1,$2,$3,$4,$5,$6,true)`,
        [id, tenantId, name, os, ip, risk]
      );
    }
    return true;
  });

  if (seeded) console.info("Legion: demo workspace seeded (admin@legion.demo / legion123).");
}

/** Test helper: empties every table while keeping the schema. */
export async function truncateAll(): Promise<void> {
  await query(
    "TRUNCATE notification_outbox, audit_log, subscriptions, alerts, assets, users, tenants, setup_token RESTART IDENTITY CASCADE"
  );
}
