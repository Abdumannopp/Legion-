/**
 * One-shot import of a legacy `legion.json` store into Postgres.
 *
 *   npm run import:json -- ./data/legion.json
 *
 * Safe to re-run: every insert is ON CONFLICT DO NOTHING, so a partial import
 * can be resumed without creating duplicates. Nothing is ever deleted — the
 * JSON file is left untouched so it stays available as a rollback.
 */
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { closePool, migrate, transaction } from "../db/pool.js";
import { config } from "../config.js";

interface LegacyDatabase {
  tenants?: Array<Record<string, unknown>>;
  users?: Array<Record<string, unknown>>;
  alerts?: Array<Record<string, unknown>>;
  assets?: Array<Record<string, unknown>>;
  audit?: Array<Record<string, unknown>>;
  subscriptions?: Array<Record<string, unknown>>;
}

const str = (v: unknown): string | null => (typeof v === "string" && v.length ? v : null);
const num = (v: unknown, fallback = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : fallback);

function trialFallback(): string {
  // Legacy tenants predate trial_ends_at. Granting a fresh window rather than
  // measuring from creation means the migration can never lock a paying
  // customer out of their own dashboard.
  return new Date(Date.now() + config.trialDays * 86_400_000).toISOString();
}

async function main(): Promise<void> {
  const path = process.argv[2] || config.dataFile;
  console.info(`Reading ${path}`);

  let legacy: LegacyDatabase;
  try {
    legacy = JSON.parse(await readFile(path, "utf8")) as LegacyDatabase;
  } catch (error) {
    console.error(`Could not read ${path}:`, error instanceof Error ? error.message : error);
    process.exit(1);
  }

  await migrate();

  const counts = { tenants: 0, users: 0, alerts: 0, assets: 0, audit: 0, subscriptions: 0 };

  await transaction(async (client) => {
    for (const t of legacy.tenants ?? []) {
      const result = await client.query(
        `INSERT INTO tenants (id, name, notification_email, trial_ends_at, created_at)
         VALUES ($1,$2,$3,$4,COALESCE($5::timestamptz, now()))
         ON CONFLICT (id) DO NOTHING`,
        [t.id, t.name ?? "Imported tenant", str(t.notification_email),
         str(t.trial_ends_at) ?? trialFallback(), str(t.created_at)]
      );
      counts.tenants += result.rowCount ?? 0;
    }

    for (const u of legacy.users ?? []) {
      const result = await client.query(
        `INSERT INTO users (id, email, password_hash, tenant_id, role, status, token_version,
                            reset_token, reset_expires, invite_token, invite_expires, invited_by, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,COALESCE($13::timestamptz, now()))
         ON CONFLICT (id) DO NOTHING`,
        [u.id, u.email, u.password_hash ?? "", u.tenant_id, u.role ?? "viewer",
         str(u.status) ?? "active", num(u.token_version), str(u.reset_token), str(u.reset_expires),
         str(u.invite_token), str(u.invite_expires), str(u.invited_by), str(u.created_at)]
      );
      counts.users += result.rowCount ?? 0;
    }

    for (const a of legacy.alerts ?? []) {
      const result = await client.query(
        `INSERT INTO alerts (tenant_id, id, title, severity, agent, status, summary, confidence,
                             ai_explanation, explained_at, source_ip, target, mitre_technique, source, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,COALESCE($15::timestamptz, now()))
         ON CONFLICT (tenant_id, id) DO NOTHING`,
        [a.tenant_id, a.id, a.title ?? "(untitled)", a.severity ?? "low", a.agent ?? "Sentinel",
         a.status ?? "open", a.summary ?? "", num(a.confidence), str(a.ai_explanation),
         str(a.explained_at), str(a.source_ip), str(a.target), str(a.mitre_technique),
         str(a.source) ?? "imported", str(a.created_at)]
      );
      counts.alerts += result.rowCount ?? 0;
    }

    for (const a of legacy.assets ?? []) {
      const result = await client.query(
        `INSERT INTO assets (id, tenant_id, name, os, ip_address, risk, online, last_seen)
         VALUES ($1,$2,$3,$4,$5,$6,$7,COALESCE($8::timestamptz, now()))
         ON CONFLICT (tenant_id, name) DO NOTHING`,
        [str(a.id) ?? `AST-${randomUUID().slice(0, 12).toUpperCase()}`, a.tenant_id, a.name,
         str(a.os) ?? "unknown", str(a.ip_address), a.risk ?? "low",
         a.online === undefined ? true : Boolean(a.online), str(a.last_seen)]
      );
      counts.assets += result.rowCount ?? 0;
    }

    for (const row of legacy.audit ?? []) {
      const result = await client.query(
        `INSERT INTO audit_log (id, tenant_id, user_id, user_email, action, resource_type,
                                resource_id, detail, ip_address, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10::timestamptz, now()))
         ON CONFLICT (id) DO NOTHING`,
        [str(row.id) ?? randomUUID(), row.tenant_id, str(row.user_id), str(row.user_email),
         row.action ?? "unknown", str(row.resource_type), str(row.resource_id),
         str(row.detail), str(row.ip_address), str(row.created_at)]
      );
      counts.audit += result.rowCount ?? 0;
    }

    for (const s of legacy.subscriptions ?? []) {
      const result = await client.query(
        `INSERT INTO subscriptions (tenant_id, status, paddle_customer_id, paddle_subscription_id,
                                    paddle_price_id, current_period_end, cancel_at_period_end, last_event_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (tenant_id) DO NOTHING`,
        [s.tenant_id, s.status ?? "trialing", str(s.paddle_customer_id) ?? "",
         str(s.paddle_subscription_id), str(s.paddle_price_id), str(s.current_period_end),
         Boolean(s.cancel_at_period_end), str(s.last_event_at)]
      );
      counts.subscriptions += result.rowCount ?? 0;
    }
  });

  console.info("Imported:", counts);
  console.info(`\nThe JSON file was not modified — keep it until you've verified the data in Postgres.`);
  await closePool();
}

main().catch(async (error) => {
  console.error("Import failed — nothing was committed:", error);
  await closePool().catch(() => {});
  process.exit(1);
});
