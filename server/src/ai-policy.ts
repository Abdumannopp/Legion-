/**
 * Who may use AI analysis, how much, and what is recorded about it.
 *
 * Kept out of ai.ts (which talks to the provider) and out of the routes (which
 * would otherwise each re-derive the rule): one decision, one place, tested
 * directly.
 */
import { config } from "./config.js";
import { query } from "./db/pool.js";
import { aiProviderName, type AiCallMeta, type AiFailure, type DataMode } from "./ai.js";
import * as store from "./store.js";
import type { Tenant } from "./types.js";

export type PolicyReason = "ok" | "no_provider" | "tenant_disabled";

export interface AiPolicy {
  /** May this organisation's data be sent to the configured provider now? */
  allowed: boolean;
  reason: PolicyReason;
  dataMode: DataMode;
  /** The third party that would see the text, or null when none is configured. */
  provider: string | null;
  /** The organisation's own choice; null = never chosen. */
  tenantSetting: boolean | null;
  /** What "never chosen" means on this deployment. */
  defaultEnabled: boolean;
}

/** AI_TENANT_DEFAULT wins; otherwise a self-hosted operator who configured a
 *  provider chose it for their own data, while hosted tenants opt in. */
export function aiDefaultEnabled(): boolean {
  if (config.aiTenantDefault === "on") return true;
  if (config.aiTenantDefault === "off") return false;
  return config.deploymentMode === "self-hosted";
}

/** Pure, so the rule can be tested without a database. */
export function decidePolicy(tenant: Pick<Tenant, "ai_enabled" | "ai_data_mode"> | null): AiPolicy {
  const provider = aiProviderName();
  const defaultEnabled = aiDefaultEnabled();
  const tenantSetting = tenant?.ai_enabled ?? null;
  const enabled = tenant ? (tenantSetting ?? defaultEnabled) : false;
  const reason: PolicyReason = !provider ? "no_provider" : !enabled ? "tenant_disabled" : "ok";
  return { allowed: reason === "ok", reason, dataMode: tenant?.ai_data_mode ?? "standard", provider, tenantSetting, defaultEnabled };
}

export async function aiPolicy(tenantId: string): Promise<AiPolicy> {
  return decidePolicy(await store.getTenant(tenantId));
}

// --- per-organisation quota --------------------------------------------------

const windows = new Map<string, number[]>();

/**
 * Provider calls are paid for by the operator and slow, and `?force=true` lets
 * an analyst repeat one at will. The quota is PER WORKSPACE ACROSS ALL
 * INSTANCES: one counter row per workspace per minute in Postgres
 * (usage_counters), incremented only while under the limit, in one atomic
 * statement — so three replicas give a workspace the same allowance as one.
 * If the database cannot be reached the check falls back to counting in this
 * process: a smaller guarantee, never "no limit".
 */
export async function consumeAiQuota(tenantId: string, now = Date.now()): Promise<{ ok: boolean; retryAfterSeconds: number }> {
  const retryAfterSeconds = Math.max(1, 60 - Math.floor((now % 60_000) / 1000));
  try {
    const r = await query(
      `INSERT INTO usage_counters (tenant_id, meter, window_start, count)
       VALUES ($1, 'ai.requests', date_trunc('minute', to_timestamp($3 / 1000.0)), 1)
       ON CONFLICT (tenant_id, meter, window_start) DO UPDATE SET count = usage_counters.count + 1
         WHERE usage_counters.count < $2
       RETURNING count`,
      [tenantId, config.aiRateLimitPerMinute, now],
    );
    return r.rowCount ? { ok: true, retryAfterSeconds: 0 } : { ok: false, retryAfterSeconds };
  } catch {
    return consumeLocalAiQuota(tenantId, now);
  }
}

/** The per-process fallback (and the old behaviour). */
export function consumeLocalAiQuota(tenantId: string, now = Date.now()): { ok: boolean; retryAfterSeconds: number } {
  const recent = (windows.get(tenantId) ?? []).filter((t) => now - t < 60_000);
  if (recent.length >= config.aiRateLimitPerMinute) {
    windows.set(tenantId, recent);
    return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((60_000 - (now - recent[0]!)) / 1000)) };
  }
  recent.push(now);
  windows.set(tenantId, recent);
  return { ok: true, retryAfterSeconds: 0 };
}
export async function resetAiQuota(): Promise<void> {
  windows.clear();
  await query("DELETE FROM usage_counters WHERE meter = 'ai.requests'").catch(() => {});
}

// --- audit -------------------------------------------------------------------

export type AiOutcome = "ai" | "local";
export type AiWhy = AiFailure | PolicyReason | "rate_limited";

/**
 * What the audit log keeps about an AI call: which provider, how big, what
 * happened. Built only from a fixed vocabulary and numbers, so it cannot carry
 * a prompt, an answer or a key even by accident.
 */
export function aiAuditDetail(o: { outcome: AiOutcome; why?: AiWhy; meta?: AiCallMeta; mode: DataMode; extra?: string }): string {
  const parts = [`ai=${o.outcome}`];
  if (o.why && o.why !== "ok") parts.push(`why=${o.why}`);
  if (o.meta?.provider) {
    parts.push(`provider=${o.meta.provider}`, `in=${o.meta.inputChars}`, `out=${o.meta.outputChars}`, `redacted=${o.meta.redactions}`, `masked=${o.meta.pseudonyms}`, `ms=${o.meta.ms}`);
    if (o.meta.httpStatus) parts.push(`http=${o.meta.httpStatus}`);
    if (o.meta.outputFlags.length) parts.push(`flags=${o.meta.outputFlags.join("+")}`);
  }
  parts.push(`mode=${o.mode}`);
  if (o.extra) parts.push(o.extra);
  return parts.join(" ");
}
