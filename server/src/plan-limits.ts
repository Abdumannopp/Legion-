/**
 * What a workspace's plan allows, and the checks that enforce it.
 *
 * Plans and prices are in plans.ts. This file answers "which plan is this
 * workspace on?" and "may it do X?". It follows two rules that predate plans:
 *
 *  - Telemetry is never dropped over billing (ADR-004). The endpoint limit is
 *    therefore REPORTED (usage, banner, upgrade prompt), not enforced by
 *    refusing events: a hole in someone's security history can never be refilled.
 *  - Stopping something is always allowed. A plan can refuse to START a feature,
 *    never to stop one (the kill switch, revoking a block).
 *
 * A self-hosted installation owns the software, so it has no plan limits.
 */
import type { NextFunction, Response } from "express";
import { config } from "./config.js";
import { query, queryOne } from "./db/pool.js";
import {
  ADDONS, PLANS, UNLIMITED, effectiveEntitlements, isPlanId,
  type AddonId, type EffectiveEntitlements, type Entitlements, type PlanId,
} from "./plans.js";
import * as store from "./store.js";

/** A workspace in its free trial gets the full Professional plan, so it can judge the product. */
export const TRIAL_PLAN: PlanId = "professional";
/** A subscription from before plans existed (one price) is the plan that price was: Professional. */
export const LEGACY_PLAN: PlanId = "professional";

export type PlanSource = "self-hosted" | "override" | "subscription" | "legacy" | "trial";
export interface ResolvedPlan extends EffectiveEntitlements { source: PlanSource }

/** price id → what it buys, from PADDLE_PLAN_PRICES / PADDLE_ADDON_PRICES. */
export function classifyPrices(priceIds: readonly string[]): { plan: PlanId | null; addons: AddonId[]; unknown: string[]; legacy: boolean } {
  const planById = new Map<string, PlanId>();
  for (const [key, id] of Object.entries(config.paddlePlanPrices)) planById.set(id, key.split(".")[0] as PlanId);
  const addonById = new Map<string, AddonId>();
  for (const [key, id] of Object.entries(config.paddleAddonPrices)) addonById.set(id, key as AddonId);
  const legacyIds = new Set(Object.values(config.paddlePriceIds));

  let plan: PlanId | null = null;
  let legacy = false;
  const addons: AddonId[] = [];
  const unknown: string[] = [];
  for (const id of priceIds) {
    if (planById.has(id)) plan = plan ?? planById.get(id)!;
    else if (addonById.has(id)) addons.push(addonById.get(id)!);
    else if (legacyIds.has(id)) { plan = plan ?? LEGACY_PLAN; legacy = true; }
    else unknown.push(id);
  }
  return { plan, addons: [...new Set(addons)], unknown, legacy };
}

/** Every price id Legion offers: the checkout may only grant access for these (audit P1-4). */
export function offeredPriceIds(): Set<string> {
  return new Set([...Object.values(config.paddlePriceIds), ...Object.values(config.paddlePlanPrices), ...Object.values(config.paddleAddonPrices)]);
}

export async function resolvePlan(tenantId: string): Promise<ResolvedPlan> {
  if (config.deploymentMode === "self-hosted") return { ...UNLIMITED, plan: "enterprise", addons: [], source: "self-hosted" };
  const [tenant, sub] = await Promise.all([store.getTenant(tenantId), store.getSubscription(tenantId)]);
  const addons = sub?.addons ?? [];
  if (tenant?.plan_override && isPlanId(tenant.plan_override)) {
    return { ...effectiveEntitlements(tenant.plan_override, addons), source: "override" };
  }
  if (sub && ["active", "trialing", "past_due", "paused", "canceled"].includes(sub.status)) {
    const plan = sub.plan ?? LEGACY_PLAN;
    return { ...effectiveEntitlements(plan, addons), source: sub.plan ? "subscription" : "legacy" };
  }
  return { ...effectiveEntitlements(TRIAL_PLAN, []), source: "trial" };
}

// --- usage --------------------------------------------------------------------

/** Machines seen in the last 30 days: the workspace's endpoint count. */
export async function endpointUsage(tenantId: string): Promise<number> {
  const r = await queryOne<{ n: number }>(
    "SELECT count(*)::int AS n FROM assets WHERE tenant_id = $1 AND last_seen > now() - interval '30 days'", [tenantId]);
  return r?.n ?? 0;
}

/** People who hold an admin seat: active admins, and admins invited but not yet joined. */
export async function adminSeats(tenantId: string, excludeUserId?: string): Promise<number> {
  const r = await queryOne<{ n: number }>(
    `SELECT count(*)::int AS n FROM workspace_memberships m
      WHERE m.tenant_id = $1 AND m.role = 'admin' AND m.status IN ('active', 'invited')
        AND ($2::uuid IS NULL OR m.user_id <> $2::uuid)`,
    [tenantId, excludeUserId ?? null]);
  return r?.n ?? 0;
}

export interface PlanUsage { endpoints: { used: number; limit: number | null; over: boolean }; admins: { used: number; limit: number | null; over: boolean } }
export async function usageOf(tenantId: string, plan: Entitlements): Promise<PlanUsage> {
  const [endpoints, admins] = await Promise.all([endpointUsage(tenantId), adminSeats(tenantId)]);
  return {
    endpoints: { used: endpoints, limit: plan.endpoints, over: plan.endpoints !== null && endpoints > plan.endpoints },
    admins: { used: admins, limit: plan.admins, over: plan.admins !== null && admins > plan.admins },
  };
}

// --- checks -------------------------------------------------------------------

export type Feature = "agentSecurity" | "aiAgents" | "paymentCheck" | "copilot" | "ipBlocking" | "autoBlocking";

export function allows(plan: Entitlements, feature: Feature): boolean {
  switch (feature) {
    case "agentSecurity": return plan.agentSecurity;
    case "aiAgents": return plan.aiAgents;
    case "paymentCheck": return plan.paymentCheck === "included";
    case "copilot": return plan.aiAnalysis !== "basic";
    case "ipBlocking": return plan.ipBlocking !== "none";
    // Automatic blocking acts without a person; "approval" plans keep a person in the loop.
    case "autoBlocking": return plan.ipBlocking === "policy" || plan.ipBlocking === "custom";
  }
}

/** The cheapest plan that includes a feature, for the "upgrade to …" message. */
export function planFor(feature: Feature): PlanId {
  for (const id of ["starter", "professional", "business", "enterprise"] as const) {
    if (allows(PLANS[id].entitlements, feature)) return id;
  }
  return "enterprise";
}

const FEATURE_LABEL: Record<Feature, string> = {
  agentSecurity: "AI Agent Security",
  aiAgents: "The five Legion agents",
  paymentCheck: "Payment fraud check",
  copilot: "The Copilot assistant",
  ipBlocking: "Blocking attacker addresses",
  autoBlocking: "Automatic blocking",
};

/** The refusal body: names what is missing, what would unlock it, and keeps `code` stable for the dashboard. */
export function planRefusal(feature: Feature, plan: PlanId): { detail: string; code: "plan_feature"; feature: Feature; plan: PlanId; upgrade_to: PlanId; addon: AddonId | null } {
  const addon: AddonId | null = feature === "agentSecurity" ? "agent_security" : feature === "paymentCheck" ? "payment_fraud" : null;
  const upgrade = planFor(feature);
  return {
    detail: `${FEATURE_LABEL[feature]} is not included in the ${PLANS[plan].name} plan.${addon ? ` Add ${ADDONS[addon].name} or upgrade to ${PLANS[upgrade].name}.` : ` Upgrade to ${PLANS[upgrade].name}.`}`,
    code: "plan_feature", feature, plan, upgrade_to: upgrade, addon,
  };
}

/** Express middleware: refuses with 403 `plan_feature` when the workspace's plan lacks `feature`. */
export function requireFeature(feature: Feature, tenantOf: (req: never) => string | undefined) {
  return async (req: never, res: Response, next: NextFunction): Promise<void> => {
    try {
      const tenantId = tenantOf(req);
      if (!tenantId) return next();
      const plan = await resolvePlan(tenantId);
      if (allows(plan, feature)) return next();
      res.status(403).json(planRefusal(feature, plan.plan));
    } catch (error) {
      next(error);
    }
  };
}

/** Whether another admin seat is free (for the invitation / promotion routes). */
export async function adminSeatFree(tenantId: string, excludeUserId?: string): Promise<{ ok: true } | { ok: false; limit: number; plan: PlanId }> {
  const plan = await resolvePlan(tenantId);
  if (plan.admins === null) return { ok: true };
  const used = await adminSeats(tenantId, excludeUserId);
  return used < plan.admins ? { ok: true } : { ok: false, limit: plan.admins, plan: plan.plan };
}

// --- retention ----------------------------------------------------------------

/**
 * Deletes alerts older than each workspace's plan allows (Starter 30 days …
 * Enterprise 365). Only on hosted installations: a self-hosted customer keeps
 * their data as long as they like. Only RESOLVED alerts are deleted: an incident
 * nobody has resolved is still an incident, however old.
 */
export async function pruneAlertsByPlan(now = new Date()): Promise<number> {
  if (config.deploymentMode === "self-hosted") return 0;
  let removed = 0;
  const tenants = await query<{ id: string }>("SELECT id FROM tenants WHERE NOT legal_hold");
  for (const t of tenants.rows) {
    const plan = await resolvePlan(t.id);
    if (!plan.retentionDays) continue;
    const r = await query(
      `DELETE FROM alerts WHERE tenant_id = $1 AND status = 'resolved' AND created_at < $2::timestamptz - make_interval(days => $3)`,
      [t.id, now.toISOString(), plan.retentionDays],
    );
    removed += r.rowCount ?? 0;
  }
  return removed;
}
