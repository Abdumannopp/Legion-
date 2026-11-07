/**
 * Legion's plans, prices and what each plan includes — the single source.
 *
 * Pure data with no imports, so the dashboard's tests can compare its own copy
 * against this one (a price shown on the website must never differ from what
 * the server enforces). Prices are USD; annual = 10 months (two months free).
 * Source: "Legion — recommended prices and plans" (commercial recommendation,
 * to be validated against real hosting and AI costs before launch).
 *
 * `null` means "by agreement" (Enterprise).
 */

export const PLAN_IDS = ["starter", "professional", "business", "enterprise"] as const;
export type PlanId = (typeof PLAN_IDS)[number];

export const ADDON_IDS = ["agent_security", "payment_fraud", "threat_intel", "endpoints_100", "ai_credits_5000"] as const;
export type AddonId = (typeof ADDON_IDS)[number];

export type IpBlocking = "none" | "approval" | "policy" | "custom";

export interface Entitlements {
  /** Endpoints (monitored machines). null = by agreement. Over the limit is reported, never dropped (see plan-limits). */
  endpoints: number | null;
  /** People with the admin role. null = by agreement. */
  admins: number | null;
  /** How long alerts are kept. */
  retentionDays: number;
  /** AI explanations: basic (Oracle) or extended (adds the Copilot assistant). */
  aiAnalysis: "basic" | "extended" | "custom";
  /** The five Legion agents and their skills. */
  aiAgents: boolean;
  /** Identities, permissions and the policy firewall for the customer's own AI agents. */
  agentSecurity: boolean;
  /** Payment check: included, or sold as an add-on. */
  paymentCheck: "addon" | "included";
  /** Blocking attacker addresses: none, with a person's approval, by policy (automatic), or custom. */
  ipBlocking: IpBlocking;
  api: "none" | "basic" | "extended" | "custom";
  support: "email" | "priority_email" | "priority" | "sla";
}

export interface Plan {
  id: PlanId;
  name: string;
  audience: string;
  /** USD per month; null = by agreement. */
  monthlyUsd: number | null;
  /** USD per year; null = by agreement. */
  annualUsd: number | null;
  /** The price is a starting price ("$999+"). */
  from: boolean;
  entitlements: Entitlements;
}

export const PLANS: Record<PlanId, Plan> = {
  starter: {
    id: "starter", name: "Starter", audience: "Small business",
    monthlyUsd: 49, annualUsd: 490, from: false,
    entitlements: { endpoints: 25, admins: 2, retentionDays: 30, aiAnalysis: "basic", aiAgents: false, agentSecurity: false, paymentCheck: "addon", ipBlocking: "none", api: "none", support: "email" },
  },
  professional: {
    id: "professional", name: "Professional", audience: "Growing company",
    monthlyUsd: 149, annualUsd: 1490, from: false,
    entitlements: { endpoints: 100, admins: 5, retentionDays: 90, aiAnalysis: "extended", aiAgents: true, agentSecurity: true, paymentCheck: "included", ipBlocking: "approval", api: "basic", support: "priority_email" },
  },
  business: {
    id: "business", name: "Business", audience: "Large IT / SOC team",
    monthlyUsd: 399, annualUsd: 3990, from: false,
    entitlements: { endpoints: 500, admins: 20, retentionDays: 180, aiAnalysis: "extended", aiAgents: true, agentSecurity: true, paymentCheck: "included", ipBlocking: "policy", api: "extended", support: "priority" },
  },
  enterprise: {
    id: "enterprise", name: "Enterprise", audience: "Large organisation",
    monthlyUsd: 999, annualUsd: null, from: true,
    entitlements: { endpoints: null, admins: null, retentionDays: 365, aiAnalysis: "custom", aiAgents: true, agentSecurity: true, paymentCheck: "included", ipBlocking: "custom", api: "custom", support: "sla" },
  },
};

/** Endpoints in the Enterprise range start here ("1,000+"). */
export const ENTERPRISE_MIN_ENDPOINTS = 1000;

export interface Addon {
  id: AddonId;
  name: string;
  /** USD per month. */
  monthlyUsd: number;
  /** What buying it changes in the product ("listed" = sold and recorded, nothing in the product is gated by it yet). */
  effect: "agent_security" | "payment_fraud" | "endpoints" | "listed";
  /** Extra endpoints per unit (endpoints_100). */
  endpoints?: number;
}

export const ADDONS: Record<AddonId, Addon> = {
  agent_security: { id: "agent_security", name: "AI Agent Security", monthlyUsd: 49, effect: "agent_security" },
  payment_fraud: { id: "payment_fraud", name: "Payment Fraud Protection", monthlyUsd: 79, effect: "payment_fraud" },
  threat_intel: { id: "threat_intel", name: "Advanced Threat Intelligence", monthlyUsd: 99, effect: "listed" },
  endpoints_100: { id: "endpoints_100", name: "Extra 100 endpoints", monthlyUsd: 25, effect: "endpoints", endpoints: 100 },
  ai_credits_5000: { id: "ai_credits_5000", name: "Extra 5,000 AI credits", monthlyUsd: 39, effect: "listed" },
};

/** Self-hosted: the customer runs the server and Wazuh; the licence is yearly and includes updates and the plan's support. */
export interface SelfHostedLicence { plan: PlanId; endpoints: number | null; annualUsd: number; from: boolean }
export const SELF_HOSTED: SelfHostedLicence[] = [
  { plan: "starter", endpoints: 25, annualUsd: 490, from: false },
  { plan: "professional", endpoints: 100, annualUsd: 1490, from: false },
  { plan: "business", endpoints: 500, annualUsd: 3990, from: false },
  { plan: "enterprise", endpoints: null, annualUsd: 7500, from: true },
];

export interface SetupService { id: string; name: string; fromUsd: number; toUsd: number | null }
export const SETUP_SERVICES: SetupService[] = [
  { id: "basic", name: "Basic Setup", fromUsd: 300, toUsd: 500 },
  { id: "professional", name: "Professional Setup", fromUsd: 750, toUsd: 1500 },
  { id: "enterprise", name: "Enterprise Integration", fromUsd: 2000, toUsd: null },
];

export function isPlanId(v: unknown): v is PlanId {
  return typeof v === "string" && (PLAN_IDS as readonly string[]).includes(v);
}
export function isAddonId(v: unknown): v is AddonId {
  return typeof v === "string" && (ADDON_IDS as readonly string[]).includes(v);
}

/**
 * What a workspace may use: its plan's entitlements, changed by the add-ons it
 * bought. A self-hosted installation owns the software: no limits.
 */
export interface EffectiveEntitlements extends Entitlements {
  plan: PlanId;
  addons: AddonId[];
}

export function effectiveEntitlements(plan: PlanId, addons: readonly AddonId[] = []): EffectiveEntitlements {
  const e: Entitlements = { ...PLANS[plan].entitlements };
  const bought = addons.filter(isAddonId);
  for (const id of bought) {
    const a = ADDONS[id];
    if (a.effect === "agent_security") e.agentSecurity = true;
    if (a.effect === "payment_fraud") e.paymentCheck = "included";
  }
  if (e.endpoints !== null) {
    const extra = bought.filter((id) => ADDONS[id].effect === "endpoints").length;
    e.endpoints += extra * (ADDONS.endpoints_100.endpoints ?? 0);
  }
  return { ...e, plan, addons: [...new Set(bought)] };
}

/** No limits and everything on: a self-hosted installation, which the customer owns. */
export const UNLIMITED: Entitlements = {
  endpoints: null, admins: null, retentionDays: 0, aiAnalysis: "custom", aiAgents: true, agentSecurity: true,
  paymentCheck: "included", ipBlocking: "custom", api: "custom", support: "sla",
};

/** Annual price as "months paid": 490 / 49 = 10, i.e. two months free. */
export const annualMonthsPaid = (p: Plan): number | null => (p.monthlyUsd && p.annualUsd ? Math.round(p.annualUsd / p.monthlyUsd) : null);
