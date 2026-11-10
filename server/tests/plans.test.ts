/**
 * The price list. These numbers come from "Legion — recommended prices and
 * plans"; a change here is a pricing decision, so it should fail a test and be
 * made on purpose.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { ADDONS, PLANS, PLAN_IDS, SELF_HOSTED, SETUP_SERVICES, annualMonthsPaid, effectiveEntitlements, UNLIMITED } from "../src/plans.js";

describe("SaaS plans", () => {
  it("monthly and annual prices", () => {
    expect(PLAN_IDS.map((id) => [id, PLANS[id].monthlyUsd, PLANS[id].annualUsd])).toEqual([
      ["starter", 49, 490], ["professional", 149, 1490], ["business", 399, 3990], ["enterprise", 999, null],
    ]);
    expect(PLANS.enterprise.from).toBe(true);
  });

  it("annual is ten months: two months free (about 16.7% off)", () => {
    for (const id of ["starter", "professional", "business"] as const) expect(annualMonthsPaid(PLANS[id])).toBe(10);
    expect(Math.round((1 - 490 / (49 * 12)) * 1000) / 10).toBe(16.7);
  });

  it("limits per plan", () => {
    const row = (id: (typeof PLAN_IDS)[number]) => { const e = PLANS[id].entitlements; return [e.endpoints, e.admins, e.retentionDays]; };
    expect(row("starter")).toEqual([25, 2, 30]);
    expect(row("professional")).toEqual([100, 5, 90]);
    expect(row("business")).toEqual([500, 20, 180]);
    expect(row("enterprise")).toEqual([null, null, 365]);
  });

  it("features per plan", () => {
    const e = (id: (typeof PLAN_IDS)[number]) => PLANS[id].entitlements;
    expect([e("starter").aiAgents, e("starter").agentSecurity, e("starter").paymentCheck, e("starter").ipBlocking]).toEqual([false, false, "addon", "none"]);
    for (const id of ["professional", "business", "enterprise"] as const) {
      expect([e(id).aiAgents, e(id).agentSecurity, e(id).paymentCheck]).toEqual([true, true, "included"]);
    }
    expect(["professional", "business", "enterprise"].map((id) => e(id as "business").ipBlocking)).toEqual(["approval", "policy", "custom"]);
    expect(PLAN_IDS.map((id) => e(id).aiAnalysis)).toEqual(["basic", "extended", "extended", "custom"]);
    expect(PLAN_IDS.map((id) => e(id).support)).toEqual(["email", "priority_email", "priority", "sla"]);
  });
});

describe("add-ons, self-hosted licences and setup", () => {
  it("add-on prices (per month)", () => {
    expect(Object.fromEntries(Object.values(ADDONS).map((a) => [a.id, a.monthlyUsd]))).toEqual({
      agent_security: 49, payment_fraud: 79, threat_intel: 99, endpoints_100: 25, ai_credits_5000: 39,
    });
  });

  it("self-hosted yearly licences", () => {
    expect(SELF_HOSTED.map((l) => [l.plan, l.endpoints, l.annualUsd, l.from])).toEqual([
      ["starter", 25, 490, false], ["professional", 100, 1490, false], ["business", 500, 3990, false], ["enterprise", null, 7500, true],
    ]);
    // The self-hosted licence for the three fixed plans costs the same as that plan's annual SaaS price.
    for (const l of SELF_HOSTED.slice(0, 3)) expect(l.annualUsd).toBe(PLANS[l.plan].annualUsd);
  });

  it("setup services", () => {
    expect(SETUP_SERVICES.map((s) => [s.name, s.fromUsd, s.toUsd])).toEqual([
      ["Basic Setup", 300, 500], ["Professional Setup", 750, 1500], ["Enterprise Integration", 2000, null],
    ]);
  });
});

describe("what a workspace gets", () => {
  it("a plan's own entitlements", () => {
    expect(effectiveEntitlements("starter")).toMatchObject({ plan: "starter", agentSecurity: false, paymentCheck: "addon", endpoints: 25 });
  });

  it("add-ons change exactly what they say", () => {
    const e = effectiveEntitlements("starter", ["agent_security", "payment_fraud", "endpoints_100", "endpoints_100"]);
    expect(e).toMatchObject({ agentSecurity: true, paymentCheck: "included", endpoints: 225, aiAgents: false, ipBlocking: "none" });
  });

  it("an unknown add-on is ignored, and Enterprise's open limits stay open", () => {
    expect(effectiveEntitlements("starter", ["made_up" as never]).addons).toEqual([]);
    expect(effectiveEntitlements("enterprise", ["endpoints_100"]).endpoints).toBeNull();
  });

  it("a self-hosted installation has no limits", () => {
    expect(UNLIMITED).toMatchObject({ endpoints: null, admins: null, agentSecurity: true, paymentCheck: "included", ipBlocking: "custom" });
  });
});

describe("the website shows what the server enforces", () => {
  it("frontend/lib/plans.ts is an exact copy of server/src/plans.ts", () => {
    const here = join(fileURLToPath(import.meta.url), "..", "..", "..");
    const server = readFileSync(join(here, "server", "src", "plans.ts"), "utf8");
    const frontend = readFileSync(join(here, "frontend", "lib", "plans.ts"), "utf8");
    expect(frontend, "copy server/src/plans.ts to frontend/lib/plans.ts").toBe(server);
  });
});
