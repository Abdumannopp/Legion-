import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ADDON_IDS, ADDONS, PLANS, PLAN_IDS, SELF_HOSTED, SETUP_SERVICES } from "./plans";
import { pricing } from "./i18n/ns/pricing";
import { planPrice } from "@/components/site/PricingCard";

const p = pricing.en;

describe("the price list on the website", () => {
  it("is the same file the server enforces", () => {
    const server = readFileSync(join(__dirname, "..", "..", "server", "src", "plans.ts"), "utf8");
    expect(readFileSync(join(__dirname, "plans.ts"), "utf8")).toBe(server);
  });

  it("monthly, annual and Enterprise prices shown on the cards", () => {
    expect(PLAN_IDS.map((id) => planPrice(id, "month").amount)).toEqual(["$49", "$149", "$399", "$999"]);
    expect(PLAN_IDS.map((id) => planPrice(id, "year").amount)).toEqual(["$490", "$1,490", "$3,990", null]);
    expect(planPrice("enterprise", "month").from).toBe(true);
  });

  it("every plan, add-on, setup service and feature has words", () => {
    for (const id of PLAN_IDS) expect(p.audience[id], id).toBeTruthy();
    for (const id of ADDON_IDS) { expect(p.addons.names[id], id).toBeTruthy(); expect(p.addons.help[id].length, id).toBeGreaterThan(10); }
    for (const s of SETUP_SERVICES) { expect(p.setup.names[s.id as "basic"], s.id).toBeTruthy(); expect(p.setup.help[s.id as "basic"], s.id).toBeTruthy(); }
    for (const id of PLAN_IDS) {
      const e = PLANS[id].entitlements;
      expect(p.compare.aiAnalysis[e.aiAnalysis]).toBeTruthy();
      expect(p.compare.paymentCheck[e.paymentCheck]).toBeTruthy();
      expect(p.compare.ipBlocking[e.ipBlocking]).toBeTruthy();
      expect(p.compare.api[e.api]).toBeTruthy();
      expect(p.compare.support[e.support]).toBeTruthy();
    }
  });

  it("limits read naturally, with open limits as such", () => {
    expect(p.headline.endpoints(25)).toBe("Up to 25 endpoints");
    expect(p.headline.endpoints(null)).toBe("1,000+ endpoints");
    expect(p.headline.admins(null)).toBe("Administrators by agreement");
    expect(p.headline.history(365)).toBe("365 days of alert history");
    expect(p.setup.range(300, 500)).toBe("$300 – $500");
    expect(p.setup.range(2000, null)).toBe("$2,000+");
  });

  it("annual saving matches the two-months-free promise", () => {
    const s = PLANS.starter;
    expect(Math.round((1 - s.annualUsd! / (s.monthlyUsd! * 12)) * 1000) / 10).toBe(16.7);
    expect(ADDONS.agent_security.monthlyUsd).toBe(49);
    expect(SELF_HOSTED.map((l) => l.annualUsd)).toEqual([490, 1490, 3990, 7500]);
  });
});
