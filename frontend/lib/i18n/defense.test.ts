import { describe, expect, it } from "vitest";
import { defense } from "./ns/defense";

const THREATS = ["ransomware", "bec", "phishing", "ddos", "ai_deception", "espionage", "supply_chain"];
const RULES = ["rapid_chain", "wide_sweep", "swarm", "velocity", "ai_manipulation", "ransomware", "mailbox_takeover", "phishing_execution", "supply_chain", "slow_intrusion", "credential_attack", "account_compromise"];

describe("Defense page text", () => {
  it.each(["en"] as const)("%s: every attack type has a name, what Legion does, and what to connect", (l) => {
    const c = defense[l].coverage;
    for (const t of THREATS) {
      expect(c.names[t], t).toBeTruthy();
      expect(c.does[t]!.length, t).toBeGreaterThan(30);
      expect(c.sources[t]!.length, t).toBeGreaterThan(10);
    }
    for (const s of ["detected", "watching", "blind", "partial"]) expect(c.status[s]).toBeTruthy();
  });

  it.each(["en"] as const)("%s: every campaign rule has a label", (l) => {
    for (const r of RULES) expect(defense[l].campaigns.rule[r], r).toBeTruthy();
  });

  it.each(["en"] as const)("%s: every reason a payment is held is explained", (l) => {
    for (const r of ["new_beneficiary", "account_under_attack", "mailbox_takeover_active", "rejected_before"]) {
      expect(defense[l].payments.reasons[r]!.length, r).toBeGreaterThan(20);
    }
    expect(defense[l].payments.confirmRelease("X")).toMatch(/X/);
  });
});
