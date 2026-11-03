import { describe, expect, it } from "vitest";
import { defense } from "./ns/defense";

const THREATS = ["ransomware", "bec", "phishing", "ddos", "ai_deception", "espionage", "supply_chain"];
const RULES = ["rapid_chain", "wide_sweep", "swarm", "velocity", "ai_manipulation", "ransomware", "mailbox_takeover", "phishing_execution", "supply_chain", "slow_intrusion"];

describe("Defense page text", () => {
  it.each(["en", "ru", "uz"] as const)("%s: every attack type has a name, what Legion does, and what to connect", (l) => {
    const c = defense[l].coverage;
    for (const t of THREATS) {
      expect(c.names[t], t).toBeTruthy();
      expect(c.does[t]!.length, t).toBeGreaterThan(30);
      expect(c.sources[t]!.length, t).toBeGreaterThan(10);
    }
    for (const s of ["detected", "watching", "blind", "partial"]) expect(c.status[s]).toBeTruthy();
  });

  it.each(["en", "ru", "uz"] as const)("%s: every campaign rule has a label", (l) => {
    for (const r of RULES) expect(defense[l].campaigns.rule[r], r).toBeTruthy();
  });

  it("ru and uz are translated", () => {
    for (const t of THREATS) {
      expect(defense.ru.coverage.does[t]).not.toBe(defense.en.coverage.does[t]);
      expect(defense.uz.coverage.does[t]).not.toBe(defense.en.coverage.does[t]);
    }
  });
});
