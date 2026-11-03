import { describe, expect, it } from "vitest";
import { team } from "./ns/team";

const SKILLS = [
  "threat_detection", "account_activity_watch", "attack_investigation", "threat_intelligence", "data_exfiltration_hunt",
  "vulnerability_analysis", "ai_security_red_team", "exposure_review", "alert_analysis", "security_reporting",
  "triage_priority", "incident_response", "containment_candidates", "threat_coverage",
  "secret_exposure_check", "sensitive_access_watch", "response_sla_review", "payment_fraud_review",
];
const AGENTS = ["Sentinel", "Hunter", "Guardian", "Oracle", "Executor"];

describe("Legion team page text", () => {
  it.each(["en"] as const)("%s: every agent and every skill has text", (locale) => {
    const m = team[locale];
    expect(Object.keys(m.agents).sort()).toEqual([...AGENTS].sort());
    for (const a of AGENTS) { expect(m.agents[a]!.role.length).toBeGreaterThan(3); expect(m.agents[a]!.job.length).toBeGreaterThan(20); }
    expect(Object.keys(m.skillLines).sort()).toEqual([...SKILLS].sort());
    for (const s of SKILLS) expect(m.skillLines[s]!.length, s).toBeGreaterThan(20);
  });

  it("counts skills in the right grammatical form", () => {
    expect(team.en.skills(1)).toBe("1 skill");
    expect(team.en.skills(3)).toBe("3 skills");
  });
});
