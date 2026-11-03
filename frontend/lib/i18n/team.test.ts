import { describe, expect, it } from "vitest";
import { team } from "./ns/team";

const SKILLS = [
  "threat_detection", "account_activity_watch", "attack_investigation", "threat_intelligence", "data_exfiltration_hunt",
  "vulnerability_analysis", "ai_security_red_team", "exposure_review", "alert_analysis", "security_reporting",
  "triage_priority", "incident_response", "containment_candidates",
];
const AGENTS = ["Sentinel", "Hunter", "Guardian", "Oracle", "Executor"];

describe("Legion team page text", () => {
  it.each(["en", "ru", "uz"] as const)("%s: every agent and every skill has text", (locale) => {
    const m = team[locale];
    expect(Object.keys(m.agents).sort()).toEqual([...AGENTS].sort());
    for (const a of AGENTS) { expect(m.agents[a]!.role.length).toBeGreaterThan(3); expect(m.agents[a]!.job.length).toBeGreaterThan(20); }
    expect(Object.keys(m.skillLines).sort()).toEqual([...SKILLS].sort());
    for (const s of SKILLS) expect(m.skillLines[s]!.length, s).toBeGreaterThan(20);
  });

  it("ru and uz are translated, not copied from English", () => {
    for (const s of SKILLS) {
      expect(team.ru.skillLines[s]).not.toBe(team.en.skillLines[s]);
      expect(team.uz.skillLines[s]).not.toBe(team.en.skillLines[s]);
    }
  });

  it("counts skills in the right grammatical form", () => {
    expect(team.en.skills(1)).toBe("1 skill");
    expect(team.en.skills(3)).toBe("3 skills");
    expect([1, 2, 5, 11, 21, 22, 25].map((n) => team.ru.skills(n))).toEqual(["1 навык", "2 навыка", "5 навыков", "11 навыков", "21 навык", "22 навыка", "25 навыков"]);
    expect(team.uz.skills(3)).toBe("3 ta skill");
  });
});
