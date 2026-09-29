import { SkillRegistry } from "../registry.js";
import type { SkillDefinition } from "../types.js";
import { alertAnalysis } from "./alert-analysis.js";
import { attackInvestigation } from "./attack-investigation.js";
import { incidentResponse } from "./incident-response.js";
import { aiSecurityRedTeam } from "./red-team.js";
import { securityReporting } from "./security-reporting.js";
import { threatDetection } from "./threat-detection.js";
import { threatIntelligence } from "./threat-intelligence.js";
import { vulnerabilityAnalysis } from "./vulnerability-analysis.js";

export const BUILTIN_SKILLS = [
  threatDetection,
  alertAnalysis,
  incidentResponse,
  threatIntelligence,
  attackInvestigation,
  vulnerabilityAnalysis,
  securityReporting,
  aiSecurityRedTeam,
] as const;

/** The skills this Legion build ships. Each registration is validated (read-only capabilities, strict input). */
export function createBuiltinRegistry(): SkillRegistry {
  const r = new SkillRegistry();
  for (const s of BUILTIN_SKILLS) r.register(s as SkillDefinition<any, any>);
  return r;
}

export { alertAnalysis, attackInvestigation, incidentResponse, aiSecurityRedTeam, securityReporting, threatDetection, threatIntelligence, vulnerabilityAnalysis };
