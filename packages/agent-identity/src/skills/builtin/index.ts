import { SkillRegistry } from "../registry.js";
import type { SkillDefinition } from "../types.js";
import { accountActivityWatch } from "./account-activity-watch.js";
import { alertAnalysis } from "./alert-analysis.js";
import { attackInvestigation } from "./attack-investigation.js";
import { containmentCandidates } from "./containment-candidates.js";
import { dataExfiltrationHunt } from "./data-exfiltration-hunt.js";
import { exposureReview } from "./exposure-review.js";
import { incidentResponse } from "./incident-response.js";
import { aiSecurityRedTeam } from "./red-team.js";
import { securityReporting } from "./security-reporting.js";
import { triagePriority } from "./triage-priority.js";
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
  accountActivityWatch,
  dataExfiltrationHunt,
  exposureReview,
  triagePriority,
  containmentCandidates,
] as const;

/** The skills this Legion build ships. Each registration is validated (read-only capabilities, strict input). */
export function createBuiltinRegistry(): SkillRegistry {
  const r = new SkillRegistry();
  for (const s of BUILTIN_SKILLS) r.register(s as SkillDefinition<any, any>);
  return r;
}

export { accountActivityWatch, containmentCandidates, dataExfiltrationHunt, exposureReview, triagePriority, alertAnalysis, attackInvestigation, incidentResponse, aiSecurityRedTeam, securityReporting, threatDetection, threatIntelligence, vulnerabilityAnalysis };
