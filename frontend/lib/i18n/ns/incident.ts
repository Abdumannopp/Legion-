import { defineMessages } from "../core";

/**
 * Incident details (app/incident/[id]/page.tsx). Alert actions and the Oracle
 * explanation buttons come from `t.dashboard.alert`.
 */
export const incident = defineMessages({
  en: {
    backToAlerts: "Back to alerts",
    loadError: "Couldn't load this incident.",
    statusError: "Couldn't update status.",
    detail: {
      detected: "Detected",
      sourceIp: "Source IP",
      notApplicable: "Not applicable",
      target: "Target",
      notSpecified: "Not specified",
      notClassified: "Not classified",
      confidence: "Detection confidence",
      detectedBy: "Source",
    },
    aiExplanation: "AI explanation",
    suggestedActions: "Suggested actions",
    suggestedIntro:
      "Rule-based suggestions from the alert pattern — not AI-generated, so you can trust exactly why each one is here.",
    manualNote:
      "These are manual checklist items for now — automated execution (the Vanguard agent) isn't wired up yet.",
  },
});
