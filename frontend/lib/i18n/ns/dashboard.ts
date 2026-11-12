import { defineMessages } from "../core";

/**
 * The alert dashboard (components/LegionDashboard.tsx). The `alert` group is
 * also used by the incident list and incident details pages, which show the
 * same alert actions and Oracle explanation.
 */
export const dashboard = defineMessages({
  en: {
    welcome: "Welcome back 👋",
    overview: "Legion Security Overview",
    searchPlaceholder: "Search alerts by ID or title",
    empty: "No alerts match this view.",
    kpi: {
      openThreats: "Open threats",
      newToday: (n: number) => `${n} new in 24 h`,
      critical: "Critical, open",
      criticalHint: "Look at these first",
      endpoints: "Endpoints online",
      endpointsOf: (online: number, total: number) => `${online} of ${total} reporting`,
      noEndpoints: "None connected yet",
      agents: "AI agents active",
      agentsOf: (active: number, total: number) => `${active} of ${total} working`,
      noAgents: "None set up",
    },
    severityTitle: "Open threats by severity",
    severityTotal: "open",
    severityNone: "Nothing open. Every alert is handled.",
    alertsTitle: "Alerts",
    live: "Live",
    alert: {
      aiConfidence: "AI confidence",
      fullDetails: "Full details",
      investigate: "Investigate",
      resolve: "Resolve",
      askOracle: "Ask Oracle to explain",
      oracleThinking: "Oracle is thinking…",
      otherLanguage: "This explanation is in another language.",
      explainInMyLanguage: "Explain in English",
      explainError: "Oracle couldn't explain this alert.",
      loadError: "Couldn't reach the Legion API. Is the backend running?",
    },
  },
});
