import { defineMessages, plural } from "../core";

export const reports = defineMessages({
  en: {
    title: "Reports",
    subtitle: "Security posture summary, generated from live alert & asset data",
    kpi: {
      totalIncidents: "Total incidents",
      resolutionRate: "Resolution rate",
      avgConfidence: "Avg. AI confidence",
      assetsOnline: "Assets online",
    },
    bySeverity: "Incidents by severity",
    byStatus: "Incidents by status",
    byAgent: "Detections by source",
    otherSource: "Other",
    noIncidents: "No incidents yet.",
    oracleCoverage: "Oracle AI explanation coverage",
    explained: "Explained",
    coverageNote: (explained: number, total: number) =>
      `${explained} of ${total} incidents have an Oracle-generated explanation on file.`,
    recentlyResolved: "Recently resolved incidents",
    nothingResolved: "Nothing resolved yet.",
    loadError: "Couldn't reach the Legion API. Is the backend running?",
  },
});
