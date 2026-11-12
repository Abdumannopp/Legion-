import { defineMessages, plural } from "../core";

/** Incident list (app/incidents/page.tsx). */
export const incidents = defineMessages({
  en: {
    title: "Incidents",
    bySeverity: (label: string) => `${label} alerts`,
    filterBy: (label: string) => `Show only ${label.toLowerCase()} alerts`,
    summary: (total: number, open: number, investigating: number) =>
      `${plural("en", total, { one: `${total} incident`, other: `${total} incidents` })} · ${open} open · ${investigating} investigating`,
    searchPlaceholder: "Search incidents by title",
    allSeverities: "All severities",
    column: {
      incident: "Incident",
      severity: "Severity",
      status: "Status",
      detectedBy: "Source",
      when: "When",
    },
    empty: "No incidents match this view.",
  },
});
