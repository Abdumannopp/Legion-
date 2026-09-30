import type { translations } from "@/lib/i18n/translations";

type T = (typeof translations)["en"];

/**
 * Where an alert came from, in words a person recognises: "Wazuh", "Test
 * alert", "AI agent protection". Unknown sources (a new integration) show
 * as sent.
 */
export function sourceLabel(source: string | null | undefined, t: T): string | null {
  if (!source) return null;
  return t.overview.sourceLabel[source] ?? source;
}

export const isTestSource = (source: string | null | undefined) => source === "legion-test" || source === "mock";
