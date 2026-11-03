import { THREAT_SIGNS, THREAT_SOURCES, THREATS, type Threat } from "./threats.js";

/*
 * Threat coverage: for each of the seven attack types, did Legion see signs of
 * it, is it watching (the right data arrives but nothing was found), or is it
 * blind (the data it would need never arrives)? Saying "blind" plainly is the
 * point: a quiet dashboard means nothing if the data is not there.
 */

export type CoverageStatus = "detected" | "watching" | "blind" | "partial";

export interface CoverageEvent { id: string; createdAt: string; text: string }

export interface ThreatCoverage {
  threat: Threat;
  status: CoverageStatus;
  detections: number;
  lastSeen: string | null;
  signs: { id: string; label: string; count: number }[];
  eventIds: string[];
  sourceSeen: boolean;
  connect: string;
}

/**
 * `aiTextAttempts`: events whose text tried to instruct an AI (prompt
 * injection), which Legion detects on every event whatever the source.
 */
export function assessCoverage(events: CoverageEvent[], opts: { aiTextAttempts?: string[] } = {}): ThreatCoverage[] {
  return THREATS.map((threat) => {
    const signs = THREAT_SIGNS.filter((s) => s.threat === threat);
    const counts = new Map<string, number>();
    const hits: CoverageEvent[] = [];
    let sourceSeen = false;
    for (const e of events) {
      const text = e.text.slice(0, 20_000);
      if (!sourceSeen && THREAT_SOURCES[threat].re.test(text)) sourceSeen = true;
      const strong = signs.filter((s) => s.strong && s.re.test(text));
      if (!strong.length) continue;
      hits.push(e);
      for (const s of strong) counts.set(s.id, (counts.get(s.id) ?? 0) + 1);
    }
    if (threat === "ai_deception") {
      for (const id of opts.aiTextAttempts ?? []) {
        if (!hits.some((h) => h.id === id)) { const e = events.find((x) => x.id === id); if (e) hits.push(e); }
        counts.set("ai_instruction_text", (counts.get("ai_instruction_text") ?? 0) + 1);
      }
    }
    // Any detection also proves the source is connected.
    if (hits.length) sourceSeen = true;
    const lastSeen = hits.map((h) => h.createdAt).sort().pop() ?? null;
    const status: CoverageStatus = hits.length
      ? "detected"
      // Deepfake calls and videos never reach Legion: at best it sees what follows them.
      : threat === "ai_deception" ? "partial"
      : sourceSeen ? "watching" : "blind";
    const labels = new Map<string, string>([...signs.map((s) => [s.id, s.label] as const), ["ai_instruction_text", "Text written to instruct an AI"]]);
    return {
      threat, status, detections: hits.length, lastSeen,
      signs: [...counts].map(([id, count]) => ({ id, label: labels.get(id) ?? id, count })).sort((a, b) => b.count - a.count),
      eventIds: hits.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 10).map((h) => h.id),
      sourceSeen, connect: THREAT_SOURCES[threat].connect,
    };
  });
}
