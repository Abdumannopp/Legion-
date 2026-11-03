/** How far an agent's current behaviour departs from its normal role. */
export type BehaviorLevel = "NORMAL" | "SUSPICIOUS" | "HIGH_RISK" | "CRITICAL";
export const LEVEL_ORDER: readonly BehaviorLevel[] = ["NORMAL", "SUSPICIOUS", "HIGH_RISK", "CRITICAL"];

export const LEVEL_THRESHOLDS = { SUSPICIOUS: 30, HIGH_RISK: 60, CRITICAL: 85 } as const;

export function levelOf(score: number): BehaviorLevel {
  return score >= LEVEL_THRESHOLDS.CRITICAL
    ? "CRITICAL"
    : score >= LEVEL_THRESHOLDS.HIGH_RISK
      ? "HIGH_RISK"
      : score >= LEVEL_THRESHOLDS.SUSPICIOUS
        ? "SUSPICIOUS"
        : "NORMAL";
}

export type SignalCategory =
  | "volume"
  | "tools"
  | "resources"
  | "destinations"
  | "failures"
  | "probing"
  | "attack_indicators"
  | "sensitive_data"
  | "agent_communication"
  | "timing"
  | "delegation"
  | "external_content";

export interface Signal {
  category: SignalCategory;
  id: string;
  points: number;
  detail: string;
  /** What was seen: new tools, destinations, rule ids… (bounded). */
  evidence?: string[];
}

/** An agent's normal behaviour, learned from its own history. */
export interface BehaviorProfile {
  events: number;
  since: string | null;
  until: string;
  /** Actions per active hour. */
  hourly: { mean: number; std: number; p95: number; activeHours: number };
  actions: Record<string, number>;
  resourceTypes: Record<string, number>;
  destinations: Record<string, number>;
  externalDestinations: Record<string, number>;
  peers: Record<string, number>;
  delegatedUsers: Record<string, number>;
  /** Share of decisions that were BLOCK. */
  blockRate: number;
  /** Share of actions on confidential or restricted data. */
  sensitiveRate: number;
  /** Agent-to-agent messages per active hour. */
  messagesPerHour: number;
  /** Activity by UTC hour of day. */
  hoursOfDay: number[];
  /** Enough history to call something "new" or "unusual". */
  established: boolean;
}

/** One event in the current window (a firewall decision, reduced). */
export interface WindowEvent {
  occurredAt: string;
  surface: string;
  action: string;
  resourceType: string | null;
  destination: string | null;
  sensitivity: string;
  decision: string;
  ruleIds: string[];
  delegatedUser: string | null;
  viaMessage: boolean;
}

export interface Assessment {
  level: BehaviorLevel;
  score: number;
  established: boolean;
  window: { start: string; end: string; events: number; blocks: number; failures: number; perHour: number };
  signals: Signal[];
}
