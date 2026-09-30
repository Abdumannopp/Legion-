import type { RiskFactor, RuleHit } from "../firewall/types.js";

/** Collects rule hits and risk factors while a tool call is analysed. */
export class Findings {
  readonly hits: RuleHit[] = [];
  readonly factors: RiskFactor[] = [];
  /** Can never be relaxed by policy mode. */
  hard(id: string, reason: string): void {
    this.hits.push({ id, effect: "BLOCK", hard: true, reason });
  }
  /** Blocks in enforce mode, warns in monitor mode. */
  soft(id: string, reason: string): void {
    this.hits.push({ id, effect: "BLOCK", hard: false, reason });
  }
  /** Waits for a person's approval of this exact call. */
  confirm(id: string, reason: string): void {
    this.hits.push({ id, effect: "CONFIRM", hard: true, reason });
  }
  warn(id: string, reason: string): void {
    this.hits.push({ id, effect: "WARN", hard: false, reason });
  }
  add(factor: string, points: number): void {
    if (points) this.factors.push({ factor, points });
  }
}
