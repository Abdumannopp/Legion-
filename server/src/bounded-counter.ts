/**
 * A fixed-window counter with a hard ceiling on memory.
 *
 * Rate limiters key their counters on things an attacker chooses (an address,
 * an email, a token). An unbounded Map is therefore an unbounded allocation the
 * attacker controls — the limiter becomes the denial of service. This one holds
 * at most `maxKeys` live counters.
 *
 * When the table is full and nothing has expired, NEW keys share one overflow
 * counter instead of evicting live ones. Evicting would let an attacker flush a
 * victim's failure count by inventing keys; sharing means a flood of fresh keys
 * throttles other fresh keys, while every key already being tracked keeps its
 * exact count. The overflow counter is the safe direction to fail.
 */
export interface Hit {
  totalHits: number;
  resetTime: Date;
}

interface Entry { count: number; resetAt: number }

export const OVERFLOW_KEY = "\u0000overflow";

export class BoundedCounter {
  private readonly entries = new Map<string, Entry>();
  private sweepAt = 0;

  constructor(
    private readonly windowMs: number,
    private readonly maxKeys: number,
    private readonly clock: () => number = Date.now,
  ) {
    if (maxKeys < 2) throw new Error("BoundedCounter needs room for at least two keys");
  }

  get size(): number { return this.entries.size; }

  private sweep(now: number): void {
    for (const [key, entry] of this.entries) if (entry.resetAt <= now) this.entries.delete(key);
    this.sweepAt = now + Math.min(this.windowMs, 10_000);
  }

  increment(key: string): Hit {
    const now = this.clock();
    if (now >= this.sweepAt || this.entries.size >= this.maxKeys) this.sweep(now);

    let slot = key;
    let entry = this.entries.get(slot);
    if (!entry || entry.resetAt <= now) {
      if (!entry && this.entries.size >= this.maxKeys - 1) {
        slot = OVERFLOW_KEY;
        entry = this.entries.get(slot);
      }
      if (!entry || entry.resetAt <= now) {
        entry = { count: 0, resetAt: now + this.windowMs };
        this.entries.set(slot, entry);
      }
    }
    entry.count += 1;
    return { totalHits: entry.count, resetTime: new Date(entry.resetAt) };
  }

  /** The current count for `key` without counting a hit (0 when unknown or expired). */
  peek(key: string): number {
    const entry = this.entries.get(key);
    return entry && entry.resetAt > this.clock() ? entry.count : 0;
  }

  decrement(key: string): void {
    const entry = this.entries.get(key) ?? this.entries.get(OVERFLOW_KEY);
    if (entry && entry.count > 0) entry.count -= 1;
  }

  reset(key: string): void {
    this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }
}
