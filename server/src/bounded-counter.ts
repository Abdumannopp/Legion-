import { randomInt } from "node:crypto";

/**
 * A fixed-window counter with a hard ceiling on memory — and on CPU.
 *
 * Rate limiters key their counters on things an attacker chooses (an address,
 * an email, a token). An unbounded Map is therefore an unbounded allocation the
 * attacker controls — the limiter becomes the denial of service. This one holds
 * at most `maxKeys` live counters.
 *
 * When the table is full and nothing has expired, NEW keys share a small, fixed
 * set of overflow counters instead of evicting live ones. Evicting would let an
 * attacker flush a victim's failure count by inventing keys; sharing means
 * every key already being tracked keeps its exact count, and a fresh key is
 * still always counted (it never gets a free pass). The overflow is the safe
 * direction to fail.
 *
 * Two properties were added after measuring a distributed flood
 * (ops/tests/ddos-resilience.mjs, 2026-10-02):
 *
 *  - Cost. The table used to be swept in full on EVERY call once it was full:
 *    ~600 µs instead of ~1 µs, per limiter, per request. A flood from many
 *    addresses then pinned a CPU inside the limiter itself. Entries are now
 *    kept in expiry order (all windows are equal, and a refreshed key is moved
 *    to the back), so a sweep stops at the first live entry and a saturated
 *    table costs O(1) per call.
 *
 *  - Blast radius. All fresh keys used to share ONE overflow counter, so a
 *    flood from more than `maxKeys` addresses throttled every new legitimate
 *    address at the shared limit. They are now spread over `overflowBuckets`
 *    counters chosen by a per-process salted hash (an attacker cannot aim at
 *    a bucket), so a flood only reaches the share of fresh keys that hashes
 *    into the buckets it manages to saturate.
 */
export interface Hit {
  totalHits: number;
  resetTime: Date;
}

interface Entry { count: number; resetAt: number }

export const OVERFLOW_KEY = "\u0000overflow";
const DEFAULT_OVERFLOW_BUCKETS = 256;

export class BoundedCounter {
  private readonly entries = new Map<string, Entry>();
  private readonly buckets: number;
  private readonly salt = randomInt(1, 0x7fffffff);
  private sweepAt = 0;

  constructor(
    private readonly windowMs: number,
    private readonly maxKeys: number,
    private readonly clock: () => number = Date.now,
    overflowBuckets = DEFAULT_OVERFLOW_BUCKETS,
  ) {
    if (maxKeys < 2) throw new Error("BoundedCounter needs room for at least two keys");
    // Never let the overflow take more than a quarter of the table.
    this.buckets = Math.max(1, Math.min(overflowBuckets, Math.floor(maxKeys / 4)));
  }

  get size(): number { return this.entries.size; }

  /** Hits held in the overflow counters (fresh keys that did not fit). For metrics and tests. */
  get overflowTotal(): number {
    let total = 0;
    for (const [key, entry] of this.entries) if (key.startsWith(OVERFLOW_KEY)) total += entry.count;
    return total;
  }

  private overflowSlot(key: string): string {
    let h = this.salt;
    for (let i = 0; i < key.length; i++) h = Math.imul(h ^ key.charCodeAt(i), 16777619);
    return `${OVERFLOW_KEY}${(h >>> 0) % this.buckets}`;
  }

  /**
   * Drops expired entries from the front. The Map iterates in insertion order
   * and every entry is inserted with the same window, so the oldest entries
   * expire first: stop at the first live one. (If the clock steps backwards the
   * order is only approximate — cleanup is then late, never wrong, and the
   * table stays bounded because increment() also refreshes expired keys.)
   */
  private sweep(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.resetAt > now) break;
      this.entries.delete(key);
    }
    this.sweepAt = now + Math.min(this.windowMs, 10_000);
  }

  private live(slot: string, now: number): Entry | undefined {
    const entry = this.entries.get(slot);
    if (entry && entry.resetAt <= now) {
      // Expired: remove it so a fresh entry is appended at the back, in expiry order.
      this.entries.delete(slot);
      return undefined;
    }
    return entry;
  }

  increment(key: string): Hit {
    const now = this.clock();
    if (now >= this.sweepAt || this.entries.size >= this.maxKeys) this.sweep(now);

    let slot = key;
    let entry = this.live(slot, now);
    if (!entry) {
      if (this.entries.size >= this.maxKeys - this.buckets) {
        slot = this.overflowSlot(key);
        entry = this.live(slot, now);
      }
      if (!entry) {
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
    const entry = this.entries.get(key) ?? this.entries.get(this.overflowSlot(key));
    if (entry && entry.count > 0) entry.count -= 1;
  }

  reset(key: string): void {
    this.entries.delete(key);
  }

  clear(): void {
    this.entries.clear();
  }
}
