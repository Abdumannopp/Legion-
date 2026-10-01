/**
 * Password (and recovery-code) hashing, off the event loop.
 *
 * bcryptjs is pure JavaScript: a cost-12 hash or comparison is ~200 ms of CPU
 * on whichever thread runs it. On the main thread that froze the whole
 * instance — webhook ingestion, dashboards, WebSocket heartbeats and the
 * Redis replies the rate limiter waits for — while unauthenticated sign-in
 * attempts arrived (PRODUCTION-VALIDATION-2026-10-01.md, RED-1: /health went
 * from 3 ms to 1.5–24 s under 30 concurrent failed sign-ins).
 *
 * So the work runs in a small pool of worker threads, using the same
 * library (every existing $2a/$2b hash keeps working), and the amount of it
 * waiting is bounded: past that, a request is refused at once with
 * `HashingBusyError` (503 + Retry-After) instead of queueing without limit.
 * Sign-in can be slowed by a flood; the rest of the API cannot.
 */
import { createRequire } from "node:module";
import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";
import { config } from "./config.js";

/** Too much hashing is already waiting; the caller should retry shortly. */
export class HashingBusyError extends Error {
  readonly status = 503;
  constructor() {
    super("Too many sign-ins are being processed right now. Try again in a few seconds.");
    this.name = "HashingBusyError";
  }
}

type Op = "hash" | "compare";
interface Job { id: number; op: Op; a: string; b: string | number; resolve: (v: unknown) => void; reject: (e: Error) => void }
interface Slot { worker: Worker; pending: Map<number, Job> }

// The worker resolves bcryptjs by absolute path (its CommonJS build), so the
// same source works from src/ under the test runner and from dist/.
const BCRYPT_PATH = createRequire(import.meta.url).resolve("bcryptjs");
const WORKER_SOURCE = `
const { parentPort } = require("node:worker_threads");
const bcrypt = require(${JSON.stringify(BCRYPT_PATH)});
parentPort.on("message", ({ id, op, a, b }) => {
  try {
    const result = op === "hash" ? bcrypt.hashSync(a, b) : bcrypt.compareSync(a, b);
    parentPort.postMessage({ id, result });
  } catch (error) {
    parentPort.postMessage({ id, error: String((error && error.message) || error) });
  }
});
`;

export interface PoolOptions {
  /** Worker threads. Default: one per CPU, keeping one CPU for the event loop, at most 4. */
  workers?: number;
  /** Jobs allowed to wait or run in total before new ones are refused. */
  maxPending?: number;
}

export class HashPool {
  private slots: Slot[] = [];
  private nextId = 1;
  readonly size: number;
  readonly maxPending: number;

  constructor(opts: PoolOptions = {}) {
    this.size = Math.max(1, opts.workers ?? Math.min(4, Math.max(1, availableParallelism() - 1)));
    // Each worker clears roughly 4–5 cost-12 hashes a second; 8 waiting per
    // worker keeps the worst wait around two seconds.
    this.maxPending = Math.max(this.size, opts.maxPending ?? this.size * 8);
  }

  /** Jobs waiting or running right now. */
  get pending(): number {
    return this.slots.reduce((n, s) => n + s.pending.size, 0);
  }

  private spawn(index: number): Slot {
    const worker = new Worker(WORKER_SOURCE, { eval: true });
    // The pool never keeps a process alive on its own (tests, shutdown).
    worker.unref();
    const slot: Slot = { worker, pending: new Map() };
    worker.on("message", (msg: { id: number; result?: unknown; error?: string }) => {
      const job = slot.pending.get(msg.id);
      if (!job) return;
      slot.pending.delete(msg.id);
      if (msg.error !== undefined) job.reject(new Error(msg.error));
      else job.resolve(msg.result);
    });
    const fail = (error: Error) => {
      // A dead worker fails only its own jobs; the next call gets a fresh one.
      for (const job of slot.pending.values()) job.reject(error);
      slot.pending.clear();
      if (this.slots[index] === slot) this.slots[index] = undefined as unknown as Slot;
    };
    worker.on("error", fail);
    worker.on("exit", (code) => { if (code !== 0) fail(new Error(`password worker exited with code ${code}`)); else fail(new Error("password worker stopped")); });
    this.slots[index] = slot;
    return slot;
  }

  private run<T>(op: Op, a: string, b: string | number): Promise<T> {
    if (this.pending >= this.maxPending) return Promise.reject(new HashingBusyError());
    // The least busy worker (spawned on first use).
    let best: Slot | null = null;
    for (let i = 0; i < this.size; i++) {
      const slot = this.slots[i] ?? this.spawn(i);
      if (!best || slot.pending.size < best.pending.size) best = slot;
    }
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      best!.pending.set(id, { id, op, a, b, resolve: resolve as (v: unknown) => void, reject });
      best!.worker.postMessage({ id, op, a, b });
    });
  }

  hash(plain: string, cost: number): Promise<string> {
    return this.run<string>("hash", plain, cost);
  }

  compare(plain: string, hash: string): Promise<boolean> {
    return this.run<boolean>("compare", plain, hash);
  }

  async close(): Promise<void> {
    const slots = this.slots.filter(Boolean);
    this.slots = [];
    await Promise.all(slots.map((s) => s.worker.terminate()));
  }
}

let shared: HashPool | null = null;
function pool(): HashPool {
  shared ??= new HashPool({ workers: config.passwordHashWorkers || undefined, maxPending: config.passwordHashMaxPending || undefined });
  return shared;
}

/** bcrypt hash on the worker pool. Throws HashingBusyError when saturated. */
export function hashPassword(plain: string, cost = 12): Promise<string> {
  return pool().hash(plain, cost);
}

/** bcrypt comparison on the worker pool. Throws HashingBusyError when saturated. */
export function comparePassword(plain: string, hash: string): Promise<boolean> {
  return pool().compare(plain, hash);
}

/** Health/metrics and tests. */
export function hashingLoad(): { workers: number; pending: number; maxPending: number } {
  const p = pool();
  return { workers: p.size, pending: p.pending, maxPending: p.maxPending };
}
