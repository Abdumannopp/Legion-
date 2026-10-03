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
 *
 * A flood of guesses from many addresses can still fill that bound, and then
 * everyone's sign-in is refused. So the pool has two lanes: a browser that
 * has signed in to the account before, and a signed-in user re-entering their
 * password, are served first from capacity of their own (HashOptions.priority).
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
type Lane = "normal" | "priority";
interface Job { id: number; op: Op; a: string; b: string | number; lane: Lane; resolve: (v: unknown) => void; reject: (e: Error) => void }
interface Slot { worker: Worker; job: Job | null }

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
  /** Extra room reserved for priority jobs (see HashOptions.priority). Default: maxPending. */
  maxPriority?: number;
}

export interface HashOptions {
  /**
   * Served before every normal job, from capacity a flood cannot use up.
   * For people the server already has reason to trust: a browser that has
   * signed in to THIS account before (index.ts, the known-device cookie), or
   * a signed-in user confirming their password. A flood of unauthenticated
   * sign-in guesses fills the normal lane; these still get through.
   */
  priority?: boolean;
}

/**
 * Jobs wait here, in the main thread, and each worker gets exactly one at a
 * time — so the next job a worker takes is always the most urgent waiting
 * one. (Posting every job to a worker as it arrived queued it behind all the
 * others already sent there, and a priority could not overtake them.)
 */
export class HashPool {
  private slots: (Slot | undefined)[] = [];
  private readonly waiting: Record<Lane, Job[]> = { priority: [], normal: [] };
  private readonly inFlight: Record<Lane, number> = { priority: 0, normal: 0 };
  private nextId = 1;
  readonly size: number;
  readonly maxPending: number;
  readonly maxPriority: number;

  constructor(opts: PoolOptions = {}) {
    this.size = Math.max(1, opts.workers ?? Math.min(4, Math.max(1, availableParallelism() - 1)));
    // Each worker clears roughly 4–5 cost-12 hashes a second; 8 waiting per
    // worker keeps the worst wait around two seconds.
    this.maxPending = Math.max(this.size, opts.maxPending ?? this.size * 8);
    this.maxPriority = Math.max(1, opts.maxPriority ?? this.maxPending);
  }

  private count(lane: Lane): number {
    return this.waiting[lane].length + this.inFlight[lane];
  }

  /** Normal jobs waiting or running right now. */
  get pending(): number {
    return this.count("normal");
  }

  /** Priority jobs waiting or running right now. */
  get pendingPriority(): number {
    return this.count("priority");
  }

  private spawn(index: number): Slot {
    const worker = new Worker(WORKER_SOURCE, { eval: true });
    // The pool never keeps a process alive on its own (tests, shutdown).
    worker.unref();
    const slot: Slot = { worker, job: null };
    const settle = (job: Job) => {
      slot.job = null;
      this.inFlight[job.lane]--;
    };
    worker.on("message", (msg: { id: number; result?: unknown; error?: string }) => {
      const job = slot.job;
      if (!job || job.id !== msg.id) return;
      settle(job);
      if (msg.error !== undefined) job.reject(new Error(msg.error));
      else job.resolve(msg.result);
      this.dispatch();
    });
    const fail = (error: Error) => {
      // A dead worker fails only its own job; the next dispatch spawns a fresh one.
      if (this.slots[index] === slot) this.slots[index] = undefined;
      const job = slot.job;
      if (job) { settle(job); job.reject(error); }
      this.dispatch();
    };
    worker.on("error", fail);
    worker.on("exit", (code) => fail(new Error(code !== 0 ? `password worker exited with code ${code}` : "password worker stopped")));
    this.slots[index] = slot;
    return slot;
  }

  /** Hands waiting jobs, most urgent first, to idle workers. */
  private dispatch(): void {
    for (let i = 0; i < this.size; i++) {
      const next = this.waiting.priority[0] ?? this.waiting.normal[0];
      if (!next) return;
      const slot = this.slots[i] ?? this.spawn(i);
      if (slot.job) continue;
      this.waiting[next.lane].shift();
      slot.job = next;
      this.inFlight[next.lane]++;
      slot.worker.postMessage({ id: next.id, op: next.op, a: next.a, b: next.b });
    }
  }

  private run<T>(op: Op, a: string, b: string | number, opts: HashOptions = {}): Promise<T> {
    const lane: Lane = opts.priority ? "priority" : "normal";
    const limit = lane === "priority" ? this.maxPriority : this.maxPending;
    if (this.count(lane) >= limit) return Promise.reject(new HashingBusyError());
    return new Promise<T>((resolve, reject) => {
      this.waiting[lane].push({ id: this.nextId++, op, a, b, lane, resolve: resolve as (v: unknown) => void, reject });
      this.dispatch();
    });
  }

  hash(plain: string, cost: number, opts?: HashOptions): Promise<string> {
    return this.run<string>("hash", plain, cost, opts);
  }

  compare(plain: string, hash: string, opts?: HashOptions): Promise<boolean> {
    return this.run<boolean>("compare", plain, hash, opts);
  }

  async close(): Promise<void> {
    const slots = this.slots.filter((s): s is Slot => Boolean(s));
    this.slots = [];
    await Promise.all(slots.map((s) => s.worker.terminate()));
  }
}

let shared: HashPool | null = null;
function pool(): HashPool {
  shared ??= new HashPool({ workers: config.passwordHashWorkers || undefined, maxPending: config.passwordHashMaxPending || undefined, maxPriority: config.passwordHashMaxPriority || undefined });
  return shared;
}

/** bcrypt hash on the worker pool. Throws HashingBusyError when saturated. */
export function hashPassword(plain: string, cost = 12, opts?: HashOptions): Promise<string> {
  return pool().hash(plain, cost, opts);
}

/** bcrypt comparison on the worker pool. Throws HashingBusyError when saturated. */
export function comparePassword(plain: string, hash: string, opts?: HashOptions): Promise<boolean> {
  return pool().compare(plain, hash, opts);
}

/** Health/metrics and tests. */
export function hashingLoad(): { workers: number; pending: number; maxPending: number; pendingPriority: number; maxPriority: number } {
  const p = pool();
  return { workers: p.size, pending: p.pending, maxPending: p.maxPending, pendingPriority: p.pendingPriority, maxPriority: p.maxPriority };
}
