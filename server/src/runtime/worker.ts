/**
 * The runtime worker: claims due SOC jobs and runs their handler. Every
 * handler is idempotent (the action engine's queued → running move is a
 * compare-and-set; workflow runs are unique per alert and mode), so a job run
 * twice after a lost lease does its work once.
 *
 * Handlers act only inside the job's own tenant. Nothing here executes a live
 * action: `action.run` simulates, as everywhere in v0.
 */
import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { z } from "zod";
import { config } from "../config.js";
import { failAbandoned, getAction, isPaused, MAX_RUN_ATTEMPTS, RUNNING_STALE_SECONDS, runQueued } from "../actions/engine.js";
import { runWorkflow } from "../orchestrator/engine.js";
import { appendAuditEventNow } from "../audit/events.js";
import { claimJobs, completeJob, deadLetterAbandoned, deferJob, failJob, type Job, type JobKind } from "./queue.js";

type Outcome = { ok: true } | { defer: number };
type Handler = (job: Job) => Promise<Outcome>;

const uuid = z.string().regex(/^[0-9a-f-]{36}$/i);
const PAUSE_RECHECK_SECONDS = 60;
const RUNNING_RECHECK_SECONDS = 15;

const HANDLERS: Record<JobKind, Handler> = {
  "action.run": async (job) => {
    const { action_request_id } = z.strictObject({ action_request_id: uuid }).parse(job.payload);
    if (await isPaused(job.tenant_id)) return { defer: PAUSE_RECHECK_SECONDS };
    const before = await getAction(job.tenant_id, action_request_id);
    if (!before) return { ok: true }; // erased with its workspace
    if (before.status === "queued") { await runQueued(job.tenant_id, action_request_id); }
    else if (before.status === "running") {
      // Someone is running it — or its worker died. A simulation takes milliseconds, so past the
      // stale window it is abandoned and runQueued takes it over; before that, look again soon.
      // The job must NOT complete while the action is unresolved, or a crash would strand it.
      if (before.attempts >= MAX_RUN_ATTEMPTS && Date.now() - Date.parse(before.updated_at) > RUNNING_STALE_SECONDS * 1000) { await failAbandoned(job.tenant_id, action_request_id); return { ok: true }; }
      const after = await runQueued(job.tenant_id, action_request_id);
      if (after?.status === "running") return { defer: RUNNING_RECHECK_SECONDS };
    }
    return { ok: true }; // done, or settled some other way (cancelled, rejected, expired…)
  },
  "workflow.run": async (job) => {
    const p = z.strictObject({ workflow: z.string().regex(/^[a-z_]{1,40}$/), alert_id: z.string().max(64), mode: z.enum(["shadow", "simulation"]) }).parse(job.payload);
    if (await isPaused(job.tenant_id)) return { defer: PAUSE_RECHECK_SECONDS };
    await runWorkflow(job.tenant_id, p.workflow, p.alert_id, p.mode, { kind: "system", component: "runtime" });
    return { ok: true };
  },
};

export interface RunReport { claimed: number; done: number; deferred: number; retried: number; dead: number; lost: number }

export const workerId = (): string => `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;

export async function runOnce(opts: { owner?: string; limit?: number } = {}): Promise<RunReport> {
  const owner = opts.owner ?? workerId();
  const report: RunReport = { claimed: 0, done: 0, deferred: 0, retried: 0, dead: 0, lost: 0 };
  report.dead += await deadLetterAbandoned();
  const jobs = await claimJobs(owner, opts.limit ?? 20);
  report.claimed = jobs.length;
  for (const job of jobs) {
    try {
      const out = await HANDLERS[job.kind](job);
      if ("defer" in out) { if (await deferJob(job, out.defer)) report.deferred++; else report.lost++; continue; }
      if (await completeJob(job)) report.done++; else report.lost++;
    } catch (error) {
      const r = await failJob(job, error instanceof Error ? error.message : "job failed");
      if (r === "dead") await appendAuditEventNow(job.tenant_id, { category: "runtime", event: "job.dead", actor: { kind: "system", component: "runtime" }, subject_type: "job", subject_id: job.id, detail: { kind: job.kind, attempts: job.attempts } }).catch(() => {});
      report[r === "retry" ? "retried" : r]++;
    }
  }
  return report;
}

let timer: NodeJS.Timeout | null = null;
let busy = false;

/** This instance's heartbeat, for monitoring: a worker that stopped ticking is as bad as a queue that stopped draining. */
const health = { lastTickAt: null as number | null, lastErrorAt: null as number | null, ticks: 0, errors: 0, lastReport: null as RunReport | null };
export function runtimeHealth(): { running: boolean; last_tick_seconds_ago: number | null; ticks: number; errors: number; last_error_seconds_ago: number | null; last_report: RunReport | null } {
  const ago = (t: number | null) => (t === null ? null : Math.round((Date.now() - t) / 1000));
  return { running: timer !== null, last_tick_seconds_ago: ago(health.lastTickAt), ticks: health.ticks, errors: health.errors, last_error_seconds_ago: ago(health.lastErrorAt), last_report: health.lastReport };
}

export function startRuntime(intervalMs = config.runtimePollSeconds * 1000): void {
  if (timer || !config.runtimeWorker) return;
  const owner = workerId();
  const tick = async () => {
    if (busy) return;
    busy = true;
    try {
      health.lastReport = await runOnce({ owner });
      health.lastTickAt = Date.now();
      health.ticks++;
    } catch (error) {
      health.errors++; health.lastErrorAt = Date.now();
      console.error("SOC runtime tick failed:", error instanceof Error ? error.message : error);
    } finally { busy = false; }
  };
  timer = setInterval(() => void tick(), intervalMs);
  timer.unref();
  void tick();
}

export function stopRuntime(): void {
  if (timer) clearInterval(timer);
  timer = null;
}
