/**
 * The SOC core's durable job queue (table soc_jobs).
 *
 *  - enqueueJob takes the caller's transaction client: the job commits or
 *    rolls back together with the state change that needs it.
 *  - claimJobs hands each due job to exactly one worker (SKIP LOCKED) with a
 *    lease. A job whose worker died is claimable again once the lease ends.
 *  - finishing requires the lease: owner AND attempt number must still match,
 *    so a worker that lost its lease cannot overwrite the new owner's work.
 *  - failures back off exponentially; after max_attempts the job is dead.
 */
import { randomUUID } from "node:crypto";
import type pg from "pg";
import { query, queryAll, queryOne } from "../db/pool.js";

export const JOB_KINDS = ["action.run", "workflow.run"] as const;
export type JobKind = (typeof JOB_KINDS)[number];

export interface Job {
  tenant_id: string;
  id: string;
  kind: JobKind;
  payload: Record<string, unknown>;
  attempts: number;
  max_attempts: number;
  lease_owner: string;
}

export const LEASE_SECONDS = 120;
export const BACKOFF_BASE_SECONDS = 15;
export const BACKOFF_MAX_SECONDS = 3600;

export async function enqueueJob(
  client: pg.PoolClient, tenantId: string, kind: JobKind, payload: Record<string, unknown>, dedupeKey: string,
  opts: { maxAttempts?: number; delaySeconds?: number } = {},
): Promise<boolean> {
  const r = await client.query(
    `INSERT INTO soc_jobs (tenant_id, id, kind, payload, dedupe_key, max_attempts, run_after)
     VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
     ON CONFLICT (tenant_id, kind, dedupe_key) DO NOTHING`,
    [tenantId, randomUUID(), kind, JSON.stringify(payload), dedupeKey.slice(0, 200), opts.maxAttempts ?? 5, opts.delaySeconds ?? 0],
  );
  return r.rowCount === 1;
}

/**
 * Claims up to `limit` due jobs across all workspaces. Each row carries its
 * own tenant_id, and every handler works only inside that tenant.
 */
export async function claimJobs(owner: string, limit: number, leaseSeconds = LEASE_SECONDS): Promise<Job[]> {
  return queryAll<Job>(
    `UPDATE soc_jobs j SET status = 'running', attempts = j.attempts + 1, lease_owner = $1,
            lease_until = now() + make_interval(secs => $3), updated_at = now()
       FROM (SELECT tenant_id, id FROM soc_jobs
              WHERE run_after <= now()
                AND (status = 'queued' OR (status = 'running' AND lease_until < now()))
                AND attempts < max_attempts
              ORDER BY run_after
              LIMIT $2
              FOR UPDATE SKIP LOCKED) due
      WHERE j.tenant_id = due.tenant_id AND j.id = due.id
      RETURNING j.tenant_id, j.id, j.kind, j.payload, j.attempts, j.max_attempts, j.lease_owner`,
    [owner, limit, leaseSeconds],
  );
}

// Every finishing statement is fenced: tenant, id, lease owner AND attempt number must still match.
export async function completeJob(job: Job): Promise<boolean> {
  const r = await query(
    `UPDATE soc_jobs SET status = 'done', lease_owner = NULL, lease_until = NULL, last_error = NULL, finished_at = now(), updated_at = now() WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND attempts = $4 AND status = 'running'`,
    [job.tenant_id, job.id, job.lease_owner, job.attempts],
  );
  return r.rowCount === 1;
}

/** Not a failure: try again later without spending an attempt (e.g. the workspace is paused). */
export async function deferJob(job: Job, seconds: number): Promise<boolean> {
  const r = await query(
    `UPDATE soc_jobs SET status = 'queued', attempts = attempts - 1, lease_owner = NULL, lease_until = NULL,
            run_after = now() + make_interval(secs => $5), updated_at = now() WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND attempts = $4 AND status = 'running'`,
    [job.tenant_id, job.id, job.lease_owner, job.attempts, seconds],
  );
  return r.rowCount === 1;
}

export async function failJob(job: Job, error: string): Promise<"retry" | "dead" | "lost"> {
  const backoff = Math.min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * 2 ** Math.max(0, job.attempts - 1));
  const row = await queryOne<{ status: string }>(
    `UPDATE soc_jobs SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
            last_error = $5, lease_owner = NULL, lease_until = NULL, updated_at = now(),
            run_after = now() + make_interval(secs => $6),
            finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END
      WHERE tenant_id = $1 AND id = $2 AND lease_owner = $3 AND attempts = $4 AND status = 'running' RETURNING status`,
    [job.tenant_id, job.id, job.lease_owner, job.attempts, error.replace(/\s+/g, " ").slice(0, 500), backoff],
  );
  return row ? (row.status === "dead" ? "dead" : "retry") : "lost";
}

/** A job still running after its lease, on its last attempt: the worker died. Dead, not retried forever. */
export async function deadLetterAbandoned(): Promise<number> {
  const r = await query(
    `UPDATE soc_jobs SET status = 'dead', lease_owner = NULL, lease_until = NULL, finished_at = now(), updated_at = now(),
            last_error = 'worker stopped during the final attempt; outcome unknown'
      WHERE status = 'running' AND lease_until < now() AND attempts >= max_attempts`,
  );
  return r.rowCount ?? 0;
}

export interface RuntimeStatus { queued: number; running: number; done: number; dead: number; oldest_queued_seconds: number | null }

export async function runtimeStatus(tenantId: string): Promise<RuntimeStatus> {
  const r = await queryOne<RuntimeStatus>(
    `SELECT count(*) FILTER (WHERE status = 'queued')::int AS queued,
            count(*) FILTER (WHERE status = 'running')::int AS running,
            count(*) FILTER (WHERE status = 'done')::int AS done,
            count(*) FILTER (WHERE status = 'dead')::int AS dead,
            floor(extract(epoch FROM now() - min(created_at) FILTER (WHERE status = 'queued')))::int AS oldest_queued_seconds
       FROM soc_jobs WHERE tenant_id = $1`,
    [tenantId],
  );
  return r!;
}

export async function listJobs(tenantId: string, opts: { status?: string; limit: number }) {
  return queryAll(
    `SELECT id, kind, status, attempts, max_attempts, run_after, last_error, created_at, finished_at
       FROM soc_jobs WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2) ORDER BY created_at DESC LIMIT $3`,
    [tenantId, opts.status ?? null, opts.limit],
  );
}
