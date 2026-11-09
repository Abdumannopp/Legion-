/**
 * Configured integrations (integration_connections) and the worker that polls
 * the pull ones.
 *
 * The worker runs on every instance. A connection is claimed with a lease
 * (FOR UPDATE SKIP LOCKED), so one instance polls it at a time; the lease
 * owner is the fencing token for writing the result back, so an instance that
 * stalled past its lease cannot overwrite the cursor of the one that took
 * over. Ingestion is idempotent (ingest.ts), so a poll that is repeated after
 * a crash re-delivers findings that are dropped as duplicates.
 */
import { randomUUID } from "node:crypto";
import { hostname } from "node:os";
import { config } from "../config.js";
import { query, queryAll, queryOne } from "../db/pool.js";
import * as box from "../secret-box.js";
import type { Alert } from "../types.js";
import { ingestFindings } from "./ingest.js";
import { scrubError } from "./scrub.js";
import { withTenant } from "../db/rls.js";
import { connectedPushAdapter, outboundAdapter, pullAdapter, pullKinds } from "./registry.js";

export interface ConnectionView {
  id: string;
  kind: string;
  name: string;
  status: "active" | "paused" | "error" | "disabled";
  config: Record<string, unknown>;
  has_secrets: boolean;
  poll_seconds: number;
  next_poll_at: string;
  last_success_at: string | null;
  last_error: string | null;
  failures: number;
  created_at: string;
}

export class ConnectionError extends Error {
  constructor(readonly code: "unknown_kind" | "invalid_config" | "missing_secret" | "not_found", message: string) { super(message); }
}

const iso = (v: unknown) => (v ? new Date(v as string).toISOString() : null);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const view = (r: any): ConnectionView => ({
  id: r.id, kind: r.kind, name: r.name, status: r.status, config: r.config ?? {}, has_secrets: Boolean(r.secrets_enc),
  poll_seconds: r.poll_seconds, next_poll_at: iso(r.next_poll_at)!, last_success_at: iso(r.last_success_at),
  last_error: r.last_error ?? null, failures: r.failures, created_at: iso(r.created_at)!,
});
const sealContext = (id: string, tenantId: string) => `integration:${tenantId}:${id}`;

export async function create(
  tenantId: string,
  input: { kind: string; name: string; config: unknown; secrets: Record<string, string>; pollSeconds?: number },
  createdBy: string,
): Promise<ConnectionView> {
  const adapter = pullAdapter(input.kind) ?? outboundAdapter(input.kind) ?? connectedPushAdapter(input.kind);
  // Outbound and push connections are never polled.
  const outbound = !pullAdapter(input.kind);
  if (!adapter || adapter.manifest.status !== "available") throw new ConnectionError("unknown_kind", "That integration is not available.");
  const parsed = adapter.configSchema.safeParse(input.config ?? {});
  if (!parsed.success) throw new ConnectionError("invalid_config", `${parsed.error.issues[0]?.path.join(".") || "config"}: ${parsed.error.issues[0]?.message}`);
  const missing = adapter.secretFields.filter((f) => typeof input.secrets?.[f] !== "string" || !input.secrets[f]);
  if (missing.length) throw new ConnectionError("missing_secret", `Missing: ${missing.join(", ")}`);
  const secrets = Object.fromEntries(adapter.secretFields.map((f) => [f, input.secrets[f]!]));
  const secretProblem = outboundAdapter(input.kind)?.validateSecrets?.(secrets);
  if (secretProblem) throw new ConnectionError("invalid_config", secretProblem);
  const id = randomUUID();
  const row = await queryOne(
    // An outbound connector is never polled: its next_poll_at is parked far in the future.
    `INSERT INTO integration_connections (id, tenant_id, kind, name, config, secrets_enc, poll_seconds, created_by, next_poll_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $9 THEN '9999-01-01'::timestamptz ELSE now() END) RETURNING *`,
    [id, tenantId, input.kind, input.name, JSON.stringify(parsed.data), adapter.secretFields.length ? box.seal(JSON.stringify(secrets), "integration-secret", sealContext(id, tenantId)) : null,
      input.pollSeconds ?? 300, createdBy, outbound],
  );
  return view(row);
}

export async function list(tenantId: string): Promise<ConnectionView[]> {
  return (await queryAll("SELECT * FROM integration_connections WHERE tenant_id = $1 AND status <> 'disabled' ORDER BY created_at", [tenantId])).map(view);
}

/** Pause, resume, or remove (disable and forget its secrets). Tenant-scoped. */
export async function setStatus(tenantId: string, id: string, status: "active" | "paused" | "disabled"): Promise<ConnectionView> {
  const row = await queryOne(
    `UPDATE integration_connections
        SET status = $3, updated_at = now(), failures = CASE WHEN $3 = 'active' THEN 0 ELSE failures END,
            next_poll_at = CASE WHEN $3 = 'active' THEN now() ELSE next_poll_at END,
            secrets_enc = CASE WHEN $3 = 'disabled' THEN NULL ELSE secrets_enc END,
            cursor = CASE WHEN $3 = 'disabled' THEN NULL ELSE cursor END
      WHERE id = $1 AND tenant_id = $2 AND status <> 'disabled' RETURNING *`,
    [id, tenantId, status],
  );
  if (!row) throw new ConnectionError("not_found", "Integration not found.");
  return view(row);
}

/** The webhook secret and workspace of an active GitHub connection, or null. */
export async function githubSecret(id: string): Promise<{ id: string; tenantId: string; secret: string } | null> {
  // Before the signature is checked the workspace is unknown: the bounded owner function (migration 0014) returns this one row.
  const row = await queryOne<{ id: string; tenant_id: string; secrets_enc: string | null }>("SELECT * FROM legion_github_connection($1)", [id]);
  if (!row?.secrets_enc) return null;
  const opened = box.open(row.secrets_enc, "integration-secret", sealContext(row.id, row.tenant_id));
  if (opened === null) return null;
  try { const secret = (JSON.parse(opened) as { webhook_secret?: unknown }).webhook_secret; return typeof secret === "string" && secret ? { id: row.id, tenantId: row.tenant_id, secret } : null; } catch { return null; }
}

/** Health for push connections: the last time a verified delivery arrived. */
export async function touchSuccess(id: string, tenantId: string): Promise<void> {
  await query("UPDATE integration_connections SET last_success_at = now(), last_error = NULL, failures = 0, updated_at = now() WHERE id = $1 AND tenant_id = $2", [id, tenantId]).catch(() => { /* health is best effort */ });
}

// --- The poll worker ---------------------------------------------------------

export const INSTANCE = config.instanceId || `${hostname()}:${process.pid}`;
const FAILURES_BEFORE_ERROR = 10;

export interface PollReport { claimed: number; succeeded: number; failed: number; ingested: number; duplicates: number }

/** Claims due connections and polls them. Safe on any number of instances. */
export async function runDuePolls(opts: { limit?: number; concurrency?: number; leaseSeconds?: number; timeoutMs?: number; realtime?: (a: Alert) => unknown; owner?: string } = {}): Promise<PollReport> {
  const owner = opts.owner ?? INSTANCE;
  // Audit A-4: connections are polled in parallel (they are mostly waiting for the vendor), a few at a time per
  // instance. The batch is two rounds of the concurrency, and the lease covers those rounds at the worst case
  // (every poll hitting its timeout), so a connection is never taken over while its own instance still works on it.
  const concurrency = Math.max(1, Math.min(opts.concurrency ?? config.integrationPollConcurrency, 50));
  const limit = Math.max(1, Math.min(opts.limit ?? concurrency * 2, 100));
  const timeoutMs = opts.timeoutMs ?? 120_000;
  const leaseSeconds = opts.leaseSeconds ?? Math.ceil(limit / concurrency) * Math.ceil(timeoutMs / 1000) + 60;
  const report: PollReport = { claimed: 0, succeeded: 0, failed: 0, ingested: 0, duplicates: 0 };
  // Due connections of every workspace, through the bounded owner function (migration 0014).
  const claimed = await queryAll(
    "SELECT * FROM legion_connections_claim($1, $2, $3, $4, $5::text[])",
    [limit, leaseSeconds, owner, config.region, pullKinds()],
  );

  report.claimed = claimed.length;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pollOne = (c: any) => withTenant(c.tenant_id, async () => {
    const adapter = pullAdapter(c.kind);
    let secrets: Record<string, string> | null = null;
    try {
      if (!adapter) throw new Error("integration no longer available");
      secrets = c.secrets_enc ? JSON.parse(box.open(c.secrets_enc, "integration-secret", sealContext(c.id, c.tenant_id)) ?? "null") : {};
      if (secrets === null) throw new Error("stored credentials cannot be decrypted with the current keyring");
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let result: Awaited<ReturnType<typeof adapter.poll>>;
      try {
        result = await adapter.poll({ id: c.id, tenantId: c.tenant_id, config: c.config ?? {}, secrets }, c.cursor ?? null, controller.signal);
      } finally {
        clearTimeout(timer);
      }
      const ingest = await ingestFindings(c.tenant_id, c.kind, result.findings, { realtime: opts.realtime });
      report.ingested += ingest.ingested.length;
      report.duplicates += ingest.duplicates.length;
      await query(
        `UPDATE integration_connections
            SET cursor = $3, next_poll_at = now() + make_interval(secs => poll_seconds), failures = 0,
                last_success_at = now(), last_error = NULL, lease_until = NULL, lease_owner = NULL, updated_at = now()
          WHERE id = $1 AND lease_owner = $2`,
        [c.id, owner, JSON.stringify(result.cursor ?? null)],
      );
      report.succeeded++;
    } catch (error) {
      report.failed++;
      // The adapter's message, scrubbed of every form of the stored credentials (audit A-8) and bounded.
      const message = scrubError(error instanceof Error ? error.message : "poll failed", secrets ?? {});
      await query(
        `UPDATE integration_connections
            SET failures = failures + 1, last_error = $3, lease_until = NULL, lease_owner = NULL, updated_at = now(),
                next_poll_at = now() + make_interval(secs => LEAST(3600, poll_seconds * power(2, LEAST(failures, 6))::int)),
                status = CASE WHEN failures + 1 >= $4 THEN 'error' ELSE status END
          WHERE id = $1 AND lease_owner = $2`,
        [c.id, owner, message, FAILURES_BEFORE_ERROR],
      ).catch(() => { /* the lease lapses; the next claim retries */ });
    }
  });
  // A small pool: `concurrency` polls in flight at once; each worker takes the next claimed connection.
  const queue = [...claimed];
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    for (let c = queue.shift(); c; c = queue.shift()) await pollOne(c).catch(() => { /* pollOne records its own failures */ });
  }));
  return report;
}

let timer: NodeJS.Timeout | null = null;
let busy = false;
export function startIntegrationWorker(intervalMs: number, realtime?: (a: Alert) => unknown): void {
  stopIntegrationWorker();
  timer = setInterval(() => {
    if (busy) return;
    busy = true;
    // A full batch means more may be due: keep going (at most 20 rounds per tick) instead of waiting for the next tick.
    (async () => {
      const batch = Math.min(config.integrationPollConcurrency * 2, 100);
      for (let round = 0; round < 20; round++) {
        const report = await runDuePolls({ realtime });
        if (report.claimed < batch) break;
      }
    })()
      .catch((error) => console.error("Legion: integration poll failed:", error instanceof Error ? error.message : "unknown error"))
      .finally(() => { busy = false; });
  }, intervalMs);
  timer.unref();
}
export function stopIntegrationWorker(): void {
  if (timer) clearInterval(timer);
  timer = null;
}
