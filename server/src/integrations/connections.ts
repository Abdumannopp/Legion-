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
import { pullAdapter } from "./registry.js";

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
  const adapter = pullAdapter(input.kind);
  if (!adapter || adapter.manifest.status !== "available") throw new ConnectionError("unknown_kind", "That integration is not available.");
  const parsed = adapter.configSchema.safeParse(input.config ?? {});
  if (!parsed.success) throw new ConnectionError("invalid_config", `${parsed.error.issues[0]?.path.join(".") || "config"}: ${parsed.error.issues[0]?.message}`);
  const missing = adapter.secretFields.filter((f) => typeof input.secrets?.[f] !== "string" || !input.secrets[f]);
  if (missing.length) throw new ConnectionError("missing_secret", `Missing: ${missing.join(", ")}`);
  const secrets = Object.fromEntries(adapter.secretFields.map((f) => [f, input.secrets[f]!]));
  const id = randomUUID();
  const row = await queryOne(
    `INSERT INTO integration_connections (id, tenant_id, kind, name, config, secrets_enc, poll_seconds, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
    [id, tenantId, input.kind, input.name, JSON.stringify(parsed.data), adapter.secretFields.length ? box.seal(JSON.stringify(secrets), "integration-secret", sealContext(id, tenantId)) : null,
      input.pollSeconds ?? 300, createdBy],
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

// --- The poll worker ---------------------------------------------------------

export const INSTANCE = config.instanceId || `${hostname()}:${process.pid}`;
const FAILURES_BEFORE_ERROR = 10;

export interface PollReport { claimed: number; succeeded: number; failed: number; ingested: number; duplicates: number }

/** Claims due connections and polls them. Safe on any number of instances. */
export async function runDuePolls(opts: { limit?: number; leaseSeconds?: number; timeoutMs?: number; realtime?: (a: Alert) => unknown; owner?: string } = {}): Promise<PollReport> {
  const owner = opts.owner ?? INSTANCE;
  const report: PollReport = { claimed: 0, succeeded: 0, failed: 0, ingested: 0, duplicates: 0 };
  const claimed = await queryAll(
    `UPDATE integration_connections SET lease_until = now() + make_interval(secs => $2), lease_owner = $3
      WHERE id IN (
        SELECT c.id FROM integration_connections c JOIN tenants t ON t.id = c.tenant_id
         WHERE c.status = 'active' AND c.next_poll_at <= now() AND (c.lease_until IS NULL OR c.lease_until < now())
           -- Data residency: only workspaces this deployment serves.
           AND COALESCE(t.region, $4) = $4
         ORDER BY c.next_poll_at LIMIT $1 FOR UPDATE OF c SKIP LOCKED)
      RETURNING *`,
    [opts.limit ?? 10, opts.leaseSeconds ?? 300, owner, config.region],
  );
  report.claimed = claimed.length;
  for (const c of claimed) {
    const adapter = pullAdapter(c.kind);
    try {
      if (!adapter) throw new Error("integration no longer available");
      const secrets = c.secrets_enc ? JSON.parse(box.open(c.secrets_enc, "integration-secret", sealContext(c.id, c.tenant_id)) ?? "null") : {};
      if (secrets === null) throw new Error("stored credentials cannot be decrypted with the current keyring");
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 120_000);
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
      // Fixed prefix + the adapter's message, bounded: never a secret (adapters
      // do not put credentials in errors; the length cap limits what could slip).
      const message = (error instanceof Error ? error.message : "poll failed").replace(/\s+/g, " ").slice(0, 300);
      await query(
        `UPDATE integration_connections
            SET failures = failures + 1, last_error = $3, lease_until = NULL, lease_owner = NULL, updated_at = now(),
                next_poll_at = now() + make_interval(secs => LEAST(3600, poll_seconds * power(2, LEAST(failures, 6))::int)),
                status = CASE WHEN failures + 1 >= $4 THEN 'error' ELSE status END
          WHERE id = $1 AND lease_owner = $2`,
        [c.id, owner, message, FAILURES_BEFORE_ERROR],
      ).catch(() => { /* the lease lapses; the next claim retries */ });
    }
  }
  return report;
}

let timer: NodeJS.Timeout | null = null;
let busy = false;
export function startIntegrationWorker(intervalMs: number, realtime?: (a: Alert) => unknown): void {
  stopIntegrationWorker();
  timer = setInterval(() => {
    if (busy) return;
    busy = true;
    runDuePolls({ realtime })
      .catch((error) => console.error("Legion: integration poll failed:", error instanceof Error ? error.message : "unknown error"))
      .finally(() => { busy = false; });
  }, intervalMs);
  timer.unref();
}
export function stopIntegrationWorker(): void {
  if (timer) clearInterval(timer);
  timer = null;
}
