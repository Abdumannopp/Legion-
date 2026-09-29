/**
 * Reliable notification delivery (transactional outbox).
 *
 * What was wrong: when an alert arrived, its email was sent with
 * `void sendMail(...)` — fire and forget. If the mail server hiccuped, the
 * alert was stored but nobody was told, and nothing ever tried again. A
 * re-sent Wazuh event was then skipped as a duplicate, so even a retry from
 * the sensor could not recover the lost email.
 *
 * Now: the notification is written to `notification_outbox` in the SAME
 * database transaction as the alert. Either both exist or neither does. A
 * background worker delivers due rows and retries failures with exponential
 * backoff up to a maximum, after which the row is kept as 'dead' for an
 * administrator to see.
 *
 * Duplicates: the unique (tenant, kind, dedupe_key) index means a
 * notification can only be enqueued once. A row is claimed with
 * FOR UPDATE SKIP LOCKED plus a lease, so two workers never send the same row
 * at the same time. One gap is unavoidable without the mail server's help: if
 * the process dies after the mail server accepted the message but before the
 * row is marked sent, it will be sent again — so every retry carries the same
 * Message-ID, letting mail systems recognise the copy.
 *
 * Realtime: the dashboard's "new alert" frame is a job here too
 * (kind 'realtime_alert'), so a Redis outage or a crash right after commit
 * delays the frame instead of silently dropping it for other instances.
 *
 * Leases are fenced. `attempts` is incremented by every claim, so it doubles
 * as a fencing token: a worker only records the outcome if the row is still
 * 'sending' with the attempt number it claimed. Before each attempt the lease
 * is renewed (so a long batch cannot outlive it), and each attempt is capped
 * well below the lease, so a live worker's row is never reclaimed mid-send.
 * A row whose worker died during its FINAL attempt is dead-lettered rather
 * than reclaimed forever — a message that crashes the process cannot loop.
 */
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { config } from "./config.js";
import { query, transaction } from "./db/pool.js";
import { alertEmail, mailEnabled, sendMail, type MailResult } from "./mailer.js";
import { isLocale } from "./i18n.js";
import { publishOrThrow } from "./realtime.js";
import * as store from "./store.js";
import type { Alert, Severity } from "./types.js";

type NewAlert = Parameters<typeof store.insertAlert>[0];
export type Sender = (m: { to: string; subject: string; text: string; html?: string; messageId?: string }) => Promise<MailResult>;
/** Fans a realtime frame out to every instance; throws if it could not. */
export type Publisher = (tenantId: string, payload: unknown) => Promise<void>;
export type JobKind = "alert_email" | "realtime_alert";

const severityRank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
/** How long a claimed row stays reserved for the worker that claimed it. */
const LEASE_SECONDS = 120;
/** One delivery attempt may take at most this long — well inside the lease. */
export const ATTEMPT_TIMEOUT_MS = 60_000;

/** Delay before attempt n+1 after n failures: base·2^(n-1), capped at 1 hour. */
export function backoffSeconds(failures: number, base = config.notifyRetryBaseSeconds): number {
  return Math.min(3600, base * 2 ** Math.max(0, failures - 1));
}

/**
 * Mail server errors can echo the SMTP login. Keep the reason useful for an
 * operator, but never store the configured credentials or a URL's userinfo.
 */
export function sanitizeError(detail: string | undefined): string {
  let s = String(detail ?? "unknown error");
  for (const secret of [config.smtpPassword, config.smtpUser]) {
    if (secret && secret.length >= 3) s = s.split(secret).join("[redacted]");
  }
  for (const secret of [config.redisUrl, redisPassword()]) {
    if (secret && secret.length >= 3) s = s.split(secret).join("[redacted]");
  }
  // user:password@ and the Redis-style :password@ (empty user).
  s = s.replace(/\/\/[^/\s:@]*:[^/\s@]+@/g, "//[redacted]@");
  s = s.replace(/\b(?:Bearer|Basic)\s+\S+/gi, "[redacted]");
  s = s.replace(/\b(pass(?:word)?|pwd|token|secret)\s*[=:]\s*\S+/gi, "$1=[redacted]");
  return s.slice(0, 300);
}

function redisPassword(): string {
  try {
    return config.redisUrl ? decodeURIComponent(new URL(config.redisUrl).password) : "";
  } catch {
    return "";
  }
}

const capWarned = new Map<string, number>();
function capWarn(tenantId: string): void {
  const last = capWarned.get(tenantId) ?? 0;
  if (Date.now() - last < 3_600_000) return;
  if (capWarned.size > 10_000) capWarned.clear();
  capWarned.set(tenantId, Date.now());
  console.warn(`Legion: alert email cap (${config.alertEmailHourlyCap}/hour) reached for tenant ${tenantId}; further alerts this hour are not emailed.`);
}

/** In the caller's transaction: queue the alert email if this alert needs one. */
async function enqueueAlertEmail(client: PoolClient, alert: Alert): Promise<boolean> {
  const threshold = config.alertEmailMinSeverity;
  if (threshold === "off" || !mailEnabled()) return false;
  if (severityRank[alert.severity] < severityRank[threshold]) return false;
  const t = await client.query("SELECT notification_email, notification_locale FROM tenants WHERE id = $1", [alert.tenant_id]);
  const recipient = t.rows[0]?.notification_email as string | undefined;
  if (!recipient) return false;
  // A per-tenant ceiling on alert email. A sensor (or anyone holding its
  // credential) controls alert titles and how many alerts arrive; without a cap
  // it controls how much mail this platform sends. Alerts beyond the cap are
  // stored and shown as usual — only the email is skipped.
  const sent = await client.query(
    "SELECT count(*)::int AS n FROM notification_outbox WHERE tenant_id = $1 AND kind = 'alert_email' AND created_at > now() - interval '1 hour'",
    [alert.tenant_id]
  );
  if (Number(sent.rows[0]?.n ?? 0) >= config.alertEmailHourlyCap) {
    capWarn(alert.tenant_id);
    return false;
  }
  // Rendered now, in the organisation's chosen language, and stored as-is:
  // a retry sends exactly what was queued.
  const locale = isLocale(t.rows[0]?.notification_locale) ? t.rows[0].notification_locale : "en";

  const res = await client.query(
    `INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, max_attempts)
     VALUES ($1, $2, 'alert_email', $3, $4, $5, $6)
     ON CONFLICT (tenant_id, kind, dedupe_key) DO NOTHING`,
    [randomUUID(), alert.tenant_id, alert.id, recipient, JSON.stringify(alertEmail(alert, locale)), config.notifyMaxAttempts]
  );
  return (res.rowCount ?? 0) === 1;
}

/** In the caller's transaction: queue the dashboard frame for this alert. */
async function enqueueRealtime(client: PoolClient, alert: Alert, payload: unknown): Promise<void> {
  // recipient '' — nothing to address; an old worker mid rolling-deploy that
  // mistakes this for an email fails locally ("no recipients") and sends nothing.
  await client.query(
    `INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, max_attempts)
     VALUES ($1, $2, 'realtime_alert', $3, '', $4, $5)
     ON CONFLICT (tenant_id, kind, dedupe_key) DO NOTHING`,
    [randomUUID(), alert.tenant_id, alert.id, JSON.stringify(payload), config.realtimeMaxAttempts]
  );
}

export interface IngestOptions {
  /** Asset the alert was raised on; upserted in the same transaction. */
  asset?: { name: string; ip: string | null; os: string | null } | null;
  /** Builds the realtime frame; when given, it is queued durably. */
  realtime?: (alert: Alert) => unknown;
}

/**
 * Stores the alert and, atomically, everything that must follow from it: the
 * asset upsert, its email and its realtime frame. Either all of it is
 * committed or none of it is, so a caller that got a result may report
 * success, and a caller that got an error must not (the sender retries).
 *
 * Returns null when the alert already existed (a duplicate), in which case
 * nothing is queued — the first copy's jobs are already in the outbox.
 * No network I/O happens here: SMTP and Redis are only touched by the worker.
 */
export async function insertAlertAndNotify(alert: NewAlert, opts: IngestOptions = {}): Promise<Alert | null> {
  const stored = await transaction(async (client) => {
    const inserted = await store.insertAlert(alert, client);
    if (!inserted) return null;
    if (opts.asset?.name) {
      await store.upsertAsset(inserted.tenant_id, opts.asset.name, opts.asset.ip, opts.asset.os, client);
    }
    await enqueueAlertEmail(client, inserted);
    if (opts.realtime) await enqueueRealtime(client, inserted, opts.realtime(inserted));
    return inserted;
  });
  if (stored) kick();
  return stored;
}

interface OutboxRow {
  id: string;
  tenant_id: string;
  kind: JobKind;
  recipient: string;
  payload: unknown;
  attempts: number;
  max_attempts: number;
}

/**
 * A row still 'sending' after its lease ran out, on its last allowed attempt:
 * the worker died mid-attempt (crash, OOM, deploy). Reclaiming it would exceed
 * max_attempts — and if the message itself kills the process, loop forever.
 */
async function deadLetterAbandoned(kind: JobKind | null): Promise<number> {
  const res = await query<{ id: string }>(
    `UPDATE notification_outbox
        SET status = 'dead', locked_until = NULL,
            last_error = 'worker stopped during the final attempt; outcome unknown'
      WHERE status = 'sending' AND locked_until < now() AND attempts >= max_attempts
        AND ($1::text IS NULL OR kind = $1)
      RETURNING id`,
    [kind]
  );
  for (const r of res.rows) console.error(`Legion: notification ${r.id} dead-lettered (worker stopped during final attempt)`);
  return res.rowCount ?? 0;
}

/** Claims due rows: pending ones whose time has come, and 'sending' ones
 *  whose worker died (lease expired) and that still have attempts left. */
async function claim(limit: number, kind: JobKind | null): Promise<OutboxRow[]> {
  const res = await query<OutboxRow>(
    `UPDATE notification_outbox SET status = 'sending', attempts = attempts + 1,
            locked_until = now() + make_interval(secs => $2)
      WHERE id IN (
        SELECT id FROM notification_outbox
         WHERE ((status = 'pending' AND next_attempt_at <= now())
            OR (status = 'sending' AND locked_until < now() AND attempts < max_attempts))
           AND ($3::text IS NULL OR kind = $3)
         ORDER BY next_attempt_at
         LIMIT $1
         FOR UPDATE SKIP LOCKED)
      RETURNING id, tenant_id, kind, recipient, payload, attempts, max_attempts`,
    [limit, LEASE_SECONDS, kind]
  );
  return res.rows;
}

/** Re-takes the lease right before an attempt. False: another worker owns it. */
async function renewLease(row: OutboxRow): Promise<boolean> {
  const res = await query(
    `UPDATE notification_outbox SET locked_until = now() + make_interval(secs => $3)
      WHERE id = $1 AND status = 'sending' AND attempts = $2`,
    [row.id, row.attempts, LEASE_SECONDS]
  );
  return (res.rowCount ?? 0) === 1;
}

/** Records an outcome only if this worker still holds the row (fencing). */
async function complete(row: OutboxRow, sql: string, params: unknown[]): Promise<boolean> {
  const res = await query(`${sql} WHERE id = $1 AND status = 'sending' AND attempts = $2`, [row.id, row.attempts, ...params]);
  if ((res.rowCount ?? 0) === 1) return true;
  console.warn(`Legion: notification ${row.id} attempt ${row.attempts} finished after losing its lease; outcome not recorded`);
  return false;
}

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`attempt timed out after ${Math.round(ms / 1000)}s`)), ms);
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

type Outcome = { ok: true } | { ok: false; detail: string };

async function attempt(row: OutboxRow, send: Sender, publish: Publisher): Promise<Outcome> {
  if (row.kind === "realtime_alert") {
    await publish(row.tenant_id, row.payload);
    return { ok: true };
  }
  const payload = row.payload as { subject: string; text: string; html?: string };
  const result = await send({ to: row.recipient, ...payload, messageId: `<${row.id}@legion.notification>` });
  if (result.sent) return { ok: true };
  return { ok: false, detail: result.reason === "not_configured" ? "SMTP is not configured" : String(result.detail ?? "send failed") };
}

export interface DeliveryReport { sent: number; retrying: number; dead: number }

export interface DeliverOptions {
  send?: Sender;
  publish?: Publisher;
  limit?: number;
  /** Only this kind of job; all kinds when omitted. */
  kind?: JobKind;
  /** Per-attempt cap (tests shorten it). */
  attemptTimeoutMs?: number;
}

/** Delivers what is due now. Safe to run from several instances at once. */
export async function deliverDue(opts: DeliverOptions = {}): Promise<DeliveryReport> {
  const send = opts.send ?? sendMail;
  const publish = opts.publish ?? publishOrThrow;
  const kind = opts.kind ?? null;
  const report: DeliveryReport = { sent: 0, retrying: 0, dead: 0 };
  report.dead += await deadLetterAbandoned(kind);

  for (const row of await claim(opts.limit ?? 50, kind)) {
    if (!(await renewLease(row))) continue;

    let outcome: Outcome;
    try {
      outcome = await withTimeout(attempt(row, send, publish), opts.attemptTimeoutMs ?? ATTEMPT_TIMEOUT_MS);
    } catch (error) {
      outcome = { ok: false, detail: error instanceof Error ? error.message : String(error) };
    }

    if (outcome.ok) {
      if (await complete(row, "UPDATE notification_outbox SET status = 'sent', sent_at = now(), locked_until = NULL, last_error = NULL", [])) {
        report.sent++;
      }
      continue;
    }

    const reason = sanitizeError(outcome.detail);
    if (row.attempts >= row.max_attempts) {
      if (await complete(row, "UPDATE notification_outbox SET status = 'dead', locked_until = NULL, last_error = $3", [reason])) {
        console.error(`Legion: notification ${row.id} (${row.kind}) gave up after ${row.attempts} attempts: ${reason}`);
        report.dead++;
      }
    } else {
      const base = row.kind === "realtime_alert" ? config.realtimeRetryBaseSeconds : config.notifyRetryBaseSeconds;
      if (await complete(
        row,
        `UPDATE notification_outbox SET status = 'pending', locked_until = NULL, last_error = $3,
                next_attempt_at = now() + make_interval(secs => $4)`,
        [reason, backoffSeconds(row.attempts, base)]
      )) {
        report.retrying++;
      }
    }
  }
  return report;
}

export interface QueueMetrics {
  /** Waiting for their first or next attempt. */
  pending: number;
  /** Of those, how many have already failed at least once. */
  retrying: number;
  /** Claimed by a worker right now. */
  in_flight: number;
  /** Failed permanently (dead letter); needs an operator. */
  dead: number;
  /** Age of the oldest job not yet delivered (pending or in flight), or null. */
  oldest_pending_age_seconds: number | null;
}

/** Queue health, for one organisation or (no tenantId) the whole platform. */
export async function queueMetrics(tenantId?: string): Promise<QueueMetrics & { by_kind: Record<string, QueueMetrics> }> {
  const res = await query<{ kind: string; pending: string; retrying: string; in_flight: string; dead: string; oldest: string | null }>(
    `SELECT kind,
            count(*) FILTER (WHERE status = 'pending')                  AS pending,
            count(*) FILTER (WHERE status = 'pending' AND attempts > 0) AS retrying,
            count(*) FILTER (WHERE status = 'sending')                  AS in_flight,
            count(*) FILTER (WHERE status = 'dead')                     AS dead,
            floor(extract(epoch FROM now() - min(created_at) FILTER (WHERE status IN ('pending', 'sending')))) AS oldest
       FROM notification_outbox
      WHERE status IN ('pending', 'sending', 'dead')
        AND ($1::uuid IS NULL OR tenant_id = $1)
      GROUP BY kind`,
    [tenantId ?? null]
  );
  const empty = (): QueueMetrics => ({ pending: 0, retrying: 0, in_flight: 0, dead: 0, oldest_pending_age_seconds: null });
  const total = empty();
  const by_kind: Record<string, QueueMetrics> = { alert_email: empty(), realtime_alert: empty() };
  for (const r of res.rows) {
    const m: QueueMetrics = {
      pending: Number(r.pending), retrying: Number(r.retrying), in_flight: Number(r.in_flight), dead: Number(r.dead),
      oldest_pending_age_seconds: r.oldest === null ? null : Number(r.oldest),
    };
    by_kind[r.kind] = m;
    total.pending += m.pending; total.retrying += m.retrying; total.in_flight += m.in_flight; total.dead += m.dead;
    if (m.oldest_pending_age_seconds !== null) {
      total.oldest_pending_age_seconds = Math.max(total.oldest_pending_age_seconds ?? 0, m.oldest_pending_age_seconds);
    }
  }
  return { ...total, by_kind };
}

/** Delivered realtime frames have no value once pushed; keep a day for debugging. */
export async function pruneDeliveredRealtime(): Promise<number> {
  const res = await query(
    "DELETE FROM notification_outbox WHERE kind = 'realtime_alert' AND status = 'sent' AND sent_at < now() - interval '1 day'"
  );
  return res.rowCount ?? 0;
}

/** An administrator's view of their own organisation's deliveries. */
export async function listDeliveries(tenantId: string, limit = 100) {
  const res = await query(
    `SELECT id, kind, dedupe_key AS subject_id, recipient, status, attempts, max_attempts,
            next_attempt_at, last_error, created_at, sent_at
       FROM notification_outbox WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [tenantId, Math.min(Math.max(limit, 1), 500)]
  );
  return res.rows;
}

// --- Background worker -------------------------------------------------------

let timer: NodeJS.Timeout | null = null;
let running = false;

let lastPrune = 0;
/** Set when a kick arrives mid-tick, so fresh work runs right after, not a poll later. */
let again = false;

async function tick(): Promise<void> {
  if (running) {
    again = true;
    return;
  }
  running = true;
  try {
    // Separate passes, run side by side: a slow mail server must not hold
    // back the dashboard frames, nor a Redis outage the emails.
    const results = await Promise.allSettled([deliverDue({ kind: "realtime_alert" }), deliverDue({ kind: "alert_email" })]);
    for (const r of results) {
      if (r.status === "rejected") {
        console.error("Legion: notification worker failed:", r.reason instanceof Error ? r.reason.message : "unknown error");
      }
    }
    if (Date.now() - lastPrune > 3_600_000) {
      lastPrune = Date.now();
      await pruneDeliveredRealtime();
    }
  } catch (error) {
    console.error("Legion: notification worker failed:", error instanceof Error ? error.message : "unknown error");
  } finally {
    running = false;
    if (again && timer) {
      again = false;
      void tick();
    }
  }
}

/** Try right away after enqueueing, so the normal case has no polling delay. */
export function kick(): void {
  if (timer) void tick();
}

export function startOutboxWorker(): void {
  if (timer) return;
  timer = setInterval(() => void tick(), config.notifyPollSeconds * 1000);
  timer.unref();
  void tick(); // pick up anything left over from before a restart
}

export function stopOutboxWorker(): void {
  if (timer) clearInterval(timer);
  timer = null;
}
