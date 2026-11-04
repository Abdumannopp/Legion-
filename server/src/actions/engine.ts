/**
 * Action Engine v0 — the one door every action goes through.
 *
 *   propose → validate (closed catalog, strict input) → policy (enforced on
 *   this path) → DENY: denied | RECORD_ONLY: recorded | REQUIRE_APPROVAL:
 *   approval request, awaiting | ALLOW: queued → simulated.
 *
 * Guarantees:
 *  - Idempotent: the same idempotency key returns the same request; the same
 *    key with a different action is refused.
 *  - Who acts (ActorRef) and where the request came from (origin) are set by
 *    server code, never by the request body or a model.
 *  - Approval is consumed atomically with the transition that uses it.
 *  - A queued action runs once: the move to `running` is a compare-and-set.
 *  - v0 only simulates. `live` is refused here, by the policy engine and by
 *    the database (CHECK), and there is no live executor to call.
 *  - The workspace emergency stop refuses new actions and holds queued ones.
 */
import { randomUUID } from "node:crypto";
import type pg from "pg";
import { queryAll, queryOne, transaction } from "../db/pool.js";
import { cancelApproval, consumeApproval, createApproval, getApproval, type Approval } from "../approvals/engine.js";
import { canonicalJson, digestOf } from "../policy/canonical.js";
import { catalogEntry } from "../policy/catalog.js";
import { evaluatePolicy, type PolicyOutcome } from "../policy/evaluate.js";
import { getActivePolicy, recordDecision } from "../policy/store.js";
import type { ActorRef, Origin } from "../policy/types.js";
import { simulate } from "./simulate.js";
import { enqueueJob } from "../runtime/queue.js";

export type ActionStatus = "denied" | "recorded" | "awaiting_approval" | "rejected" | "expired" | "cancelled" | "queued" | "running" | "simulated" | "failed";

export interface ActionRequest {
  id: string; tenant_id: string; idempotency_key: string; action_id: string; risk_class: string;
  input: Record<string, unknown>; action_digest: string; target: string | null; reason: string | null;
  actor: ActorRef; origin: Origin; execution_mode: "shadow" | "simulation"; status: ActionStatus;
  policy_decision: string; policy_decision_id: string; approval_id: string | null;
  result: Record<string, unknown> | null; error: string | null; attempts: number; created_at: string; updated_at: string;
}

const COLUMNS = `tenant_id, id, idempotency_key, action_id, risk_class, input, action_digest, target, reason, actor, origin, execution_mode,
  status, policy_decision, policy_decision_id, approval_id, result, error, attempts, created_at, updated_at`;
type Row = Omit<ActionRequest, "created_at" | "updated_at"> & { created_at: Date; updated_at: Date };
const toAction = (r: Row): ActionRequest => ({ ...r, created_at: r.created_at.toISOString(), updated_at: r.updated_at.toISOString() });

export class ActionError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) { super(message); }
}

export interface Proposal {
  action_id: string;
  input: unknown;
  actor: ActorRef;
  origin: Origin;
  mode: string;
  idempotency_key: string;
  reason?: string;
}

const IDEMPOTENCY = /^[A-Za-z0-9_.:-]{8,100}$/;

/** What is being asked, exactly: the thing approvals are bound to. */
export function actionDigest(tenantId: string, actionId: string, input: Record<string, unknown>, mode: string): string {
  return digestOf({ tenant_id: tenantId, action_id: actionId, input, mode });
}

async function event(client: pg.PoolClient, tenantId: string, id: string, from: ActionStatus | null, to: ActionStatus, actor: ActorRef, note?: string) {
  await client.query(
    "INSERT INTO action_events (tenant_id, action_id, from_status, to_status, actor, note) VALUES ($1, $2, $3, $4, $5, $6)",
    [tenantId, id, from, to, JSON.stringify(actor), note?.slice(0, 500) ?? null],
  );
}

export async function isPaused(tenantId: string, client?: pg.PoolClient): Promise<boolean> {
  const sql = "SELECT actions_paused FROM soc_controls WHERE tenant_id = $1";
  const row = client ? (await client.query<{ actions_paused: boolean }>(sql, [tenantId])).rows[0] : await queryOne<{ actions_paused: boolean }>(sql, [tenantId]);
  return row?.actions_paused ?? false;
}

export async function setPaused(tenantId: string, paused: boolean, userId: string, reason?: string): Promise<void> {
  await queryOne(
    `INSERT INTO soc_controls (tenant_id, actions_paused, reason, changed_by) VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant_id) DO UPDATE SET actions_paused = EXCLUDED.actions_paused, reason = EXCLUDED.reason, changed_by = EXCLUDED.changed_by, changed_at = now()`,
    [tenantId, paused, reason?.slice(0, 500) ?? null, userId],
  );
}

/**
 * Accepts (or refuses) a proposal. Returns the stored request and whether it
 * was a replay of an earlier proposal with the same idempotency key.
 * An ALLOWed simulation is queued here; call `runQueued` to simulate it.
 */
export async function proposeAction(tenantId: string, p: Proposal): Promise<{ action: ActionRequest; replayed: boolean }> {
  const entry = catalogEntry(p.action_id);
  if (!entry) throw new ActionError(422, "unknown_action", "Unknown action");
  if (p.mode !== "shadow" && p.mode !== "simulation") throw new ActionError(422, "mode_not_available", "Only shadow and simulation modes are available");
  if (!IDEMPOTENCY.test(p.idempotency_key)) throw new ActionError(422, "bad_idempotency_key", "idempotency_key: 8–100 letters, digits, . _ : -");
  const parsed = entry.input.safeParse(p.input);
  if (!parsed.success) {
    const issue = parsed.error.issues[0]!;
    throw new ActionError(422, "invalid_input", `input${issue.path.length ? "." + issue.path.join(".") : ""}: ${issue.message}`);
  }
  const input = parsed.data;
  if (Buffer.byteLength(canonicalJson(input)) > 8192) throw new ActionError(422, "invalid_input", "input is too large");
  const digest = actionDigest(tenantId, p.action_id, input, p.mode);

  // Replay first: same key, same action → same answer, no second evaluation.
  const existing = await queryOne<Row>(`SELECT ${COLUMNS} FROM action_requests WHERE tenant_id = $1 AND idempotency_key = $2`, [tenantId, p.idempotency_key]);
  if (existing) {
    if (existing.action_digest !== digest) throw new ActionError(409, "idempotency_conflict", "This idempotency key was already used for a different action");
    return { action: toAction(existing), replayed: true };
  }
  if (await isPaused(tenantId)) throw new ActionError(423, "paused", "Actions are paused in this workspace");

  const active = await getActivePolicy(tenantId);
  const started = process.hrtime.bigint();
  const outcome: PolicyOutcome = evaluatePolicy({ action_id: p.action_id, actor: p.actor, origin: p.origin, mode: p.mode }, active?.document ?? null);
  const latency = Number((process.hrtime.bigint() - started) / 1000n);
  const target = entry.targetOf(input);

  // Shadow: evaluate and record, nothing else — not even an approval request.
  const status: ActionStatus =
    outcome.decision === "DENY" ? "denied"
    : p.mode === "shadow" || outcome.decision === "RECORD_ONLY" ? "recorded"
    : outcome.decision === "REQUIRE_APPROVAL" ? "awaiting_approval"
    : "queued";

  try {
    const action = await transaction(async (client) => {
      const id = randomUUID();
      const decisionId = await recordDecision(tenantId, outcome, {
        enforcement: "enforced", call_site: "action_engine", actor: p.actor, origin: p.origin, mode: p.mode as "shadow" | "simulation",
        target, input_digest: digestOf(input), legacy_outcome: null, latency_us: latency,
        policy: active ? { version: active.version, hash: active.hash } : null,
      }, client);
      let approval: Approval | null = null;
      if (status === "awaiting_approval") {
        approval = await createApproval(client, tenantId, {
          subject_id: id, action_id: p.action_id, risk_class: entry.class === "R0" ? "R1" : entry.class, action_digest: digest,
          summary: `${entry.summary}: ${target ?? p.action_id}`, requested_by: p.actor,
        });
      }
      const row = (await client.query<Row>(
        `INSERT INTO action_requests (tenant_id, id, idempotency_key, action_id, risk_class, input, action_digest, target, reason, actor, origin,
           execution_mode, status, policy_decision, policy_decision_id, approval_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING ${COLUMNS}`,
        [tenantId, id, p.idempotency_key, p.action_id, entry.class, canonicalJson(input), digest, target, p.reason?.slice(0, 500) ?? null,
          JSON.stringify(p.actor), p.origin, p.mode, status, outcome.decision, decisionId, approval?.id ?? null],
      )).rows[0]!;
      await event(client, tenantId, id, null, status, p.actor, outcome.reason_codes.join(","));
      // Durable: if nothing runs it inline (crash after commit), the runtime will.
      if (status === "queued") await enqueueJob(client, tenantId, "action.run", { action_request_id: id }, `action:${id}`);
      return toAction(row);
    });
    return { action, replayed: false };
  } catch (error) {
    // Two identical proposals racing: the loser returns the winner's request.
    if ((error as { code?: string }).code === "23505") {
      const winner = await queryOne<Row>(`SELECT ${COLUMNS} FROM action_requests WHERE tenant_id = $1 AND idempotency_key = $2`, [tenantId, p.idempotency_key]);
      if (winner && winner.action_digest === digest) return { action: toAction(winner), replayed: true };
      if (winner) throw new ActionError(409, "idempotency_conflict", "This idempotency key was already used for a different action");
    }
    throw error;
  }
}

/**
 * Brings an action up to date with its approval: approved → consumed and
 * queued (in one transaction); rejected/expired/cancelled → the same here.
 * Safe to call any number of times, from any number of places at once.
 */
export async function syncWithApproval(tenantId: string, actionId: string, by: ActorRef): Promise<ActionRequest | null> {
  return transaction(async (client) => {
    const row = (await client.query<Row>(`SELECT ${COLUMNS} FROM action_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [tenantId, actionId])).rows[0];
    if (!row) return null;
    if (row.status !== "awaiting_approval" || !row.approval_id) return toAction(row);
    const approval = (await client.query<{ status: string; expires_at: Date }>(
      "SELECT status, expires_at FROM approval_requests WHERE tenant_id = $1 AND id = $2", [tenantId, row.approval_id],
    )).rows[0];
    let next: ActionStatus | null = null;
    if (approval?.status === "approved") {
      if (await isPaused(tenantId, client)) return toAction(row); // stays approved, picked up after resume
      next = (await consumeApproval(client, tenantId, row.approval_id, row.action_digest)) ? "queued" : "expired";
    } else if (approval?.status === "rejected") next = "rejected";
    else if (approval?.status === "expired" || (approval?.status === "pending" && approval.expires_at <= new Date())) next = "expired";
    else if (approval?.status === "cancelled") next = "cancelled";
    if (!next) return toAction(row);
    const updated = (await client.query<Row>(
      `UPDATE action_requests SET status = $3, updated_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING ${COLUMNS}`, [tenantId, actionId, next],
    )).rows[0]!;
    await event(client, tenantId, actionId, "awaiting_approval", next, by, `approval ${approval?.status ?? "missing"}`);
    if (next === "queued") await enqueueJob(client, tenantId, "action.run", { action_request_id: actionId }, `action:${actionId}`);
    return toAction(updated);
  });
}

/**
 * Simulates a queued action, at most once: the queued → running move is a
 * compare-and-set, so concurrent callers cannot both run it.
 */
export async function runQueued(tenantId: string, actionId: string): Promise<ActionRequest | null> {
  const system: ActorRef = { kind: "system", component: "action_engine" };
  const claimed = await transaction(async (client) => {
    if (await isPaused(tenantId, client)) return null;
    const r = (await client.query<Row>(
      `UPDATE action_requests SET status = 'running', attempts = attempts + 1, updated_at = now()
        WHERE tenant_id = $1 AND id = $2 AND status = 'queued' AND execution_mode = 'simulation' RETURNING ${COLUMNS}`,
      [tenantId, actionId],
    )).rows[0];
    if (r) await event(client, tenantId, actionId, "queued", "running", system);
    return r ?? null;
  });
  if (!claimed) return getAction(tenantId, actionId);
  let result: Record<string, unknown> | null = null;
  let error: string | null = null;
  try { result = await simulate(tenantId, claimed.action_id, claimed.input); } catch (e) { error = (e instanceof Error ? e.message : "simulation failed").slice(0, 500); }
  return transaction(async (client) => {
    const to: ActionStatus = error ? "failed" : "simulated";
    const r = (await client.query<Row>(
      `UPDATE action_requests SET status = $3, result = $4, error = $5, updated_at = now()
        WHERE tenant_id = $1 AND id = $2 AND status = 'running' RETURNING ${COLUMNS}`,
      [tenantId, actionId, to, result ? JSON.stringify(result) : null, error],
    )).rows[0];
    if (!r) return null;
    await event(client, tenantId, actionId, "running", to, system, error ?? undefined);
    return toAction(r);
  });
}

export async function cancelAction(tenantId: string, actionId: string, by: ActorRef): Promise<ActionRequest | null> {
  return transaction(async (client) => {
    const row = (await client.query<Row>(`SELECT ${COLUMNS} FROM action_requests WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, [tenantId, actionId])).rows[0];
    if (!row) return null;
    if (row.status !== "awaiting_approval" && row.status !== "queued") throw new ActionError(409, "not_cancellable", `An action that is ${row.status} cannot be cancelled`);
    if (row.approval_id) await cancelApproval(client, tenantId, row.approval_id);
    const updated = (await client.query<Row>(
      `UPDATE action_requests SET status = 'cancelled', updated_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING ${COLUMNS}`, [tenantId, actionId],
    )).rows[0]!;
    await event(client, tenantId, actionId, row.status, "cancelled", by);
    return toAction(updated);
  });
}

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function getAction(tenantId: string, id: string): Promise<ActionRequest | null> {
  if (!UUID.test(id)) return null;
  const row = await queryOne<Row>(`SELECT ${COLUMNS} FROM action_requests WHERE tenant_id = $1 AND id = $2`, [tenantId, id]);
  return row ? toAction(row) : null;
}

export async function actionEvents(tenantId: string, id: string) {
  const rows = await queryAll<{ from_status: string | null; to_status: string; actor: ActorRef; note: string | null; at: Date }>(
    "SELECT from_status, to_status, actor, note, at FROM action_events WHERE tenant_id = $1 AND action_id = $2 ORDER BY seq", [tenantId, id],
  );
  return rows.map((r) => ({ ...r, at: r.at.toISOString() }));
}

export async function listActions(tenantId: string, opts: { status?: ActionStatus; limit: number }): Promise<ActionRequest[]> {
  const rows = await queryAll<Row>(
    `SELECT ${COLUMNS} FROM action_requests WHERE tenant_id = $1 AND ($2::text IS NULL OR status = $2) ORDER BY created_at DESC, id LIMIT $3`,
    [tenantId, opts.status ?? null, opts.limit],
  );
  return rows.map(toAction);
}

/** The approval request behind an action (for the UI). */
export const approvalOf = (tenantId: string, a: ActionRequest) => (a.approval_id ? getApproval(tenantId, a.approval_id) : Promise.resolve(null));
