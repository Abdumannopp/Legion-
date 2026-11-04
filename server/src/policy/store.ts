/**
 * Policy versions (immutable) and the active pointer. Every write is checked
 * against the version the writer last saw (optimistic concurrency): two admins
 * editing at once cannot silently overwrite each other.
 */
import { randomUUID } from "node:crypto";
import type pg from "pg";
import { query, queryAll, queryOne, transaction } from "../db/pool.js";
import { canonicalJson, sha256Hex } from "./canonical.js";
import { parsePolicyDocument, type PolicyDocument } from "./document.js";
import type { PolicyOutcome } from "./evaluate.js";
import type { ActorRef, ExecutionMode, Origin } from "./types.js";

export interface ActivePolicy { version: number; hash: string; document: PolicyDocument; updated_at: string }

export class PolicyConflict extends Error {
  constructor(readonly current: number) { super(`The policy changed meanwhile (now version ${current}); reload and try again`); }
}
export class PolicyInvalid extends Error {}

export const policyHash = (doc: PolicyDocument): string => sha256Hex(canonicalJson(doc));

export async function getActivePolicy(tenantId: string): Promise<ActivePolicy | null> {
  const row = await queryOne<{ version: number; hash: string; document: unknown; updated_at: Date }>(
    `SELECT d.version, d.hash, d.document, a.updated_at
       FROM policy_active a JOIN policy_documents d ON d.tenant_id = a.tenant_id AND d.version = a.version
      WHERE a.tenant_id = $1`,
    [tenantId],
  );
  if (!row) return null;
  // A stored document is re-validated on read: one that no longer parses (the
  // catalog lost an action) is treated as no policy — the safe default — and
  // never as "everything allowed".
  const parsed = parsePolicyDocument(row.document);
  if (!parsed.ok || policyHash(parsed.document) !== row.hash) return null;
  return { version: row.version, hash: row.hash, document: parsed.document, updated_at: row.updated_at.toISOString() };
}

export async function listPolicyVersions(tenantId: string): Promise<Array<{ version: number; hash: string; created_by: string | null; note: string | null; created_at: string; active: boolean }>> {
  const rows = await queryAll<{ version: number; hash: string; created_by: string | null; note: string | null; created_at: Date; active: boolean }>(
    `SELECT d.version, d.hash, d.created_by, d.note, d.created_at, (a.version = d.version) IS TRUE AS active
       FROM policy_documents d LEFT JOIN policy_active a ON a.tenant_id = d.tenant_id
      WHERE d.tenant_id = $1 ORDER BY d.version DESC LIMIT 100`,
    [tenantId],
  );
  return rows.map((r) => ({ ...r, created_at: r.created_at.toISOString() }));
}

/**
 * Stores a new version and makes it active. `expectedVersion` is the active
 * version the writer saw (0 = there was none).
 */
export async function putPolicy(tenantId: string, raw: unknown, opts: { expectedVersion: number; userId: string; note?: string }): Promise<ActivePolicy> {
  const parsed = parsePolicyDocument(raw);
  if (!parsed.ok) throw new PolicyInvalid(parsed.error);
  const doc = parsed.document;
  const hash = policyHash(doc);
  return transaction(async (client) => {
    // Serialises writers for this workspace (the tenant row always exists).
    const locked = await client.query("SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE", [tenantId]);
    if (!locked.rowCount) throw new PolicyInvalid("No such workspace");
    const current = (await client.query<{ version: number }>("SELECT version FROM policy_active WHERE tenant_id = $1", [tenantId])).rows[0]?.version ?? 0;
    if (current !== opts.expectedVersion) throw new PolicyConflict(current);
    const next = (await client.query<{ v: number }>("SELECT coalesce(max(version), 0) + 1 AS v FROM policy_documents WHERE tenant_id = $1", [tenantId])).rows[0]!.v;
    await client.query(
      "INSERT INTO policy_documents (tenant_id, version, document, hash, created_by, note) VALUES ($1, $2, $3, $4, $5, $6)",
      [tenantId, next, canonicalJson(doc), hash, opts.userId, opts.note?.slice(0, 200) ?? null],
    );
    const row = await client.query<{ updated_at: Date }>(
      `INSERT INTO policy_active (tenant_id, version, updated_by) VALUES ($1, $2, $3)
       ON CONFLICT (tenant_id) DO UPDATE SET version = EXCLUDED.version, updated_by = EXCLUDED.updated_by, updated_at = now()
       RETURNING updated_at`,
      [tenantId, next, opts.userId],
    );
    return { version: next, hash, document: doc, updated_at: row.rows[0]!.updated_at.toISOString() };
  });
}

/** Rolling back = storing an older version's content again, as a new version. */
export async function rollbackPolicy(tenantId: string, toVersion: number, opts: { expectedVersion: number; userId: string }): Promise<ActivePolicy | null> {
  const old = await queryOne<{ document: unknown }>("SELECT document FROM policy_documents WHERE tenant_id = $1 AND version = $2", [tenantId, toVersion]);
  if (!old) return null;
  return putPolicy(tenantId, old.document, { ...opts, note: `rollback to v${toVersion}` });
}

export interface DecisionRecord {
  enforcement: "shadow" | "enforced";
  call_site: string;
  actor: ActorRef;
  origin: Origin;
  mode: ExecutionMode;
  target: string | null;
  input_digest: string | null;
  legacy_outcome: string | null;
  latency_us: number;
  policy: { version: number; hash: string } | null;
}

export async function recordDecision(tenantId: string, outcome: PolicyOutcome, rec: DecisionRecord, client?: pg.PoolClient): Promise<string> {
  const id = randomUUID();
  await (client ? client.query.bind(client) : query)(
    `INSERT INTO policy_decisions (tenant_id, id, enforcement, call_site, action_id, risk_class, actor, origin, execution_mode, target,
       input_digest, decision, autonomy, matched_rule_ids, reason_codes, explanation, policy_version, policy_hash,
       catalog_version, engine_version, legacy_outcome, latency_us)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
    [
      tenantId, id, rec.enforcement, rec.call_site, outcome.action_id.slice(0, 64), outcome.risk_class, JSON.stringify(rec.actor), rec.origin, rec.mode,
      rec.target?.slice(0, 200) ?? null, rec.input_digest, outcome.decision, outcome.autonomy, outcome.matched_rule_ids, outcome.reason_codes,
      outcome.explanation, rec.policy?.version ?? null, rec.policy?.hash ?? null, outcome.catalog_version, outcome.engine_version,
      rec.legacy_outcome?.slice(0, 64) ?? null, Math.min(rec.latency_us, 2_000_000_000),
    ],
  );
  return id;
}

export interface StoredDecision {
  id: string; created_at: string; enforcement: string; call_site: string; action_id: string; risk_class: string | null;
  actor: ActorRef; origin: string; execution_mode: string; target: string | null; decision: string; autonomy: string | null;
  matched_rule_ids: string[]; reason_codes: string[]; explanation: string; policy_version: number | null; legacy_outcome: string | null;
}

export async function listDecisions(tenantId: string, opts: { limit: number; actionId?: string }): Promise<StoredDecision[]> {
  const rows = await queryAll<StoredDecision & { created_at: Date }>(
    `SELECT id, created_at, enforcement, call_site, action_id, risk_class, actor, origin, execution_mode, target, decision, autonomy,
            matched_rule_ids, reason_codes, explanation, policy_version, legacy_outcome
       FROM policy_decisions WHERE tenant_id = $1 AND ($2::text IS NULL OR action_id = $2)
      ORDER BY created_at DESC, id LIMIT $3`,
    [tenantId, opts.actionId ?? null, opts.limit],
  );
  return rows.map((r) => ({ ...r, created_at: r.created_at.toISOString() }));
}
