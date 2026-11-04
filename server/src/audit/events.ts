/**
 * The SOC core's audit stream (table soc_audit_events): one chain per
 * workspace, each event keyed-hashed over the previous one.
 *
 *   hash = HMAC-SHA256(key, prev_hash || canonical(event))
 *
 * - Appends are serialised per workspace (transaction advisory lock), so the
 *   sequence has no gaps and no forks, even under concurrency.
 * - Callers pass their transaction client: the event commits with the change
 *   it describes, or not at all.
 * - The key (SOC_AUDIT_KEY, else derived from JWT_SECRET) never reaches the
 *   database: someone who can write rows cannot produce a valid chain.
 * - Events carry ids, decisions and reasons — never request text, alert
 *   text, secrets or model output.
 */
import { createHmac, hkdfSync, randomUUID } from "node:crypto";
import type pg from "pg";
import { config } from "../config.js";
import { queryAll, transaction } from "../db/pool.js";
import { canonicalJson } from "../policy/canonical.js";
import type { ActorRef } from "../policy/types.js";

export const GENESIS = "0".repeat(64);
export type AuditCategory = "policy" | "approval" | "action" | "workflow" | "runtime" | "memory" | "controls";

export interface AuditEventInput {
  category: AuditCategory;
  event: string;
  actor: ActorRef | { kind: "human"; user_id: string };
  subject_type?: string | null;
  subject_id?: string | null;
  detail?: Record<string, string | number | boolean | null | string[]>;
}

function key(): { id: string; key: Buffer } {
  if (config.socAuditKey) return { id: "configured", key: Buffer.from(hkdfSync("sha256", config.socAuditKey, "legion-soc-audit", "soc audit chain v1", 32)) };
  return { id: "jwt-derived", key: Buffer.from(hkdfSync("sha256", config.jwtSecret, "legion-soc-audit", "soc audit chain v1", 32)) };
}

interface Body { tenant_id: string; seq: number; id: string; at: string; category: string; event: string; actor: unknown; subject_type: string | null; subject_id: string | null; detail: unknown; key_id: string }

export function chainHash(k: Buffer, prev: string, body: Body): string {
  return createHmac("sha256", k).update(prev).update("\n").update(canonicalJson(body)).digest("hex");
}

export async function appendAuditEvent(client: pg.PoolClient, tenantId: string, e: AuditEventInput): Promise<{ seq: number; hash: string }> {
  if (!/^[a-z_]{1,32}\.[a-z_]{1,32}$/.test(e.event)) throw new Error(`invalid audit event name: ${e.event}`);
  await client.query("SELECT pg_advisory_xact_lock(hashtext('soc_audit:' || $1))", [tenantId]);
  const last = (await client.query<{ seq: string; hash: string }>(
    "SELECT seq, hash FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1", [tenantId],
  )).rows[0];
  const { id: keyId, key: k } = key();
  const body: Body = {
    tenant_id: tenantId, seq: last ? Number(last.seq) + 1 : 1, id: randomUUID(),
    // Millisecond precision, fixed here: what is hashed is exactly what is stored.
    at: new Date().toISOString(), category: e.category, event: e.event, actor: e.actor,
    subject_type: e.subject_type ?? null, subject_id: e.subject_id?.slice(0, 100) ?? null, detail: e.detail ?? {}, key_id: keyId,
  };
  const prev = last?.hash ?? GENESIS;
  const hash = chainHash(k, prev, body);
  await client.query(
    `INSERT INTO soc_audit_events (tenant_id, seq, id, at, category, event, actor, subject_type, subject_id, detail, key_id, prev_hash, hash)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [tenantId, body.seq, body.id, body.at, body.category, body.event, JSON.stringify(body.actor), body.subject_type, body.subject_id,
      JSON.stringify(body.detail), keyId, prev, hash],
  );
  return { seq: body.seq, hash };
}

/** For callers without a transaction of their own. */
export const appendAuditEventNow = (tenantId: string, e: AuditEventInput) => transaction((c) => appendAuditEvent(c, tenantId, e));

type Row = Omit<Body, "seq" | "at"> & { seq: string; at: Date; prev_hash: string; hash: string };

export interface VerifyResult { ok: boolean; events: number; head: string; broken_at: number | null; reason: string | null }

/** Re-computes the whole chain of one workspace. */
export async function verifyAuditChain(tenantId: string): Promise<VerifyResult> {
  const rows = await queryAll<Row>(
    `SELECT tenant_id, seq, id, at, category, event, actor, subject_type, subject_id, detail, key_id, prev_hash, hash
       FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq`, [tenantId],
  );
  const { id: keyId, key: k } = key();
  let prev = GENESIS;
  let expectedSeq = 1;
  for (const r of rows) {
    const seq = Number(r.seq);
    const fail = (reason: string): VerifyResult => ({ ok: false, events: rows.length, head: prev, broken_at: seq, reason });
    if (seq !== expectedSeq) return fail(`sequence gap: expected ${expectedSeq}`);
    if (r.prev_hash !== prev) return fail("previous-hash mismatch");
    if (r.key_id !== keyId) return fail(`signed with key "${r.key_id}", verifying with "${keyId}"`);
    const body: Body = { tenant_id: r.tenant_id, seq, id: r.id, at: r.at.toISOString(), category: r.category, event: r.event, actor: r.actor,
      subject_type: r.subject_type, subject_id: r.subject_id, detail: r.detail, key_id: r.key_id };
    if (chainHash(k, prev, body) !== r.hash) return fail("content does not match its hash");
    prev = r.hash;
    expectedSeq++;
  }
  return { ok: true, events: rows.length, head: prev, broken_at: null, reason: null };
}

export async function listAuditEvents(tenantId: string, opts: { category?: string; limit: number; beforeSeq?: number }) {
  const rows = await queryAll<Row>(
    `SELECT tenant_id, seq, id, at, category, event, actor, subject_type, subject_id, detail, key_id, prev_hash, hash
       FROM soc_audit_events WHERE tenant_id = $1 AND ($2::text IS NULL OR category = $2) AND ($3::bigint IS NULL OR seq < $3)
      ORDER BY seq DESC LIMIT $4`,
    [tenantId, opts.category ?? null, opts.beforeSeq ?? null, opts.limit],
  );
  return rows.map(({ tenant_id: _t, ...r }) => ({ ...r, seq: Number(r.seq), at: r.at.toISOString() }));
}
