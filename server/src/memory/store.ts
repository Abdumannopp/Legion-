/**
 * SOC memory: what people (or Legion's deterministic code) recorded about an
 * address, host, account or alert title. Facts for context — never
 * instructions, never permissions.
 *
 *  - Sources are `human` (taken from the session) or `system`; a language
 *    model has no way to write here.
 *  - Text is cleaned (control and invisible characters removed) and bounded;
 *    subject keys are validated per type (an ip must be an IP address).
 *  - Every entry expires (at most a year); a workspace holds at most
 *    MAX_PER_TENANT live entries.
 *  - Memory can only make Legion MORE careful: e.g. a person marking an
 *    address as a false positive makes the orchestrator skip containment for
 *    it; nothing in memory can make an action more likely to run.
 */
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { query, queryAll, queryOne, transaction } from "../db/pool.js";

export const MEMORY_KINDS = ["note", "false_positive", "known_benign"] as const;
export const SUBJECT_TYPES = ["ip", "host", "account", "alert_title"] as const;
export type MemoryKind = (typeof MEMORY_KINDS)[number];
export type SubjectType = (typeof SUBJECT_TYPES)[number];
export const MAX_PER_TENANT = 10_000;
export const MAX_TTL_DAYS = 365;

export interface Memory {
  id: string; kind: MemoryKind; subject_type: SubjectType; subject_key: string; content: string;
  source: "human" | "system"; created_by: string | null; created_at: string; expires_at: string;
}

export class MemoryError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

const INVISIBLE = /[\u0000-\u0008\u000b-\u001f\u007f​-‏‪-‮⁠-⁤﻿\u{E0000}-\u{E007F}]/gu;
export const cleanText = (s: string, max: number) => s.replace(INVISIBLE, "").trim().slice(0, max);

/** Normalised subject key, or null when it is not a valid key of that type. */
export function subjectKey(type: SubjectType, raw: string): string | null {
  const v = cleanText(String(raw ?? ""), 200);
  if (!v) return null;
  if (type === "ip") return isIP(v) ? v.toLowerCase() : null;
  if (type === "host" || type === "account") return /^[\w.@\\$-]{1,200}$/u.test(v) ? v.toLowerCase() : null;
  return v.toLowerCase();
}

type Row = Omit<Memory, "created_at" | "expires_at"> & { created_at: Date; expires_at: Date };
const toMemory = (r: Row): Memory => ({ ...r, created_at: r.created_at.toISOString(), expires_at: r.expires_at.toISOString() });
const COLUMNS = "id, kind, subject_type, subject_key, content, source, created_by, created_at, expires_at";

export async function addMemory(tenantId: string, m: { kind: MemoryKind; subject_type: SubjectType; subject_key: string; content: string; source: "human" | "system"; created_by: string | null; ttl_days: number }): Promise<Memory> {
  const key = subjectKey(m.subject_type, m.subject_key);
  if (!key) throw new MemoryError(422, `subject_key is not a valid ${m.subject_type}`);
  const content = cleanText(m.content, 2000);
  if (!content) throw new MemoryError(422, "content is empty");
  const ttl = Math.floor(m.ttl_days);
  if (!(ttl >= 1 && ttl <= MAX_TTL_DAYS)) throw new MemoryError(422, `ttl_days must be between 1 and ${MAX_TTL_DAYS}`);
  // Quota check and insert serialised per workspace (transaction-scoped advisory lock): exact, even under concurrency.
  const row = await transaction(async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('soc_memory:' || $1))", [tenantId]);
    return (await client.query<Row>(
      `INSERT INTO soc_memory (tenant_id, id, kind, subject_type, subject_key, content, source, created_by, expires_at)
       SELECT $1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(days => $9)
        WHERE (SELECT count(*) FROM soc_memory WHERE tenant_id = $1 AND expires_at > now()) < $10
       RETURNING ${COLUMNS}`,
      [tenantId, randomUUID(), m.kind, m.subject_type, key, content, m.source, m.created_by, ttl, MAX_PER_TENANT],
    )).rows[0] ?? null;
  });
  if (!row) throw new MemoryError(409, `This workspace already holds ${MAX_PER_TENANT} memory entries; remove some first`);
  return toMemory(row);
}

export async function listMemory(tenantId: string, opts: { subject_type?: SubjectType; subject_key?: string; limit: number }): Promise<Memory[]> {
  const key = opts.subject_type && opts.subject_key ? subjectKey(opts.subject_type, opts.subject_key) : null;
  const rows = await queryAll<Row>(
    `SELECT ${COLUMNS} FROM soc_memory
      WHERE tenant_id = $1 AND expires_at > now() AND ($2::text IS NULL OR subject_type = $2) AND ($3::text IS NULL OR subject_key = $3)
      ORDER BY created_at DESC, id LIMIT $4`,
    [tenantId, opts.subject_type ?? null, key, opts.limit],
  );
  return rows.map(toMemory);
}

/** Live memories about any of these subjects (for the orchestrator's context). */
export async function recall(tenantId: string, subjects: Array<{ type: SubjectType; key: string | null | undefined }>): Promise<Memory[]> {
  const pairs = subjects.map((s) => (s.key ? { type: s.type, key: subjectKey(s.type, s.key) } : null)).filter((p): p is { type: SubjectType; key: string } => Boolean(p?.key));
  if (!pairs.length) return [];
  const rows = await queryAll<Row>(
    `SELECT ${COLUMNS} FROM soc_memory
      WHERE tenant_id = $1 AND expires_at > now()
        AND (subject_type, subject_key) IN (SELECT * FROM unnest($2::text[], $3::text[]))
      ORDER BY created_at DESC LIMIT 50`,
    [tenantId, pairs.map((p) => p.type), pairs.map((p) => p.key)],
  );
  return rows.map(toMemory);
}

export async function forget(tenantId: string, id: string, by: { user_id: string; role: string }): Promise<"deleted" | "not_found" | "forbidden"> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) return "not_found";
  const row = await queryOne<{ created_by: string | null }>("SELECT created_by FROM soc_memory WHERE tenant_id = $1 AND id = $2", [tenantId, id]);
  if (!row) return "not_found";
  if (row.created_by !== by.user_id && by.role !== "admin") return "forbidden";
  await query("DELETE FROM soc_memory WHERE tenant_id = $1 AND id = $2", [tenantId, id]);
  return "deleted";
}

/** Retention: expired entries are deleted (every workspace). */
export async function pruneExpiredMemory(): Promise<number> {
  const r = await query("DELETE FROM soc_memory WHERE expires_at <= now()");
  return r.rowCount ?? 0;
}
