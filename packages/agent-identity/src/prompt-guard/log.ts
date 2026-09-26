import type { Pool, PoolClient } from "pg";
import { chainHash, GENESIS, lockChain } from "../chain.js";
import { digest, findSecrets } from "../firewall/scan.js";
import type { Principal } from "../types.js";
import type { Classification, ContentRiskSummary, ContentSource, FieldHint } from "./types.js";

export interface IngestionRow {
  seq: string;
  eventId: string;
  occurredAt: string;
  tenantId: string;
  principalType: string;
  principalId: string;
  principalName: string;
  source: string;
  sourceId: string | null;
  fieldHint: string | null;
  verdict: string;
  riskScore: number;
  findings: unknown;
  contentDigest: string;
  contentLength: number;
  contentPreview: string;
  requestId: string | null;
}

const COLUMNS: [Exclude<keyof IngestionRow, "seq">, string][] = [
  ["eventId", "event_id"], ["occurredAt", "occurred_at"], ["tenantId", "tenant_id"], ["principalType", "principal_type"],
  ["principalId", "principal_id"], ["principalName", "principal_name"], ["source", "source"], ["sourceId", "source_id"],
  ["fieldHint", "field_hint"], ["verdict", "verdict"], ["riskScore", "risk_score"], ["findings", "findings"],
  ["contentDigest", "content_digest"], ["contentLength", "content_length"], ["contentPreview", "content_preview"],
  ["requestId", "request_id"],
];

/** A short preview for investigators: invisible characters already removed, secrets masked. */
export function previewOf(sanitized: string): string {
  const cut = sanitized.length > 300 ? `${sanitized.slice(0, 300)}…(${sanitized.length})` : sanitized;
  return findSecrets(cut).length ? "[REDACTED: contains credentials]" : cut;
}

export class IngestionLog {
  constructor(private readonly pool: Pool) {}

  static build(
    ctx: { tenantId: string; principal: Principal; requestId?: string },
    item: { eventId: string; source: ContentSource; sourceId?: string; fieldHint?: FieldHint; content: string; classification: Classification },
  ): Omit<IngestionRow, "seq"> {
    const c = item.classification;
    return {
      eventId: item.eventId,
      occurredAt: new Date().toISOString(),
      tenantId: ctx.tenantId,
      principalType: ctx.principal.type,
      principalId: ctx.principal.id,
      principalName: ctx.principal.displayName.slice(0, 200),
      source: item.source,
      sourceId: item.sourceId?.slice(0, 200) ?? null,
      fieldHint: item.fieldHint ?? null,
      verdict: c.verdict,
      riskScore: c.riskScore,
      findings: c.findings.map((f) => ({ ...f, excerpt: f.excerpt && findSecrets(f.excerpt).length ? "[REDACTED]" : f.excerpt })),
      contentDigest: digest(item.content),
      contentLength: item.content.length,
      contentPreview: previewOf(c.sanitized),
      requestId: ctx.requestId ?? null,
    };
  }

  async record(row: Omit<IngestionRow, "seq">): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const prev = await lockChain(client, "content_ingestion_log", row.tenantId);
      const values = COLUMNS.map(([k]) => (k === "findings" ? JSON.stringify(row[k]) : row[k]));
      await client.query(
        `INSERT INTO content_ingestion_log (chain_key, ${COLUMNS.map(([, c]) => c).join(", ")}, prev_hash, hash)
         VALUES ($1, ${COLUMNS.map((_, i) => `$${i + 2}`).join(", ")}, $${COLUMNS.length + 2}, $${COLUMNS.length + 3})`,
        [row.tenantId, ...values, prev, chainHash(prev, row)],
      );
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Unreviewed flagged content for one principal. Malicious counts until a
   * person acknowledges it (looking back at most 30 days, to bound the
   * query); suspicious counts within `suspiciousWindowSeconds`.
   */
  async summary(tenantId: string, principalId: string, suspiciousWindowSeconds: number): Promise<ContentRiskSummary> {
    const res = await this.pool.query(
      `SELECT count(*) FILTER (WHERE verdict = 'malicious')::int AS malicious,
              count(*) FILTER (WHERE verdict = 'suspicious' AND occurred_at > now() - make_interval(secs => $3))::int AS suspicious,
              coalesce(max(risk_score), 0)::int AS max_score,
              max(occurred_at) AS last_at
         FROM content_ingestion_log
        WHERE tenant_id = $1 AND principal_id = $2
          AND occurred_at > now() - interval '30 days'
          AND seq > coalesce((SELECT acknowledged_through_seq FROM content_risk_acknowledgements
                               WHERE tenant_id = $1 AND principal_id = $2), 0)`,
      [tenantId, principalId, suspiciousWindowSeconds],
    );
    const r = res.rows[0];
    return {
      unacknowledgedMalicious: r.malicious,
      unacknowledgedSuspicious: r.suspicious,
      maxScore: r.max_score,
      lastEventAt: r.last_at ? new Date(r.last_at).toISOString() : null,
    };
  }

  /** Moves the review cursor to the principal's latest event. Returns how many flagged events it covered. */
  async acknowledge(c: PoolClient, tenantId: string, principalId: string, by: string, reason: string) {
    const latest = await c.query(
      `SELECT coalesce(max(seq), 0) AS through, count(*)::int AS n FROM content_ingestion_log
        WHERE tenant_id = $1 AND principal_id = $2
          AND seq > coalesce((SELECT acknowledged_through_seq FROM content_risk_acknowledgements WHERE tenant_id = $1 AND principal_id = $2), 0)`,
      [tenantId, principalId],
    );
    const through = String(latest.rows[0].through);
    await c.query(
      `INSERT INTO content_risk_acknowledgements (tenant_id, principal_id, acknowledged_through_seq, acknowledged_by, reason)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, principal_id) DO UPDATE SET
         acknowledged_through_seq = GREATEST(content_risk_acknowledgements.acknowledged_through_seq, EXCLUDED.acknowledged_through_seq),
         acknowledged_by = EXCLUDED.acknowledged_by, acknowledged_at = now(), reason = EXCLUDED.reason`,
      [tenantId, principalId, through, by, reason],
    );
    return { throughSeq: through, cleared: latest.rows[0].n as number };
  }

  async list(tenantId: string, f: { verdict?: string; principalId?: string; source?: string; before?: string; limit?: number } = {}) {
    const where = ["tenant_id = $1"];
    const args: unknown[] = [tenantId];
    const add = (col: string, v: unknown) => { args.push(v); where.push(`${col} = $${args.length}`); };
    if (f.verdict) add("verdict", f.verdict);
    if (f.principalId) add("principal_id", f.principalId);
    if (f.source) add("source", f.source);
    if (f.before) { args.push(f.before); where.push(`seq < $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
    const res = await this.pool.query(
      `SELECT * FROM content_ingestion_log WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${args.length}`, args);
    return res.rows.map(toRow);
  }

  async verifyChain(tenantId: string): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.pool.query("SELECT * FROM content_ingestion_log WHERE chain_key = $1 ORDER BY seq", [tenantId]);
    let prev = GENESIS;
    let n = 0;
    for (const r of res.rows) {
      n++;
      const { seq, ...fields } = toRow(r);
      if (r.prev_hash !== prev || r.hash !== chainHash(prev, fields)) return { ok: false, brokenAtSeq: seq, rows: n };
      prev = r.hash;
    }
    return { ok: true, rows: n };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRow(r: any): IngestionRow {
  const out = { seq: String(r.seq) } as IngestionRow;
  for (const [k, c] of COLUMNS) (out as unknown as Record<string, unknown>)[k] = r[c];
  out.occurredAt = new Date(r.occurred_at).toISOString();
  return out;
}
