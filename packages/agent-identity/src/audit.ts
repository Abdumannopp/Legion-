import { createHash } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { Principal, PrincipalType } from "./types.js";

export type AuditOutcome = "attempt" | "success" | "failure" | "denied";

export interface AuditEvent {
  principal: Principal;
  action: string;
  outcome: AuditOutcome;
  /** Tenant the event belongs to. Defaults to the principal's tenant. */
  tenantId?: string | null;
  resourceType?: string;
  resourceId?: string;
  reason?: string;
  requestId?: string;
  ip?: string;
  userAgent?: string;
  details?: Record<string, unknown>;
}

export interface AuditRow {
  seq: string;
  occurredAt: string;
  tenantId: string | null;
  principalType: PrincipalType;
  principalId: string;
  principalName: string;
  onBehalfOf: string | null;
  credentialId: string | null;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  outcome: AuditOutcome;
  reason: string | null;
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
  details: Record<string, unknown>;
}

const GENESIS = "0".repeat(64);
const GLOBAL_CHAIN = "__global__";

/** JSON with object keys sorted at every level, so jsonb's reordering cannot change a hash. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return `{${Object.keys(obj)
      .sort()
      .filter((k) => obj[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

type HashedFields = Omit<AuditRow, "seq"> & { chainKey: string };

function rowHash(prevHash: string, f: HashedFields): string {
  return createHash("sha256").update(prevHash).update("\n").update(canonical(f)).digest("hex");
}

function truncate(value: string | undefined, max: number): string | null {
  if (value === undefined || value === null) return null;
  return value.length > max ? value.slice(0, max) : value;
}

export class AuditLog {
  constructor(private readonly pool: Pool) {}

  /**
   * Appends one event. Resolves only after the row is committed — callers
   * that must not act without a trace (requirePermission) await this first.
   *
   * Pass `inTx` to write inside the caller's open transaction, so a change
   * and its audit row commit together or not at all.
   */
  async record(e: AuditEvent, inTx?: PoolClient): Promise<void> {
    const p = e.principal;
    const tenantId = e.tenantId !== undefined ? e.tenantId : p.tenantId;
    const fields: HashedFields = {
      chainKey: tenantId ?? GLOBAL_CHAIN,
      occurredAt: new Date().toISOString(),
      tenantId,
      principalType: p.type,
      principalId: p.id,
      principalName: truncate(p.displayName, 200) ?? "",
      onBehalfOf: p.type === "ai_agent" || p.type === "service_account" ? p.ownerUserId : null,
      credentialId: p.type === "ai_agent" || p.type === "service_account" ? p.credentialId : null,
      action: e.action,
      resourceType: e.resourceType ?? null,
      resourceId: e.resourceId ?? null,
      outcome: e.outcome,
      reason: truncate(e.reason, 500),
      requestId: e.requestId ?? null,
      ip: truncate(e.ip, 64),
      userAgent: truncate(e.userAgent, 300),
      details: e.details ?? {},
    };

    const write = async (client: PoolClient) => {
      // One writer per chain at a time keeps the chain linear; different
      // tenants never wait on each other.
      await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`audit:${fields.chainKey}`]);
      const last = await client.query<{ hash: string }>(
        "SELECT hash FROM principal_audit_log WHERE chain_key = $1 ORDER BY seq DESC LIMIT 1",
        [fields.chainKey],
      );
      const prevHash = last.rows[0]?.hash ?? GENESIS;
      await client.query(
        `INSERT INTO principal_audit_log
          (chain_key, occurred_at, tenant_id, principal_type, principal_id, principal_name, on_behalf_of,
           credential_id, action, resource_type, resource_id, outcome, reason, request_id, ip, user_agent,
           details, prev_hash, hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`,
        [
          fields.chainKey, fields.occurredAt, fields.tenantId, fields.principalType, fields.principalId,
          fields.principalName, fields.onBehalfOf, fields.credentialId, fields.action, fields.resourceType,
          fields.resourceId, fields.outcome, fields.reason, fields.requestId, fields.ip, fields.userAgent,
          JSON.stringify(fields.details), prevHash, rowHash(prevHash, fields),
        ],
      );
    };

    if (inTx) return write(inTx);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await write(client);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  async list(
    tenantId: string,
    filter: {
      principalType?: PrincipalType;
      principalId?: string;
      /** Events performed by OR performed on this identity. */
      involving?: { id: string; resourceType: string };
      before?: string;
      limit?: number;
    } = {},
  ): Promise<AuditRow[]> {
    const where = ["tenant_id = $1"];
    const args: unknown[] = [tenantId];
    const add = (sql: string, ...vals: unknown[]) => {
      let s = sql;
      for (const v of vals) {
        args.push(v);
        s = s.replace("?", `$${args.length}`);
      }
      where.push(s);
    };
    if (filter.principalType) add("principal_type = ?", filter.principalType);
    if (filter.principalId) add("principal_id = ?", filter.principalId);
    if (filter.involving) {
      add("(principal_id = ? OR (resource_type = ? AND resource_id = ?))",
        filter.involving.id, filter.involving.resourceType, filter.involving.id);
    }
    if (filter.before) add("seq < ?", filter.before);
    args.push(Math.min(Math.max(filter.limit ?? 100, 1), 500));
    const res = await this.pool.query(
      `SELECT * FROM principal_audit_log WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${args.length}`,
      args,
    );
    return res.rows.map(toRow);
  }

  /**
   * Recomputes a tenant's chain from the first row. Returns the first row
   * whose content or link does not match — i.e. where history was altered.
   */
  async verifyChain(tenantId: string | null): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const chainKey = tenantId ?? GLOBAL_CHAIN;
    const res = await this.pool.query(
      "SELECT * FROM principal_audit_log WHERE chain_key = $1 ORDER BY seq ASC",
      [chainKey],
    );
    let prev = GENESIS;
    let n = 0;
    for (const r of res.rows) {
      n++;
      const { seq, ...rest } = toRow(r);
      const expected = rowHash(prev, { chainKey, ...rest });
      if (r.prev_hash !== prev || r.hash !== expected) return { ok: false, brokenAtSeq: seq, rows: n };
      prev = r.hash;
    }
    return { ok: true, rows: n };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRow(r: any): AuditRow {
  return {
    seq: String(r.seq),
    occurredAt: new Date(r.occurred_at).toISOString(),
    tenantId: r.tenant_id,
    principalType: r.principal_type,
    principalId: r.principal_id,
    principalName: r.principal_name,
    onBehalfOf: r.on_behalf_of,
    credentialId: r.credential_id,
    action: r.action,
    resourceType: r.resource_type,
    resourceId: r.resource_id,
    outcome: r.outcome,
    reason: r.reason,
    requestId: r.request_id,
    ip: r.ip,
    userAgent: r.user_agent,
    details: r.details,
  };
}
