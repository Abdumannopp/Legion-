import { createHash } from "node:crypto";
import type { PoolClient } from "pg";

/*
 * Shared tamper-evidence for append-only tables (principal_audit_log,
 * firewall_decisions). Each row stores sha256(prev_hash + "\n" + canonical
 * JSON of its fields); one chain per tenant.
 */

export const GENESIS = "0".repeat(64);
export const GLOBAL_CHAIN = "__global__";

/** JSON with object keys sorted at every level, so jsonb's reordering cannot change a hash. */
export function canonical(value: unknown): string {
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

export function chainHash(prevHash: string, fields: unknown): string {
  return createHash("sha256").update(prevHash).update("\n").update(canonical(fields)).digest("hex");
}

/**
 * Takes the chain's lock for the rest of the caller's transaction and returns
 * the hash to link to. One writer per chain at a time keeps it linear;
 * different tenants never wait on each other.
 */
export async function lockChain(client: PoolClient, table: string, chainKey: string): Promise<string> {
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`${table}:${chainKey}`]);
  const last = await client.query<{ hash: string }>(
    `SELECT hash FROM ${table} WHERE chain_key = $1 ORDER BY seq DESC LIMIT 1`,
    [chainKey],
  );
  return last.rows[0]?.hash ?? GENESIS;
}
