/**
 * F-04 (PR-3a): row-level security for the tables Legion only ever reaches workspace-first.
 *
 * Isolation between workspaces was enforced by the application alone: every query carries
 * `tenant_id = $1`, and a static guard (tests/tenant-query-guard.test.ts) checks that it does.
 * One forgotten predicate in a future change would still leak. With DB_RLS=enforce the database
 * checks too: migration 0009 puts a policy on each table below that only shows (and only accepts)
 * rows of the workspace the API declared for the current request or job.
 *
 * How the workspace is declared: `withTenant(tenantId, fn)` (an AsyncLocalStorage context, set by
 * authentication, the webhook, the agent API and every per-workspace worker loop). pool.ts hands it
 * to Postgres with each query as the setting legion.tenant_id. Without a context the policy shows
 * nothing and accepts nothing (fail closed); in enforce mode pool.ts also refuses such a query
 * outright, so a missed code path is loud, not an empty page.
 *
 * Scope and limits: the policy binds the API's role only when it does not own the tables (the
 * owner/runtime split, F-02), and it guards against forgotten predicates, not against SQL
 * injection (a session that can run arbitrary SQL can also set legion.tenant_id). Users, tenants,
 * billing and the credential tables are not in this first group: their lookups (sign-in by e-mail,
 * webhook key id, Paddle subscription id) happen before the workspace is known.
 */
import { AsyncLocalStorage } from "node:async_hooks";

/** The tenant-scoped tables of the first group: the MUST_SCOPE set of the tenant-query guard. */
export const RLS_TABLES = [
  "alerts", "assets", "audit_log",
  "policy_documents", "policy_active", "policy_decisions",
  "approval_requests", "approval_decisions", "action_requests", "action_events",
  "soc_controls", "workflow_runs", "learning_signals", "soc_audit_events",
] as const;

// Also a quoted name ("alerts"), as statements built from a table list write it.
const RLS_TABLE_RE = new RegExp(`\\b(?:from|join|into|update)\\s+"?(${RLS_TABLES.join("|")})\\b`, "i");

/** The RLS table a statement touches, if any (the same shape the tenant-query guard reads). */
export function touchesRlsTable(sql: string): string | null {
  return RLS_TABLE_RE.exec(sql)?.[1]?.toLowerCase() ?? null;
}

const scope = new AsyncLocalStorage<{ tenantId: string }>();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Runs `fn` with `tenantId` as the workspace every query inside it is limited to. */
export function withTenant<T>(tenantId: string, fn: () => T): T {
  if (!UUID.test(tenantId)) throw new Error("withTenant: not a workspace id");
  return scope.run({ tenantId }, fn);
}

/**
 * For functions that are handed their workspace explicitly (store.audit, store.insertAlert, …):
 * the request's or job's own workspace wins when there is one (so a wrong argument cannot widen
 * it); otherwise the argument is the context. Returns fn's result.
 */
export function inTenant<T>(tenantId: string, fn: () => T): T {
  return scope.getStore() ? fn() : withTenant(tenantId, fn);
}

/** The workspace declared for the current request or job, if any. */
export function currentTenant(): string | null {
  return scope.getStore()?.tenantId ?? null;
}

export class RlsContextError extends Error {
  constructor(table: string) {
    super(`DB_RLS=enforce: a query on ${table} ran without a workspace context (wrap the caller in withTenant)`);
    this.name = "RlsContextError";
  }
}
