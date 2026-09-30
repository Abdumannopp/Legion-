/**
 * Static guard: every SQL statement in the server that touches a tenant-owned
 * table must be scoped to a tenant — or be a reviewed exception, listed below
 * WITH THE REASON it is safe.
 *
 * A new query against alerts/assets/audit_log/... without `tenant_id` fails this
 * test until someone either scopes it or adds it here after review. That is the
 * point: cross-tenant leaks come from the one query nobody looked at twice.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const SRC = join(__dirname, "..", "src");

/** Tables that hold (or lead to) one organisation's data. */
const TENANT_TABLES = [
  "alerts", "assets", "audit_log", "subscriptions", "webhook_credentials", "webhook_nonces",
  "notification_outbox", "users", "refresh_tokens", "mfa_recovery_codes", "mfa_used_counters", "tenants",
];

/** Tables whose rows are ALWAYS reached tenant-first by these functions; must never be read unscoped. */
const MUST_SCOPE = new Set(["alerts", "assets", "audit_log"]);

interface Exception { file: string; table: string; match?: RegExp; reason: string }

const REVIEWED: Exception[] = [
  // --- the tenants table itself: its primary key IS the tenant id
  { file: "*", table: "tenants", match: /\btenants\s+WHERE\s+id\s*=\s*(\$1|ANY)/i, reason: "keyed by the tenant id itself" },
  { file: "*", table: "tenants", match: /^SELECT (1|count\(\*\)(::bigint)?) (AS count )?FROM tenants( LIMIT 1)?$/i, reason: "existence/count probe for first-run setup; returns no tenant data" },
  { file: "*", table: "tenants", match: /^INSERT INTO tenants/i, reason: "creates a tenant (signup, seed)" },
  { file: "store.ts", table: "tenants", match: /^UPDATE tenants SET .* WHERE id = \$1/i, reason: "keyed by the tenant id; callers pass req.user.tenant_id" },
  { file: "store.ts", table: "tenants", match: /WHERE notification_email_token_hash = \$1/i, reason: "confirming a notification address by the hash of a 256-bit one-time token; the row's own tenant is returned and audited" },
  // --- per-user state: the user id comes from a verified session / challenge token, and the user row carries its tenant
  { file: "mfa.ts", table: "users", reason: "the authenticated user's own MFA seed, by user id" },
  { file: "mfa.ts", table: "mfa_used_counters", reason: "per-user replay counters, by user id" },
  { file: "mfa.ts", table: "mfa_recovery_codes", reason: "per-user recovery codes, by user id" },
  { file: "sessions.ts", table: "refresh_tokens", reason: "sessions by user id or by the hash of a 256-bit token; tenant is re-derived from the user row" },
  { file: "store.ts", table: "users", match: /WHERE (id = \$1|lower\(email\) = lower\(\$1\)|invite_token_hash = \$1|reset_token_hash = \$1|verify_token_hash = \$1)/i,
    reason: "identity lookups (login, token verification, the session's own user). Every endpoint that touches ANOTHER user goes through findUserInTenant" },
  { file: "store.ts", table: "users", match: /^UPDATE users SET \$\{sets\.join/i, reason: "updateUser(id): every caller first resolved the user with findUserInTenant or is the user itself (reviewed in index.ts)" },
  { file: "store.ts", table: "subscriptions", match: /WHERE paddle_subscription_id = \$1/i, reason: "Paddle webhook (signature-verified) resolves the subscription's own tenant from the row" },
  // --- workers: rows were claimed first; the row carries tenant_id and the work uses it
  { file: "outbox.ts", table: "notification_outbox", reason: "worker bookkeeping by row id after a claim; delivery uses row.tenant_id/recipient fixed at enqueue" },
  { file: "outbox.ts", table: "tenants", reason: "enqueue reads the ALERT's own tenant's notification address" },
  { file: "webhook-credentials.ts", table: "webhook_nonces", reason: "replay nonces keyed by the credential's key id (itself tenant-bound)" },
  { file: "webhook-credentials.ts", table: "webhook_credentials", match: /WHERE key_id = \$1 (AND \(last_used_at|RETURNING)/i,
    reason: "touch on use (after signature verification) / rotate after a tenant-scoped SELECT … FOR UPDATE" },
  // --- maintenance, not request paths
  { file: "secrets-migration.ts", table: "users", reason: "boot-time re-encryption of MFA seeds across all rows; no data leaves the process" },
  { file: "workspaces.ts", table: "users", match: /^UPDATE users SET default_workspace_id = (NULL|\$2) WHERE id = \$1/i,
    reason: "the signed-in person's own landing workspace, by their user id; the workspace was checked to be an active membership of theirs" },
  { file: "secrets-migration.ts", table: "webhook_credentials", reason: "boot-time re-encryption across all rows" },
  { file: "seed.ts", table: "tenants", reason: "demo seeding" },
  { file: "setup-token.ts", table: "tenants", reason: "first-run probe" },
  { file: "index.ts", table: "tenants", match: /^SELECT 1 FROM tenants LIMIT 1$/i, reason: "first-run probe" },
];

interface Stmt { file: string; line: number; sql: string; tables: string[] }

function statements(): Stmt[] {
  const out: Stmt[] = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
    const src = readFileSync(join(SRC, file), "utf8");
    for (const m of src.matchAll(/(["'`])(\s*(?:SELECT|UPDATE|INSERT|DELETE|WITH)\b[\s\S]*?)\1/g)) {
      const sql = m[2]!.replace(/\s+/g, " ").trim();
      const tables = TENANT_TABLES.filter((t) => new RegExp(`\\b(from|join|into|update)\\s+${t}\\b`, "i").test(sql));
      if (tables.length) out.push({ file, line: src.slice(0, m.index).split("\n").length, sql, tables });
    }
  }
  return out;
}

describe("every tenant-owned query is tenant-scoped or a reviewed exception", () => {
  const all = statements();

  it("finds the queries (the scanner itself works)", () => {
    expect(all.length).toBeGreaterThan(80);
    expect(all.some((s) => s.file === "store.ts" && /FROM alerts WHERE tenant_id = \$1 AND id = \$2/.test(s.sql))).toBe(true);
  });

  it("no unscoped statement outside the reviewed list", () => {
    const unreviewed: string[] = [];
    for (const s of all) {
      if (/tenant_id/i.test(s.sql)) continue;
      for (const t of s.tables) {
        const ok = REVIEWED.some((e) => (e.file === "*" || e.file === s.file) && e.table === t && (!e.match || e.match.test(s.sql)));
        // Dynamic WHERE builders are checked separately below.
        const dynamic = /\$\{where\.join/.test(s.sql) && MUST_SCOPE.has(t);
        if (!ok && !dynamic) unreviewed.push(`${s.file}:${s.line} [${t}] ${s.sql.slice(0, 120)}`);
      }
    }
    expect(unreviewed).toEqual([]);
  });

  it("alerts, assets and the audit log are never touched without tenant_id — no exceptions exist for them", () => {
    const bad = all.filter((s) => s.tables.some((t) => MUST_SCOPE.has(t)) && !/tenant_id/i.test(s.sql) && !/\$\{where\.join/.test(s.sql));
    expect(bad.map((s) => `${s.file}:${s.line} ${s.sql.slice(0, 100)}`)).toEqual([]);
    expect(REVIEWED.filter((e) => MUST_SCOPE.has(e.table))).toEqual([]);
  });

  it("every dynamic WHERE builder starts from the tenant condition", () => {
    const src = readFileSync(join(SRC, "store.ts"), "utf8");
    const dynamic = all.filter((s) => s.file === "store.ts" && /\$\{where\.join/.test(s.sql));
    expect(dynamic.length).toBeGreaterThanOrEqual(4);
    for (const s of dynamic) {
      // The nearest `const where = [...]` above the statement must begin with tenant_id = $1.
      const before = src.split("\n").slice(0, s.line).join("\n");
      const decl = [...before.matchAll(/const where(?:: string\[\])? = \[([^\]]*)\]/g)].pop();
      expect(decl?.[1], `${s.file}:${s.line}`).toMatch(/^\s*"tenant_id = \$1"/);
      const params = [...before.matchAll(/const params(?:: unknown\[\])? = \[([^\]]*)\]/g)].pop();
      expect(params?.[1], `${s.file}:${s.line} binds the tenant as $1`).toMatch(/^\s*tenantId\s*$/);
    }
  });

  it("the reviewed list has no stale entries (each still matches a real query)", () => {
    const stale = REVIEWED.filter((e) => !all.some((s) => (e.file === "*" || e.file === s.file) && s.tables.includes(e.table) && (!e.match || e.match.test(s.sql)) && !/tenant_id/i.test(s.sql)));
    expect(stale.map((e) => `${e.file} ${e.table} ${e.match ?? ""}`)).toEqual([]);
  });
});
