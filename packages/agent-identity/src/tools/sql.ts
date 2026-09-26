import type { Findings } from "./findings.js";

/*
 * A deliberately conservative SQL reader. It does not try to understand
 * every valid query; it accepts a narrow, checkable subset and refuses the
 * rest:
 *   - exactly one SELECT / INSERT / UPDATE / DELETE statement (WITH … SELECT ok)
 *   - no comments tricks, no dollar quoting, no dangerous functions, no catalog access
 *   - every table referenced by name, in the public schema, and allowlisted
 *   - UPDATE and DELETE always have a WHERE
 *   - scoped to the agent's tenant through a bound parameter, once per table
 *   - SELECT carries a LIMIT within the policy's row cap
 */

export type SqlVerb = "select" | "insert" | "update" | "delete";

export interface SqlReading {
  verb: SqlVerb | null;
  tables: string[];
}

const DANGEROUS = /\b(?:pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|pg_ls_waldir|lo_import|lo_export|lo_get|lo_put|dblink\w*|pg_sleep\w*|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|set_config|pg_advisory\w*|query_to_xml|xpath|copy|program|pg_execute_server_program|current_setting|version|inet_server_addr)\s*\(|\bcopy\b|\bexecute\b|\binto\s+outfile\b|\bload_file\b|\bxp_cmdshell\b/i;
const CATALOG = /\b(?:pg_catalog|information_schema|pg_shadow|pg_authid|pg_user|pg_roles|pg_settings|pg_stat_activity|pg_hba_file_rules|pg_proc|pg_class|pg_namespace)\b/i;
const TABLE_REF = /\b(?:from|join|into|update)\s+((?:"[^"]+"|[a-z_][a-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[a-z_][a-z0-9_$]*))?)/gi;

/** Removes string literals (after checking them for tricks) so keywords inside strings don't count. */
function stripLiterals(sql: string, f: Findings): string {
  if (/\$[a-z_]*\$/i.test(sql)) f.hard("sql.dollar_quoting", "Dollar-quoted strings are not accepted (used to smuggle code blocks).");
  if (/\bE'/i.test(sql)) f.hard("sql.escape_string", "Escape-string literals are not accepted; pass values as parameters.");
  return sql.replace(/'(?:[^']|'')*'/g, "''");
}

export function analyzeSql(
  sql: string,
  params: unknown[],
  ctx: { tenantId: string; maxRows: number; tables: Record<string, string[]>; protectedTables: ReadonlySet<string> },
  f: Findings,
): SqlReading {
  if (/--|\/\*/.test(sql)) f.hard("sql.comments", "SQL comments are not accepted (a common way to hide or truncate clauses).");
  let s = stripLiterals(sql, f).replace(/\s+/g, " ").trim().replace(/;\s*$/, "");
  if (s.includes(";")) f.hard("sql.multiple_statements", "Exactly one statement per call.");
  s = s.toLowerCase();

  const first = /^\s*(\w+)/.exec(s)?.[1] ?? "";
  let verb: SqlVerb | null = null;
  if (first === "with") {
    verb = /\)\s*(insert|update|delete)\b/.test(s) ? null : "select";
    if (!verb) f.hard("sql.cte_write", "Data-modifying WITH queries are not accepted.");
  } else if (["select", "insert", "update", "delete"].includes(first)) {
    verb = first as SqlVerb;
  } else {
    f.hard("sql.statement_not_allowed", `${first.toUpperCase() || "This"} statements are not available to agents (only SELECT, INSERT, UPDATE, DELETE).`);
  }
  // A SELECT that also writes (select … into, or a writing subquery) is a write.
  if (verb === "select" && /\b(?:insert|update|delete|into)\b/.test(s.replace(/^with .*?\)\s*select/, "select"))) {
    f.hard("sql.hidden_write", "A SELECT that writes is not accepted.");
  }
  if (DANGEROUS.test(s)) f.hard("sql.dangerous_function", "Uses a function or statement that reaches the server, files, the network or other sessions.");
  if (CATALOG.test(s)) f.hard("sql.catalog_access", "System catalogs and settings are not available to agents.");

  // FROM also appears inside some functions and operators; drop those first.
  const forTables = s
    .replace(/\b(?:extract|substring|trim|position|overlay)\s*\([^()]*\)/g, "fn()")
    .replace(/\bis\s+(?:not\s+)?distinct\s+from\b/g, "=");
  const tables: string[] = [];
  for (const m of forTables.matchAll(TABLE_REF)) {
    const ref = m[1]!.replace(/"/g, "").replace(/\s/g, "");
    const [schema, name] = ref.includes(".") ? ref.split(".") : ["public", ref];
    if (schema !== "public") f.hard("sql.schema", `Only the public schema is available (${ref}).`);
    if (name && !tables.includes(name)) tables.push(name);
  }
  if (!tables.length && verb) f.hard("sql.no_table", "The statement must name the table it reads or changes.");
  for (const t of tables) {
    if (ctx.protectedTables.has(t)) f.hard("db.protected_table", `${t} holds identities, secrets or audit history.`);
    else if (!ctx.tables[t]) f.hard("db.table_not_allowed", `${t} is not opened to agents by this organisation's policy.`);
    else if (verb && !ctx.tables[t]!.includes(verb)) f.hard("db.operation_not_allowed", `${verb} on ${t} is not allowed.`);
  }

  if ((verb === "update" || verb === "delete") && !/\bwhere\b/.test(s)) {
    f.hard("sql.unbounded_write", `${verb.toUpperCase()} without WHERE would touch every row.`);
  }

  // Tenant scope: tenant_id = $n with params[n-1] === the agent's tenant, once per table.
  const bound = [...s.matchAll(/(?:^|[\s(,.])"?tenant_id"?\s*=\s*\$(\d+)/g)].map((m) => Number(m[1]));
  let scoped = bound.filter((n) => params[n - 1] === ctx.tenantId).length;
  if (verb === "insert") {
    const cols = /insert into [^(]+\(([^)]*)\)\s*values\s*\(([^)]*)\)/.exec(s);
    if (cols) {
      const names = cols[1]!.split(",").map((c) => c.trim().replace(/"/g, ""));
      const values = cols[2]!.split(",").map((v) => v.trim());
      const i = names.indexOf("tenant_id");
      const ph = i >= 0 ? /^\$(\d+)$/.exec(values[i] ?? "") : null;
      if (ph && params[Number(ph[1]) - 1] === ctx.tenantId) scoped++;
    }
  }
  if (bound.some((n) => params[n - 1] !== ctx.tenantId)) f.hard("sql.foreign_tenant", "A tenant_id parameter names another organisation.");
  if (verb && scoped < tables.length) {
    f.hard("sql.tenant_scope", "Every table must be restricted with tenant_id = $n, bound to the agent's own organisation.");
  }

  if (verb === "select") {
    const limit = /\blimit\s+(\d+)\s*$/.exec(s) ?? /\blimit\s+(\d+)\b/.exec(s);
    if (!limit) f.soft("sql.no_limit", "SELECT needs a LIMIT.");
    else if (Number(limit[1]) > ctx.maxRows) f.soft("db.row_limit", `LIMIT ${limit[1]} exceeds ${ctx.maxRows}.`);
  }
  return { verb, tables };
}
