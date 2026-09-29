import { loadModule, parseSync } from "libpg-query";
import type { Findings } from "./findings.js";

/*
 * Tenant scope, decided on PostgreSQL's own parse tree.
 *
 * The regular expressions in sql.ts look for the text "tenant_id = $n". Text is
 * not structure: every one of these contains that text and still reads other
 * organisations' rows, and each got past the text check:
 *
 *   WHERE NOT (tenant_id = $1)                       -- scope inverted
 *   WHERE (tenant_id = $1) IS NOT TRUE               -- scope inverted
 *   WHERE CASE WHEN tenant_id = $1 THEN false ELSE true END
 *   FROM alerts a, alerts b WHERE a.tenant_id = $1   -- b never counted
 *   FROM alerts a JOIN alerts b ON true
 *     WHERE a.tenant_id = $1 AND a.tenant_id = $1    -- counted twice, b free
 *   SELECT "set_config"('legion.agent_tenant_id', …) -- quoted name dodges the list
 *
 * So the rule is structural. For every SELECT / UPDATE / DELETE at every level
 * (subqueries, CTE bodies, UNION branches), every table it reads must be
 * restricted by a top-level AND conjunct `<that table>.tenant_id = $n` whose
 * parameter is the caller's own tenant — in the WHERE clause, or in the ON of a
 * join that actually filters that table. A conjunct is the only position where
 * a condition is guaranteed to hold for every returned row; anywhere else (under
 * NOT, OR, CASE, IS …) it is just an expression.
 * Writes may not move rows to another tenant, and INSERT … ON CONFLICT DO UPDATE
 * (which updates whatever row it collides with) must be scoped too.
 *
 * The parser is libpg-query: the real PostgreSQL grammar compiled to WASM, so
 * "what Postgres will execute" and "what was checked" are the same tree.
 */

await loadModule();

type Node = Record<string, any>;

/** Functions that reach the server, files, the network, other sessions or settings. */
const FORBIDDEN_FUNCTION = /^(?:pg_|lo_|dblink|set_config$|current_setting$|query_to_xml|table_to_xml|cursor_to_xml|schema_to_xml|database_to_xml|xpath|version$|inet_server_|inet_client_|txid_|current_user$|session_user$|current_database$|current_schema)/;
const CATALOG_SCHEMAS = new Set(["pg_catalog", "information_schema", "pg_toast"]);

interface Ref { name: string; relname: string }

export interface AstReading { ok: boolean; tables: string[] }

function unwrap(e: Node | undefined): Node | undefined {
  let n = e;
  while (n?.TypeCast) n = n.TypeCast.arg;
  return n;
}

function paramTenant(expr: Node | undefined, params: unknown[], tenantId: string): "own" | "foreign" | null {
  const e = unwrap(expr);
  if (!e?.ParamRef) return null;
  return params[e.ParamRef.number - 1] === tenantId ? "own" : "foreign";
}

/** `x.tenant_id` → "x"; bare `tenant_id` → null; anything else → undefined. */
function tenantColumn(expr: Node | undefined): string | null | undefined {
  const fields: Node[] | undefined = unwrap(expr)?.ColumnRef?.fields;
  if (!fields) return undefined;
  const names = fields.map((f) => f.String?.sval as string | undefined);
  if (names[names.length - 1] !== "tenant_id") return undefined;
  return names.length === 1 ? null : names[names.length - 2] ?? null;
}

function conjuncts(expr: Node | undefined): Node[] {
  if (!expr) return [];
  if (expr.BoolExpr?.boolop === "AND_EXPR") return (expr.BoolExpr.args as Node[]).flatMap(conjuncts);
  return [expr];
}

/** If this conjunct is `<q>.tenant_id = <own tenant param>`, the qualifier (null = unqualified). */
function scopeQualifier(conj: Node, params: unknown[], tenantId: string): string | null | undefined {
  const a = conj.A_Expr;
  if (!a || a.kind !== "AEXPR_OP") return undefined;
  if ((a.name as Node[]).map((n) => n.String?.sval).join(".") !== "=") return undefined;
  for (const [col, val] of [[a.lexpr, a.rexpr], [a.rexpr, a.lexpr]] as const) {
    const q = tenantColumn(col);
    if (q !== undefined && paramTenant(val, params, tenantId) === "own") return q;
  }
  return undefined;
}

class Checker {
  readonly tables = new Set<string>();
  private readonly ctes: string[][] = [];

  constructor(private readonly params: unknown[], private readonly tenantId: string, private readonly f: Findings) {}

  private isCte(name: string): boolean {
    return this.ctes.some((level) => level.includes(name));
  }

  /** Walks FROM items, collecting table references and the join conditions that filter them. */
  private fromItem(item: Node, out: Ref[], scopes: Array<{ targets: Ref[]; expr: Node }>): void {
    if (item.RangeVar) {
      const rv = item.RangeVar;
      const schema = rv.schemaname as string | undefined;
      if (schema && CATALOG_SCHEMAS.has(schema)) this.f.hard("sql.catalog_access", "System catalogs and settings are not available to agents.");
      else if (schema && schema !== "public") this.f.hard("sql.schema", `Only the public schema is available (${schema}.${rv.relname}).`);
      const relname = rv.relname as string;
      if (!schema && this.isCte(relname)) return; // a CTE: its own body is checked where it is defined
      this.tables.add(relname);
      out.push({ name: (rv.alias?.aliasname as string | undefined) ?? relname, relname });
      return;
    }
    if (item.JoinExpr) {
      const j = item.JoinExpr;
      const left: Ref[] = [], right: Ref[] = [];
      this.fromItem(j.larg, left, scopes);
      this.fromItem(j.rarg, right, scopes);
      out.push(...left, ...right);
      if (j.quals) {
        // ON filters only the side(s) whose rows it can remove.
        const targets = j.jointype === "JOIN_INNER" ? [...left, ...right]
          : j.jointype === "JOIN_LEFT" ? right
          : j.jointype === "JOIN_RIGHT" ? left
          : [];
        scopes.push({ targets, expr: j.quals });
      }
      if (j.usingClause || j.isNatural) {
        this.f.hard("sql.join_form", "Use JOIN … ON with explicit conditions (USING / NATURAL joins are not accepted).");
      }
      return;
    }
    if (item.RangeSubselect) return; // the subquery is a statement of its own and is checked as one
    if (item.RangeFunction || item.RangeTableFunc || item.RangeTableSample) {
      this.f.hard("sql.table_function", "Only tables may appear in FROM; functions and table samples are not accepted.");
      return;
    }
    this.f.hard("sql.unsupported", "This form of FROM clause is not accepted.");
  }

  /** Every reference must be restricted by a conjunct naming it. */
  private requireScoped(kind: string, refs: Ref[], where: Node | undefined, joinScopes: Array<{ targets: Ref[]; expr: Node }>): void {
    if (refs.length === 0) return;
    const scoped = new Set<Ref>();
    const apply = (targets: Ref[], expr: Node | undefined) => {
      for (const c of conjuncts(expr)) {
        const q = scopeQualifier(c, this.params, this.tenantId);
        if (q === undefined) continue;
        for (const r of targets) {
          if (q === null ? refs.length === 1 : q === r.name) scoped.add(r);
        }
      }
    };
    apply(refs, where);
    for (const s of joinScopes) apply(s.targets, s.expr);
    const missing = refs.filter((r) => !scoped.has(r));
    if (missing.length) {
      this.f.hard(
        "sql.tenant_scope",
        `Every table must be restricted with tenant_id = $n, bound to the agent's own organisation, as a condition every row must meet (${kind}: ${missing.map((r) => r.name === r.relname ? r.name : `${r.relname} ${r.name}`).join(", ")} is not).`,
      );
    }
  }

  private requireOwnTenantValue(targets: Node[] | undefined, what: string): void {
    for (const t of targets ?? []) {
      const rt = t.ResTarget;
      if (rt?.name === "tenant_id" && paramTenant(rt.val, this.params, this.tenantId) !== "own") {
        this.f.hard("sql.tenant_move", `${what} may not set tenant_id to anything but the agent's own organisation.`);
      }
    }
  }

  private withClause(w: Node | undefined): boolean {
    if (!w) return false;
    this.ctes.push((w.ctes as Node[]).map((c) => c.CommonTableExpr?.ctename as string));
    return true;
  }

  /** Recursively visits every node; statements get their level check on the way. */
  visit(node: unknown): void {
    if (Array.isArray(node)) { for (const n of node) this.visit(n); return; }
    if (!node || typeof node !== "object") return;
    const n = node as Node;

    if (n.FuncCall) {
      const names = (n.FuncCall.funcname as Node[]).map((x) => String(x.String?.sval ?? "").toLowerCase());
      const name = names[names.length - 1] ?? "";
      // SQL-standard syntax (EXTRACT, SUBSTRING, TRIM …) is qualified with
      // pg_catalog by the parser itself; only a schema the author wrote counts.
      const written = n.FuncCall.funcformat !== "COERCE_SQL_SYNTAX";
      if (FORBIDDEN_FUNCTION.test(name) || (written && names.slice(0, -1).some((s) => CATALOG_SCHEMAS.has(s)))) {
        this.f.hard("sql.dangerous_function", `Uses a function that reaches the server, files, the network, other sessions or settings (${name}).`);
      }
    }
    if (n.SQLValueFunction) {
      // CURRENT_USER, SESSION_USER, CURRENT_CATALOG …: identity of the connection, not data.
      this.f.hard("sql.dangerous_function", "Session information functions are not available to agents.");
    }

    if (n.SelectStmt) return this.select(n.SelectStmt);
    if (n.UpdateStmt) return this.update(n.UpdateStmt);
    if (n.DeleteStmt) return this.delete(n.DeleteStmt);
    if (n.InsertStmt) return this.insert(n.InsertStmt);

    for (const v of Object.values(n)) this.visit(v);
  }

  private select(s: Node): void {
    const pushed = this.withClause(s.withClause);
    if (s.withClause) this.visit(s.withClause);
    if (s.intoClause) this.f.hard("sql.hidden_write", "A SELECT that writes is not accepted.");
    if (s.op && s.op !== "SETOP_NONE") {
      // Set-operation branches are bare SelectStmt bodies, not wrapped nodes.
      if (s.larg) this.select(s.larg);
      if (s.rarg) this.select(s.rarg);
    } else {
      const refs: Ref[] = [];
      const scopes: Array<{ targets: Ref[]; expr: Node }> = [];
      for (const item of (s.fromClause as Node[] | undefined) ?? []) this.fromItem(item, refs, scopes);
      this.requireScoped("SELECT", refs, s.whereClause, scopes);
      for (const key of ["fromClause", "targetList", "whereClause", "groupClause", "havingClause", "sortClause", "valuesLists", "distinctClause", "windowClause", "limitCount", "limitOffset"]) {
        this.visit(s[key]);
      }
    }
    if (pushed) this.ctes.pop();
  }

  private update(u: Node): void {
    const pushed = this.withClause(u.withClause);
    if (u.withClause) this.visit(u.withClause);
    const refs: Ref[] = [];
    const scopes: Array<{ targets: Ref[]; expr: Node }> = [];
    this.fromItem({ RangeVar: u.relation }, refs, scopes);
    for (const item of (u.fromClause as Node[] | undefined) ?? []) this.fromItem(item, refs, scopes);
    this.requireScoped("UPDATE", refs, u.whereClause, scopes);
    this.requireOwnTenantValue(u.targetList, "UPDATE");
    for (const key of ["targetList", "whereClause", "fromClause", "returningList"]) this.visit(u[key]);
    if (pushed) this.ctes.pop();
  }

  private delete(d: Node): void {
    const pushed = this.withClause(d.withClause);
    if (d.withClause) this.visit(d.withClause);
    const refs: Ref[] = [];
    const scopes: Array<{ targets: Ref[]; expr: Node }> = [];
    this.fromItem({ RangeVar: d.relation }, refs, scopes);
    for (const item of (d.usingClause as Node[] | undefined) ?? []) this.fromItem(item, refs, scopes);
    this.requireScoped("DELETE", refs, d.whereClause, scopes);
    for (const key of ["whereClause", "usingClause", "returningList"]) this.visit(d[key]);
    if (pushed) this.ctes.pop();
  }

  private insert(i: Node): void {
    const pushed = this.withClause(i.withClause);
    if (i.withClause) this.visit(i.withClause);
    const refs: Ref[] = [];
    this.fromItem({ RangeVar: i.relation }, refs, []);
    const cols = ((i.cols as Node[] | undefined) ?? []).map((c) => c.ResTarget?.name as string);
    const at = cols.indexOf("tenant_id");
    const values: Node[][] | undefined = i.selectStmt?.SelectStmt?.valuesLists?.map((l: Node) => l.List.items);
    if (!values) {
      this.f.hard("sql.insert_select", "INSERT must use VALUES with an explicit tenant_id (INSERT … SELECT is not accepted).");
    } else if (at < 0 || values.some((row) => paramTenant(row[at], this.params, this.tenantId) !== "own")) {
      this.f.hard("sql.tenant_scope", "Every inserted row must set tenant_id = $n, bound to the agent's own organisation.");
    }
    const oc = i.onConflictClause;
    if (oc?.action === "ONCONFLICT_UPDATE") {
      // DO UPDATE changes whichever row the insert collided with — possibly another organisation's.
      const target = refs[0];
      if (target) this.requireScoped("ON CONFLICT DO UPDATE", [target], oc.whereClause, []);
      this.requireOwnTenantValue(oc.targetList, "ON CONFLICT DO UPDATE");
      this.visit(oc.targetList); this.visit(oc.whereClause);
    }
    this.visit(i.selectStmt?.SelectStmt?.valuesLists);
    this.visit(i.returningList);
    if (pushed) this.ctes.pop();
  }
}

/**
 * Parses and checks one statement. `ok: false` means it did not parse (the
 * caller reports that); findings are added to `f` either way.
 */
export function checkSqlAst(sql: string, params: unknown[], tenantId: string, f: Findings): AstReading {
  let stmts: Node[];
  try {
    stmts = (parseSync(sql).stmts ?? []).map((s) => s.stmt as Node);
  } catch {
    f.hard("sql.unparseable", "The statement is not valid PostgreSQL.");
    return { ok: false, tables: [] };
  }
  if (stmts.length !== 1) return { ok: false, tables: [] }; // multiple statements are refused by the caller
  const c = new Checker(params, tenantId, f);
  c.visit(stmts[0]);
  return { ok: true, tables: [...c.tables] };
}
