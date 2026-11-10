#!/usr/bin/env node
// Legion pilot preflight: the deployment checklist, as code.
//
//   node ops/pilot-preflight.mjs --env .env.pilot --compose docker-compose.pilot.yml
//   node ops/pilot-preflight.mjs --env .env.pilot --db --database-url postgresql://legion_app:…@127.0.0.1:5432/legion
//   add --json for machine-readable output
//
// Exit code 0: no FAIL (WARNs are listed and need a decision). 1: at least one
// FAIL — do not deploy. It reads files and, with --db, makes read-only checks
// (every probe runs inside a transaction that is rolled back). It never prints
// a secret value.
//
// Needs `npm run build -w server` first for the exact key-format check
// (server/dist/keyring-parse.js); without it that one check is a WARN.
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
const flag = (name) => args.includes(`--${name}`);

const results = [];
const add = (level, area, id, text, detail) => results.push({ level, area, id, text, ...(detail ? { detail } : {}) });
const pass = (area, id, text) => add("PASS", area, id, text);
const warn = (area, id, text, detail) => add("WARN", area, id, text, detail);
const fail = (area, id, text, detail) => add("FAIL", area, id, text, detail);
const check = (ok, area, id, okText, failText, detail) => (ok ? pass(area, id, okText) : fail(area, id, failText, detail));

// ---------------------------------------------------------------------------
function parseEnv(text) {
  const env = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (m) env[m[1]] = m[2].replace(/^['"]|['"]$/g, "");
  }
  return env;
}
const PLACEHOLDER = /change-?me|replace|example|placeholder|your-|xxxx|local-|secret$/i;
const strong = (v) => typeof v === "string" && v.length >= 32 && new Set(v).size >= 10 && !PLACEHOLDER.test(v);

// ---------------------------------------------------------------------------
function configChecks(env) {
  const A = "config";
  check(strong(env.JWT_SECRET), A, "jwt", "JWT_SECRET is long and random", "JWT_SECRET is missing, short (<32), repetitive or a placeholder");
  check(strong(env.SOC_AUDIT_KEY), A, "soc-audit-key", "SOC_AUDIT_KEY is set and strong", "SOC_AUDIT_KEY must be set explicitly (32+ random chars); without it the audit chain key is derived from JWT_SECRET and breaks when that rotates");
  check(strong(env.HEALTH_METRICS_TOKEN), A, "metrics-token", "HEALTH_METRICS_TOKEN is set and strong", "HEALTH_METRICS_TOKEN must be set (32+ chars): without it /metrics does not exist and the pilot has no monitoring");
  check(strong(env.POSTGRES_ADMIN_PASSWORD), A, "pg-admin-pw", "database admin password is strong", "POSTGRES_ADMIN_PASSWORD is missing or weak");
  check(strong(env.APP_DB_PASSWORD), A, "pg-app-pw", "application database password is strong", "APP_DB_PASSWORD is missing or weak");

  check(strong(env.PAYMENT_HASH_KEY), A, "payment-hash-key", "PAYMENT_HASH_KEY is set and strong", "PAYMENT_HASH_KEY must be set (32+ random chars): it protects the bank accounts the payment check recognises, and production refuses to start without it");
  const secrets = { JWT_SECRET: env.JWT_SECRET, SOC_AUDIT_KEY: env.SOC_AUDIT_KEY, PAYMENT_HASH_KEY: env.PAYMENT_HASH_KEY, HEALTH_METRICS_TOKEN: env.HEALTH_METRICS_TOKEN, POSTGRES_ADMIN_PASSWORD: env.POSTGRES_ADMIN_PASSWORD, APP_DB_PASSWORD: env.APP_DB_PASSWORD };
  const present = Object.entries(secrets).filter(([, v]) => v);
  const dup = present.filter(([, v], i) => present.findIndex(([, w]) => w === v) !== i).map(([k]) => k);
  check(dup.length === 0, A, "secrets-distinct", "every secret is different from every other", `these secrets reuse another secret's value: ${dup.join(", ")}`);
  check(!env.POSTGRES_ADMIN_PASSWORD || env.POSTGRES_ADMIN_PASSWORD !== env.APP_DB_PASSWORD, A, "pg-pw-split", "the API's database password differs from the admin's", "the API and the admin share a database password: the least-privilege role would be pointless");

  // Encryption keyring: the real parser from the build, never printing the key.
  const keys = env.LEGION_ENCRYPTION_KEYS;
  const parserPath = join(ROOT, "server", "dist", "keyring-parse.js");
  if (!keys || PLACEHOLDER.test(keys)) fail(A, "enc-keys", "LEGION_ENCRYPTION_KEYS is missing or a placeholder (MFA seeds and webhook secrets would not be encrypted with a dedicated key)");
  else if (existsSync(parserPath)) {
    return import(pathToFileURL(parserPath).href).then(({ parseKeyring }) => {
      const r = parseKeyring(keys, env.LEGION_ENCRYPTION_KEY_ID || "");
      check(r.ok, A, "enc-keys", "LEGION_ENCRYPTION_KEYS parses (id:key, 32-byte keys)", `LEGION_ENCRYPTION_KEYS is malformed: ${r.error}`);
    }).then(() => rest(env));
  } else warn(A, "enc-keys", "LEGION_ENCRYPTION_KEYS is set but not format-checked (run `npm run build -w server` first)");
  return rest(env);
}

async function rest(env) {
  const A = "config";
  const url = (v) => { try { return new URL(v); } catch { return null; } };
  const front = url(env.FRONTEND_URL ?? "");
  check(front?.protocol === "https:", A, "frontend-https", "FRONTEND_URL is https", "FRONTEND_URL must be an https:// URL");
  check(front && !["localhost", "127.0.0.1", "example.com"].includes(front.hostname) && !/\.example\.com$/.test(front.hostname), A, "frontend-host", `FRONTEND_URL points at ${front?.hostname}`, "FRONTEND_URL still names a placeholder or local host");
  const origins = (env.CORS_ORIGINS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  check(origins.length > 0 && origins.every((o) => o.startsWith("https://") && o !== "*"), A, "cors", "CORS_ORIGINS lists only https origins", "CORS_ORIGINS must list explicit https:// origins (no *, no http)");
  check(!!front && origins.includes(front.origin), A, "cors-frontend", "the dashboard origin is allowed", "CORS_ORIGINS does not include the FRONTEND_URL origin");
  check(!!env.TRUSTED_PROXIES && !/^\s*(true|\*|0\.0\.0\.0\/0)\s*$/i.test(env.TRUSTED_PROXIES), A, "trusted-proxies", "TRUSTED_PROXIES is an explicit list", "TRUSTED_PROXIES must name the proxy (e.g. 127.0.0.1,172.16.0.0/12), never 'true' or a wildcard: otherwise anyone can forge their IP");
  try {
    const { parseTrustedProxies } = await import(pathToFileURL(join(ROOT, "server", "dist", "edge-parse.js")).href);
    const r = parseTrustedProxies(env.TRUSTED_PROXIES ?? "");
    check(r.ok, A, "trusted-proxies-parse", "TRUSTED_PROXIES parses", `TRUSTED_PROXIES is malformed: ${r.error}`);
  } catch { /* build not present: covered by the warning above */ }
  check(!!env.SMTP_HOST && !PLACEHOLDER.test(env.SMTP_HOST), A, "smtp", "SMTP_HOST is set", "SMTP_HOST is required in production (invitations, resets, alert mail)");
  check((env.REFRESH_COOKIE_PATH ?? "") === "/api/auth", A, "cookie-path", "REFRESH_COOKIE_PATH matches the /api proxy path", "REFRESH_COOKIE_PATH should be /api/auth behind the shipped nginx config (the browser sees the refresh endpoint under /api)");
  for (const k of ["NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_WS_URL"]) {
    const u = url(env[k] ?? "");
    check(!!u && (u.protocol === "https:" || u.protocol === "wss:"), A, k.toLowerCase(), `${k} is TLS`, `${k} must be https:// / wss://`);
  }
  // The pilot's own safety switches must not be overridden from the env file.
  for (const [k, bad] of [["POLICY_ENGINE_MODE", ["off"]], ["ORCHESTRATOR_AUTO_MODE", []]]) {
    if (env[k] !== undefined) warn(A, `override-${k.toLowerCase()}`, `${k}=${env[k]} is set in the env file; docker-compose.pilot.yml fixes this value and ignores it`);
  }
  if (env.DEPLOYMENT_MODE && env.DEPLOYMENT_MODE !== "self-hosted") fail(A, "mode", `DEPLOYMENT_MODE=${env.DEPLOYMENT_MODE}: the pilot is one workspace, self-hosted (no public sign-up, no billing)`);
  if (env.AI_PROVIDER || env.OPENROUTER_API_KEY || env.GROQ_API_KEY) warn(A, "ai-provider", "an AI provider is configured: alert text would leave your infrastructure. Confirm the data-processing terms and keep the workspace in strict data mode (PILOT.md §4)");
  else pass(A, "ai-provider", "no external AI provider configured (explanations use Legion's own text)");
}

// ---------------------------------------------------------------------------
function dockerfileChecks() {
  const A = "container";
  for (const f of ["server/Dockerfile", "frontend/Dockerfile"]) {
    const text = readFileSync(join(ROOT, f), "utf8");
    const stages = text.split(/^FROM /m).slice(1);
    const last = stages[stages.length - 1] ?? "";
    const user = [...last.matchAll(/^USER\s+(\S+)/gm)].pop()?.[1];
    check(!!user && !["root", "0"].includes(user), A, `${f}:user`, `${f}: final image runs as '${user}'`, `${f}: final image does not drop root (no USER, or USER root)`);
    const froms = [...text.matchAll(/^FROM\s+(\S+)/gm)].map((m) => m[1]);
    check(froms.every((i) => !/:latest$/.test(i) && i.includes(":")), A, `${f}:tags`, `${f}: base images use explicit tags`, `${f}: a base image is untagged or :latest`);
    if (froms.some((i) => !i.includes("@sha256:"))) warn(A, `${f}:digest`, `${f}: base image is pinned by tag, not by digest (@sha256:…). Pin digests when the pilot image is built.`);
    check(!/^ADD\s+https?:/m.test(text), A, `${f}:add-url`, `${f}: no remote ADD`, `${f}: downloads with ADD from a URL`);
  }
}

function composeChecks(file) {
  const A = "container";
  let cfg;
  // The compose file reads `.env.pilot` next to itself. Resolve it from a private
  // copy of the env file so the check works wherever the real one lives.
  const tmp = mkdtempSync(join(tmpdir(), "legion-preflight-"));
  try {
    if (opt("env")) copyFileSync(resolve(opt("env")), join(tmp, ".env.pilot"));
    const out = execFileSync("docker", ["compose", "--project-directory", opt("env") ? tmp : dirname(resolve(file)), ...(opt("env") ? ["--env-file", join(tmp, ".env.pilot")] : []), "-f", resolve(file), "config", "--format", "json"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    cfg = JSON.parse(out);
  } catch (e) {
    fail(A, "compose", `docker compose could not resolve ${file}`, String(e.stderr || e.message).split("\n").slice(0, 3).join(" | "));
    return;
  } finally { rmSync(tmp, { recursive: true, force: true }); }
  pass(A, "compose", `${file} resolves with the given env file`);
  const svc = cfg.services ?? {};
  const names = Object.keys(svc);
  for (const n of names) {
    const s = svc[n];
    check(s.read_only === true, A, `${n}:read-only`, `${n}: read-only root filesystem`, `${n}: root filesystem is writable`);
    check((s.cap_drop ?? []).includes("ALL"), A, `${n}:cap-drop`, `${n}: all capabilities dropped${s.cap_add?.length ? ` (adds back ${s.cap_add.join(",")})` : ""}`, `${n}: capabilities are not dropped`);
    check((s.security_opt ?? []).some((o) => o.startsWith("no-new-privileges")), A, `${n}:nnp`, `${n}: no-new-privileges`, `${n}: can gain privileges`);
    check(!!s.mem_limit || !!s.deploy?.resources?.limits?.memory, A, `${n}:mem`, `${n}: memory limit set`, `${n}: no memory limit`);
    check(!!s.pids_limit, A, `${n}:pids`, `${n}: process limit set`, `${n}: no process limit`);
    check(s.privileged !== true && !s.pid && s.network_mode !== "host" && !(s.volumes ?? []).some((v) => String(v.source ?? "").includes("docker.sock")), A, `${n}:no-host`, `${n}: not privileged, no host pid/network, no docker socket`, `${n}: privileged / host namespace / docker socket`);
    const img = s.image ?? "";
    if (img && !/:local$/.test(img)) check(img.includes(":") && !img.endsWith(":latest"), A, `${n}:image-tag`, `${n}: image tag pinned (${img})`, `${n}: image is untagged or latest`);
    if (!s.healthcheck && n !== "db-provision") warn(A, `${n}:health`, `${n}: no healthcheck`);
    for (const p of s.ports ?? []) check(p.host_ip === "127.0.0.1", A, `${n}:port-${p.published}`, `${n}: port ${p.published} is published on 127.0.0.1 only`, `${n}: port ${p.published} is published on ${p.host_ip || "ALL interfaces"}`);
  }
  for (const n of ["postgres", "redis"]) check(!(svc[n]?.ports ?? []).length, A, `${n}:unpublished`, `${n}: not published at all`, `${n}: publishes a port`);
  const dataNet = cfg.networks?.data;
  check(dataNet?.internal === true, A, "net-internal", "the data network is internal (no inbound, no outbound)", "the data network is not internal");
  for (const n of ["postgres", "redis"]) check(Object.keys(svc[n]?.networks ?? {}).every((x) => x === "data"), A, `${n}:networks`, `${n}: only on the internal network`, `${n}: also on a routable network`);
  const be = svc.backend?.environment ?? {};
  const want = { NODE_ENV: "production", DEPLOYMENT_MODE: "self-hosted", POLICY_ENGINE_MODE: "shadow", ORCHESTRATOR_AUTO_MODE: "shadow", SEED_DEMO_DATA: "false", COOKIE_SECURE: "true", RUNTIME_WORKER: "on" };
  for (const [k, v] of Object.entries(want)) check(be[k] === v, "pilot-safety", `backend:${k}`, `backend ${k}=${v}`, `backend ${k} is '${be[k] ?? "unset"}', expected '${v}'`);
  const dbUrl = String(be.DATABASE_URL ?? "");
  check(/\/\/legion_app:/.test(dbUrl) && !/\/\/(postgres|legion_admin|root):/.test(dbUrl), "database", "backend:db-role", "the API connects as the least-privilege role legion_app", "the API's DATABASE_URL does not use legion_app");
  check(!("DATABASE_ADMIN_URL" in be), "database", "backend:no-admin-url", "the superuser connection string is not given to the API", "the API container receives DATABASE_ADMIN_URL");
  check(!("POSTGRES_ADMIN_PASSWORD" in be), "database", "backend:no-admin-pw", "the admin password is not given to the API container", "the API container receives the admin password");
  check("db-provision" in svc && svc.backend?.depends_on?.["db-provision"]?.condition === "service_completed_successfully", "database", "provision-first", "the API waits for role provisioning to finish", "the API does not wait for db-provision");
}

// ---------------------------------------------------------------------------
function hostChecks(envFile) {
  const A = "host";
  if (!envFile) return;
  const mode = statSync(envFile).mode & 0o777;
  check((mode & 0o077) === 0, A, "env-mode", `${envFile} is mode ${mode.toString(8)} (owner only)`, `${envFile} is readable by others (mode ${mode.toString(8)}): chmod 600`);
  if (!resolve(envFile).startsWith(ROOT + "/")) pass(A, "env-ignored", `${envFile} is outside the repository (it cannot be committed)`);
  else try {
    execFileSync("git", ["check-ignore", "-q", envFile], { cwd: ROOT, stdio: "ignore" });
    pass(A, "env-ignored", `${envFile} is ignored by git`);
  } catch (e) {
    if (e.status === 1) fail(A, "env-ignored", `${envFile} is NOT ignored by git: a commit would publish every secret`);
    else warn(A, "env-ignored", `could not ask git whether ${envFile} is ignored`);
  }
  const nginx = existsSync(join(ROOT, "deploy", "nginx.conf")) ? readFileSync(join(ROOT, "deploy", "nginx.conf"), "utf8") : "";
  check(/limit_req_zone/.test(nginx) && /proxy_pass/.test(nginx), A, "nginx", "deploy/nginx.conf provides rate limits and the reverse proxy", "deploy/nginx.conf is missing or lacks rate limits");
  warn(A, "tls-manual", "TLS certificates and the public listener are the host's nginx/certbot: verify with `curl -sI https://YOUR-DOMAIN` and an SSL Labs / testssl.sh run (PILOT.md §5)");
}

// ---------------------------------------------------------------------------
async function dbChecks(urlStr) {
  const A = "database";
  const { default: pg } = await import(pathToFileURL(join(ROOT, "node_modules", "pg", "lib", "index.js")).href).catch(() => import("pg"));
  const client = new pg.Client({ connectionString: urlStr, connectionTimeoutMillis: 8000 });
  try { await client.connect(); } catch (e) { fail(A, "connect", `cannot connect: ${e.message}`); return; }
  try {
    const me = (await client.query("SELECT current_user AS u, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication, rolcanlogin FROM pg_roles WHERE rolname = current_user")).rows[0];
    check(!me.rolsuper && !me.rolcreaterole && !me.rolcreatedb && !me.rolbypassrls && !me.rolreplication, A, "role-attrs", `role ${me.u}: no superuser, CREATEROLE, CREATEDB, BYPASSRLS or REPLICATION`, `role ${me.u} has elevated attributes (${["rolsuper", "rolcreaterole", "rolcreatedb", "rolbypassrls", "rolreplication"].filter((k) => me[k]).join(", ")})`);
    check(me.u !== "postgres", A, "not-postgres", "the API does not use the 'postgres' role", "the API connects as 'postgres'");
    const memberships = (await client.query("SELECT r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)")).rows.map((r) => r.rolname);
    check(memberships.length === 0, A, "memberships", "the role is a member of no other role", `the role is a member of: ${memberships.join(", ")}`);

    const probe = async (id, sql, okText, badText) => {
      await client.query("BEGIN");
      try { await client.query(sql); await client.query("ROLLBACK"); fail(A, id, badText); }
      catch (e) { await client.query("ROLLBACK").catch(() => {}); pass(A, id, `${okText} (${String(e.code ?? "error")})`); }
    };
    await probe("no-file-read", "SELECT pg_read_file('/etc/passwd')", "cannot read server files", "the role CAN read server files");
    await probe("no-program", "COPY (SELECT 1) TO PROGRAM 'true'", "cannot run programs on the server", "the role CAN run programs on the database server");
    await probe("no-create-role", "CREATE ROLE legion_preflight_probe", "cannot create roles", "the role CAN create roles");
    await probe("no-ext", "CREATE EXTENSION IF NOT EXISTS file_fdw", "cannot create untrusted extensions", "the role CAN create extensions");

    const files = existsSync(join(ROOT, "server", "src", "db", "migrations")) ? readdirSync(join(ROOT, "server", "src", "db", "migrations")).filter((f) => f.endsWith(".sql")).length : 0;
    const applied = (await client.query("SELECT count(*)::int AS n FROM legion_migrations").catch(() => ({ rows: [{ n: -1 }] }))).rows[0].n;
    if (applied === -1) warn(A, "migrations", "legion_migrations does not exist yet: the API has not started against this database (expected before the first boot)");
    else check(applied === files, A, "migrations", `${applied}/${files} versioned migrations applied`, `${applied} migrations applied but ${files} exist: deploy the matching build before starting`);

    const trig = (await client.query("SELECT count(*)::int AS n FROM pg_trigger WHERE tgname LIKE '%append_only%' AND NOT tgisinternal").catch(() => ({ rows: [{ n: 0 }] }))).rows[0].n;
    if (applied === -1) { /* nothing to check yet */ } else check(trig >= 6, A, "append-only", `${trig} append-only triggers protect the audit and decision tables`, `only ${trig} append-only triggers found`);

    const live = (await client.query("SELECT count(*)::int AS n FROM action_requests WHERE execution_mode NOT IN ('shadow','simulation')").catch(() => ({ rows: [{ n: 0 }] }))).rows[0].n;
    check(live === 0, "pilot-safety", "no-live-actions", "no action exists in a mode other than shadow/simulation", `${live} action(s) exist outside shadow/simulation`);
    const ten = (await client.query("SELECT count(*)::int AS n FROM tenants").catch(() => ({ rows: [{ n: 0 }] }))).rows[0].n;
    if (ten > 1) warn("pilot-safety", "one-tenant", `${ten} workspaces exist; the pilot is meant to start with ONE isolated test workspace`); else pass("pilot-safety", "one-tenant", `${ten} workspace(s)`);

    // Honest finding: an owner can switch a trigger off.
    const owns = (await client.query("SELECT c.relname FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner WHERE r.rolname = current_user AND c.relname IN ('audit_log','soc_audit_events','policy_decisions','action_events')").catch(() => ({ rows: [] }))).rows.length;
    if (owns > 0) warn(A, "owner-can-disable-triggers", `the API role OWNS ${owns} append-only table(s); an owner can DISABLE their triggers. The SOC audit chain is keyed (tampering stays detectable) but the plain audit_log is not. Mitigation: ship chain checkpoints off-host; fix: split migrator/runtime roles (PILOT.md §4, risk R-3).`);
    const ssl = (await client.query("SELECT coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS ssl")).rows[0].ssl;
    if (!ssl) warn(A, "db-tls", "this database connection is not TLS. Acceptable only on the internal docker network or a loopback socket; use DB_SSL=true with a verified CA for any managed or remote database.");
    else pass(A, "db-tls", "the database connection uses TLS");
  } finally { await client.end().catch(() => {}); }
}

// ---------------------------------------------------------------------------
async function main() {
  const envFile = opt("env");
  if (envFile && !existsSync(envFile)) { console.error(`env file not found: ${envFile}`); process.exit(2); }
  if (envFile) { await configChecks(parseEnv(readFileSync(envFile, "utf8"))); hostChecks(envFile); }
  dockerfileChecks();
  if (opt("compose")) composeChecks(opt("compose"));
  if (flag("db")) {
    const url = opt("database-url") || process.env.DATABASE_URL;
    if (!url) fail("database", "url", "--db needs --database-url (or DATABASE_URL)"); else await dbChecks(url);
  }
  const counts = { PASS: 0, WARN: 0, FAIL: 0 };
  for (const r of results) counts[r.level]++;
  if (flag("json")) console.log(JSON.stringify({ counts, results }, null, 2));
  else {
    let area = "";
    for (const r of results.sort((a, b) => a.area.localeCompare(b.area))) {
      if (r.area !== area) { area = r.area; console.log(`\n[${area}]`); }
      console.log(`  ${r.level.padEnd(4)} ${r.text}${r.detail ? `  — ${r.detail}` : ""}`);
    }
    console.log(`\n${counts.PASS} passed, ${counts.WARN} warning(s), ${counts.FAIL} FAILED`);
    console.log(counts.FAIL ? "NOT READY: fix every FAIL before deploying." : counts.WARN ? "No blockers. Decide on each warning, and record the decision in PILOT.md §12." : "Ready.");
  }
  process.exit(counts.FAIL ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(2); });
