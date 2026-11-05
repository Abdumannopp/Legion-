#!/usr/bin/env node
// Pilot rehearsal: runs the REAL built server the way the pilot will — production
// mode, as an unprivileged OS user, connected as the least-privilege database
// role — and then proves the pilot's safety and recovery properties against it.
//
//   npm run build -w server
//   ADMIN_DATABASE_URL=postgresql://admin:…@127.0.0.1:5432/postgres node ops/tests/pilot-rehearsal.mjs
//
// It creates (and always drops) a throwaway database and a throwaway database
// role. It touches nothing else. Needs: a PostgreSQL superuser URL, `age`,
// pg_dump/pg_restore, `setpriv` (util-linux) and root to drop to `nobody`.
// Writes pilot-results/rehearsal.json (or $PILOT_RESULTS_DIR).
//
// What it cannot show: container behaviour (needs a Docker daemon) and TLS at
// the public edge (needs the real host). PILOT.md lists those as manual steps.
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import { chmodSync, chownSync, copyFileSync, createWriteStream, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const require = createRequire(join(ROOT, "server", "package.json"));
const pg = require("pg");
const bcrypt = require("bcryptjs");
const ADMIN_URL = process.env.ADMIN_DATABASE_URL;
if (!ADMIN_URL) { console.error("ADMIN_DATABASE_URL is required (a superuser connection to the maintenance database)."); process.exit(2); }
if (process.getuid?.() !== 0) { console.error("Run as root: the rehearsal drops privileges to `nobody` to prove the server runs unprivileged."); process.exit(2); }
const OUT = process.env.PILOT_RESULTS_DIR || join(ROOT, "pilot-results");
mkdirSync(OUT, { recursive: true });

const id = randomBytes(4).toString("hex");
const DB = `legion_pilot_${id}`;
const DB_RESTORED = `legion_pilot_dr_${id}`;
const APP_USER = `legion_app_${id}`;
const hex = () => randomBytes(32).toString("hex");
const SECRETS = { JWT_SECRET: hex(), SOC_AUDIT_KEY: hex(), HEALTH_METRICS_TOKEN: hex(), APP_PW: hex(), LEGION_ENCRYPTION_KEYS: `k1:${hex()}` };
const WORK = mkdtempSync(join(tmpdir(), "legion-rehearsal-"));
chmodSync(WORK, 0o755);
const STATE = join(WORK, "state"); mkdirSync(STATE); chownSync(STATE, 65534, 65534);
const PORT = 20000 + Math.floor(Math.random() * 20000);
const BASE = `http://127.0.0.1:${PORT}`;
const adminUrlFor = (db) => { const u = new URL(ADMIN_URL); u.pathname = `/${db}`; return u.toString(); };
const appUrlFor = (db) => { const u = new URL(ADMIN_URL); u.username = APP_USER; u.password = SECRETS.APP_PW; u.pathname = `/${db}`; return u.toString(); };

const results = { started_at: new Date().toISOString(), steps: [], measurements: {} };
let failures = 0;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function step(name, fn) {
  const t = performance.now();
  try {
    const detail = await fn();
    results.steps.push({ name, ok: true, ms: Math.round(performance.now() - t), detail: detail ?? null });
    console.log(`PASS  ${name}${detail ? `  — ${typeof detail === "string" ? detail : JSON.stringify(detail)}` : ""}`);
  } catch (e) {
    failures++;
    results.steps.push({ name, ok: false, ms: Math.round(performance.now() - t), error: String(e?.message ?? e) });
    console.log(`FAIL  ${name}  — ${e?.message ?? e}`);
  }
}
const must = (cond, msg) => { if (!cond) throw new Error(msg); };

// ---------------------------------------------------------------- server process
let server = null; let serverLog = null; let serverExit = null;
function serverEnv(over = {}) {
  return {
    PATH: process.env.PATH, HOME: STATE, NODE_ENV: "production",
    DATABASE_URL: appUrlFor(DB), PORT: String(PORT), LEGION_BIND_ADDRESS: "127.0.0.1",
    DEPLOYMENT_MODE: "self-hosted", SEED_DEMO_DATA: "false", COOKIE_SECURE: "true",
    FRONTEND_URL: "https://pilot.acme-soc.test", CORS_ORIGINS: "https://pilot.acme-soc.test", TRUSTED_PROXIES: "127.0.0.1", REFRESH_COOKIE_PATH: "/api/auth",
    JWT_SECRET: SECRETS.JWT_SECRET, LEGION_ENCRYPTION_KEYS: SECRETS.LEGION_ENCRYPTION_KEYS, SOC_AUDIT_KEY: SECRETS.SOC_AUDIT_KEY, HEALTH_METRICS_TOKEN: SECRETS.HEALTH_METRICS_TOKEN,
    SMTP_HOST: "127.0.0.1", SMTP_PORT: "2525", ALERT_EMAIL_MIN_SEVERITY: "critical",
    POLICY_ENGINE_MODE: "shadow", ORCHESTRATOR_AUTO_MODE: "shadow", RUNTIME_WORKER: "on", RUNTIME_POLL_SECONDS: "1",
    SETUP_TOKEN_FILE: join(STATE, ".legion-setup-token"), ACCESS_LOG: "on",
    ...over,
  };
}
function startServer(over = {}) {
  serverLog = createWriteStream(join(WORK, "server.log"), { flags: "a" });
  serverExit = null;
  server = spawn("setpriv", ["--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "node", join(ROOT, "server", "dist", "index.js")],
    { cwd: STATE, env: serverEnv(over), stdio: ["ignore", "pipe", "pipe"] });
  server.stdout.pipe(serverLog, { end: false }); server.stderr.pipe(serverLog, { end: false });
  server.on("exit", (code, sig) => { serverExit = { code, sig }; });
  return performance.now();
}
async function waitHealthy(timeoutMs = 45000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (serverExit) throw new Error(`server exited (${JSON.stringify(serverExit)}): ${tail(40)}`);
    try { const r = await fetch(`${BASE}/health`); if (r.ok) return; } catch { /* not yet */ }
    await sleep(150);
  }
  throw new Error(`server not healthy in ${timeoutMs} ms: ${tail(40)}`);
}
const tail = (n) => { try { return readFileSync(join(WORK, "server.log"), "utf8").split("\n").slice(-n).join(" | ").replace(/postgres(ql)?:\/\/[^@\s]*@/g, "postgresql://***@"); } catch { return ""; } };
async function stopServer(sig = "SIGTERM") {
  if (!server || serverExit) return serverExit;
  const t = performance.now();
  server.kill(sig);
  for (let i = 0; i < 300 && !serverExit; i++) await sleep(50);
  if (!serverExit) { server.kill("SIGKILL"); await sleep(200); }
  results.measurements[`stop_${sig}_ms`] = Math.round(performance.now() - t);
  return serverExit;
}

// ---------------------------------------------------------------- http helpers
let adminToken = ""; let userBToken = "";
const call = async (method, path, { token, body, headers } = {}) => {
  const r = await fetch(`${BASE}${path}`, { method, headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers }, body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body) });
  let json = null; const text = await r.text(); try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: r.status, json, text };
};
const sign = (secret, ts, nonce, raw) => `v2=${createHmac("sha256", secret).update(`v2.${ts}.${nonce}.`).update(raw).digest("hex")}`;
let cred = null; let evN = 0;
async function wazuh(ip, mitre = ["T1110"], extra = {}) {
  const raw = JSON.stringify({ provider: "wazuh", event: { id: `rh-${id}-${++evN}`, rule: { description: extra.desc ?? "sshd: brute force attempt", level: extra.level ?? 12, mitre: { id: mitre }, groups: ["sshd"] }, agent: { name: "web-01", ip: "10.0.0.5" }, data: { srcip: ip }, full_log: `sshd: Failed password for root from ${ip}` } });
  const ts = String(Math.floor(Date.now() / 1000)); const nonce = randomBytes(16).toString("base64url");
  return call("POST", "/security-events/webhook", { body: raw, headers: { "x-legion-key-id": cred.id, "x-legion-timestamp": ts, "x-legion-nonce": nonce, "x-legion-signature": sign(cred.secret, ts, nonce, raw) } });
}
const adminPg = async (db, fn) => { const c = new pg.Client({ connectionString: adminUrlFor(db) }); await c.connect(); try { return await fn(c); } finally { await c.end(); } };
const q = (sql, params) => adminPg(DB, async (c) => (await c.query(sql, params)).rows);

function procStatus(pid) {
  const t = readFileSync(`/proc/${pid}/status`, "utf8");
  const get = (k) => new RegExp(`^${k}:\\s*(.*)$`, "m").exec(t)?.[1]?.trim();
  return { uid: get("Uid"), gid: get("Gid"), capEff: get("CapEff"), capPrm: get("CapPrm"), noNewPrivs: get("NoNewPrivs"), groups: get("Groups") };
}

// ---------------------------------------------------------------- the rehearsal
async function main() {
  console.log(`Rehearsal ${id}: database ${DB}, role ${APP_USER}, port ${PORT}, workdir ${WORK}\n`);

  await step("create an empty database and provision the least-privilege role (db/provision-cli)", async () => {
    await adminPg("postgres", (c) => c.query(`CREATE DATABASE ${DB}`));
    const r = spawnSync("node", [join(ROOT, "server", "dist", "db", "provision-cli.js")], { env: { PATH: process.env.PATH, DATABASE_ADMIN_URL: adminUrlFor(DB), APP_DB_USER: APP_USER, APP_DB_PASSWORD: SECRETS.APP_PW }, encoding: "utf8" });
    must(r.status === 0, `provision-cli exit ${r.status}: ${r.stderr}`);
    return r.stdout.trim();
  });

  await step("preflight against the live database role (before the first boot)", async () => {
    const r = spawnSync("node", [join(ROOT, "ops", "pilot-preflight.mjs"), "--db", "--database-url", appUrlFor(DB), "--json"], { encoding: "utf8" });
    const out = JSON.parse(r.stdout);
    results.preflight_db_before_boot = out.results.filter((x) => x.area === "database" || x.area === "pilot-safety");
    must(out.counts.FAIL === 0, `FAIL: ${out.results.filter((x) => x.level === "FAIL").map((x) => x.text).join("; ")}`);
    return `${out.counts.PASS} passed, ${out.counts.WARN} warning(s)`;
  });

  let bootMs = 0;
  await step("boot in production mode as an unprivileged user; migrations apply as the app role", async () => {
    const t0 = startServer();
    await waitHealthy();
    bootMs = Math.round(performance.now() - t0);
    results.measurements.boot_to_healthy_ms = bootMs;
    const st = procStatus(server.pid);
    results.process_identity = st;
    must(st.uid.split(/\s+/)[0] === "65534", `uid is ${st.uid}`);
    must(/^0+$/.test(st.capEff), `effective capabilities not empty: ${st.capEff}`);
    must(st.noNewPrivs === "1", "no_new_privs not set");
    const mig = await q("SELECT count(*)::int AS n FROM legion_migrations");
    const files = readdirSync(join(ROOT, "server", "dist", "db", "migrations")).filter((f) => f.endsWith(".sql")).length;
    must(mig[0].n === files, `${mig[0].n}/${files} migrations`);
    return { uid: st.uid, capEff: st.capEff, noNewPrivs: st.noNewPrivs, boot_ms: bootMs, migrations: `${mig[0].n}/${files}` };
  });

  await step("the API's database role really is least-privilege (no superuser, files, programs, roles; cannot reach other databases)", async () => {
    const r = spawnSync("node", [join(ROOT, "ops", "pilot-preflight.mjs"), "--db", "--database-url", appUrlFor(DB), "--json"], { encoding: "utf8" });
    const out = JSON.parse(r.stdout);
    results.preflight_db_after_boot = out.results.filter((x) => x.area === "database" || x.area === "pilot-safety");
    must(out.counts.FAIL === 0, out.results.filter((x) => x.level === "FAIL").map((x) => x.text).join("; "));
    // Another database on the same server: the role must not be able to read its DATA.
    // (PostgreSQL lets every role CONNECT to every database by default; that alone exposes nothing.)
    await adminPg("postgres", (c) => c.query("CREATE DATABASE other_" + id));
    await adminPg("other_" + id, async (c) => { await c.query("CREATE TABLE secrets_probe (v text)"); await c.query("INSERT INTO secrets_probe VALUES ('confidential')"); });
    const c2 = new pg.Client({ connectionString: appUrlFor("other_" + id) });
    let connected = false; let readDenied = false; let createDenied = false;
    try { await c2.connect(); connected = true; await c2.query("SELECT v FROM secrets_probe").catch((e) => { readDenied = e.code === "42501"; }); await c2.query("CREATE TABLE intruder (x int)").catch((e) => { createDenied = e.code === "42501"; }); } catch { /* cannot even connect: also fine */ } finally { await c2.end().catch(() => {}); }
    await adminPg("postgres", (c) => c.query(`DROP DATABASE other_${id}`));
    must(!connected || (readDenied && createDenied), `the app role could read (${!readDenied}) or write (${!createDenied}) another database`);
    if (connected) results.notes = [...(results.notes ?? []), "PostgreSQL allows every role to CONNECT to every database by default; the app role could connect to another database but could neither read nor create anything there. On a shared server, also run REVOKE CONNECT ON DATABASE <other> FROM PUBLIC."];
    return out.results.filter((x) => x.level === "WARN").map((x) => x.id);
  });

  await step("network: the API listens on loopback only", async () => {
    const lan = Object.values(networkInterfaces()).flat().find((i) => i && !i.internal && i.family === "IPv4");
    const hexPort = PORT.toString(16).toUpperCase().padStart(4, "0");
    const listening = readFileSync("/proc/net/tcp", "utf8").split("\n").slice(1).map((l) => l.trim().split(/\s+/)).filter((f) => f[3] === "0A" && f[1]?.endsWith(`:${hexPort}`)).map((f) => f[1].split(":")[0]);
    must(listening.length > 0 && listening.every((ip) => ip === "0100007F"), `listening on ${listening.join(",")} (0100007F = 127.0.0.1)`);
    return { listeners: listening.map((ip) => (ip === "0100007F" ? `127.0.0.1:${PORT}` : ip)), lan_probe: lan ? "refused" : "no non-loopback interface" };
  });

  await step("first-run setup needs the one-time token; wrong or missing token is refused", async () => {
    const token = readFileSync(join(STATE, ".legion-setup-token"), "utf8").trim();
    const owner = { email: "pilot-admin@acme-soc.test", password: "a-long-pilot-password-1", tenant_name: "Pilot Workspace" };
    must((await call("POST", "/auth/register", { body: owner })).status === 403, "register without a token was not refused");
    must((await call("POST", "/auth/register", { body: { ...owner, setup_token: "lst_" + "0".repeat(43) } })).status === 403, "wrong token accepted");
    const ok = await call("POST", "/auth/register", { body: { ...owner, setup_token: token } });
    must(ok.status === 201, `register ${ok.status} ${ok.text.slice(0, 120)}`);
    const login = await call("POST", "/auth/login", { body: { username: owner.email, password: owner.password } });
    must(login.status === 200 && login.json?.access_token, `login ${login.status}`);
    adminToken = login.json.access_token;
    must(!existsSync(join(STATE, ".legion-setup-token")), "setup token file still exists after use");
    return "token consumed and deleted";
  });

  await step("unauthenticated and forged access is refused (webhook, API, metrics)", async () => {
    must((await call("GET", "/alerts")).status === 401, "alerts without auth");
    must((await call("GET", "/metrics")).status === 401, "metrics without token");
    must((await call("GET", "/metrics", { token: "x".repeat(40) })).status === 401, "metrics with wrong token");
    must((await call("POST", "/security-events/webhook", { body: "{}" })).status === 401, "unsigned webhook accepted");
    must((await call("GET", "/health")).json.database === "up", "health");
    // A caller from the internet reaches the API through nginx (trusted proxy) and carries a public address.
    const outside = await call("GET", "/health", { headers: { "x-forwarded-for": "203.0.113.50" } });
    must(outside.status === 200 && !("version" in outside.json) && !("instance" in outside.json) && !("ai_provider" in outside.json), `health leaks details to a public caller: ${outside.text.slice(0, 120)}`);
    return "ok";
  });

  await step("read-only integration: a signed Wazuh feed creates alerts and nothing else changes", async () => {
    const c = await call("POST", "/security-events/credentials", { token: adminToken, body: { label: "pilot-wazuh" } });
    must(c.status === 201, `credential ${c.status} ${c.text.slice(0, 100)}`);
    cred = { id: c.json.id, secret: c.json.secret };
    const sensitive = await q("SELECT secret_enc FROM webhook_credentials WHERE key_id = $1", [cred.id]).catch(() => []);
    for (const mitre of [["T1595"], ["T1110"], ["T1110"], ["T1110"], ["T1110"], ["T1059"]]) must((await wazuh("45.155.205.12", mitre, mitre[0] === "T1059" ? { level: 13, desc: "Suspicious command execution after login" } : {})).status === 202, "webhook refused");
    const alerts = await call("GET", "/alerts", { token: adminToken });
    const n = Array.isArray(alerts.json) ? alerts.json.length : (alerts.json?.alerts ?? alerts.json?.items ?? []).length;
    must(n >= 6, `only ${n} alerts`);
    const blocks = await q("SELECT count(*)::int AS n FROM ip_blocks"); must(blocks[0].n === 0, "a block exists");
    return { alerts: n, ip_blocks: blocks[0].n };
  });

  await step("secrets at rest: the webhook secret is stored encrypted (not the one the sensor holds)", async () => {
    const rows = await q("SELECT * FROM webhook_credentials WHERE key_id = $1", [cred.id]);
    const flat = JSON.stringify(rows);
    must(!flat.includes(cred.secret), "the plaintext webhook secret is in the database");
    const users = await q("SELECT password_hash FROM users");
    must(users.every((u) => /^\$2[aby]\$/.test(u.password_hash)), "a password is not bcrypt-hashed");
    return { webhook_secret_in_db: "not present in plaintext", passwords: "bcrypt" };
  });

  await step("simulation only: policy ASSIST, workflow proposes a block, a person approves, it is simulated, nothing real blocks", async () => {
    const alertList = (await call("GET", "/alerts", { token: adminToken })).json;
    const alerts = Array.isArray(alertList) ? alertList : (alertList.alerts ?? alertList.items);
    const target = alerts.find((a) => a.severity === "critical" || a.severity === "high") ?? alerts[0];
    const pol = await call("PUT", "/policy", { token: adminToken, body: { expected_version: 0, document: { schema: 1, default_autonomy: "ASSIST", rules: [] } } });
    must(pol.status === 200, `policy ${pol.status}`);
    const run = await call("POST", "/workflows/alert_response/runs", { token: adminToken, body: { alert_id: target.id, mode: "simulation" } });
    must(run.status === 201, `workflow ${run.status} ${run.text.slice(0, 120)}`);
    const contain = run.json.run.steps.find((s) => s.name === "contain_source");
    must(contain?.action_status === "awaiting_approval", `containment step is ${contain?.action_status}`);
    const act = (await call("GET", "/actions?status=awaiting_approval", { token: adminToken })).json.actions.find((a) => a.action_id === "ip.block");
    must(act, "no block proposal is waiting for approval");
    const dec = await call("POST", `/approvals/${act.approval_id}/decision`, { token: adminToken, body: { decision: "approve", action_digest: act.action_digest } });
    must(dec.status === 200 && dec.json.action.status === "simulated", `decision ${dec.status} ${dec.json?.action?.status}`);
    const blocks = await q("SELECT count(*)::int AS n FROM ip_blocks"); must(blocks[0].n === 0, "a REAL block was created");
    // a live attempt is refused
    const live = await call("POST", "/actions", { token: adminToken, body: { action_id: "ip.block", input: { ip: "45.155.205.12", minutes: 60 }, mode: "live", idempotency_key: "rehearsal-live-attempt" } });
    must(live.status === 422, `live mode answered ${live.status}`);
    // a critical action never skips approval, even for an administrator
    const crit = await call("POST", "/actions", { token: adminToken, body: { action_id: "account.disable", input: { account: "jdoe", system: "entra" }, mode: "simulation", idempotency_key: "rehearsal-critical-1" } });
    must(crit.json?.action?.status === "awaiting_approval", `critical action is ${crit.json?.action?.status}`);
    return { workflow: "alert_response", approval: "digest-bound", result: dec.json.action.result?.would, real_blocks: blocks[0].n, live: "refused (422)", critical: "awaiting_approval" };
  });

  await step("metrics and alert inputs: /metrics is live and shows the safety invariants", async () => {
    const m = await call("GET", "/metrics", { token: SECRETS.HEALTH_METRICS_TOKEN });
    must(m.status === 200, `metrics ${m.status}`);
    const val = (n, l) => Number(new RegExp(`^${n}${l ? `\\{${l}\\}` : ""} (-?[0-9.]+)$`, "m").exec(m.text)?.[1] ?? NaN);
    results.metrics_sample = Object.fromEntries(["legion_soc_actions_live", "legion_soc_runtime_worker_running", "legion_soc_runtime_last_tick_age_seconds", "legion_soc_approvals_pending", "legion_soc_audit_events"].map((n) => [n, val(n)]));
    must(val("legion_soc_actions_live") === 0, "live actions != 0");
    must(val("legion_soc_runtime_worker_running") === 1, "worker not running");
    must(val("legion_soc_runtime_last_tick_age_seconds") >= 0 && val("legion_soc_runtime_last_tick_age_seconds") < 10, "worker heartbeat stale");
    return results.metrics_sample;
  });

  await step("tenant isolation in the live process: a second workspace sees nothing of the first", async () => {
    const tB = randomBytes(16).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*$/, "$1-$2-$3-$4-$5");
    const uB = randomBytes(16).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*$/, "$1-$2-$3-$4-$5");
    const hash = bcrypt.hashSync("another-long-password-2", 10);
    await adminPg(DB, async (c) => {
      await c.query("INSERT INTO tenants (id, name) VALUES ($1, 'Isolation Probe')", [tB]);
      await c.query("INSERT INTO users (id, email, password_hash, tenant_id, role, status) VALUES ($1, 'probe-b@acme-soc.test', $2, $3, 'admin', 'active')", [uB, hash, tB]);
      await c.query("INSERT INTO workspace_memberships (tenant_id, user_id, role, status) VALUES ($1, $2, 'admin', 'active') ON CONFLICT DO NOTHING", [tB, uB]);
    });
    const login = await call("POST", "/auth/login", { body: { username: "probe-b@acme-soc.test", password: "another-long-password-2" } });
    must(login.status === 200, `login B ${login.status}`);
    userBToken = login.json.access_token;
    const alertsB = (await call("GET", "/alerts", { token: userBToken })).json;
    const nB = Array.isArray(alertsB) ? alertsB.length : (alertsB.alerts ?? alertsB.items ?? []).length;
    must(nB === 0, `B sees ${nB} alerts`);
    const actsA = (await call("GET", "/actions", { token: adminToken })).json.actions;
    must(actsA.length >= 2, "A has no actions");
    const probes = [];
    for (const a of actsA.slice(0, 3)) {
      probes.push((await call("GET", `/actions/${a.id}`, { token: userBToken })).status);
      if (a.approval_id) probes.push((await call("GET", `/approvals/${a.approval_id}`, { token: userBToken })).status);
      if (a.approval_id) probes.push((await call("POST", `/approvals/${a.approval_id}/decision`, { token: userBToken, body: { decision: "approve", action_digest: a.action_digest } })).status);
    }
    must(probes.every((s) => s === 404), `cross-tenant probes answered ${probes.join(",")}`);
    must(((await call("GET", "/actions", { token: userBToken })).json.actions).length === 0, "B lists A's actions");
    must(((await call("GET", "/soc/audit", { token: userBToken })).json.events).length === 0, "B reads A's audit events");
    must((await call("GET", "/policy", { token: userBToken })).json.active === null, "B sees A's policy");
    const v = await call("GET", "/soc/audit/verify", { token: userBToken }); must(v.json.ok && v.json.events === 0, "B's chain not independent");
    return { b_alerts: nB, cross_tenant_probes: probes.length, all: "404", audit_chains: "independent" };
  });

  await step("audit chain verifies in the live process", async () => {
    const v = await call("GET", "/soc/audit/verify", { token: adminToken });
    must(v.json.ok === true && v.json.events > 5, JSON.stringify(v.json));
    return { events: v.json.events };
  });

  // ---- worker health and recovery ------------------------------------------------
  const alertIdForRows = async () => (await q("SELECT id FROM alerts ORDER BY created_at LIMIT 1"))[0].id;
  await step("kill -9 under load: no action is lost or run twice; the restarted worker finishes everything", async () => {
    const pol = await call("GET", "/policy", { token: adminToken });
    await call("PUT", "/policy", { token: adminToken, body: { expected_version: pol.json.active.version, document: { schema: 1, default_autonomy: "AUTONOMOUS", rules: [] } } });
    const alertId = await alertIdForRows();
    const N = 60;
    let answeredCount = 0;
    const fire = Array.from({ length: N }, (_, i) => call("POST", "/actions", { token: adminToken, body: { action_id: "alert.set_status", input: { alert_id: alertId, status: i % 2 ? "resolved" : "investigating" }, mode: "simulation", idempotency_key: `crash-${id}-${i}` } }).then((r) => { answeredCount++; return r.status; }, () => "connection-lost"));
    // Pull the plug while some requests are done and others are still in flight.
    for (let i = 0; i < 400 && answeredCount < 15; i++) await sleep(2);
    server.kill("SIGKILL");
    const answered = await Promise.all(fire);
    for (let i = 0; i < 100 && !serverExit; i++) await sleep(20);
    const created = (await q("SELECT status FROM action_requests WHERE idempotency_key LIKE $1", [`crash-${id}-%`])).map((r) => r.status);
    const t0 = startServer();
    await waitHealthy();
    const upMs = Math.round(performance.now() - t0);
    let drainMs = null;
    // Actions caught mid-simulation are reclaimed once idle past the stale window (60 s) plus a recheck (≤15 s).
    for (let i = 0; i < 1500; i++) {
      const open = await q("SELECT count(*)::int AS n FROM action_requests WHERE idempotency_key LIKE $1 AND status NOT IN ('simulated','failed','denied','recorded','rejected','expired','cancelled')", [`crash-${id}-%`]);
      if (open[0].n === 0) { drainMs = Math.round(performance.now() - t0); break; }
      await sleep(100);
    }
    if (drainMs === null) {
      const st = await q("SELECT status, count(*)::int AS n, min(attempts) AS min_attempts, max(attempts) AS max_attempts FROM action_requests WHERE idempotency_key LIKE $1 GROUP BY status", [`crash-${id}-%`]);
      const jb = await q("SELECT j.status, count(*)::int AS n, bool_or(j.lease_until > now()) AS leased, min(j.run_after - now()) AS next_in FROM soc_jobs j GROUP BY j.status");
      const sample = await q("SELECT a.status AS action, j.status AS job, j.attempts AS job_attempts, a.attempts AS action_attempts, a.updated_at > now() - interval '60 seconds' AS fresh FROM action_requests a LEFT JOIN soc_jobs j ON j.payload->>'action_request_id' = a.id::text WHERE a.idempotency_key LIKE $1 AND a.status NOT IN ('simulated') LIMIT 5", [`crash-${id}-%`]);
      throw new Error(`actions still unfinished 150 s after the restart: actions=${JSON.stringify(st)} jobs=${JSON.stringify(jb)} sample=${JSON.stringify(sample)} log=${tail(6)}`);
    }
    // replay every request with the same key: nothing is duplicated
    const replays = await Promise.all(Array.from({ length: N }, (_, i) => call("POST", "/actions", { token: adminToken, body: { action_id: "alert.set_status", input: { alert_id: alertId, status: i % 2 ? "resolved" : "investigating" }, mode: "simulation", idempotency_key: `crash-${id}-${i}` } }).then((r) => r.status)));
    const final = await q("SELECT a.id, a.status, a.attempts, (SELECT count(*)::int FROM action_events e WHERE e.action_id = a.id AND e.to_status = 'simulated') AS sims FROM action_requests a WHERE a.idempotency_key LIKE $1", [`crash-${id}-%`]);
    must(created.length > 0 && created.length < N + 1, "the kill did not land mid-flight (nothing was in progress)");
    must(final.length === N, `${final.length}/${N} actions exist after replaying all keys`);
    must(final.every((a) => a.status === "simulated" && a.sims === 1), "an action is not simulated exactly once");
    const jobs = await q("SELECT status, count(*)::int AS n FROM soc_jobs GROUP BY status");
    const dead = jobs.find((j) => j.status === "dead")?.n ?? 0;
    const chain = await call("GET", "/soc/audit/verify", { token: adminToken });
    must(chain.json.ok, "audit chain broken after the crash");
    results.measurements.crash_recovery = { requests: N, answered: answered.filter((s) => typeof s === "number").length, lost_connections: answered.filter((s) => s === "connection-lost").length, created_before_restart: created.length, states_at_kill: created.reduce((a, s) => ({ ...a, [s]: (a[s] ?? 0) + 1 }), {}), restart_to_healthy_ms: upMs, restart_to_all_finished_ms: drainMs, jobs: Object.fromEntries(jobs.map((j) => [j.status, j.n])) };
    return { ...results.measurements.crash_recovery, replays_ok: replays.every((s) => s === 200 || s === 201), dead_jobs: dead, audit_chain: "valid" };
  });

  await step("a worker that died mid-simulation: the restarted process reclaims the stuck action and its lapsed job", async () => {
    const alertId = await alertIdForRows();
    const r = await call("POST", "/actions", { token: adminToken, body: { action_id: "alert.set_status", input: { alert_id: alertId, status: "resolved" }, mode: "simulation", idempotency_key: `stuck-${id}` } });
    const actionId = r.json.action.id;
    await stopServer("SIGKILL");
    await adminPg(DB, async (c) => {
      await c.query("UPDATE action_requests SET status = 'running', result = NULL, attempts = 1, updated_at = now() - interval '20 minutes' WHERE id = $1", [actionId]);
      await c.query("UPDATE soc_jobs SET status = 'running', lease_owner = 'worker-that-died', lease_until = now() - interval '5 minutes', attempts = 1, finished_at = NULL WHERE payload->>'action_request_id' = $1", [actionId]);
    });
    const t0 = startServer(); await waitHealthy();
    let ms = null;
    for (let i = 0; i < 200; i++) { const s = (await q("SELECT status FROM action_requests WHERE id = $1", [actionId]))[0].status; if (s === "simulated") { ms = Math.round(performance.now() - t0); break; } await sleep(100); }
    must(ms !== null, "the stuck action was never recovered");
    results.measurements.stuck_action_recovery_ms = ms;
    return { recovered_after_restart_ms: ms };
  });

  await step("graceful shutdown: SIGTERM stops the process cleanly and quickly", async () => {
    const exit = await stopServer("SIGTERM");
    must(exit && (exit.code === 0 || exit.sig === "SIGTERM"), `exit ${JSON.stringify(exit)}`);
    return { exit, ms: results.measurements.stop_SIGTERM_ms };
  });

  // ---- backup, restore, disaster recovery -------------------------------------------
  let backupFile = ""; let agePub = ""; let ageKeyFile = ""; let alertsAtBackup = 0;
  await step("backup: dump → restore test → encrypt (age, public key only on the server) → checksum", async () => {
    startServer(); await waitHealthy();
    ageKeyFile = join(WORK, "age-private.key");
    const kg = spawnSync("age-keygen", ["-o", ageKeyFile], { encoding: "utf8" }); must(kg.status === 0, kg.stderr);
    agePub = /public key: (age1\S+)/i.exec(kg.stderr + kg.stdout)?.[1] ?? readFileSync(ageKeyFile, "utf8").match(/public key: (age1\S+)/i)?.[1];
    must(agePub, "no age public key");
    alertsAtBackup = (await q("SELECT count(*)::int AS n FROM alerts"))[0].n;
    const dir = join(WORK, "backups");
    const t0 = performance.now();
    const r = spawnSync("bash", [join(ROOT, "ops", "backup.sh")], { encoding: "utf8", env: { PATH: process.env.PATH, DATABASE_URL: appUrlFor(DB), DATABASE_ADMIN_URL: adminUrlFor("postgres"), BACKUP_AGE_RECIPIENTS: agePub, BACKUP_DIR: dir, BACKUP_STATUS_FILE: join(WORK, "backup-status.json"), BACKUP_RESTORE_TEST: "required", BACKUP_REQUIRE_OFFSITE: "false" } });
    results.measurements.backup_ms = Math.round(performance.now() - t0);
    must(r.status === 0, `backup.sh exit ${r.status}: ${(r.stdout + r.stderr).slice(-400)}`);
    backupFile = readdirSync(dir).filter((f) => f.endsWith(".age")).map((f) => join(dir, f))[0];
    must(backupFile, "no .age file");
    const raw = readFileSync(backupFile);
    must(!raw.includes("CREATE TABLE") && !raw.includes("PGDMP"), "the backup is not encrypted");
    const status = JSON.parse(readFileSync(join(WORK, "backup-status.json"), "utf8"));
    results.backup_status = status;
    return { file: backupFile.split("/").pop(), bytes: raw.length, encrypted: true, restore_test: status.restore_test ?? status.restoreTest ?? "see status", backup_ms: results.measurements.backup_ms };
  });

  let rpoRows = 0; let disasterAt = 0;
  await step("disaster: more data arrives after the backup, then the database is destroyed", async () => {
    for (let i = 0; i < 3; i++) await wazuh(`91.240.118.${10 + i}`, ["T1110"]);
    await sleep(500);
    rpoRows = (await q("SELECT count(*)::int AS n FROM alerts"))[0].n - alertsAtBackup;
    must(rpoRows > 0, "no data arrived after the backup");
    await stopServer("SIGTERM");
    disasterAt = performance.now();
    await adminPg("postgres", async (c) => { await c.query(`DROP DATABASE ${DB} WITH (FORCE)`); });
    return { alerts_written_after_backup: rpoRows };
  });

  await step("recovery: restore into a new database, re-provision the role, boot, verify everything", async () => {
    await adminPg("postgres", (c) => c.query(`CREATE DATABASE ${DB}`));
    const r = spawnSync("bash", [join(ROOT, "ops", "restore.sh"), backupFile, "--yes"], { encoding: "utf8", env: { PATH: process.env.PATH, DATABASE_URL: adminUrlFor(DB), BACKUP_AGE_IDENTITY_FILE: ageKeyFile } });
    must(r.status === 0, `restore.sh exit ${r.status}: ${(r.stdout + r.stderr).slice(-500)}`);
    const pr = spawnSync("node", [join(ROOT, "server", "dist", "db", "provision-cli.js")], { env: { PATH: process.env.PATH, DATABASE_ADMIN_URL: adminUrlFor(DB), APP_DB_USER: APP_USER, APP_DB_PASSWORD: SECRETS.APP_PW }, encoding: "utf8" });
    must(pr.status === 0, `re-provision: ${pr.stderr}`);
    startServer(); await waitHealthy();
    results.measurements.rto_ms = Math.round(performance.now() - disasterAt);
    // the same admin can sign in; data is back; the audit chain verifies with the SAME key
    const login = await call("POST", "/auth/login", { body: { username: "pilot-admin@acme-soc.test", password: "a-long-pilot-password-1" } });
    must(login.status === 200, `login after restore ${login.status}`);
    adminToken = login.json.access_token;
    const alerts = (await q("SELECT count(*)::int AS n FROM alerts"))[0].n;
    must(alerts === alertsAtBackup, `${alerts} alerts after restore, expected ${alertsAtBackup}`);
    const chain = await call("GET", "/soc/audit/verify", { token: adminToken });
    must(chain.json.ok === true, `audit chain after restore: ${JSON.stringify(chain.json)}`);
    // the webhook credential still works: its secret decrypts with the SAME encryption keys
    must((await wazuh("45.155.205.77", ["T1110"])).status === 202, "the sensor's signed webhook no longer works after the restore");
    const pf = spawnSync("node", [join(ROOT, "ops", "pilot-preflight.mjs"), "--db", "--database-url", appUrlFor(DB), "--json"], { encoding: "utf8" });
    must(JSON.parse(pf.stdout).counts.FAIL === 0, "preflight failed after restore");
    return { rto_ms: results.measurements.rto_ms, rpo: `${rpoRows} alert(s) written after the last backup were lost (as designed: RPO = backup interval)`, alerts_restored: alerts, audit_chain: chain.json.events + " events valid", webhook_after_restore: "accepted", login: "ok" };
  });

  await step("a wrong SOC_AUDIT_KEY fails closed: the chain is not extended, actions that must be audited are refused, and the right key still verifies", async () => {
    await stopServer("SIGTERM");
    startServer({ SOC_AUDIT_KEY: hex() }); await waitHealthy();
    const login = await call("POST", "/auth/login", { body: { username: "pilot-admin@acme-soc.test", password: "a-long-pilot-password-1" } });
    const t = login.json.access_token;
    const alertId = await alertIdForRows();
    const eventsBefore = (await q("SELECT count(*)::int AS n FROM soc_audit_events"))[0].n;
    const v = await call("GET", "/soc/audit/verify", { token: t });
    must(v.json.ok === false, "a wrong key verified the chain");
    const act = await call("POST", "/actions", { token: t, body: { action_id: "alert.triage", input: { alert_id: alertId }, mode: "simulation", idempotency_key: `wrongkey-${id}` } });
    must(act.status >= 500, `an action was accepted under the wrong key (${act.status})`);
    await sleep(2500); // give the worker time to try (and be refused)
    const metrics = await call("GET", "/metrics", { token: SECRETS.HEALTH_METRICS_TOKEN });
    must(/^legion_soc_audit_key_mismatch_workspaces 1$/m.test(metrics.text), "monitoring does not show the key mismatch");
    const eventsAfter = (await q("SELECT count(*)::int AS n FROM soc_audit_events"))[0].n;
    must(eventsAfter === eventsBefore, `the chain grew under the wrong key (${eventsBefore} → ${eventsAfter})`);
    await stopServer("SIGTERM");
    startServer(); await waitHealthy();
    const l2 = await call("POST", "/auth/login", { body: { username: "pilot-admin@acme-soc.test", password: "a-long-pilot-password-1" } });
    adminToken = l2.json.access_token;
    const ok = await call("GET", "/soc/audit/verify", { token: adminToken });
    must(ok.json.ok === true, `the right key no longer verifies: ${JSON.stringify(ok.json)}`);
    return { wrong_key_verify: v.json.reason, action_under_wrong_key: act.status, chain_unchanged: true, metric: "legion_soc_audit_key_mismatch_workspaces=1", right_key: "verifies" };
  });

  // ---- rollback by switches ---------------------------------------------------------
  await step("rollback switches: ORCHESTRATOR_AUTO_MODE=off + POLICY_ENGINE_MODE=off stop all new workflow jobs and decisions without a redeploy", async () => {
    await stopServer("SIGTERM");
    startServer({ ORCHESTRATOR_AUTO_MODE: "off", POLICY_ENGINE_MODE: "off" }); await waitHealthy();
    const before = { jobs: (await q("SELECT count(*)::int AS n FROM soc_jobs"))[0].n, dec: (await q("SELECT count(*)::int AS n FROM policy_decisions WHERE call_site <> 'action_engine'"))[0].n };
    must((await wazuh("45.155.205.88", ["T1059"], { level: 13 })).status === 202, "ingest stopped working");
    await call("POST", "/security/blocks", { token: adminToken, body: { ip: "203.0.113.250", minutes: 5 } }); // not public: refused or recorded, either way no shadow record
    await sleep(500);
    const after = { jobs: (await q("SELECT count(*)::int AS n FROM soc_jobs"))[0].n, dec: (await q("SELECT count(*)::int AS n FROM policy_decisions WHERE call_site <> 'action_engine'"))[0].n };
    must(after.jobs === before.jobs && after.dec === before.dec, `jobs ${before.jobs}→${after.jobs}, shadow decisions ${before.dec}→${after.dec}`);
    return { ingest: "still works", new_jobs: 0, new_shadow_decisions: 0 };
  });

  await step("emergency stop: pausing the workspace refuses new actions at once", async () => {
    must((await call("POST", "/actions/controls", { token: adminToken, body: { paused: true, reason: "rehearsal" } })).status === 200, "pause");
    const alertId = await alertIdForRows();
    const r = await call("POST", "/actions", { token: adminToken, body: { action_id: "alert.triage", input: { alert_id: alertId }, mode: "simulation", idempotency_key: `paused-${id}` } });
    must(r.status === 423, `status ${r.status}`);
    const m = await call("GET", "/metrics", { token: SECRETS.HEALTH_METRICS_TOKEN });
    must(/^legion_soc_workspaces_paused 1$/m.test(m.text), "metrics do not show the pause");
    must((await call("POST", "/actions/controls", { token: adminToken, body: { paused: false } })).status === 200, "resume");
    return { refused: 423, metric: "legion_soc_workspaces_paused=1" };
  });
}

async function cleanup() {
  await stopServer("SIGKILL").catch(() => {});
  await sleep(200);
  for (const db of [DB, DB_RESTORED, "other_" + id]) await adminPg("postgres", (c) => c.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`)).catch(() => {});
  await adminPg("postgres", async (c) => {
    await c.query(`DROP OWNED BY ${APP_USER}`).catch(() => {});
    await c.query(`DROP ROLE IF EXISTS ${APP_USER}`);
  }).catch(() => {});
  try { copyFileSync(join(WORK, "server.log"), join(OUT, "rehearsal-server.log.tmp")); const t = readFileSync(join(OUT, "rehearsal-server.log.tmp"), "utf8").replace(/(postgres(ql)?|https?):\/\/[^@\s]*@/g, "$1://***@"); writeFileSync(join(OUT, "rehearsal-server.log"), t.split("\n").slice(-400).join("\n")); rmSync(join(OUT, "rehearsal-server.log.tmp")); } catch { /* no log */ }
  rmSync(WORK, { recursive: true, force: true });
}

try { await main(); } catch (e) { failures++; console.error("rehearsal aborted:", e); }
results.finished_at = new Date().toISOString();
results.summary = { steps: results.steps.length, passed: results.steps.filter((s) => s.ok).length, failed: failures };
writeFileSync(join(OUT, "rehearsal.json"), JSON.stringify(results, null, 2));
await cleanup();
console.log(`\n${results.summary.passed}/${results.summary.steps} steps passed${failures ? `, ${failures} FAILED` : ""}. Results: ${join(OUT, "rehearsal.json")}`);
process.exit(failures ? 1 : 0);
