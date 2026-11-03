#!/usr/bin/env node
/**
 * Resistance to denial-of-service, measured — not assumed.
 *
 * PART A — the built API in production mode, attacked directly while a
 * legitimate dashboard user and a legitimate Wazuh sensor keep working:
 *   1. baseline                         legit traffic only
 *   2. distributed junk flood           thousands of source addresses, each
 *                                       under its own per-address limit (the
 *                                       case per-IP limits cannot stop):
 *                                       unauthenticated reads, 404s, forged
 *                                       webhooks, sign-in guesses (which cost
 *                                       a password hash each)
 *   3. oversized bodies                 10 MB POSTs; memory must not grow
 *   4. connection exhaustion            thousands of idle sockets plus
 *                                       slow-loris (headers trickled forever)
 *   5. recovery                         latency returns to baseline
 *
 * PART B — the same attacks through a REAL nginx running deploy/nginx.conf,
 * and the real-IP handling that decides whether per-address limits work
 * behind a CDN (ops/update-cloudflare-ips.sh generates the trusted ranges).
 *
 *   npm --prefix server run build
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/ddos-resilience.mjs [--part a|b|all] [--json out.json]
 *
 * The attackers run in their own processes so that generating load does not
 * distort the latency of the legitimate clients being measured. All of it runs
 * on one machine, so absolute numbers are relative, not a capacity plan.
 */
import { fork, spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import {
  REPO, client, freePort, freshDatabase, reporter, signedWebhook, sleep, startApi, until, wazuhAlert, webhookBody,
} from "./lib/harness.mjs";

// --- attacker mode (a child process) -------------------------------------------------------------------------------

if (process.argv.includes("--attacker")) {
  const cfg = JSON.parse(process.argv[process.argv.indexOf("--attacker") + 1]);
  const agent = new http.Agent({ keepAlive: true, maxSockets: cfg.conc });
  const counts = {};
  const tally = (k) => { counts[k] = (counts[k] ?? 0) + 1; };
  const ip = () => `${100 + Math.floor(Math.random() * 100)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}.${1 + Math.floor(Math.random() * 250)}`;
  const cheapReq = () => (Math.random() < 0.6 ? { method: "GET", path: "/alerts" } : { method: "GET", path: `/nope-${Math.floor(Math.random() * 1e6)}` });
  const forgedReq = () => ({ method: "POST", path: "/security-events/webhook", body: webhookBody(wazuhAlert(Math.floor(Math.random() * 1e9))), headers: { "content-type": "application/json", "x-legion-key-id": `whk_${randomBytes(16).toString("base64url")}`, "x-legion-timestamp": String(Math.floor(Date.now() / 1000)), "x-legion-nonce": randomBytes(12).toString("base64url"), "x-legion-signature": `v2=${randomBytes(32).toString("hex")}` } });
  // A sign-in guess costs the server one password hash, whoever sends it.
  const loginReq = () => ({ method: "POST", path: "/auth/login", body: JSON.stringify({ username: `victim${Math.floor(Math.random() * 1e6)}@example.com`, password: "guess-guess-guess" }), headers: { "content-type": "application/json" } });
  const kinds = {
    cheap: cheapReq, forged: forgedReq, login: loginReq,
    junk: () => { const r = Math.random(); return r < 0.55 ? cheapReq() : r < 0.75 ? forgedReq() : loginReq(); },
    big: () => ({ method: "POST", path: Math.random() < 0.5 ? "/auth/login" : "/security-events/webhook", body: Buffer.alloc(10 * 1024 * 1024, 0x61), headers: { "content-type": "application/json" } }),
  };
  const end = Date.now() + cfg.ms;
  const one = () => new Promise((resolve) => {
    const k = kinds[cfg.kind]();
    let done = false;
    const finish = (key) => { if (!done) { done = true; tally(key); resolve(); } };
    const req = http.request({ host: "127.0.0.1", port: cfg.port, path: k.path, method: k.method, agent, timeout: 8000, headers: { ...(k.headers ?? {}), "x-forwarded-for": cfg.noSpoof ? undefined : ip(), ...(k.body ? { "content-length": Buffer.byteLength(k.body) } : {}) } }, (res) => {
      res.resume();
      res.on("end", () => finish(res.statusCode));
    });
    req.on("timeout", () => { req.destroy(); finish("timeout"); });
    req.on("error", (e) => finish(`ERR:${e.code ?? e.name}`));
    if (k.body) req.write(k.body);
    req.end();
  });
  await Promise.all(Array.from({ length: cfg.conc }, async () => { while (Date.now() < end) await one(); }));
  process.stdout.write(JSON.stringify(counts));
  process.exit(0);
}

// --- harness ---------------------------------------------------------------------------------------------------------

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const argv = process.argv;
const PART = argv.includes("--part") ? argv[argv.indexOf("--part") + 1] : "all";
const jsonOut = argv.includes("--json") ? argv[argv.indexOf("--json") + 1] : null;
const R = reporter("denial-of-service resilience");
const { check, section, note } = R;
const FRONTEND = "https://app.legion.test";
const SCRIPT = fileURLToPath(import.meta.url);
// DOS_SCALE=0.5 halves every phase (CI); the checks are the same.
const SCALE = Number(process.env.DOS_SCALE || 1);
const secs = (n) => Math.max(3, Math.round(n * SCALE));

/** Attack processes: `n` children, each running `kind` at `conc` concurrency for `ms`. Resolves to merged status counts. */
function attack(kind, { port, ms, conc, n = 2, noSpoof = false }) {
  return Promise.all(Array.from({ length: n }, () => new Promise((resolve) => {
    const child = fork(SCRIPT, ["--attacker", JSON.stringify({ kind, port, ms, conc, noSpoof })], { silent: true });
    let out = "";
    child.stdout.on("data", (d) => { out += d; });
    child.on("exit", () => { try { resolve(JSON.parse(out)); } catch { resolve({}); } });
  }))).then((all) => all.reduce((a, c) => { for (const [k, v] of Object.entries(c)) a[k] = (a[k] ?? 0) + v; return a; }, {}));
}

const pct = (a, p) => (a.length ? Math.round([...a].sort((x, y) => x - y)[Math.min(a.length - 1, Math.floor((p / 100) * a.length))]) : null);
const summarise = (xs) => ({ n: xs.length, p50: pct(xs, 50), p95: pct(xs, 95), p99: pct(xs, 99), max: pct(xs, 100) });

/**
 * Legitimate traffic, measured by phase: a dashboard user reading (2/s, well
 * under the 300/min per-address limit), a Wazuh sensor posting signed events
 * (5/s), and a person signing in (1 every 2 s, spread over 40 legitimate addresses so each stays under the 10/min per-address limit — informational: the password
 * hashing queue is, by design, the part an attacker can crowd).
 */
function legitTraffic(base, { token, cred, deviceCookie }) {
  const phases = {};
  let phase = "idle";
  let running = true;
  const bucket = () => (phases[phase] ??= { read: [], readFail: 0, sensorFirstTry: 0, sensorTotal: 0, sensorLost: 0, sensor: [], signinOk: 0, signinBusy: 0, signinOther: 0, knownOk: 0, knownBusy: 0, knownOther: 0 });
  const user = client(base, { ip: "203.0.113.10", token });
  const loops = [
    (async () => {
      while (running) {
        const b = bucket(); const t = performance.now();
        const r = await Promise.race([user.call("/alerts?limit=20"), sleep(10_000).then(() => ({ status: 0 }))]).catch(() => ({ status: 0 }));
        if (r.status === 200) b.read.push(performance.now() - t); else b.readFail++;
        await sleep(500);
      }
    })(),
    (async () => {
      let n = 5_000_000;
      while (running) {
        const b = bucket(); const body = webhookBody(wazuhAlert(n++, { level: 3 }));
        b.sensorTotal++;
        let ok = false;
        for (let attempt = 0; attempt < 4 && !ok; attempt++) {
          const t = performance.now();
          const r = await Promise.race([signedWebhook(base, cred.id, cred.secret, body, { ip: "203.0.113.20" })(), sleep(10_000).then(() => ({ status: 0 }))]).catch(() => ({ status: 0 }));
          if (r.status === 202 || r.status === 200) { ok = true; b.sensor.push(performance.now() - t); if (attempt === 0) b.sensorFirstTry++; }
          else await sleep(250 * (attempt + 1)); // what custom-legion.py does: retry, then spool
        }
        if (!ok) b.sensorLost++;
        await sleep(200);
      }
    })(),
    (async () => {
      let signins = 0;
      while (running) {
        const b = bucket();
        const r = await Promise.race([client(base, { ip: `203.0.113.${40 + (signins++ % 40)}` }).call("/auth/login", { method: "POST", body: { username: "legit@example.com", password: "Legit-password-12345" } }), sleep(10_000).then(() => ({ status: 0 }))]).catch(() => ({ status: 0 }));
        if (r.status === 200) b.signinOk++; else if (r.status === 503) b.signinBusy++; else b.signinOther++;
        await sleep(2000);
      }
    })(),
    // The same person from a browser that has signed in before (known-device
    // cookie): served from the priority lane. Every 7 s stays inside the
    // per-account priority budget (10 / min).
    (async () => {
      let n = 0;
      while (running && deviceCookie) {
        const b = bucket();
        const r = await Promise.race([client(base, { ip: `203.0.113.${100 + (n++ % 40)}`, headers: { cookie: deviceCookie } }).call("/auth/login", { method: "POST", body: { username: "legit@example.com", password: "Legit-password-12345" } }), sleep(10_000).then(() => ({ status: 0 }))]).catch(() => ({ status: 0 }));
        if (r.status === 200) b.knownOk++; else if (r.status === 503) b.knownBusy++; else b.knownOther++;
        await sleep(7000);
      }
    })(),
  ];
  return {
    setPhase(p) { phase = p; bucket(); },
    async stop() { running = false; await Promise.all(loops); return phases; },
    phases,
  };
}

/** CPU seconds (user + system) the process has used so far, from /proc (Linux). */
const cpuSeconds = (pid) => { try { const f = readFileSync(`/proc/${pid}/stat`, "utf8").split(") ")[1].split(" "); return (Number(f[11]) + Number(f[12])) / 100; } catch { return null; } };
const rssKb = (pid) => { try { return Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, "utf8"))?.[1]); } catch { return null; } };

// --- PART A -----------------------------------------------------------------------------------------------------------

async function partA() {
  const db = await freshDatabase(ADMIN, "legion_dos");
  const port = await freePort();
  const env = {
    NODE_ENV: "production", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url, JWT_SECRET: randomBytes(48).toString("hex"),
    LEGION_ENCRYPTION_KEYS: `dos:${randomBytes(32).toString("hex")}`, FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true", SMTP_HOST: "127.0.0.1", SMTP_PORT: "9",
    // Tuning experiments: DOS_API_ENV='{"PASSWORD_HASH_WORKERS":"2"}'
    ...JSON.parse(process.env.DOS_API_ENV || "{}"),
  };
  const api = await startApi(env, { port });
  try {
    section("A. setup");
    check("built API up in production mode", api.up, api.log().slice(-500));
    const c = client(api.base, { headers: { origin: FRONTEND }, ip: "203.0.113.1" });
    const setupToken = /(lst_[A-Za-z0-9_-]+)/.exec(api.log())?.[1];
    await c.call("/auth/register", { method: "POST", body: { email: "legit@example.com", password: "Legit-password-12345", tenant_name: "Legit Co", setup_token: setupToken } });
    const login = await c.call("/auth/login", { method: "POST", body: { username: "legit@example.com", password: "Legit-password-12345" } });
    c.setToken(login.body.access_token);
    const cred = await c.call("/security-events/credentials", { method: "POST", body: { label: "sensor" } });
    check("legitimate user and sensor key ready", Boolean(c.token) && cred.status === 201);

    const deviceCookie = login.setCookies.map((x) => x.split(";")[0]).find((x) => x.startsWith("legion_device="));
    check("a full sign-in hands the browser a known-device cookie", Boolean(deviceCookie));
    const legit = legitTraffic(api.base, { token: c.token, cred: cred.body, deviceCookie });
    const pid = api.proc.pid;

    legit.setPhase("1 baseline"); section("A1. baseline (legitimate traffic only)");
    await sleep(secs(12) * 1000);

    const rssSamples = { start: rssKb(pid) };
    const floods = {};
    for (const [label, kind, dur] of [["2a cheap reads/404s", "cheap", secs(12)], ["2b forged webhooks", "forged", secs(12)], ["2c sign-in guesses", "login", secs(12)], ["2d all combined", "junk", secs(20)]].filter(([, k]) => !process.env.DOS_ONLY_KIND || k === process.env.DOS_ONLY_KIND)) {
      legit.setPhase(label); section(`A2. distributed flood — ${label} (${dur} s, 2 attackers × 120 connections, thousands of source addresses)`);
      const cpu0 = cpuSeconds(pid);
      floods[label] = await attack(kind, { port, ms: dur * 1000, conc: 120 });
      const total = Object.values(floods[label]).reduce((a, b) => a + b, 0);
      const cpu = cpuSeconds(pid) - cpu0;
      note(`${label}: responses`, { ...floods[label], per_second: Math.round(total / dur), api_cpu_percent_of_one_core: Math.round((cpu / dur) * 100) });
      legit.setPhase(`${label} → recovery`); await sleep(4_000);
    }
    rssSamples.afterFlood = rssKb(pid);

    if (argv.includes("--flood-only")) {
      const only = await legit.stop();
      note("legitimate traffic by phase", Object.fromEntries(Object.entries(only).map(([k, v]) => [k, { read: summarise(v.read), readFail: v.readFail, sensor: summarise(v.sensor), sensorFirstTry: `${v.sensorFirstTry}/${v.sensorTotal}`, sensorLost: v.sensorLost, signin: { ok: v.signinOk, busy503: v.signinBusy, other: v.signinOther } }])));
      return;
    }
    section("A3. oversized bodies (2 rounds of 10 s of 10 MB POSTs; memory must plateau, not grow)");
    for (const round of [1, 2]) {
      legit.setPhase(`3.${round} oversized bodies`);
      const bigCounts = await attack("big", { port, ms: secs(10) * 1000, conc: 8, n: 1 });
      note(`round ${round} responses`, bigCounts);
      check(`round ${round}: oversized bodies are refused (413) or dropped, never accepted`, !(bigCounts[200] || bigCounts[202]), JSON.stringify(bigCounts));
      rssSamples[`afterBig${round}`] = rssKb(pid);
      await sleep(6_000);
      rssSamples[`settled${round}`] = rssKb(pid);
    }
    note("API memory (RSS, MB)", Object.fromEntries(Object.entries(rssSamples).map(([k, v]) => [k, v && Math.round(v / 1024)])));
    const grew = rssSamples.settled2 - rssSamples.settled1;
    check("memory plateaus: the second round of 10 MB bodies adds < 60 MB over the first (no leak)", grew < 60 * 1024, `${Math.round(grew / 1024)} MB`);

    legit.setPhase("5 connection exhaustion"); section("A4. connection exhaustion (3,000 idle sockets + 500 slow-loris, until the server reaps them)");
    const idle = [], slow = [];
    let opened = 0, refused = 0;
    const open = (list, trickle) => new Promise((resolve) => {
      const s = net.connect({ host: "127.0.0.1", port }, () => {
        opened++;
        if (trickle) { s.write("GET /health HTTP/1.1\r\nHost: legion\r\n"); s._t = setInterval(() => { try { s.write("X-Slow: 1\r\n"); } catch { /* closed */ } }, 4000); }
        resolve();
      });
      s.on("error", () => { refused++; resolve(); });
      s._closedAt = null; s.on("close", () => { s._closedAt = Date.now(); clearInterval(s._t); });
      list.push(s);
    });
    const tOpen = Date.now();
    for (let i = 0; i < 3000; i += 100) await Promise.all(Array.from({ length: 100 }, () => open(idle, false)));
    for (let i = 0; i < 500; i += 100) await Promise.all(Array.from({ length: 100 }, () => open(slow, true)));
    note("sockets opened / refused", { opened, refused });
    // Legit traffic is being measured the whole time. Wait for the server to reap them.
    const reaped = await until(async () => [...idle, ...slow].every((s) => s._closedAt), 45_000, 500);
    const closeTimes = [...idle, ...slow].filter((s) => s._closedAt).map((s) => (s._closedAt - tOpen) / 1000);
    note("seconds until the server closed the idle / slow sockets", { fastest: Math.min(...closeTimes), slowest: Math.max(...closeTimes), closed: closeTimes.length, of: idle.length + slow.length });
    check("every silent and slow-loris socket is closed by the server itself within 45 s (HTTP_FIRST_REQUEST_TIMEOUT_SECONDS=15)", Boolean(reaped), `${closeTimes.length}/${idle.length + slow.length} closed`);
    for (const s of [...idle, ...slow]) s.destroy();

    legit.setPhase("6 recovery"); section("A5. recovery");
    await sleep(10_000);

    const phases = await legit.stop();
    note("legitimate traffic by phase", Object.fromEntries(Object.entries(phases).map(([k, v]) => [k, { read: summarise(v.read), readFail: v.readFail, sensor: summarise(v.sensor), sensorFirstTry: `${v.sensorFirstTry}/${v.sensorTotal}`, sensorLost: v.sensorLost, signin: { ok: v.signinOk, busy503: v.signinBusy, other: v.signinOther }, knownDevice: { ok: v.knownOk, busy503: v.knownBusy, other: v.knownOther } }])));
    const base1 = phases["1 baseline"];
    check("baseline: every read and sensor event succeeded", base1.readFail === 0 && base1.sensorLost === 0 && base1.sensorFirstTry === base1.sensorTotal, JSON.stringify(base1).slice(0, 200));
    for (const name of Object.keys(phases).filter((p) => p !== "1 baseline")) {
      const p = phases[name];
      check(`${name}: no sensor event lost (retries included)`, p.sensorLost === 0, `${p.sensorLost} lost`);
      check(`${name}: dashboard reads succeed ≥ 90%`, p.read.length + p.readFail === 0 || p.read.length / (p.read.length + p.readFail) >= 0.9, `${p.read.length} ok / ${p.readFail} failed`);
    }
    const collateral = Object.entries(phases).filter(([, p]) => p.signinOther > 0).map(([k, p]) => `${k}: ${p.signinOther}`);
    check("a legitimate sign-in is never throttled as collateral of a distributed flood (only 'busy' 503 when the hashing queue is full)", collateral.length === 0, collateral.join(", "));
    check("legitimate sign-ins never fail outright outside the flood phases", Object.entries(phases).filter(([k]) => /baseline|recovery|oversized|connection/.test(k)).every(([, p]) => p.signinBusy === 0), "");
    const known = Object.values(phases).reduce((a, p) => ({ ok: a.ok + p.knownOk, busy: a.busy + p.knownBusy, other: a.other + p.knownOther }), { ok: 0, busy: 0, other: 0 });
    const knownInFlood = Object.entries(phases).filter(([k]) => /^2[cd] [^→]*$/.test(k)).reduce((a, [, p]) => ({ ok: a.ok + p.knownOk, busy: a.busy + p.knownBusy }), { ok: 0, busy: 0 });
    note("sign-in from a known device (all phases / during the sign-in floods)", { all: known, duringSignInFloods: knownInFlood });
    check("a known device signs in throughout — including while the sign-in floods make others wait (priority lane)", known.busy === 0 && known.other === 0 && knownInFlood.ok > 0, JSON.stringify({ known, knownInFlood }));
    const recov = phases["6 recovery"];
    check("recovery: reads back to normal speed (p95 < 300 ms)", pct(recov.read, 95) < 300, JSON.stringify(summarise(recov.read)));
    check("recovery: sign-in works again", recov.signinOk > 0 && recov.signinBusy === 0, JSON.stringify({ ok: recov.signinOk, busy: recov.signinBusy, other: recov.signinOther }));
    check("API still alive and healthy after everything", (await fetch(`${api.base}/health`).then((r) => r.status).catch(() => 0)) === 200);
    check("no unhandled errors in the API log", !/Unhandled|TypeError|ReferenceError|ERR_/.test(api.log().replace(/Unhandled error: [A-Za-z]*Error \[?[A-Z_]*\]?: (?:Too many|Connection|request|aborted)[^\n]*/g, "")), (api.log().match(/.*(Unhandled|TypeError|ReferenceError).*/) ?? [""])[0]);
  } finally {
    await api.stop().catch(() => {});
    await db.drop();
  }
}

// --- PART B -----------------------------------------------------------------------------------------------------------

/** Cloudflare-style range lists for the updater (documentation addresses; `trustLoopback` adds the test client's own address). */
function rangeFixture(dir, { trustLoopback }) {
  mkdirSync(dir, { recursive: true });
  const v4 = ["192.0.2.0/24", "198.18.0.0/15", "203.0.113.0/24", "100.64.0.0/10", "172.31.0.0/16", ...(trustLoopback ? ["127.0.0.1/32"] : [])];
  writeFileSync(join(dir, "ips-v4"), v4.join("\n") + "\n");
  writeFileSync(join(dir, "ips-v6"), ["2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48"].join("\n") + "\n");
}

/** deploy/nginx.conf, unchanged except what a test machine forces: ports, upstreams, the real-IP include. */
function startNginx({ dir, port, apiPort, dashboardPort, snippet }) {
  mkdirSync(join(dir, "logs"), { recursive: true });
  let site = readFileSync(join(REPO, "deploy", "nginx.conf"), "utf8");
  const swaps = [
    [/listen 80;/, `listen 127.0.0.1:${port};`],
    [/^\s*listen \[::\]:80;\n/m, ""],
    [/server 127\.0\.0\.1:8000;/, `server 127.0.0.1:${apiPort};`],
    [/server localhost:3000;/, `server 127.0.0.1:${dashboardPort};`],
    [/# include \/etc\/nginx\/legion-cloudflare\.conf;/, `include ${snippet};`],
  ];
  for (const [from, to] of swaps) {
    if (!from.test(site)) throw new Error(`deploy/nginx.conf no longer contains ${from} — update the test`);
    site = site.replace(from, to);
  }
  writeFileSync(join(dir, "site.conf"), site);
  const main = join(dir, "nginx.conf");
  writeFileSync(main, `worker_processes 1;\npid ${dir}/nginx.pid;\nerror_log ${dir}/logs/error.log warn;\nevents { worker_connections 4096; }\nhttp {\n  access_log off;\n  client_body_temp_path ${dir}/body; proxy_temp_path ${dir}/proxy; fastcgi_temp_path ${dir}/fcgi; uwsgi_temp_path ${dir}/uwsgi; scgi_temp_path ${dir}/scgi;\n  include ${dir}/site.conf;\n}\n`);
  // -e: the compiled-in error log (/var/log/nginx) is opened before the config is read; a non-root test run must not depend on it.
  const args = ["-p", dir, "-c", main, "-e", join(dir, "logs", "startup.log")];
  const test = spawnSync("nginx", [...args, "-t"], { encoding: "utf8" });
  const proc = spawn("nginx", [...args, "-g", "daemon off;"], { stdio: "ignore" });
  return { test, proc, port, base: `http://127.0.0.1:${port}`, stop: () => { proc.kill("SIGTERM"); } };
}

/** A tiny dashboard stand-in so `location /` has something to proxy to. */
function startDashboardStub() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => { res.setHeader("content-type", "text/html"); res.end("<html>dashboard</html>"); });
    server.listen(0, "127.0.0.1", () => resolve({ port: server.address().port, close: () => server.close() }));
  });
}

/** nginx's own refusal is an HTML page; Legion's refusals are JSON. */
const byNginx = (r) => r.status === 429 && /html/.test(r.headers.get("content-type") ?? "");
const byLegion = (r) => r.status === 429 && /json/.test(r.headers.get("content-type") ?? "");

async function burst(base, n, { path, method = "GET", headers = {}, body }) {
  return Promise.all(Array.from({ length: n }, () => fetch(`${base}${path}`, { method, headers, body, redirect: "manual" }).then((r) => { r.arrayBuffer().catch(() => {}); return r; }).catch((e) => ({ status: 0, headers: new Headers(), error: e.code }))));
}

async function partB() {
  const nginxV = spawnSync("nginx", ["-v"], { encoding: "utf8" });
  if (nginxV.error) { check("nginx is installed (needed for part B)", false, "nginx not found on PATH"); return; }
  section("B. setup");
  note("nginx", (nginxV.stderr || nginxV.stdout).trim());
  const work = mkdtempSync(join(tmpdir(), "legion-nginx-"));
  const db = await freshDatabase(ADMIN, "legion_dosb");
  const apiPort = await freePort();
  const api = await startApi({
    NODE_ENV: "production", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url, JWT_SECRET: randomBytes(48).toString("hex"),
    LEGION_ENCRYPTION_KEYS: `dosb:${randomBytes(32).toString("hex")}`, FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true", SMTP_HOST: "127.0.0.1", SMTP_PORT: "9",
  }, { port: apiPort });
  const dash = await startDashboardStub();
  const servers = [];
  try {
    section("B1. the updater script produces a snippet nginx accepts");
    // Two generated snippets: one that trusts the connecting test client (stands in for Cloudflare), one that does not (a stranger).
    const fixCf = join(work, "fix-cf"), fixOther = join(work, "fix-other");
    rangeFixture(fixCf, { trustLoopback: true }); rangeFixture(fixOther, { trustLoopback: false });
    const snipCf = join(work, "cf.conf"), snipOther = join(work, "other.conf");
    for (const [fix, out] of [[fixCf, snipCf], [fixOther, snipOther]]) {
      const r = spawnSync("bash", [join(REPO, "ops", "update-cloudflare-ips.sh"), "--from-dir", fix, "--out", out], { encoding: "utf8" });
      check(`updater writes ${out.split("/").pop()}`, r.status === 0 && existsSync(out), r.stderr);
    }
    const cfPort = await freePort(), otherPort = await freePort();
    const cf = startNginx({ dir: join(work, "nginx-cf"), port: cfPort, apiPort, dashboardPort: dash.port, snippet: snipCf });
    const other = startNginx({ dir: join(work, "nginx-other"), port: otherPort, apiPort, dashboardPort: dash.port, snippet: snipOther });
    servers.push(cf, other);
    check("`nginx -t` accepts deploy/nginx.conf with the generated snippet included", cf.test.status === 0 && other.test.status === 0, cf.test.stderr + other.test.stderr);
    const ready = await until(async () => (await fetch(`${cf.base}/api/health`)).status === 200 && (await fetch(`${other.base}/api/health`)).status === 200, 15_000, 200);
    check("both nginx instances proxy /api/health to the API", Boolean(ready), "");
    const dashRes = await fetch(`${cf.base}/`).then((r) => r.text()).catch(() => "");
    check("/ is proxied to the dashboard", dashRes.includes("dashboard"), dashRes.slice(0, 100));
    const hdr = await fetch(`${cf.base}/api/health`);
    check("nginx adds its security headers and does not announce its version", /nosniff/.test(hdr.headers.get("x-content-type-options") ?? "") && /strict-transport-security/i.test([...hdr.headers.keys()].join(",")) && hdr.headers.get("server") === "nginx", JSON.stringify([...hdr.headers]));

    section("B2. request limits at nginx (before a request costs Node anything)");
    const login = { path: "/api/auth/login", method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.1" }, body: JSON.stringify({ username: "nobody@example.com", password: "wrong-wrong-wrong" }) };
    const first = await burst(cf.base, 80, login);
    const nginxRefused = first.filter(byNginx).length;
    note("80 sign-in attempts in one burst from one real address (nginx: 30/min, burst 20)", { refusedByNginx: nginxRefused, refusedByLegion: first.filter(byLegion).length, reached_the_API: first.filter((r) => r.status === 401).length });
    check("nginx itself refuses the excess with 429 — most of the burst never reaches Node", nginxRefused >= 40, String(nginxRefused));
    const junk = await burst(cf.base, 400, { path: `/api/nope-${Math.random()}`, headers: { "cf-connecting-ip": "198.51.100.3" } });
    check("a flood of unauthenticated API requests is cut at nginx (20 r/s, burst 200)", junk.filter(byNginx).length >= 150, String(junk.filter(byNginx).length));
    const wh = await burst(cf.base, 120, { path: "/api/security-events/webhook", method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.4" }, body: "{}" });
    check("the sensor webhook is NOT rate-limited by nginx (a busy Wazuh manager is never throttled there)", wh.filter(byNginx).length === 0, `${wh.filter(byNginx).length} nginx refusals`);

    section("B3. the real client address behind a CDN");
    const a = await burst(cf.base, 1, login);
    const b = await burst(cf.base, 1, { ...login, headers: { ...login.headers, "cf-connecting-ip": "198.51.100.2" } });
    check("trusted CDN: the visitor already throttled stays throttled …", byNginx(a[0]), String(a[0].status));
    check("… and a different visitor behind the same CDN is unaffected (own bucket, reaches the API)", b[0].status === 401, String(b[0].status));
    // Legion itself must see the real address too: its own per-address sign-in limit (10 / min) is the proof.
    const mk = (ip) => ({ ...login, headers: { ...login.headers, "cf-connecting-ip": ip }, body: JSON.stringify({ username: `u${ip}@example.com`, password: "wrong-wrong-wrong" }) });
    const seq = async (base, ip, n) => { const out = []; for (let i = 0; i < n; i++) out.push((await burst(base, 1, mk(ip)))[0]); return out; };
    const x = await seq(cf.base, "198.51.100.50", 14);
    const y = await burst(cf.base, 1, mk("198.51.100.51"));
    note("Legion's per-address sign-in limit through nginx (14 attempts from X, then 1 from Y)", { x: x.map((r) => r.status).join(","), y: y[0].status });
    check("trusted CDN: Legion throttles visitor X on its own limit but still serves visitor Y (it sees the real addresses)", x.some(byLegion) && y[0].status === 401, `${x.map((r) => r.status)} / ${y[0].status}`);

    // The same traffic through nginx that does NOT trust the sender (an attacker who reaches the origin directly, or a stale range list).
    const o1 = await burst(other.base, 80, login);
    let escaped = 0;
    for (let i = 0; i < 60; i++) { const r = (await burst(other.base, 1, mk(`198.51.100.${100 + i}`)))[0]; if (r.status === 401) escaped++; }
    note("untrusted sender rotating CF-Connecting-IP over 60 values after a burst", { escapedLimits: escaped, burstRefusedByNginx: o1.filter(byNginx).length });
    check("untrusted sender: a forged CF-Connecting-IP is ignored — rotating it does not escape nginx's limits", escaped <= 2, `${escaped} of 60 got through`);

    section("B4. slow clients at nginx");
    const tSlow = Date.now();
    let slowSock;
    const slow = await new Promise((resolve) => {
      slowSock = net.connect({ host: "127.0.0.1", port: cfPort }, () => { slowSock.write("GET /api/health HTTP/1.1\r\nHost: legion\r\n"); });
      slowSock.on("close", () => resolve((Date.now() - tSlow) / 1000)); slowSock.on("error", () => {});
      setTimeout(() => resolve(null), 30_000);
    });
    slowSock.destroy();
    note("seconds until nginx dropped a slow-loris client (client_header_timeout 15s)", slow);
    check("nginx drops a client that never finishes its headers within ~15 s", slow !== null && slow >= 13 && slow <= 20, String(slow));

    // Connections held open by a half-sent body count against limit_conn (300 per address).
    const held = [];
    const hold = (ip) => new Promise((resolve) => {
      const s = net.connect({ host: "127.0.0.1", port: cfPort }, () => {
        s.write(`POST /api/security-events/webhook HTTP/1.1\r\nHost: legion\r\nCF-Connecting-IP: ${ip}\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{`);
        resolve();
      });
      s.on("error", () => resolve()); held.push(s);
    });
    for (let i = 0; i < 320; i += 80) await Promise.all(Array.from({ length: 80 }, () => hold("198.51.100.200")));
    await sleep(1500);
    const over = await burst(cf.base, 1, { path: "/api/health", headers: { "cf-connecting-ip": "198.51.100.200" } });
    const other2 = await burst(cf.base, 1, { path: "/api/health", headers: { "cf-connecting-ip": "198.51.100.201" } });
    check("one address holding 320 half-sent requests is refused further connections (limit_conn 300)", byNginx(over[0]), String(over[0].status));
    check("… while another visitor is served normally during it", other2[0].status === 200, String(other2[0].status));
    for (const s of held) s.destroy();
    check("the API stayed healthy through all of it", (await fetch(`${api.base}/health`).then((r) => r.status).catch(() => 0)) === 200);
  } finally {
    for (const s of servers) s.stop();
    dash.close();
    await api.stop().catch(() => {});
    await db.drop();
  }
}

try {
  if (PART === "a" || PART === "all") await partA();
  if (PART === "b" || PART === "all") await partB();
} catch (err) {
  check("ran to completion", false, err instanceof Error ? err.stack : String(err));
} finally {
  const failed = R.summary();
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(R.results, null, 2));
  process.exit(failed ? 1 : 0);
}
