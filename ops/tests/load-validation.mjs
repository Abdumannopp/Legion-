#!/usr/bin/env node
/**
 * Load and scalability validation of the BUILT API: several instances behind
 * one Postgres and one Redis, many workspaces, many dashboard users, a burst
 * of sensor events (with duplicates), the mail server failing in the middle
 * of a second burst, and one instance SIGKILLed while that burst is in flight.
 *
 * It measures, it does not assume: latency percentiles per request type,
 * throughput, error codes, Postgres connections, outbox backlog and the time
 * it takes to drain, and whether every event became exactly one alert, one
 * email (where one is due) and reached the right dashboard socket.
 *
 *   npm --prefix server run build
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/load-validation.mjs [--json out.json]
 *
 * Sizing (env): LOAD_INSTANCES=3 LOAD_ORGS=20 LOAD_USERS_PER_ORG=5 LOAD_EVENTS=3000 LOAD_CONCURRENCY=64
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import {
  client, decodeQP, freePort, freshDatabase, realtime, reporter, signedWebhook, smtpSink, sql, startApi, until, sleep,
  wazuhAlert, webhookBody,
} from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const jsonOut = process.argv.includes("--json") ? process.argv[process.argv.indexOf("--json") + 1] : null;
const N_INST = Number(process.env.LOAD_INSTANCES || 3);
const N_ORGS = Number(process.env.LOAD_ORGS || 20);
const USERS_PER_ORG = Number(process.env.LOAD_USERS_PER_ORG || 5);
const N_EVENTS = Number(process.env.LOAD_EVENTS || 3000);
const CONC = Number(process.env.LOAD_CONCURRENCY || 64);
const FRONTEND = "https://app.legion.test";
const R = reporter("load validation");
const { check, section, note } = R;

const lat = {}; // kind -> [ms]
const codes = {}; // kind -> {status: n}
function record(kind, ms, status) {
  (lat[kind] ??= []).push(ms);
  (codes[kind] ??= {})[status] = ((codes[kind] ??= {})[status] ?? 0) + 1;
}
function pct(a, p) { if (!a.length) return null; const s = [...a].sort((x, y) => x - y); return Math.round(s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]); }
const stats = (kind) => ({ n: lat[kind]?.length ?? 0, p50: pct(lat[kind] ?? [], 50), p95: pct(lat[kind] ?? [], 95), p99: pct(lat[kind] ?? [], 99), max: pct(lat[kind] ?? [], 100), codes: codes[kind] });

async function timed(kind, fn) {
  const t = performance.now();
  try {
    const r = await fn();
    record(kind, performance.now() - t, r.status);
    return r;
  } catch (e) {
    record(kind, performance.now() - t, `ERR:${e.cause?.code ?? e.name}`);
    return { status: 0, error: e };
  }
}

/** Runs `tasks` (thunks) with at most `n` in flight. */
async function pool(tasks, n) {
  let i = 0;
  const workers = Array.from({ length: n }, async () => { while (i < tasks.length) { const t = tasks[i++]; await t(); } });
  await Promise.all(workers);
}

let db, smtp, redis, insts = [];
const env = {};

async function main() {
  section("setup");
  db = await freshDatabase(ADMIN, "legion_load");
  smtp = await smtpSink(await freePort());
  const redisPort = await freePort();
  redis = spawn("redis-server", ["--port", String(redisPort), "--save", "", "--appendonly", "no", "--bind", "127.0.0.1"], { stdio: "ignore" });
  await sleep(500);
  Object.assign(env, {
    NODE_ENV: "production", DEPLOYMENT_MODE: "saas", DATABASE_URL: db.url, REDIS_URL: `redis://127.0.0.1:${redisPort}`,
    JWT_SECRET: randomBytes(48).toString("hex"), LEGION_ENCRYPTION_KEYS: `load:${randomBytes(32).toString("hex")}`,
    FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true", SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtp.port),
    HEALTH_METRICS_TOKEN: "load-metrics-token-0123456789abcdef",
    // Test-time cadence only: the worker polls every second and retries after
    // 2 s instead of 30 s, so a backlog can be seen to drain within the run.
    NOTIFY_POLL_SECONDS: "1", NOTIFY_RETRY_BASE_SECONDS: "2",
    // Many high alerts per workspace in one hour is the point of the test.
    ALERT_EMAIL_HOURLY_CAP: "100000",
  });
  for (let i = 0; i < N_INST; i++) insts.push(await startApi(env, { name: `api${i}`, port: await freePort() }));
  check(`${N_INST} API instances up (shared Postgres + Redis)`, insts.every((x) => x.up), insts.map((x) => x.log().slice(-300)).join("\n"));
  const inst = (i) => insts[i % insts.length];

  // Connection pressure sampler.
  let peakConns = 0, sampling = true;
  const sampler = (async () => {
    while (sampling) {
      const r = await sql(ADMIN, "postgres", "SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = $1", [db.db]).catch(() => [{ n: 0 }]);
      peakConns = Math.max(peakConns, r[0].n);
      await sleep(500);
    }
  })();

  section(`workspaces: ${N_ORGS} organisations sign up concurrently`);
  const orgs = [];
  await pool(Array.from({ length: N_ORGS }, (_, k) => async () => {
    const ip = `198.18.${k}.1`;
    const email = `owner${k}-${randomBytes(2).toString("hex")}@example.com`, password = `Load-test-password-${k}!`;
    const c = client(inst(k).base, { ip, headers: { origin: FRONTEND } });
    const reg = await timed("signup", () => c.call("/auth/register", { method: "POST", body: { tenant_name: `Load org ${k}`, email, password } }));
    const mail = await until(async () => smtp.messages.find((m) => m.to.some((t) => t.includes(email))), 30_000);
    const token = mail && /verify-email\?token=([A-Za-z0-9_-]+)/.exec(decodeQP(mail.data))?.[1];
    await c.call("/auth/verify-email", { method: "POST", body: { token } });
    const login = await timed("login", () => c.call("/auth/login", { method: "POST", body: { username: email, password } }));
    c.setToken(login.body?.access_token);
    await c.call("/notifications/settings", { method: "PATCH", body: { notification_email: `alerts${k}@example.com` } });
    const cm = await until(async () => smtp.messages.find((m) => m.to.some((t) => t.includes(`alerts${k}@example.com`))), 30_000);
    const ct = cm && /confirm-notification-email\?token=([A-Za-z0-9_-]+)/.exec(decodeQP(cm.data))?.[1];
    await c.call("/notifications/confirm", { method: "POST", body: { token: ct } });
    const cred = await c.call("/security-events/credentials", { method: "POST", body: { label: "load" } });
    const me = await c.call("/auth/me");
    orgs.push({ k, ip, email, password, c, cookie: login.setCookies?.map((x) => x.split(";")[0]).join("; "), cred: cred.body, tenant: me.body.tenant_id, ok: reg.status === 201 && Boolean(c.token) && cred.status === 201 });
  }), 10);
  check(`all ${N_ORGS} workspaces signed up, confirmed, keyed`, orgs.length === N_ORGS && orgs.every((o) => o.ok), orgs.filter((o) => !o.ok).map((o) => o.k).join(","));

  // One realtime socket per organisation, each on some instance — fan-out has to cross instances.
  for (const o of orgs) o.ws = await realtime(inst(o.k + 1).base, o.cookie, FRONTEND);
  check("every workspace has a live socket", orgs.every((o) => o.ws.ok));

  // Dashboard users: sessions per org, reading while the burst runs.
  const users = [];
  for (const o of orgs) for (let u = 0; u < USERS_PER_ORG; u++) users.push({ o, c: client(inst(o.k + u).base, { ip: `198.19.${o.k}.${u + 1}`, token: o.c.token }) });
  let reading = true;
  const readers = users.map(async (u, j) => {
    const paths = ["/alerts?limit=50", "/overview", "/alerts/stats"];
    let n = 0;
    while (reading) {
      const p = paths[(j + n++) % paths.length];
      await timed(`read ${p.split("?")[0]}`, () => u.c.call(p));
      await sleep(200 + Math.random() * 300);
    }
  });

  section(`burst 1: ${N_EVENTS} sensor events (10% re-sent) across ${N_INST} instances, concurrency ${CONC}`);
  const levels = [3, 7, 10, 12];
  const events = [];
  for (let i = 0; i < N_EVENTS; i++) {
    const o = orgs[i % orgs.length];
    const a = wazuhAlert(100000 + i, { level: levels[i % levels.length], agent: `host-${o.k}-${i % 7}`, srcip: `10.${o.k}.${(i >> 8) & 255}.${i & 255}` });
    events.push({ o, body: webhookBody(a), level: a.rule.level });
  }
  const resend = events.filter((_, i) => i % 10 === 0);
  const sends = [...events, ...resend].map((e, i) => async () => {
    for (let attempt = 0; attempt < 5; attempt++) {
      const r = await timed("webhook", () => signedWebhook(inst(i + attempt).base, e.o.cred.id, e.o.cred.secret, e.body, { ip: `198.20.${e.o.k}.9` })());
      if (r.status === 202 || r.status === 200) return;
      await sleep(200 * (attempt + 1));
    }
    e.failed = true;
  });
  const t1 = performance.now();
  await pool(sends, CONC);
  const secs1 = (performance.now() - t1) / 1000;
  note("burst 1 throughput", `${Math.round(sends.length / secs1)} requests/s (${sends.length} in ${secs1.toFixed(1)} s)`);
  note("webhook latency (ms)", stats("webhook"));
  check("no event lost to an error after the sensor's retries", events.every((e) => !e.failed));
  const http5xx = Object.entries(codes.webhook ?? {}).filter(([s]) => String(s).startsWith("5") || String(s).startsWith("ERR")).reduce((a, [, n]) => a + n, 0);
  check("no 5xx or connection error on the webhook during burst 1", http5xx === 0, JSON.stringify(codes.webhook));
  const perOrg = await sql(ADMIN, db.db, "SELECT tenant_id, count(*)::int AS n FROM alerts WHERE source = 'wazuh' GROUP BY tenant_id");
  const expectPer = Math.ceil(N_EVENTS / N_ORGS);
  check("exactly one alert per distinct event, per workspace (duplicates collapsed)", perOrg.length === N_ORGS && perOrg.every((r) => Math.abs(r.n - expectPer) <= 1) && perOrg.reduce((a, r) => a + r.n, 0) === N_EVENTS, JSON.stringify(perOrg.slice(0, 5)));
  const highCount = events.filter((e) => e.level >= 10).length;
  const drained1 = await until(async () => {
    const r = await sql(ADMIN, db.db, "SELECT count(*) FILTER (WHERE status <> 'sent')::int AS open, count(*) FILTER (WHERE kind = 'alert_email' AND status = 'sent')::int AS emails FROM notification_outbox");
    return r[0].open === 0 ? r[0] : null;
  }, 180_000, 1000);
  check("outbox fully drained after burst 1", Boolean(drained1), JSON.stringify(await sql(ADMIN, db.db, "SELECT kind, status, count(*)::int FROM notification_outbox GROUP BY 1,2")));
  // Alert emails go to each workspace's confirmed alert address; the only other
  // mail to that address was its confirmation link.
  const alertMails = () => smtp.messages.filter((m) => m.to.some((t) => /alerts\d+@example\.com/.test(t)) && !/confirm-notification-email/.test(decodeQP(m.data)));
  check(`one email per high/critical alert (${highCount}), none twice`, drained1 && drained1.emails === highCount && new Set(alertMails().map((m) => /Message-ID:\s*(\S+)/i.exec(m.data)?.[1])).size === alertMails().length, JSON.stringify({ emails: drained1?.emails, expected: highCount, sink: alertMails().length }));
  const wsMissing = [];
  for (const o of orgs) {
    const ids = new Set((await sql(ADMIN, db.db, "SELECT id FROM alerts WHERE tenant_id = $1 AND source = 'wazuh'", [o.tenant])).map((r) => r.id));
    const got = new Set(o.ws.frames.filter((f) => f?.alert?.id).map((f) => f.alert.id));
    const foreign = [...got].filter((id) => !ids.has(id));
    const missing = [...ids].filter((id) => !got.has(id));
    if (missing.length || foreign.length) wsMissing.push({ k: o.k, missing: missing.length, foreign: foreign.length });
  }
  check("every alert reached its own workspace's socket (across instances), and no other workspace's", wsMissing.length === 0, JSON.stringify(wsMissing.slice(0, 5)));

  section("burst 2: mail server failing + one instance SIGKILLed mid-burst");
  smtp.setMode("fail");
  const burst2 = [];
  for (let i = 0; i < Math.round(N_EVENTS / 3); i++) {
    const o = orgs[i % orgs.length];
    const a = wazuhAlert(900000 + i, { level: 12, agent: `b2-${o.k}`, srcip: `172.16.${o.k}.${i & 255}` });
    burst2.push({ o, body: webhookBody(a) });
  }
  let killed = false;
  const sends2 = burst2.map((e, i) => async () => {
    if (i === Math.floor(burst2.length / 2) && !killed) { killed = true; insts[0].proc.kill("SIGKILL"); }
    for (let attempt = 0; attempt < 8; attempt++) {
      const target = insts[(i + attempt) % insts.length];
      const r = await timed("webhook (burst 2)", () => signedWebhook(target.base, e.o.cred.id, e.o.cred.secret, e.body, { ip: `198.20.${e.o.k}.9` })());
      if (r.status === 202 || r.status === 200) return;
      await sleep(250 * (attempt + 1));
    }
    e.failed = true;
  });
  await pool(sends2, CONC);
  check("burst 2: every event accepted despite the killed instance (sensor retries elsewhere)", burst2.every((e) => !e.failed));
  const backlog = await (await fetch(`${insts[1].base}/health/outbox`, { headers: { authorization: `Bearer ${env.HEALTH_METRICS_TOKEN}` } })).json();
  note("outbox while mail fails", backlog);
  check("backlog is visible in queue health while mail fails", JSON.stringify(backlog).match(/"(pending|retrying)":\s*[1-9]/), JSON.stringify(backlog));
  insts[0] = await startApi(env, { name: "api0", port: insts[0].port });
  check("killed instance restarted", insts[0].up);
  smtp.setMode("accept");
  const tDrain = performance.now();
  const drained2 = await until(async () => {
    const r = await sql(ADMIN, db.db, "SELECT count(*) FILTER (WHERE status NOT IN ('sent'))::int AS open, count(*) FILTER (WHERE status = 'dead')::int AS dead FROM notification_outbox");
    return r[0].open === 0 ? r[0] : null;
  }, 300_000, 1000);
  note("drain time after mail recovers", drained2 ? `${((performance.now() - tDrain) / 1000).toFixed(1)} s (includes the 120 s lease on jobs the killed instance held)` : "did not drain");
  check("outbox drained after the mail server recovered (no dead letters)", Boolean(drained2), JSON.stringify(await sql(ADMIN, db.db, "SELECT kind, status, count(*)::int FROM notification_outbox GROUP BY 1,2")));
  const b2 = await sql(ADMIN, db.db, "SELECT count(*)::int AS n FROM alerts WHERE target LIKE 'b2-%'");
  check("burst 2: exactly one alert per event", b2[0].n === burst2.length, `${b2[0].n} vs ${burst2.length}`);
  const ids = alertMails().map((m) => /Message-ID:\s*(\S+)/i.exec(m.data)?.[1]);
  const dupMsg = ids.length - new Set(ids).size;
  note("alert emails received", { total: ids.length, duplicate_message_ids: dupMsg, expected: highCount + burst2.length });
  check("every due email delivered after recovery", ids.length - dupMsg >= highCount + burst2.length, `${ids.length - dupMsg} < ${highCount + burst2.length}`);
  check("duplicate deliveries (SIGKILL mid-send) are at most the in-flight sends, and carry the same Message-ID", dupMsg <= CONC, String(dupMsg));

  section("rate limits under concurrency, across instances");
  const target = orgs[0];
  let failuresBefore429 = 0, first429 = null;
  await pool(Array.from({ length: 60 }, (_, i) => async () => {
    const r = await client(inst(i).base, { ip: `198.51.${i}.7` }).call("/auth/login", { method: "POST", body: { username: target.email, password: `wrong-${i}-password` } });
    if (r.status === 401) failuresBefore429++;
    if (r.status === 429 && first429 === null) first429 = i;
  }), 12);
  note("account lockout across instances", { failures_accepted_before_429: failuresBefore429, limit: 20 });
  check("failed sign-ins for one account are capped globally (Redis), not per instance", failuresBefore429 <= 22 && first429 !== null, String(failuresBefore429));

  reading = false;
  await Promise.all(readers);
  sampling = false;
  await sampler;
  for (const k of Object.keys(lat).filter((k) => k.startsWith("read"))) note(`${k} latency (ms)`, stats(k));
  const readErrors = Object.keys(lat).filter((k) => k.startsWith("read")).flatMap((k) => Object.entries(codes[k]).filter(([s]) => s !== "200").map(([s, n]) => `${k}:${s}=${n}`));
  note("dashboard read non-200s", readErrors.join(" ") || "none");
  const readOnlyRateLimited = readErrors.every((e) => /:(429|401|0|ERR)/.test(e));
  check("dashboard reads: no 5xx under load", readErrors.filter((e) => /:5\d\d=/.test(e)).length === 0, readErrors.join(" "));
  check("dashboard reads p95 < 1000 ms during the burst", Object.keys(lat).filter((k) => k.startsWith("read")).every((k) => stats(k).p95 < 1000), JSON.stringify(Object.keys(lat).filter((k) => k.startsWith("read")).map((k) => [k, stats(k).p95])));
  check("webhook p95 < 1000 ms during burst 1", stats("webhook").p95 < 1000, String(stats("webhook").p95));
  note("peak Postgres connections", `${peakConns} (pool max ${10} × ${N_INST} instances + background)`);
  check("Postgres connections stay within the pools' bound", peakConns <= 10 * N_INST + 5, String(peakConns));
  note("read errors only from session expiry / rate limit", readOnlyRateLimited);
  for (const i of insts) if (/TypeError|ReferenceError|Unhandled/.test(i.log())) check(`${i.name}: no unhandled errors in the log`, false, (i.log().match(/.*(TypeError|ReferenceError|Unhandled).*/) ?? [""])[0]);
}

try {
  await main();
} catch (err) {
  check("ran to completion", false, err instanceof Error ? err.stack : String(err));
} finally {
  for (const i of insts) await i.stop().catch(() => {});
  redis?.kill("SIGTERM");
  await smtp?.stop().catch(() => {});
  await db?.drop();
  const failed = R.summary();
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ results: R.results, latency: Object.fromEntries(Object.keys(lat).map((k) => [k, stats(k)])) }, null, 2));
  process.exit(failed ? 1 : 0);
}
