#!/usr/bin/env node
/**
 * Password hashing under concurrency — the release blocker found in the final
 * validation (PRODUCTION-VALIDATION-2026-10-01.md, RED-1).
 *
 * Measures, against the built API:
 *  1. how long an unrelated request (/health) waits while unauthenticated
 *     failed sign-ins arrive concurrently (bcryptjs runs on the event loop);
 *  2. whether the per-account failed-sign-in limit (20 / 15 min) holds across
 *     three instances sharing Redis when the attempts arrive concurrently.
 *
 * Exits non-zero while either fails, so it doubles as the regression test for
 * the fix.
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/auth-load-probe.mjs
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { client, freePort, freshDatabase, reporter, startApi, sleep } from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const R = reporter("auth under load");
const { check, section, note } = R;
let db, redis, insts = [];

async function healthLatency(base, n = 20) {
  const t = [];
  for (let i = 0; i < n; i++) { const s = performance.now(); await fetch(`${base}/health`); t.push(performance.now() - s); await sleep(50); }
  t.sort((a, b) => a - b);
  return { p50: Math.round(t[Math.floor(n / 2)]), max: Math.round(t[n - 1]) };
}

async function main() {
  db = await freshDatabase(ADMIN, "legion_authload");
  const rp = await freePort();
  redis = spawn("redis-server", ["--port", String(rp), "--save", "", "--appendonly", "no", "--bind", "127.0.0.1"], { stdio: "ignore" });
  await sleep(400);
  const env = {
    NODE_ENV: "development", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url, REDIS_URL: `redis://127.0.0.1:${rp}`,
    JWT_SECRET: randomBytes(48).toString("hex"), LEGION_ENCRYPTION_KEYS: `al:${randomBytes(32).toString("hex")}`,
    FRONTEND_URL: "http://localhost:3000", COOKIE_SECURE: "false",
  };
  for (let i = 0; i < 3; i++) insts.push(await startApi(env, { port: await freePort() }));
  const token = /(lst_[A-Za-z0-9_-]+)/.exec(insts.map((i) => i.log()).join(""))?.[1];
  await client(insts[0].base).call("/auth/register", { method: "POST", body: { email: "owner@example.com", password: "Correct-horse-1234", tenant_name: "Auth load", setup_token: token } });

  section("event loop under concurrent sign-in attempts (one instance)");
  const base = insts[0].base;
  const idle = await healthLatency(base);
  let stop = false, n = 0;
  // 30 attackers, each from its own address (a botnet; each stays under 10/min per address only briefly).
  const attackers = Array.from({ length: 30 }, async (_, k) => {
    while (!stop) await client(base, { ip: `10.77.${k}.${n % 250}` }).call("/auth/login", { method: "POST", body: { username: `nobody${n++}@example.com`, password: "wrong-password-123" } });
  });
  await sleep(500);
  const busy = await healthLatency(base);
  stop = true;
  await Promise.all(attackers);
  note("/health latency idle (ms)", idle);
  note("/health latency during 30 concurrent failed sign-ins (ms)", busy);
  note("sign-in attempts processed", n);
  check("an unrelated request is not stalled by concurrent sign-ins (p50 < 250 ms)", busy.p50 < 250, JSON.stringify(busy));

  section("per-account failed sign-in limit across 3 instances (Redis)");
  for (const conc of [1, 12, 30]) {
    const who = `victim${conc}@example.com`;
    let accepted = 0, i = 0;
    await Promise.all(Array.from({ length: conc }, async () => {
      while (i < 60) {
        const k = i++;
        const r = await client(insts[k % 3].base, { ip: `198.51.${conc}.${k}` }).call("/auth/login", { method: "POST", body: { username: who, password: `wrong-${k}-xxxxxxx` } });
        if (r.status === 401) accepted++;
      }
    }));
    note(`failed attempts accepted at concurrency ${conc}`, accepted);
    check(`limit of 20 holds at concurrency ${conc}`, accepted <= 20, String(accepted));
  }
  const fallbacks = insts.map((x) => (x.log().match(/counting locally/g) ?? []).length);
  note("'Redis unavailable, counting locally' per instance (Redis was healthy throughout)", fallbacks);
}

try { await main(); } catch (e) { check("ran to completion", false, e?.stack ?? String(e)); }
finally {
  for (const i of insts) await i.stop().catch(() => {});
  redis?.kill();
  await db?.drop();
  process.exit(R.summary() ? 1 : 0);
}
