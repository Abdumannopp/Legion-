/**
 * THE RECOVERY DRILL. A real disaster, end to end, with nothing mocked:
 *
 *   seed a running Legion (users, MFA, alerts, webhook credential)
 *   → encrypted backup with ops/backup.sh
 *   → the database is gone → restore into a brand-new one from the encrypted file
 *   → start the REAL server against it → prove people can sign in, MFA works,
 *     every alert is there and the realtime cursor still counts from where it was
 *   → throw Redis away and start an empty one → nothing in Postgres changes
 *   → provision the app role on the restored database and boot as it
 *   → boot with the WRONG encryption key: MFA is refused, never erased.
 *
 * If this passes, "we can recover" is a measured fact rather than a hope.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, spawnSync, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import request from "supertest";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import pg from "pg";
import { randomUUID, randomBytes } from "node:crypto";
import * as OTPAuth from "otpauth";
import { app } from "../src/index.js";
import { migrate, closePool, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";
import { issueCredential } from "./helpers/webhook.js";

const SERVER_DIR = join(__dirname, "..");
const OPS = join(SERVER_DIR, "..", "ops");
const BASE_URL = process.env.TEST_DATABASE_URL || "postgresql://legion@127.0.0.1:5433/legion_test";
const url = (db: string, user?: string, pw?: string) => {
  const u = new URL(BASE_URL); u.pathname = `/${db}`; if (user) { u.username = user; u.password = pw ?? ""; } return u.toString();
};
const RESTORED = "legion_dr_restored";
const APP_ROLE = "legion_dr_app";
const PASSWORD = "correct horse battery";
const FRONT = "http://localhost:3000";

let work: string, backups: string, priv: string, pub: string;
let redis: ChildProcess | null = null; const REDIS_PORT = 6393;
let server: { proc: ChildProcess; port: number; log: () => string } | null = null;

const seeded = { tenantA: "", tenantB: "", admin: null as null | { id: string; email: string }, mfaEmail: "", mfaSecret: "", alertIds: [] as string[], cursor: 0 };

const freePort = () => new Promise<number>((resolve) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = (s.address() as { port: number }).port; s.close(() => resolve(p)); }); });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(cond: () => Promise<boolean> | boolean, ms: number, what: string) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await cond()) return; await sleep(150); }
  throw new Error(`timed out waiting for ${what}`);
}

const startRedis = async (dir: string) => {
  mkdirSync(dir, { recursive: true });
  redis = spawn("redis-server", ["--port", String(REDIS_PORT), "--save", "", "--appendonly", "no", "--dir", dir], { stdio: "ignore" });
  await until(() => spawnSync("redis-cli", ["-p", String(REDIS_PORT), "ping"]).stdout?.toString().includes("PONG"), 5_000, "redis");
};
const stopRedis = () => { redis?.kill("SIGKILL"); redis = null; };
const redisKeys = () => spawnSync("redis-cli", ["-p", String(REDIS_PORT), "--scan"], { encoding: "utf8" }).stdout.split("\n").filter(Boolean);

async function startServer(env: Record<string, string>) {
  const port = await freePort();
  let out = "";
  const proc = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: SERVER_DIR,
    env: {
      ...process.env,
      NODE_ENV: "development", PORT: String(port), SEED_DEMO_DATA: "false",
      REDIS_URL: `redis://127.0.0.1:${REDIS_PORT}`, FRONTEND_URL: FRONT,
      JWT_SECRET: config.jwtSecret, LEGION_ENCRYPTION_KEYS: config.encryptionKeys,
      DATABASE_URL: url(RESTORED),
      ...env,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  proc.stdout!.on("data", (d) => (out += d)); proc.stderr!.on("data", (d) => (out += d));
  const handle = { proc, port, log: () => out };
  await until(async () => { try { return (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch { return false; } }, 60_000, `the server to start\n${out.slice(-1500)}`);
  server = handle;
  return handle;
}
async function stopServer() {
  if (!server) return;
  const { proc } = server; server = null;
  proc.kill("SIGTERM");
  await new Promise((r) => { proc.once("exit", r); setTimeout(() => { proc.kill("SIGKILL"); r(null); }, 8_000); });
}
const api = (path: string, init: RequestInit & { token?: string } = {}) =>
  fetch(`http://127.0.0.1:${server!.port}${path}`, {
    ...init, headers: { "content-type": "application/json", origin: FRONT, ...(init.token ? { authorization: `Bearer ${init.token}` } : {}), ...(init.headers ?? {}) },
  });
async function login(email: string, ip = "198.51.100.10") {
  const res = await api("/auth/login", { method: "POST", body: JSON.stringify({ username: email, password: PASSWORD }), headers: { "x-forwarded-for": ip } });
  return { status: res.status, body: await res.json() as Record<string, any> };
}
const totp = (secret: string, email: string) => new OTPAuth.TOTP({ issuer: config.mfaIssuer, label: email, algorithm: "SHA1", digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secret) }).generate();

function runOps(script: string, env: Record<string, string>, args: string[] = []) {
  const r = spawnSync("bash", [join(OPS, script), ...args], {
    encoding: "utf8", timeout: 180_000,
    env: { PATH: process.env.PATH, HOME: work, BACKUP_DIR: backups, BACKUP_STATUS_FILE: join(work, "status.json"), ...env } as NodeJS.ProcessEnv,
  });
  return { code: r.status ?? -1, out: (r.stdout ?? "") + (r.stderr ?? "") };
}
async function admin(sql: string) { const c = new pg.Client({ connectionString: url("postgres") }); await c.connect(); try { await c.query(sql); } finally { await c.end(); } }
/** Tables that hold what users own. Logs and sessions change with every sign-in, so they are not compared for equality. */
const SOURCE_OF_TRUTH = ["tenants", "users", "alerts", "security_events", "webhook_credentials", "mfa_recovery_codes"];
async function tableCounts(connectionString: string, only: string[] | null = null) {
  const c = new pg.Client({ connectionString }); await c.connect();
  try {
    const t = await c.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1");
    const out: Record<string, number> = {};
    for (const { table_name } of t.rows) if (!only || only.includes(table_name)) out[table_name] = (await c.query(`SELECT count(*)::int AS n FROM "${table_name}"`)).rows[0].n;
    return out;
  } finally { await c.end(); }
}

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), "legion-dr-")); backups = join(work, "backups"); priv = join(work, "recovery-private.key");
  spawnSync("age-keygen", ["-o", priv]);
  pub = execFileSync("age-keygen", ["-y", priv], { encoding: "utf8" }).trim();
  await migrate();
  await truncateAll();
  await admin(`DROP DATABASE IF EXISTS ${RESTORED}`);
  await admin(`DROP ROLE IF EXISTS ${APP_ROLE}`).catch(() => {});
}, 120_000);

afterAll(async () => {
  await stopServer(); stopRedis();
  await admin(`DROP DATABASE IF EXISTS ${RESTORED}`).catch(() => {});
  await admin(`DROP OWNED BY ${APP_ROLE}`).catch(() => {}); await admin(`DROP ROLE IF EXISTS ${APP_ROLE}`).catch(() => {});
  await closePool();
  rmSync(work, { recursive: true, force: true });
}, 60_000);

describe("disaster recovery drill", () => {
  it("1. a running Legion holds users, MFA, alerts and a webhook credential", async () => {
    const hash = await bcrypt.hash(PASSWORD, 4);
    for (const [name, key] of [["Acme SOC", "tenantA"], ["Beta Corp", "tenantB"]] as const) {
      const id = randomUUID(); seeded[key] = id;
      await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1,$2, now() + interval '14 days')", [id, name]);
    }
    const admin_ = await store.insertUser({ email: "admin@acme.example", password_hash: hash, tenant_id: seeded.tenantA, role: "admin", status: "active" });
    seeded.admin = { id: admin_.id, email: admin_.email };
    await store.insertUser({ email: "admin@beta.example", password_hash: hash, tenant_id: seeded.tenantB, role: "admin", status: "active" });
    const mfaUser = await store.insertUser({ email: "mfa@acme.example", password_hash: hash, tenant_id: seeded.tenantA, role: "analyst", status: "active" });
    seeded.mfaEmail = mfaUser.email;

    for (let i = 1; i <= 25; i++) {
      const id = `DR-${i}`; seeded.alertIds.push(id);
      await store.insertAlert({
        id, tenant_id: i % 5 === 0 ? seeded.tenantB : seeded.tenantA, title: `Alert ${i}`, severity: "high", agent: "Sentinel", status: "open",
        summary: "drill", confidence: 70, ai_explanation: null, explained_at: null, source_ip: "203.0.113.9", target: `host-${i}`, mitre_technique: "T1110", source: "test",
      });
    }
    // MFA, enrolled the way a user does it — the seed is stored sealed.
    const tok = (u: { id: string; tenant_id?: string }) => ["Authorization", `Bearer ${require("jsonwebtoken").sign({ sub: u.id, tenant_id: seeded.tenantA, token_version: 0 }, config.jwtSecret, { expiresIn: "1h" })}`] as const;
    const setup = await request(app).post("/auth/mfa/setup").set(...tok(mfaUser)).expect(200);
    seeded.mfaSecret = setup.body.secret;
    await request(app).post("/auth/mfa/enable").set(...tok(mfaUser)).send({ code: totp(seeded.mfaSecret, mfaUser.email) }).expect(200);
    await query("DELETE FROM mfa_used_counters");
    await issueCredential(seeded.tenantA, "wazuh-prod");
    seeded.cursor = (await store.listAlertsWithCursor(seeded.tenantA, {})).cursor;
    expect(seeded.cursor).toBeGreaterThan(0);
  }, 60_000);

  it("2. an encrypted backup is taken, restore-tested, and contains no plaintext secrets", async () => {
    const r = runOps("backup.sh", { DATABASE_URL: BASE_URL, DATABASE_ADMIN_URL: BASE_URL, BACKUP_AGE_RECIPIENTS: pub });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/restore test OK/);
    const file = readdirSync(backups).find((f) => f.endsWith(".dump.age"))!;
    // Decrypt to a file and read it from there: pg_restore stops reading stdin at the
    // end of the archive, which Node reports as EPIPE once the dump is large enough.
    const plainFile = join(work, "inspect.dump");
    execFileSync("age", ["-d", "-i", priv, "-o", plainFile, join(backups, file)]);
    const sql = execFileSync("pg_restore", ["-f", "-", plainFile], { encoding: "utf8", maxBuffer: 1 << 28 });
    rmSync(plainFile, { force: true });
    // The TOTP seed is sealed (AES-GCM), and the signing/encryption keys are not in the database at all.
    expect(sql).not.toContain(seeded.mfaSecret);
    expect(sql).not.toContain(config.jwtSecret);
    expect(sql).not.toContain(config.encryptionKeys.split(":")[1]!);
    expect(sql).not.toContain(PASSWORD);
    // The backup directory holds no key and no plaintext.
    expect(readdirSync(backups).filter((f) => !/\.(age|sha256)$/.test(f))).toEqual([]);
  }, 120_000);

  it("3. the database is destroyed; the backup restores into a brand-new, empty one", async () => {
    const before = await tableCounts(BASE_URL);
    await truncateAll(); // the disaster, on the original
    expect((await tableCounts(BASE_URL))["alerts"]).toBe(0);
    await admin(`CREATE DATABASE ${RESTORED}`);
    const file = join(backups, readdirSync(backups).find((f) => f.endsWith(".dump.age"))!);
    const r = runOps("restore.sh", { DATABASE_URL: url(RESTORED), BACKUP_AGE_IDENTITY_FILE: priv }, [file, "--yes"]);
    expect(r.code, r.out).toBe(0);
    expect(await tableCounts(url(RESTORED))).toEqual(before); // every table, every row
  }, 120_000);

  it("4. the real server starts on the restored database; people sign in; nothing is missing", async () => {
    await startRedis(join(work, "redis-1"));
    await startServer({});
    const health = await (await api("/health")).json() as Record<string, unknown>;
    expect(health.database).toBe("up");

    const { status, body } = await login("admin@acme.example");
    expect(status).toBe(200);
    const feed = await (await api("/alerts/feed", { token: body.access_token })).json() as { alerts: Array<{ id: string }>; cursor: number };
    const acme = seeded.alertIds.filter((_, i) => (i + 1) % 5 !== 0);
    expect(feed.alerts.map((a) => a.id).sort()).toEqual([...acme].sort());
    expect(feed.cursor).toBe(seeded.cursor);           // the realtime cursor was restored, not reset

    // Tenant B still only sees B.
    const b = await login("admin@beta.example", "198.51.100.11");
    const bFeed = await (await api("/alerts/feed", { token: b.body.access_token })).json() as { alerts: Array<{ id: string }> };
    expect(bFeed.alerts).toHaveLength(5);
  }, 120_000);

  it("5. two-factor still works after the restore (the sealed seed decrypts with the recovered key)", async () => {
    { const c = new pg.Client({ connectionString: url(RESTORED) }); await c.connect(); await c.query("DELETE FROM mfa_used_counters"); await c.end(); }
    const first = await login(seeded.mfaEmail, "198.51.100.12");
    expect(first.body.mfa_required).toBe(true);
    const verify = await api("/auth/mfa/verify", { method: "POST", body: JSON.stringify({ mfa_token: first.body.mfa_token, code: totp(seeded.mfaSecret, seeded.mfaEmail) }), headers: { "x-forwarded-for": "198.51.100.12" } });
    expect(verify.status).toBe(200);
  }, 60_000);

  it("6. the webhook credential survived: the sensor keeps working without being reissued", async () => {
    const c = new pg.Client({ connectionString: url(RESTORED) }); await c.connect();
    const r = await c.query("SELECT count(*)::int AS n FROM webhook_credentials WHERE tenant_id = $1 AND revoked_at IS NULL", [seeded.tenantA]);
    await c.end();
    expect(r.rows[0].n).toBe(1);
  });

  it("7. Redis is thrown away and rebuilt empty: Postgres is untouched and the API never depended on it", async () => {
    const t = (await login("admin@acme.example", "198.51.100.13")).body.access_token as string;
    const countsBefore = await tableCounts(url(RESTORED), SOURCE_OF_TRUTH);
    const feedBefore = await (await api("/alerts/feed", { token: t })).json() as { alerts: unknown[]; cursor: number };

    // Only throwaway state lives in Redis (rate-limit counters); no user data, no alerts.
    const keys = redisKeys();
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) expect(k, `unexpected key in Redis: ${k}`).toMatch(/^legion:rl:/);

    stopRedis();                                        // Redis dies…
    await sleep(500);
    expect((await api("/health")).status).toBe(200);    // …the API stays up,
    const during = await (await api("/alerts/feed", { token: t })).json() as { alerts: unknown[]; cursor: number };
    expect(during).toEqual(feedBefore);                  // …and reads come from Postgres
    expect((await login("admin@acme.example", "198.51.100.14")).status).toBe(200); // login still works

    await startRedis(join(work, "redis-2"));            // a NEW, EMPTY Redis
    expect(redisKeys()).toEqual([]);
    await until(() => redisKeys().some((k) => k.startsWith("legion:rl:")), 20_000, "rate-limit state to be rebuilt in Redis").catch(async () => {
      // the client reconnects on its backoff; nudge it with traffic
      for (let i = 0; i < 5; i++) { await login("admin@acme.example", `198.51.100.${20 + i}`); await sleep(500); }
      await until(() => redisKeys().length > 0, 20_000, "rate-limit state to be rebuilt in Redis");
    });
    for (const k of redisKeys()) expect(k).toMatch(/^legion:rl:/);
    expect(await tableCounts(url(RESTORED), SOURCE_OF_TRUTH)).toEqual(countsBefore);

    // Realtime after the rebuild: a socket says hello with the Postgres cursor,
    // and a change made while "Redis was gone" is recoverable from that cursor alone.
    const hello = await new Promise<{ cursor: number }>((resolve, reject) => {
      const ws = new WebSocket(`ws://127.0.0.1:${server!.port}/ws/alerts`, { headers: { cookie: `legion_token=${t}`, origin: FRONT } });
      ws.on("message", (m) => { const f = JSON.parse(String(m)); if (f.type === "hello") { ws.close(); resolve(f); } });
      ws.on("error", reject); ws.on("unexpected-response", (_r, res) => reject(new Error(`ws ${res.statusCode}`)));
    });
    expect(hello.cursor).toBe(feedBefore.cursor);
    const c = new pg.Client({ connectionString: url(RESTORED) }); await c.connect();
    await c.query(`INSERT INTO alerts (id, tenant_id, title, severity, agent, status, summary, confidence, source)
                   SELECT 'DR-AFTER', tenant_id, 'after the restore', severity, agent, status, summary, confidence, source FROM alerts WHERE tenant_id = $1 LIMIT 1`, [seeded.tenantA]);
    await c.end();
    const sync = await (await api(`/alerts/sync?after=${hello.cursor}`, { token: t })).json() as { alerts: Array<{ id: string }>; cursor: number };
    expect(sync.alerts.map((a) => a.id)).toEqual(["DR-AFTER"]);
    expect(sync.cursor).toBe(hello.cursor + 1);
  }, 120_000);

  it("8. the app role is provisioned on the restored database and the server runs as it", async () => {
    await stopServer();
    const appPassword = randomBytes(12).toString("hex");
    const prov = spawnSync(process.execPath, ["--import", "tsx", "src/db/provision-cli.ts"], {
      cwd: SERVER_DIR, encoding: "utf8",
      env: { ...process.env, DATABASE_ADMIN_URL: url(RESTORED), APP_DB_USER: APP_ROLE, APP_DB_PASSWORD: appPassword } as NodeJS.ProcessEnv,
    });
    expect(prov.status, prov.stdout + prov.stderr).toBe(0);
    const appUrl = url(RESTORED, APP_ROLE, appPassword);
    await startServer({ DATABASE_URL: appUrl });
    const c = new pg.Client({ connectionString: appUrl }); await c.connect();
    const attrs = await c.query("SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user");
    await c.end();
    expect(attrs.rows[0]).toEqual({ rolsuper: false, rolcreatedb: false, rolcreaterole: false });
    expect((await login("admin@acme.example", "198.51.100.30")).status).toBe(200);
  }, 120_000);

  it("9. with the WRONG encryption key the server refuses MFA — and destroys nothing", async () => {
    await stopServer();
    const wrong = `wrongkey:${randomBytes(32).toString("hex")}`;
    await startServer({ LEGION_ENCRYPTION_KEYS: wrong });
    const first = await login(seeded.mfaEmail, "198.51.100.31");
    expect(first.body.mfa_required).toBe(true);
    const verify = await api("/auth/mfa/verify", { method: "POST", body: JSON.stringify({ mfa_token: first.body.mfa_token, code: totp(seeded.mfaSecret, seeded.mfaEmail) }), headers: { "x-forwarded-for": "198.51.100.31" } });
    expect(verify.status).toBe(503);
    const c = new pg.Client({ connectionString: url(RESTORED) }); await c.connect();
    const row = (await c.query("SELECT mfa_enabled, mfa_secret_enc IS NOT NULL AS has_seed FROM users WHERE email = $1", [seeded.mfaEmail])).rows[0];
    await c.end();
    expect(row).toEqual({ mfa_enabled: true, has_seed: true }); // MFA configuration intact

    // With the right key restored, the same user signs in again.
    await stopServer();
    await startServer({});
    // Step 5 already spent a code; within the same 30-second step replay
    // protection would (correctly) refuse it again. Not what this checks.
    { const c = new pg.Client({ connectionString: url(RESTORED) }); await c.connect(); await c.query("DELETE FROM mfa_used_counters"); await c.end(); }
    const again = await login(seeded.mfaEmail, "198.51.100.32");
    const ok = await api("/auth/mfa/verify", { method: "POST", body: JSON.stringify({ mfa_token: again.body.mfa_token, code: totp(seeded.mfaSecret, seeded.mfaEmail) }), headers: { "x-forwarded-for": "198.51.100.32" } });
    expect(ok.status, JSON.stringify(await ok.clone().json().catch(() => null))).toBe(200);
  }, 180_000);

  it("10. with a NEW signing secret (JWT_SECRET lost) old sessions end, but everyone can sign in again", async () => {
    const before = (await login("admin@acme.example", "198.51.100.33")).body.access_token as string;
    await stopServer();
    await startServer({ JWT_SECRET: "a-brand-new-signing-secret-generated-after-the-disaster" });
    expect((await api("/alerts/feed", { token: before })).status).toBe(401);
    const after = await login("admin@acme.example", "198.51.100.34");
    expect(after.status).toBe(200);
    expect((await api("/alerts/feed", { token: after.body.access_token })).status).toBe(200);
  }, 120_000);
});
