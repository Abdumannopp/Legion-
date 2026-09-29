/**
 * ops/backup.sh, restore.sh, verify-backup.sh, prune-backups.sh, check-backup.sh
 * against a real Postgres and the real `age` tool — the scripts an operator runs.
 * A failure here means a backup that would not have saved anyone.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, statSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import request from "supertest";
import { app } from "../src/index.js";
import { config } from "../src/config.js";
import { evaluateBackupStatus, type BackupStatus } from "../src/backup-health.js";

const REPO = join(__dirname, "..", "..");
const OPS = join(REPO, "ops");
const BASE_URL = process.env.TEST_DATABASE_URL || "postgresql://legion@127.0.0.1:5433/legion_test";
const url = (db: string) => BASE_URL.replace(/\/[^/?]+(\?|$)/, `/${db}$1`);
const SRC = "legion_bk_src";
const SRC_URL = url(SRC);
const MARKER = "PLAINTEXT-MARKER-4f9c1e"; // seeded into a table; must never appear in an encrypted backup
const PASSWORD_IN_URL = "s3cr3t-pw-9x";

let work: string, backups: string, keys: { pub: string; priv: string; privFile: string; otherPrivFile: string };
// The alert receiver runs in its own process: the scripts under test call it
// with curl while spawnSync blocks this one, so an in-process server would deadlock.
let hooks: ChildProcess, hookPort = 0, hookLog = "";
const hookEntries = (): Array<{ url: string; body: string }> =>
  existsSync(hookLog) ? readFileSync(hookLog, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
const bodies = () => hookEntries().filter((e) => e.url.startsWith("/alert")).map((e) => e.body);
const pingUrls = () => hookEntries().filter((e) => !e.url.startsWith("/alert")).map((e) => e.url);

const admin = () => new pg.Client({ connectionString: url("postgres") });
async function sql(db: string, text: string) { const c = new pg.Client({ connectionString: url(db) }); await c.connect(); try { return await c.query(text); } finally { await c.end(); } }

function keypair(file: string) {
  const out = execFileSync("age-keygen", ["-o", file], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) + "";
  return execFileSync("age-keygen", ["-y", file], { encoding: "utf8" }).trim();
}

function run(script: string, env: Record<string, string | undefined> = {}, args: string[] = []) {
  const r = spawnSync("bash", [join(OPS, script), ...args], {
    encoding: "utf8", timeout: 120_000,
    env: {
      PATH: process.env.PATH, HOME: work,
      BACKUP_DIR: backups, BACKUP_STATUS_FILE: join(work, "status.json"),
      DATABASE_URL: SRC_URL, DATABASE_ADMIN_URL: SRC_URL,
      BACKUP_AGE_RECIPIENTS: keys.pub,
      ALERT_WEBHOOK_URL: `http://127.0.0.1:${hookPort}/alert`,
      HEALTHCHECK_PING_URL: `http://127.0.0.1:${hookPort}/ping`,
      ...env,
    } as NodeJS.ProcessEnv,
  });
  return { code: r.status ?? -1, out: (r.stdout ?? "") + (r.stderr ?? "") };
}
const status = () => JSON.parse(readFileSync(join(work, "status.json"), "utf8")) as Record<string, unknown>;
const files = (ext: string) => readdirSync(backups).filter((f) => f.endsWith(ext));

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), "legion-bk-"));
  const c = admin(); await c.connect();
  await c.query(`DROP DATABASE IF EXISTS ${SRC}`); await c.query(`CREATE DATABASE ${SRC}`); await c.end();
  await sql(SRC, `
    CREATE TABLE tenants (id uuid PRIMARY KEY, name text NOT NULL);
    CREATE TABLE alerts (tenant_id uuid REFERENCES tenants(id), id text, title text, PRIMARY KEY (tenant_id, id));
    INSERT INTO tenants VALUES ('00000000-0000-0000-0000-000000000001','acme'),('00000000-0000-0000-0000-000000000002','b');
    INSERT INTO alerts SELECT '00000000-0000-0000-0000-000000000001', 'SEC-'||g, '${MARKER}' FROM generate_series(1,40) g;`);
  const privFile = join(work, "private.key"), otherFile = join(work, "other.key");
  keys = { pub: keypair(privFile), priv: "", privFile, otherPrivFile: otherFile };
  keypair(otherFile);
  hookLog = join(work, "hooks.log");
  hooks = spawn("node", ["-e", `
    const http=require("http"),fs=require("fs");
    http.createServer((q,r)=>{let b="";q.on("data",d=>b+=d);q.on("end",()=>{fs.appendFileSync(${JSON.stringify(hookLog)},JSON.stringify({url:q.url,body:b})+"\\n");r.end("ok")})})
      .listen(0,"127.0.0.1",function(){console.log(this.address().port)});`], { stdio: ["ignore", "pipe", "inherit"] });
  hookPort = await new Promise<number>((resolve) => hooks.stdout!.once("data", (d) => resolve(Number(String(d).trim()))));
});
afterAll(async () => {
  hooks?.kill();
  const c = admin(); await c.connect();
  await c.query(`DROP DATABASE IF EXISTS ${SRC}`);
  const stray = await c.query("SELECT datname FROM pg_database WHERE datname LIKE 'legion_verify_%'");
  await c.end();
  expect(stray.rows).toEqual([]); // no throwaway database left behind
  rmSync(work, { recursive: true, force: true });
});
beforeEach(() => {
  rmSync(backups ?? join(work, "none"), { recursive: true, force: true });
  backups = join(work, "backups");
  rmSync(join(work, "status.json"), { force: true });
  rmSync(hookLog, { force: true });
});

describe("encrypted backup", () => {
  it("produces an age-encrypted file, a checksum, and leaves no plaintext behind", () => {
    const r = run("backup.sh");
    expect(r.code, r.out).toBe(0);
    const enc = files(".dump.age");
    expect(enc).toHaveLength(1);
    expect(readFileSync(join(backups, enc[0]!)).subarray(0, 21).toString()).toBe("age-encryption.org/v1");
    expect(files(".sha256")).toHaveLength(1);
    // Nothing readable is left in the backup directory: no .dump, no scratch dir.
    expect(files(".dump")).toEqual([]);
    expect(readdirSync(backups).filter((f) => f.startsWith(".work"))).toEqual([]);
    expect(statSync(backups).mode & 0o777).toBe(0o700);
    expect(statSync(join(backups, enc[0]!)).mode & 0o777).toBe(0o600);
  });

  it("the ciphertext does not contain the data (it does once decrypted)", () => {
    run("backup.sh");
    const file = join(backups, files(".dump.age")[0]!);
    expect(readFileSync(file).includes(Buffer.from(MARKER))).toBe(false);
    const plainFile = join(work, "inspect.dump");
    execFileSync("age", ["-d", "-i", keys.privFile, "-o", plainFile, file]);
    const text = execFileSync("pg_restore", ["-f", "-", plainFile], { encoding: "utf8", maxBuffer: 1 << 26 });
    rmSync(plainFile, { force: true });
    expect(text).toContain(MARKER);
  });

  it("cannot be decrypted with another key", () => {
    run("backup.sh");
    const file = join(backups, files(".dump.age")[0]!);
    const r = spawnSync("age", ["-d", "-i", keys.otherPrivFile, file]);
    expect(r.status).not.toBe(0);
  });

  it("refuses to run without an encryption key — never writes a plaintext backup", () => {
    const r = run("backup.sh", { BACKUP_AGE_RECIPIENTS: "" });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/Refusing to write an unencrypted backup/);
    expect(existsSync(backups) ? readdirSync(backups).filter((f) => f.startsWith("legion-")) : []).toEqual([]);
    expect(bodies().length).toBe(1); // and it alerted
  });

  it("refuses a PRIVATE key given as a recipient (keys must not live on the server)", () => {
    const secret = readFileSync(keys.privFile, "utf8").split("\n").find((l) => l.startsWith("AGE-SECRET-KEY-"))!;
    const r = run("backup.sh", { BACKUP_AGE_RECIPIENTS: secret });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/PRIVATE age key/);
    expect(r.out).not.toContain(secret);
    expect(bodies().join("")).not.toContain(secret);
  });

  it("refuses to run when a private key is sitting in the backup directory", () => {
    mkdirSync(backups, { recursive: true, mode: 0o700 });
    writeFileSync(join(backups, "notes.txt"), readFileSync(keys.privFile));
    const r = run("backup.sh");
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/never be stored together/);
  });

  it("supports several recipients — either private key recovers the backup", () => {
    const pub2 = execFileSync("age-keygen", ["-y", keys.otherPrivFile], { encoding: "utf8" }).trim();
    expect(run("backup.sh", { BACKUP_AGE_RECIPIENTS: `${keys.pub},${pub2}` }).code).toBe(0);
    const file = join(backups, files(".dump.age")[0]!);
    for (const k of [keys.privFile, keys.otherPrivFile]) expect(spawnSync("age", ["-d", "-i", k, file]).status).toBe(0);
  });

  it("an explicit opt-out writes a plaintext file that is never uploaded, and is flagged unhealthy", () => {
    const r = run("backup.sh", { BACKUP_AGE_RECIPIENTS: "", BACKUP_ALLOW_UNENCRYPTED: "true", BACKUP_UPLOAD_CMD: "touch " + join(work, "uploaded") });
    expect(r.code).toBe(0);
    expect(existsSync(join(work, "uploaded"))).toBe(false);
    expect(run("check-backup.sh").out).toMatch(/NOT encrypted/);
  });
});

describe("automatic restore test", () => {
  it("every backup is restored into a throwaway database, which is then dropped", () => {
    const r = run("backup.sh");
    expect(r.out).toMatch(/restore test OK — 2 tables, 42 rows/);
    expect(status().restore_test_result).toBe("ok");
  });

  it("a dump that cannot restore FAILS the backup, leaves no backup file, and alerts", async () => {
    // Break the restore path: a table the dump has but the restore cannot rebuild (a missing extension).
    await sql(SRC, "CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE TABLE trg (t text); CREATE INDEX trg_i ON trg USING gin (t gin_trgm_ops);");
    const admin_ = url("postgres");
    const c = new pg.Client({ connectionString: admin_ }); await c.connect();
    // Simulate: the restore target has no way to satisfy the dump — use a role without CREATEDB.
    await c.query("DROP ROLE IF EXISTS legion_bk_nocreate"); await c.query("CREATE ROLE legion_bk_nocreate LOGIN"); await c.end();
    // Swap the user through the URL API: a string replace of "legion@" misses
    // a URL that carries a password ("legion:secret@", as CI's does), which
    // silently ran this "must fail" backup as the superuser.
    const noCreate = new URL(url("postgres")); noCreate.username = "legion_bk_nocreate"; noCreate.password = "";
    const r = run("backup.sh", { DATABASE_ADMIN_URL: noCreate.toString(), BACKUP_RESTORE_TEST: "required" });
    expect(r.code).toBe(1);
    expect(files(".age")).toEqual([]);
    expect(status().last_failure_stage).toBe("restore-test");
    expect(bodies().length).toBe(1);
    expect(pingUrls()).toContain("/ping/fail");
    await sql(SRC, "DROP TABLE trg");
    const c2 = new pg.Client({ connectionString: admin_ }); await c2.connect(); await c2.query("DROP ROLE legion_bk_nocreate"); await c2.end();
  });

  it("verify-backup decrypts with the private key and restores the newest backup", () => {
    run("backup.sh");
    const r = run("verify-backup.sh", { BACKUP_AGE_IDENTITY_FILE: keys.privFile });
    expect(r.code, r.out).toBe(0);
    expect(r.out).toMatch(/restores cleanly \(2 tables, 42 rows\)/);
    expect(status().restore_test_source).toBe("verify-backup");
  });

  it("verify-backup with the wrong key fails, records it, and alerts", () => {
    run("backup.sh"); rmSync(hookLog, { force: true });
    const r = run("verify-backup.sh", { BACKUP_AGE_IDENTITY_FILE: keys.otherPrivFile });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/could not decrypt/);
    expect(status().restore_test_result).toBe("failed");
    expect(bodies()).toHaveLength(1);
  });

  it("verify-backup without the private key says exactly what is missing", () => {
    run("backup.sh");
    const r = run("verify-backup.sh", { BACKUP_AGE_IDENTITY_FILE: "" });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/BACKUP_AGE_IDENTITY_FILE/);
  });
});

describe("restoring", () => {
  it("brings the data back into a brand-new, empty database", async () => {
    run("backup.sh");
    const c = admin(); await c.connect(); await c.query("DROP DATABASE IF EXISTS legion_bk_new"); await c.query("CREATE DATABASE legion_bk_new"); await c.end();
    try {
      const file = join(backups, files(".dump.age")[0]!);
      const r = run("restore.sh", { DATABASE_URL: url("legion_bk_new"), BACKUP_AGE_IDENTITY_FILE: keys.privFile }, [file, "--yes"]);
      expect(r.code, r.out).toBe(0);
      expect((await sql("legion_bk_new", "SELECT count(*)::int AS n FROM alerts")).rows[0].n).toBe(40);
    } finally { const c2 = admin(); await c2.connect(); await c2.query("DROP DATABASE IF EXISTS legion_bk_new"); await c2.end(); }
  });

  it("refuses without --yes, and never changes the database when it fails", async () => {
    run("backup.sh");
    const file = join(backups, files(".dump.age")[0]!);
    expect(run("restore.sh", { BACKUP_AGE_IDENTITY_FILE: keys.privFile }, [file]).code).toBe(2);
    // wrong key → nothing touched
    const r = run("restore.sh", { BACKUP_AGE_IDENTITY_FILE: keys.otherPrivFile }, [file, "--yes"]);
    expect(r.code).toBe(1);
    expect((await sql(SRC, "SELECT count(*)::int AS n FROM alerts")).rows[0].n).toBe(40);
  });

  it("rejects a tampered backup by checksum before decrypting anything", () => {
    run("backup.sh");
    const file = join(backups, files(".dump.age")[0]!);
    writeFileSync(file, Buffer.concat([readFileSync(file), Buffer.from("x")]));
    const r = run("restore.sh", { BACKUP_AGE_IDENTITY_FILE: keys.privFile }, [file, "--yes"]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/checksum/);
  });
});

describe("failure is loud", () => {
  it("an unreachable database fails, records why, alerts, and does not leak the password", () => {
    const r = run("backup.sh", { DATABASE_URL: `postgresql://nobody:${PASSWORD_IN_URL}@127.0.0.1:1/nope`, DATABASE_ADMIN_URL: "" });
    expect(r.code).toBe(1);
    expect(files(".age")).toEqual([]);
    const s = status();
    expect(s.last_failure_stage).toBe("dump");
    expect(String(s.last_failure_reason)).toBeTruthy();
    expect(bodies()).toHaveLength(1);
    expect(bodies()[0]).toMatch(/backup FAILED/i);
    for (const text of [r.out, bodies()[0]!, JSON.stringify(s)]) expect(text).not.toContain(PASSWORD_IN_URL);
    expect(pingUrls()).toContain("/ping/fail");
  });

  it("a success pings the dead-man's switch and sends no alert", () => {
    expect(run("backup.sh").code).toBe(0);
    expect(bodies()).toEqual([]);
    expect(pingUrls()).toContain("/ping");
  });

  it("a failed off-server copy fails the run and alerts (the local backup is kept)", () => {
    const r = run("backup.sh", { BACKUP_UPLOAD_CMD: "echo upstream-refused >&2; exit 7" });
    expect(r.code).toBe(1);
    expect(files(".dump.age")).toHaveLength(1);
    expect(status().offsite_result).toBe("failed");
    expect(bodies()).toHaveLength(1);
  });

  it("the off-server copy receives the ENCRYPTED file and its checksum", () => {
    const dest = join(work, "offsite"); mkdirSync(dest, { recursive: true });
    const r = run("backup.sh", { BACKUP_UPLOAD_CMD: `cp "$BACKUP_FILE" "$BACKUP_CHECKSUM_FILE" ${dest}/` });
    expect(r.code, r.out).toBe(0);
    const copied = readdirSync(dest);
    expect(copied.some((f) => f.endsWith(".dump.age"))).toBe(true);
    expect(copied.some((f) => f.endsWith(".dump"))).toBe(false);
    expect(status().offsite_result).toBe("ok");
    rmSync(dest, { recursive: true, force: true });
  });

  it("check-backup: healthy after a good backup; alerts when the backup has stopped running", () => {
    run("backup.sh"); rmSync(hookLog, { force: true });
    expect(run("check-backup.sh").code).toBe(0);
    // Time passes and nothing runs: the last success is now 3 days old.
    const s = status(); s.last_success_at = new Date(Date.now() - 3 * 86_400_000).toISOString();
    writeFileSync(join(work, "status.json"), JSON.stringify(s));
    const r = run("check-backup.sh");
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/h old/);
    expect(bodies()).toHaveLength(1);
  });

  it("check-backup: alerts when there is no status at all (the job never ran)", () => {
    const r = run("check-backup.sh");
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/never run/);
    expect(bodies()).toHaveLength(1);
  });
});

describe("retention", () => {
  const stamp = (daysAgo: number, h = 3) => {
    const d = new Date(Date.UTC(2026, 8, 29, h) - daysAgo * 86_400_000);
    return d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  };
  function seed(daysAgoList: number[]) {
    mkdirSync(backups, { recursive: true });
    for (const d of daysAgoList) {
      const f = join(backups, `legion-${stamp(d)}.dump.age`);
      writeFileSync(f, "x"); writeFileSync(f + ".sha256", "x");
      // File dates must be irrelevant: set them all to "now".
      utimesSync(f, new Date(), new Date());
    }
  }
  const prune = (env: Record<string, string> = {}, args: string[] = []) =>
    spawnSync("bash", [join(OPS, "prune-backups.sh"), backups, ...args], { encoding: "utf8", env: { PATH: process.env.PATH, ...env } as NodeJS.ProcessEnv });
  const left = () => files(".age").map((f) => f.slice(7, 15));

  it("keeps 14 dailies + weeklies + monthlies from a year of nightly backups, and nothing else", () => {
    seed(Array.from({ length: 400 }, (_, i) => i));
    const r = prune();
    expect(r.status, r.stderr).toBe(0);
    const kept = files(".age").length;
    expect(kept).toBeGreaterThanOrEqual(14 + 6);
    expect(kept).toBeLessThanOrEqual(14 + 8 + 12);
    // The most recent 14 days are all there.
    for (let d = 0; d < 14; d++) expect(left()).toContain(stamp(d).slice(0, 8));
    // Every removed backup took its checksum with it, and no orphan checksums remain.
    expect(files(".sha256")).toHaveLength(kept);
    // Ancient ones are gone.
    expect(left()).not.toContain(stamp(399).slice(0, 8));
  });

  it("a dry run reports and changes nothing", () => {
    seed(Array.from({ length: 60 }, (_, i) => i));
    const r = prune({}, ["--dry-run"]);
    expect(r.stdout).toMatch(/would remove/);
    expect(files(".age")).toHaveLength(60);
  });

  it("never deletes the newest backups, even with retention set to zero", () => {
    seed([0, 1, 2, 3, 4, 5]);
    prune({ BACKUP_KEEP_DAILY: "0", BACKUP_KEEP_WEEKLY: "0", BACKUP_KEEP_MONTHLY: "0" });
    expect(files(".age")).toHaveLength(3);
    expect(left()).toContain(stamp(0).slice(0, 8));
  });

  it("uses the timestamp in the name, not the file date, and ignores files it did not make", () => {
    seed([0, 1]); writeFileSync(join(backups, "notes.txt"), "keep me"); writeFileSync(join(backups, "legion-notes.dump.age.bak"), "keep me too");
    prune({ BACKUP_KEEP_DAILY: "1", BACKUP_MIN_KEEP: "1" });
    expect(readdirSync(backups)).toContain("notes.txt");
    expect(readdirSync(backups)).toContain("legion-notes.dump.age.bak");
    expect(files(".age")).toHaveLength(1);
  });

  it("rejects nonsense settings instead of deleting on a guess", () => {
    seed([0, 1, 2, 3, 4, 5]);
    const r = prune({ BACKUP_KEEP_DAILY: "-1" });
    expect(r.status).toBe(2);
    expect(files(".age")).toHaveLength(6);
  });

  it("a backup run prunes only after it succeeded", () => {
    seed(Array.from({ length: 30 }, (_, i) => i + 1));
    const before = files(".age").length;
    run("backup.sh", { DATABASE_URL: "postgresql://x:y@127.0.0.1:1/z", DATABASE_ADMIN_URL: "" });
    expect(files(".age").length).toBe(before); // failed run: nothing was removed
  });
});

describe("health rules and the /health/backup endpoint", () => {
  const NOW = Date.parse("2026-09-29T12:00:00Z");
  const ago = (h: number) => new Date(NOW - h * 3_600_000).toISOString();
  const good: BackupStatus = { last_success_at: ago(2), restore_tested_at: ago(2), restore_test_result: "ok", encrypted: "true", offsite_result: "ok", offsite_uploaded_at: ago(2) };
  const cases: Array<[string, BackupStatus | null, boolean]> = [
    ["fresh, tested, encrypted", good, true],
    ["never ran", null, false],
    ["stale (40h)", { ...good, last_success_at: ago(40) }, false],
    ["last run failed after last success", { ...good, last_failure_at: ago(1), last_failure_reason: "pg_dump failed" }, false],
    ["failure older than the success is history", { ...good, last_failure_at: ago(5) }, true],
    ["unencrypted", { ...good, encrypted: "false" }, false],
    ["restore test failed", { ...good, restore_test_result: "failed" }, false],
    ["never restore-tested", { ...good, restore_tested_at: null, restore_test_result: null }, false],
    ["restore test 20 days old", { ...good, restore_tested_at: ago(20 * 24) }, false],
    ["offsite failed", { ...good, offsite_result: "failed" }, false],
  ];

  it.each(cases)("verdict: %s", (_name, st, expected) => {
    expect(evaluateBackupStatus(st, NOW, { maxAgeHours: 30, restoreMaxDays: 8, requireOffsite: false }).ok).toBe(expected);
  });

  it("status.mjs (used by the shell scripts) gives the same verdicts as the API for every case", async () => {
    const mod = await import(join(OPS, "lib", "status.mjs"));
    for (const [name, st, expected] of cases) {
      const a = mod.evaluate(st, NOW, { maxAgeHours: 30, restoreMaxDays: 8, requireOffsite: false });
      const b = evaluateBackupStatus(st, NOW, { maxAgeHours: 30, restoreMaxDays: 8, requireOffsite: false });
      expect(a.ok, name).toBe(expected);
      expect(a, name).toEqual(b);
    }
  });

  it("is hidden without a token, protected with one, and reports 200/503 by health", async () => {
    const saved = { t: config.healthMetricsToken, f: config.backupStatusFile };
    try {
      config.healthMetricsToken = ""; config.backupStatusFile = "";
      expect((await request(app).get("/health/backup")).status).toBe(404);
      config.healthMetricsToken = "monitor-token-123"; config.backupStatusFile = join(work, "api-status.json");
      expect((await request(app).get("/health/backup")).status).toBe(401);
      expect((await request(app).get("/health/backup").set("Authorization", "Bearer wrong")).status).toBe(401);
      const auth = ["Authorization", "Bearer monitor-token-123"] as const;
      // No status file: unhealthy, "unknown"
      let res = await request(app).get("/health/backup").set(...auth);
      expect(res.status).toBe(503); expect(res.body.status).toBe("unknown");
      writeFileSync(config.backupStatusFile, JSON.stringify({ ...good, last_success_at: new Date().toISOString(), restore_tested_at: new Date().toISOString(), offsite_uploaded_at: new Date().toISOString(), last_backup_bytes: 1234, last_backup_file: "secret-name.dump.age" }));
      res = await request(app).get("/health/backup").set(...auth);
      expect(res.status).toBe(200); expect(res.body.healthy).toBe(true); expect(res.body.encrypted).toBe(true);
      // Nothing that names files, hosts or credentials is exposed.
      expect(JSON.stringify(res.body)).not.toMatch(/secret-name|postgres|age1/);
      writeFileSync(config.backupStatusFile, JSON.stringify({ ...good, last_success_at: ago(100) }));
      res = await request(app).get("/health/backup").set(...auth);
      expect(res.status).toBe(503); expect(res.body.status).toBe("stale");
    } finally { config.healthMetricsToken = saved.t; config.backupStatusFile = saved.f; }
  });
});

describe("recovery secrets", () => {
  const fpScript = join(OPS, "secrets-fingerprint.sh");
  const KEY = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0";
  const JWT = "jwt-secret-that-must-not-be-printed-1234567890";
  const envFile = () => join(work, "recovery.env");

  it("prints fingerprints — never the secrets themselves", () => {
    writeFileSync(envFile(), `JWT_SECRET=${JWT}\nLEGION_ENCRYPTION_KEYS=k2:${KEY}\nDATABASE_URL=postgresql://u:${PASSWORD_IN_URL}@h/db\n`);
    const r = spawnSync("bash", [fpScript, envFile()], { encoding: "utf8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/JWT_SECRET\s+[0-9a-f]{12}/);
    expect(r.stdout).toMatch(/id=k2\s+[0-9a-f]{12}/);
    for (const secret of [JWT, KEY, PASSWORD_IN_URL]) expect(r.stdout + r.stderr).not.toContain(secret);
  });

  it("fails when the encryption keys (which recovery cannot do without) are missing", () => {
    writeFileSync(envFile(), `JWT_SECRET=${JWT}\n`);
    const r = spawnSync("bash", [fpScript, envFile()], { encoding: "utf8" });
    expect(r.status).toBe(1);
    expect(r.stdout).toMatch(/LEGION_ENCRYPTION_KEYS\s+MISSING/);
  });
});
