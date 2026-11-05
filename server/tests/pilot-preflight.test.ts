/**
 * The pilot checklist is code (ops/pilot-preflight.mjs). A gate that never
 * fails is worthless, so this proves both directions: a correct pilot
 * configuration passes, and each unsafe mutation is caught by name.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const ROOT = join(__dirname, "..", "..");
const hex = () => randomBytes(32).toString("hex");
let dir: string;
const dockerOk = spawnSync("docker", ["compose", "version"], { stdio: "ignore" }).status === 0;

function goodEnv(): Record<string, string> {
  const base = readFileSync(join(ROOT, "deploy", "pilot.env.example"), "utf8").replaceAll("legion-pilot.example.com", "pilot.acme-soc.test");
  const env: Record<string, string> = {};
  for (const l of base.split("\n")) { const m = /^([A-Z_]+)=(.*)$/.exec(l); if (m) env[m[1]!] = m[2]!; }
  Object.assign(env, { POSTGRES_ADMIN_PASSWORD: hex(), APP_DB_PASSWORD: hex(), JWT_SECRET: hex(), LEGION_ENCRYPTION_KEYS: `k1:${hex()}`, SOC_AUDIT_KEY: hex(), HEALTH_METRICS_TOKEN: hex(), SMTP_HOST: "smtp.mail.test" });
  return env;
}
function run(env: Record<string, string>, extra: string[] = []) {
  const f = join(dir, `.env.pilot-${randomBytes(4).toString("hex")}`);
  writeFileSync(f, Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n") + "\n", { mode: 0o600 });
  chmodSync(f, 0o600);
  const r = spawnSync("node", [join(ROOT, "ops", "pilot-preflight.mjs"), "--env", f, "--json", ...extra], { encoding: "utf8", cwd: ROOT });
  const out = JSON.parse(r.stdout) as { counts: Record<string, number>; results: Array<{ level: string; id: string; text: string }> };
  return { status: r.status, failed: out.results.filter((x) => x.level === "FAIL").map((x) => x.id), out };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "legion-pf-test-"));
  // The preflight reads the built key parser; build only when it is missing.
  if (!existsSync(join(ROOT, "server", "dist", "keyring-parse.js"))) execFileSync("npm", ["run", "build", "-w", "server"], { cwd: ROOT, stdio: "ignore" });
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("pilot preflight", () => {
  it("passes a correct configuration (exit 0, no FAIL)", () => {
    const r = run(goodEnv());
    expect(r.failed).toEqual([]);
    expect(r.status).toBe(0);
    expect(r.out.counts.PASS).toBeGreaterThan(20);
  });

  it("passes the real pilot compose file: hardened containers, internal data network, fixed safety modes", () => {
    if (!dockerOk) return; // needs only the docker CLI, not a daemon
    const r = run(goodEnv(), ["--compose", join(ROOT, "docker-compose.pilot.yml")]);
    expect(r.failed).toEqual([]);
    const ids = r.out.results.map((x) => x.id);
    for (const id of ["backend:read-only", "postgres:unpublished", "net-internal", "backend:POLICY_ENGINE_MODE", "backend:ORCHESTRATOR_AUTO_MODE", "backend:db-role", "backend:no-admin-pw", "provision-first"]) expect(ids, id).toContain(id);
  });

  const MUTATIONS: Array<[string, (e: Record<string, string>) => void, string]> = [
    ["a placeholder JWT secret", (e) => { e.JWT_SECRET = "CHANGE-ME"; }, "jwt"],
    ["a short JWT secret", (e) => { e.JWT_SECRET = "abc123"; }, "jwt"],
    ["no audit-chain key", (e) => { delete e.SOC_AUDIT_KEY; }, "soc-audit-key"],
    ["no metrics token", (e) => { e.HEALTH_METRICS_TOKEN = ""; }, "metrics-token"],
    ["the same value reused for two secrets", (e) => { e.SOC_AUDIT_KEY = e.JWT_SECRET!; }, "secrets-distinct"],
    ["the API sharing the admin database password", (e) => { e.APP_DB_PASSWORD = e.POSTGRES_ADMIN_PASSWORD!; }, "secrets-distinct"],
    ["a malformed encryption keyring", (e) => { e.LEGION_ENCRYPTION_KEYS = "k1:tooshort"; }, "enc-keys"],
    ["no encryption keyring", (e) => { delete e.LEGION_ENCRYPTION_KEYS; }, "enc-keys"],
    ["plain-http frontend", (e) => { e.FRONTEND_URL = "http://pilot.acme-soc.test"; }, "frontend-https"],
    ["a placeholder frontend host", (e) => { e.FRONTEND_URL = "https://legion-pilot.example.com"; }, "frontend-host"],
    ["wildcard CORS", (e) => { e.CORS_ORIGINS = "*"; }, "cors"],
    ["trusting every proxy", (e) => { e.TRUSTED_PROXIES = "true"; }, "trusted-proxies"],
    ["no SMTP host", (e) => { e.SMTP_HOST = ""; }, "smtp"],
    ["a plain-http API URL for the browser", (e) => { e.NEXT_PUBLIC_API_URL = "http://pilot.acme-soc.test/api"; }, "next_public_api_url"],
    ["SaaS mode", (e) => { e.DEPLOYMENT_MODE = "saas"; }, "mode"],
  ];
  for (const [name, mutate, id] of MUTATIONS) {
    it(`fails on ${name}`, () => {
      const e = goodEnv(); mutate(e);
      const r = run(e);
      expect(r.failed, JSON.stringify(r.failed)).toContain(id);
      expect(r.status).toBe(1);
    });
  }

  it("fails on a world-readable env file", () => {
    const f = join(dir, ".env.open");
    writeFileSync(f, Object.entries(goodEnv()).map(([k, v]) => `${k}=${v}`).join("\n"), { mode: 0o644 });
    chmodSync(f, 0o644);
    const r = spawnSync("node", [join(ROOT, "ops", "pilot-preflight.mjs"), "--env", f, "--json"], { encoding: "utf8", cwd: ROOT });
    expect(JSON.parse(r.stdout).results.filter((x: { level: string }) => x.level === "FAIL").map((x: { id: string }) => x.id)).toContain("env-mode");
  });

  it("never prints a secret value", () => {
    const e = goodEnv();
    const r = spawnSync("node", [join(ROOT, "ops", "pilot-preflight.mjs"), "--env", (() => { const f = join(dir, ".env.print"); writeFileSync(f, Object.entries(e).map(([k, v]) => `${k}=${v}`).join("\n"), { mode: 0o600 }); return f; })()], { encoding: "utf8", cwd: ROOT });
    for (const k of ["JWT_SECRET", "SOC_AUDIT_KEY", "HEALTH_METRICS_TOKEN", "APP_DB_PASSWORD", "POSTGRES_ADMIN_PASSWORD"]) expect(r.stdout + r.stderr).not.toContain(e[k]!);
    expect(r.stdout + r.stderr).not.toContain(e.LEGION_ENCRYPTION_KEYS!.split(":")[1]!);
  });
});
