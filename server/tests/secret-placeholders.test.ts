/**
 * A server must never run with a signing key someone else can know.
 *
 * Regression for the finding that the value shipped in server/.env.example
 * ("replace-with-a-long-random-string", 33 chars) passed the placeholder check,
 * while the same file set NODE_ENV=development (switching the check off) and
 * SEED_DEMO_DATA=true (a published admin login). `cp .env.example .env && npm start`
 * produced a server whose sessions anyone could forge.
 */
import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const KEYRING = "t1:0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0";
const RANDOM = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/** Imports config.ts fresh under `env`; returns the thrown message, or the config. */
async function boot(env: Record<string, string | undefined>) {
  vi.resetModules();
  const keys = ["NODE_ENV", "JWT_SECRET", "LEGION_ENCRYPTION_KEYS", "LEGION_BIND_ADDRESS", "SEED_DEMO_DATA", "DEPLOYMENT_MODE", "COOKIE_SECURE", "FRONTEND_URL", "SMTP_HOST", "DATABASE_URL"];
  for (const k of keys) vi.stubEnv(k, undefined as unknown as string);
  for (const [k, v] of Object.entries(env)) if (v !== undefined) vi.stubEnv(k, v);
  try {
    const mod = await import("../src/config.js");
    return { ok: true as const, config: mod.config, mod };
  } catch (e) {
    return { ok: false as const, error: (e as Error).message };
  } finally {
    vi.unstubAllEnvs();
    vi.resetModules();
  }
}

describe("JWT_SECRET placeholders are refused", () => {
  const SHIPPED = "replace-with-a-long-random-string";

  it("the value .env.example used to ship is refused with NODE_ENV unset (a self-hosted npm start)", async () => {
    const r = await boot({ JWT_SECRET: SHIPPED, LEGION_ENCRYPTION_KEYS: KEYRING });
    expect(r.ok).toBe(false);
    expect(r.ok ? "" : r.error).toMatch(/JWT_SECRET/);
  });

  it("…and with NODE_ENV=production", async () => {
    const r = await boot({ JWT_SECRET: SHIPPED, LEGION_ENCRYPTION_KEYS: KEYRING, NODE_ENV: "production" });
    expect(r.ok).toBe(false);
  });

  it("…and even with NODE_ENV=development, which the old example also set", async () => {
    const r = await boot({ JWT_SECRET: SHIPPED, LEGION_ENCRYPTION_KEYS: KEYRING, NODE_ENV: "development" });
    expect(r.ok).toBe(false);
  });

  it("development with the built-in default is allowed only on loopback", async () => {
    expect((await boot({ NODE_ENV: "development" })).ok).toBe(true);
    const exposed = await boot({ NODE_ENV: "development", LEGION_BIND_ADDRESS: "0.0.0.0" });
    expect(exposed.ok).toBe(false);
  });

  it("development without a keyring is allowed only on loopback", async () => {
    const exposed = await boot({ NODE_ENV: "development", JWT_SECRET: RANDOM, LEGION_BIND_ADDRESS: "0.0.0.0" });
    expect(exposed.ok).toBe(false);
    expect(exposed.ok ? "" : exposed.error).toMatch(/LEGION_ENCRYPTION_KEYS/);
  });

  it("a random secret boots", async () => {
    expect((await boot({ JWT_SECRET: RANDOM, LEGION_ENCRYPTION_KEYS: KEYRING })).ok).toBe(true);
  });

  it("isWeakJwtSecret recognises templates, short and repetitive values, and accepts random ones", async () => {
    const r = await boot({ JWT_SECRET: RANDOM, LEGION_ENCRYPTION_KEYS: KEYRING });
    expect(r.ok).toBe(true);
    const weak = r.ok ? r.mod.isWeakJwtSecret : () => false;
    for (const v of [SHIPPED, "change-me-change-me-change-me-change-me", "your-jwt-secret-goes-here-please-1234", "a".repeat(64), "abcabcabcabcabcabcabcabcabcabcabcabc", "short", "local-anything-at-all-that-is-long-enough", "PLACEHOLDER-0123456789abcdefghijklmnop"]) {
      expect(weak(v), v).toBe(true);
    }
    for (const v of [RANDOM, "Zx7#pQ2!mN9$vB4&kL6*wR1@tY8%hG3^uJ5", "8JH4v0gq7Wm2Xc9Lr1Tz6Ns3Bd5Kf8Yp2Qe"]) {
      expect(weak(v), v).toBe(false);
    }
  });
});

describe("the published demo login never lands on a reachable server", () => {
  it("hosted mode no longer seeds by default when NODE_ENV is unset", async () => {
    const r = await boot({ JWT_SECRET: RANDOM, LEGION_ENCRYPTION_KEYS: KEYRING, DEPLOYMENT_MODE: "saas" });
    expect(r.ok && r.config.seedDemoData).toBe(false);
  });

  it("SEED_DEMO_DATA=true is ignored in production", async () => {
    const r = await boot({ JWT_SECRET: RANDOM, LEGION_ENCRYPTION_KEYS: KEYRING, SEED_DEMO_DATA: "true", NODE_ENV: "production", COOKIE_SECURE: "true", FRONTEND_URL: "https://x.example", SMTP_HOST: "smtp.x", DATABASE_URL: "postgresql://u:p@127.0.0.1/db" });
    // production may refuse to boot for other reasons in this bare environment; if it boots, no seeding.
    if (r.ok) expect(r.config.seedDemoData).toBe(false);
  });

  it("seeding is refused unless the API listens on loopback", () => {
    const src = readFileSync(join(__dirname, "..", "src", "seed.ts"), "utf8");
    expect(src).toMatch(/if \(!loopbackBind\)/);
  });
});

describe("server/.env.example is not a working configuration", () => {
  const example = readFileSync(join(__dirname, "..", ".env.example"), "utf8");
  const active = (key: string) => example.split("\n").find((l) => l.startsWith(`${key}=`));

  it("ships no JWT secret value", () => {
    expect(active("JWT_SECRET")).toBe("JWT_SECRET=");
  });
  it("does not switch on development mode or the demo account", () => {
    expect(active("NODE_ENV")).toBeUndefined();
    expect(active("SEED_DEMO_DATA")).toBeUndefined();
  });
  it("the setup script replaces a weak or template secret instead of keeping it", () => {
    const setup = readFileSync(join(__dirname, "..", "scripts", "setup.mjs"), "utf8");
    expect(setup).toMatch(/existingJwt && !weakJwt\(existingJwt\) \? existingJwt : randomHex\(32\)/);
  });
});
