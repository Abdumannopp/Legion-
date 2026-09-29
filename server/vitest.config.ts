import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Set before any source module loads: config.ts reads these at import time,
    // and NODE_ENV=test stops index.ts binding a port or running migrations
    // (the suite owns that lifecycle itself).
    env: {
      NODE_ENV: "test",
      // The bulk of the suite exercises the hosted behaviour (trials,
      // subscription gating, open sign-up). Self-hosted mode has its own file,
      // which flips config.deploymentMode for the cases it covers.
      DEPLOYMENT_MODE: "saas",
      DATABASE_URL:
        process.env.TEST_DATABASE_URL ||
        "postgresql://legion@127.0.0.1:5433/legion_test",
      JWT_SECRET: "test-secret-that-is-long-enough-to-be-realistic",
      FRONTEND_URL: "http://localhost:3000",
      SECURITY_EVENT_WEBHOOK_SECRET: "test-webhook-secret",
      TRIAL_DAYS: "14",
      // Production default for a hosted tenant is "AI off until an administrator
      // turns it on". The older suites exercise the model path, so they run with
      // it on; ai-hardening.test.ts sets each tenant's state explicitly.
      AI_TENANT_DEFAULT: "on",
      // A real (test-only) keyring: the suite exercises the configured path, not
      // the development fallback. Tests that rotate keys change config directly.
      LEGION_ENCRYPTION_KEYS: "t1:0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0",
    },
    include: ["tests/**/*.test.ts"],
    // Files share one database, so they must not interleave.
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
