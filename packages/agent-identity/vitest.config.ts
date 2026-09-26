import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Every test file shares one Postgres database; run files one at a time.
    fileParallelism: false,
    hookTimeout: 30_000,
    testTimeout: 30_000,
  },
});
