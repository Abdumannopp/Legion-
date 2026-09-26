import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// The security assessment: attack scenarios that record what actually
// happened (not assertions of what should). Kept apart from the unit tests
// so an undefended attack is reported, not a CI failure.
//   npx vitest run --config assessment/vitest.config.ts
export default defineConfig({
  root: fileURLToPath(new URL("..", import.meta.url)),
  test: {
    include: ["assessment/**/*.assess.ts"],
    fileParallelism: false,
    hookTimeout: 60_000,
    testTimeout: 60_000,
  },
});
