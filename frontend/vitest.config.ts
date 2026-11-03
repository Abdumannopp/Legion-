import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// The realtime logic (lib/realtime) is deliberately free of React and the DOM, so
// it is tested in plain Node with injected sockets, clocks and fetches.
export default defineConfig({
  resolve: { alias: { "@": fileURLToPath(new URL(".", import.meta.url)) } },
  test: {
    environment: "node",
    include: ["lib/**/*.test.ts", "hooks/**/*.test.ts"],
  },
});
