/**
 * Audit P1-9: under systemd, `npm start` runs the API and the dashboard through
 * `concurrently`. Without --kill-others, a crashed API left concurrently (and
 * the unit) running, so systemd never restarted anything.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { KEEP_ALIVE_TIMEOUT_MS } from "../src/edge.js";

const root = join(fileURLToPath(import.meta.url), "..", "..", "..");
const startScript = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).scripts.start as string;
const unit = readFileSync(join(root, "deploy", "legion.service"), "utf8");

describe("the service restarts when the API dies", () => {
  it("npm start stops everything when either process exits", () => {
    expect(startScript).toMatch(/^concurrently --kill-others /);
  });

  it("systemd restarts the unit whatever the exit status", () => {
    expect(unit).toMatch(/^Restart=always$/m);
  });

  it("really: one process exiting makes concurrently exit (non-zero) instead of running on", () => {
    const bin = join(root, "node_modules", ".bin", "concurrently");
    const r = spawnSync(bin, ["--kill-others", "node -e \"process.exit(1)\"", "node -e \"setTimeout(()=>{}, 60000)\""], {
      timeout: 20_000, encoding: "utf8",
    });
    expect(r.error).toBeUndefined(); // did not hit the 20 s timeout
    expect(r.status).not.toBe(0);
  });
});

describe("nginx and Node agree on idle connections (audit P2-19)", () => {
  const nginx = readFileSync(join(root, "deploy", "nginx.conf"), "utf8");
  const upstreams = [...nginx.matchAll(/upstream\s+(\w+)\s*\{([^}]*)\}/g)];

  it("every upstream drops an idle connection before Node does", () => {
    expect(upstreams.length).toBeGreaterThanOrEqual(2);
    for (const [, name, body] of upstreams) {
      const m = /keepalive_timeout\s+(\d+)s;/.exec(body!);
      expect(m, `${name} has no keepalive_timeout`).not.toBeNull();
      expect(Number(m![1]) * 1000, name).toBeLessThan(KEEP_ALIVE_TIMEOUT_MS);
    }
  });
});

describe("one lockfile (audit P2-17)", () => {
  it("workspace members have no lockfile of their own that could pin different versions", () => {
    const workspaces = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).workspaces as string[];
    expect(workspaces.length).toBeGreaterThan(0);
    for (const w of workspaces) {
      expect(existsSync(join(root, w, "package-lock.json")), `${w}/package-lock.json`).toBe(false);
    }
    expect(existsSync(join(root, "package-lock.json"))).toBe(true);
  });
});
