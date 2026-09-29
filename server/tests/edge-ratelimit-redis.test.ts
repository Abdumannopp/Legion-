/**
 * The same promise against a REAL redis-server: shared counting while it is up,
 * an enforced limit while it is killed or frozen (SIGSTOP = accepts nothing,
 * answers nothing), and recovery when it returns.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawn, type ChildProcess } from "node:child_process";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";

const PORT = 6391;
process.env.REDIS_URL = `redis://127.0.0.1:${PORT}`;
process.env.LEGION_ENFORCE_RATE_LIMITS = "1";
const { makeLimiter, initRateLimitStore, closeRateLimitStore, redisConnected } = await import("../src/ratelimit.js");

let redis: ChildProcess | null = null;
const startRedis = async () => {
  redis = spawn("redis-server", ["--port", String(PORT), "--save", "", "--appendonly", "no"], { stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 400));
};
const until = async (cond: () => boolean, ms: number) => {
  const end = Date.now() + ms;
  while (!cond() && Date.now() < end) await new Promise((r) => setTimeout(r, 50));
  return cond();
};

let server: http.Server; let base = "";
const hit = async (user: string) => (await fetch(`${base}/login`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ user }),
})).status;

beforeAll(async () => {
  await startRedis();
  await initRateLimitStore();
  const app = express();
  app.use(express.json());
  app.post("/login", makeLimiter({
    windowMs: 60_000, limit: 3, prefix: "realredis", failuresOnly: true,
    key: (req) => `u:${req.body?.user}`,
  }), (_req, res) => res.status(401).json({}));
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  server?.close();
  redis?.kill("SIGKILL");
  // Shutdown must complete even though Redis is already gone.
  const t0 = Date.now();
  await closeRateLimitStore();
  expect(Date.now() - t0).toBeLessThan(3_000);
});

describe("against a real Redis", () => {
  it("counts through Redis while it is healthy", async () => {
    expect(await until(redisConnected, 3_000)).toBe(true);
    expect([await hit("healthy"), await hit("healthy"), await hit("healthy"), await hit("healthy")]).toEqual([401, 401, 401, 429]);
  });

  it("keeps enforcing after Redis is killed mid-attack", async () => {
    await hit("killed"); // one attempt while up
    redis!.kill("SIGKILL");
    await until(() => !redisConnected(), 3_000);
    const t0 = Date.now();
    const rest = [await hit("killed"), await hit("killed"), await hit("killed")];
    expect(rest).toEqual([401, 401, 429]);
    expect(Date.now() - t0).toBeLessThan(2_000);
  });

  it("keeps enforcing, without stalling, while Redis is frozen", async () => {
    await startRedis();
    expect(await until(redisConnected, 5_000)).toBe(true);
    redis!.kill("SIGSTOP"); // TCP stays open; nothing ever answers
    try {
      const t0 = Date.now();
      const codes: number[] = [];
      for (let i = 0; i < 5; i++) codes.push(await hit("frozen"));
      expect(codes).toEqual([401, 401, 401, 429, 429]);
      expect(Date.now() - t0).toBeLessThan(3_000);
    } finally { redis!.kill("SIGCONT"); }
  });
});
