/**
 * Audit P1-10: a request ID on every response, and one structured access-log
 * line per request that never carries a token, a query string or a body.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import { app } from "../src/index.js";
import { config } from "../src/config.js";
import { setAccessLogSink } from "../src/access-log.js";
import { closePool, migrate } from "../src/db/pool.js";

const lines: string[] = [];
const saved = config.accessLog;
beforeAll(async () => {
  await migrate();
  (config as { accessLog: boolean }).accessLog = true;
  setAccessLogSink((l) => lines.push(l));
});
afterAll(async () => {
  (config as { accessLog: boolean }).accessLog = saved;
  setAccessLogSink(null);
  await closePool();
});
beforeEach(() => { lines.length = 0; });

const lastLine = async () => {
  await new Promise((r) => setTimeout(r, 20)); // "finish" fires after the response
  return JSON.parse(lines.at(-1)!);
};

describe("request IDs and the access log", () => {
  it("every response carries a server-made request id, also on errors and 404s", async () => {
    const a = await request(app).get("/alerts").expect(401);
    const b = await request(app).get("/no-such-route");
    expect(a.headers["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(b.headers["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(a.headers["x-request-id"]).not.toBe(b.headers["x-request-id"]);
  });

  it("a client cannot choose its request id (log correlation cannot be forged)", async () => {
    const r = await request(app).get("/alerts").set("x-request-id", "forged-123");
    expect(r.headers["x-request-id"]).not.toBe("forged-123");
  });

  it("writes one JSON line with the route pattern, status, latency and the same id", async () => {
    const r = await request(app).get("/alerts?search=secret-term").expect(401);
    const line = await lastLine();
    expect(line).toMatchObject({ msg: "http", method: "GET", status: 401, rid: r.headers["x-request-id"] });
    expect(typeof line.ms).toBe("number");
    expect(lines.at(-1)).not.toContain("secret-term");
  });

  it("logs the pattern, never a token inside the URL", async () => {
    const token = "inv_" + "a".repeat(40);
    await request(app).get(`/auth/invite/${token}`);
    const line = await lastLine();
    expect(lines.join("\n")).not.toContain(token);
    expect(line.route).toMatch(/:token|\(unmatched\)/);
  });

  it("never logs the request body (passwords)", async () => {
    await request(app).post("/auth/login").send({ username: "x@example.com", password: "Sup3r-Secret-Pass" });
    await lastLine();
    expect(lines.join("\n")).not.toContain("Sup3r-Secret-Pass");
    expect(lines.join("\n")).not.toContain("x@example.com");
  });

  it("ACCESS_LOG off writes nothing, and the id is still returned", async () => {
    (config as { accessLog: boolean }).accessLog = false;
    try {
      const r = await request(app).get("/alerts");
      await new Promise((res) => setTimeout(res, 20));
      expect(lines).toHaveLength(0);
      expect(r.headers["x-request-id"]).toBeTruthy();
    } finally {
      (config as { accessLog: boolean }).accessLog = true;
    }
  });
});
