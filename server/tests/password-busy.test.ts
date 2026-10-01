/**
 * Sign-in under a hashing flood (RED-1, PRODUCTION-VALIDATION-2026-10-01.md):
 * with the worker pool saturated, sign-in answers 503 + Retry-After — in the
 * caller's language — while the rest of the API keeps answering, and the
 * account works again as soon as the flood passes.
 */
import { vi } from "vitest";
// One worker and one slot, so a handful of concurrent sign-ins saturates it.
// Hoisted: config.ts reads these when it is first imported.
vi.hoisted(() => {
  process.env.PASSWORD_HASH_WORKERS = "1";
  process.env.PASSWORD_HASH_MAX_PENDING = "1";
});
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { hashingLoad } from "../src/passwords.js";

beforeAll(async () => {
  await migrate();
  await truncateAll();
  const t = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Busy Co')", [t]);
  await store.insertUser({ email: "busy@example.com", password_hash: await bcrypt.hash("password123", 12), tenant_id: t, role: "admin", status: "active" });
});
afterAll(async () => {
  await closePool();
  // Do not leak the tiny pool into test files that run after this one.
  delete process.env.PASSWORD_HASH_WORKERS;
  delete process.env.PASSWORD_HASH_MAX_PENDING;
});

describe("a sign-in flood", () => {
  it("is answered 503 + Retry-After past the pool's limit, without stalling the API", async () => {
    expect(hashingLoad()).toMatchObject({ workers: 1, maxPending: 1 });
    const logins = Array.from({ length: 6 }, (_, i) =>
      request(app).post("/auth/login").set("Accept-Language", i === 5 ? "ru" : "en").send({ username: "busy@example.com", password: `wrong-${i}` }));
    // While they are in flight, the rest of the API answers.
    const t0 = Date.now();
    const health = await request(app).get("/health");
    expect(health.status).toBe(200);
    expect(Date.now() - t0).toBeLessThan(500);

    const results = await Promise.all(logins);
    const busy = results.filter((r) => r.status === 503);
    expect(busy.length).toBeGreaterThan(0);
    expect(results.filter((r) => r.status === 401).length).toBeGreaterThan(0);
    for (const r of busy) {
      expect(r.headers["retry-after"]).toBe("2");
      expect(r.body.code).toBe("auth_busy");
    }
    const ru = results[5];
    if (ru.status === 503) expect(ru.body.detail).toMatch(/Повторите/);
  });

  it("once the flood has passed, the right password signs in", async () => {
    await new Promise((r) => setTimeout(r, 1500));
    const ok = await request(app).post("/auth/login").send({ username: "busy@example.com", password: "password123" });
    expect(ok.status).toBe(200);
    expect(ok.body.access_token).toBeTruthy();
  });
});
