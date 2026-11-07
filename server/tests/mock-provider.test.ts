/**
 * Audit P2-15: the mock provider fabricates a high-severity alert. It must not
 * exist on a real installation.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";

let admin: User;
const savedEnv = process.env.NODE_ENV;
const bearer = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;

beforeAll(async () => { await migrate(); });
afterAll(async () => { process.env.NODE_ENV = savedEnv; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  const tenant = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'T', now() + interval '14 days')", [tenant]);
  admin = await store.insertUser({ email: "admin@t.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenant, role: "admin", status: "active" });
});

describe("the mock provider", () => {
  it("does not exist on a real installation (NODE_ENV unset or production)", async () => {
    for (const env of [undefined, "production"]) {
      if (env === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = env;
      try {
        await request(app).post("/security-events/sync").set("Authorization", bearer(admin)).expect(404);
      } finally { process.env.NODE_ENV = savedEnv; }
    }
    expect((await query("SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1", [admin.tenant_id])).rows[0].n).toBe(0);
  });

  it("still works for development and tests", async () => {
    await request(app).post("/security-events/sync").set("Authorization", bearer(admin)).expect(200);
  });
});
