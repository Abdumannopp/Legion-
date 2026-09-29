/**
 * Self-hosted mode: the customer runs Legion on their own server.
 *
 * The behaviours here are the ones that differ from the hosted service, and
 * each exists because the hosted assumptions actively harm a self-hosted
 * install.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { randomUUID } from "node:crypto";
import { app, accessState } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";
import type { User } from "../src/types.js";
import { issueSetupToken } from "../src/setup-token.js";

const PASSWORD = "password123";
let passwordHash = "";
let tenantId: string;
let admin: User;

function tokenFor(u: User): string {
  return jwt.sign(
    { sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version },
    config.jwtSecret, { algorithm: "HS256", expiresIn: "1h" }
  );
}
const asUser = (u: User) => ["Authorization", `Bearer ${tokenFor(u)}`] as const;

beforeAll(async () => {
  await migrate();
  passwordHash = await bcrypt.hash(PASSWORD, 10);
  // config is a plain object and isSelfHosted() reads it per call, so flipping
  // it here switches the whole app over for this file.
  config.deploymentMode = "self-hosted";
});

afterAll(async () => {
  config.deploymentMode = "saas";
  await closePool();
});

beforeEach(async () => {
  await truncateAll();
  tenantId = randomUUID();
  // Deliberately given an EXPIRED trial: a self-hosted install must ignore it.
  await query(
    "INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() - interval '30 days')",
    [tenantId, "On-Prem Corp"]
  );
  admin = await store.insertUser({
    email: "admin@onprem.local", password_hash: passwordHash,
    tenant_id: tenantId, role: "admin", status: "active",
  });
});

describe("the install never locks its owner out", () => {
  it("ignores an expired trial", async () => {
    // The hosted trial would expire on the customer's own server and demand a
    // subscription that does not exist — bricking software they already bought.
    expect(await accessState(tenantId)).toBe("ok");
    await request(app).get("/alerts").set(...asUser(admin)).expect(200);
  });

  it("ignores a canceled subscription record", async () => {
    await query(
      `INSERT INTO subscriptions (tenant_id, status, paddle_customer_id)
       VALUES ($1, 'canceled', 'ctm_stale')`,
      [tenantId]
    );
    expect(await accessState(tenantId)).toBe("ok");
    await request(app).get("/alerts").set(...asUser(admin)).expect(200);
  });

  it("still allows writes, not just reads", async () => {
    const analyst = await store.insertUser({
      email: "analyst@onprem.local", password_hash: passwordHash,
      tenant_id: tenantId, role: "analyst", status: "active",
    });
    await request(app)
      .post("/alerts")
      .set(...asUser(analyst))
      .send({ title: "On-prem finding", severity: "high", agent: "Hunter", summary: "detail" })
      .expect(201);
  });
});

describe("registration is first-run setup, not an open door", () => {
  it("allows the very first workspace — with the console's setup token", async () => {
    await truncateAll(); // a brand new installation
    // The token is what proves the caller has access to the server itself.
    // tests/first-admin.test.ts covers the refusals and the race.
    const setup_token = await issueSetupToken();
    await request(app)
      .post("/auth/register")
      .send({ email: "owner@onprem.local", password: "a-good-password", tenant_name: "On-Prem Corp", setup_token })
      .expect(201);
  });

  it("refuses a second workspace once set up", async () => {
    // Otherwise every internet-reachable installation is a public sign-up
    // portal for the customer's own security console.
    const res = await request(app)
      .post("/auth/register")
      .send({ email: "stranger@example.com", password: "a-good-password", tenant_name: "Not Yours" })
      .expect(403);
    expect(res.body.detail).toMatch(/already set up/i);
  });

  it("still lets an admin invite colleagues", async () => {
    const res = await request(app)
      .post("/users/invite")
      .set(...asUser(admin))
      .send({ email: "analyst2@onprem.local", role: "analyst" })
      .expect(201);
    expect(res.body.status).toBe("invited");
  });
});

describe("billing is absent", () => {
  it("hides the subscription endpoint", async () => {
    await request(app).get("/billing/subscription").set(...asUser(admin)).expect(404);
  });

  it("hides checkout and portal", async () => {
    await request(app).post("/billing/checkout-context").set(...asUser(admin)).expect(404);
    await request(app).post("/billing/portal").set(...asUser(admin)).expect(404);
  });

  it("hides the Paddle webhook", async () => {
    await request(app).post("/billing/webhook").send({ event_type: "subscription.created" }).expect(404);
  });

  it("tells the dashboard which mode it is in", async () => {
    const res = await request(app).get("/auth/me").set(...asUser(admin)).expect(200);
    expect(res.body.deployment_mode).toBe("self-hosted");
  });
});

describe("everything else still works", () => {
  it("keeps authentication and RBAC intact", async () => {
    await request(app).get("/alerts").expect(401);
    const viewer = await store.insertUser({
      email: "viewer@onprem.local", password_hash: passwordHash,
      tenant_id: tenantId, role: "viewer", status: "active",
    });
    await request(app)
      .post("/alerts")
      .set(...asUser(viewer))
      .send({ title: "x", severity: "low", agent: "Sentinel", summary: "y" })
      .expect(403);
  });

  it("keeps tenant scoping intact", async () => {
    // Multi-tenancy is not removed on-prem — it is simply unused by most
    // installs, and removing it would be a large change for no gain.
    const otherId = randomUUID();
    await query("INSERT INTO tenants (id, name) VALUES ($1, 'Other')", [otherId]);
    await store.insertAlert({
      id: "OTHER-1", tenant_id: otherId, title: "Not yours", severity: "low",
      agent: "Sentinel", status: "open", summary: "x", confidence: 1,
      ai_explanation: null, explained_at: null, source_ip: null, target: null,
      mitre_technique: null, source: "test",
    });
    await request(app).get("/alerts/OTHER-1").set(...asUser(admin)).expect(404);
  });

  it("keeps sensor ingestion working", async () => {
    const { issueCredential, sendSigned } = await import("./helpers/webhook.js");
    const cred = await issueCredential(tenantId);
    await sendSigned(app, cred, {
      provider: "wazuh",
      event: { id: "onprem-1", rule: { description: "Test event", level: 10 }, agent: { name: "srv-1" } },
    }).expect(202);
  });
});
