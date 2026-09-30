import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query, queryOne } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { config } from "../src/config.js";
import type { Role, Severity, User, UserStatus } from "../src/types.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

const PASSWORD = "password123";
let passwordHash = "";

// --- Fixtures ----------------------------------------------------------------

async function addTenant(name: string, trialDaysFromNow = 14): Promise<string> {
  const id = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, $3)", [
    id, name, new Date(Date.now() + trialDaysFromNow * 86_400_000).toISOString(),
  ]);
  return id;
}

async function addUser(
  tenantId: string, email: string, role: Role, status: UserStatus = "active"
): Promise<User> {
  return store.insertUser({
    email, password_hash: passwordHash, tenant_id: tenantId, role, status,
  });
}

async function addAlert(tenantId: string, id: string, target = "host-1", severity: Severity = "high") {
  await store.insertAlert({
    id, tenant_id: tenantId, title: `Alert ${id}`, severity, agent: "Sentinel",
    status: "open", summary: "test alert", confidence: 80,
    ai_explanation: null, explained_at: null, source_ip: "203.0.113.9",
    target, mitre_technique: "T1110", source: "test",
  });
}

async function addSubscription(tenantId: string, status: string, paddleSubId = `sub_${randomUUID().slice(0, 8)}`) {
  await query(
    `INSERT INTO subscriptions (tenant_id, status, paddle_customer_id, paddle_subscription_id)
     VALUES ($1, $2, 'ctm_test', $3)`,
    [tenantId, status, paddleSubId]
  );
}

/** Mints a token the same way the server does, so tests don't pay for bcrypt
 *  on every request. Login itself is covered by its own tests. */
function tokenFor(user: User): string {
  return mint({ sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version }, { algorithm: "HS256", expiresIn: "1h" });
}
const asUser = (user: User) => ["Authorization", `Bearer ${tokenFor(user)}`] as const;

/** Re-reads a user so a token can be minted from its current token_version. */
const reload = async (user: User): Promise<User> => (await store.findUserById(user.id))!;

let tenantA: string, tenantB: string;
let adminA: User, analystA: User, viewerA: User, adminB: User;

beforeAll(async () => {
  await migrate();
  passwordHash = await bcrypt.hash(PASSWORD, 10);
});

afterAll(async () => {
  await closePool();
});

beforeEach(async () => {
  await truncateAll();
  tenantA = await addTenant("Tenant A");
  tenantB = await addTenant("Tenant B");
  adminA = await addUser(tenantA, "admin-a@example.com", "admin");
  analystA = await addUser(tenantA, "analyst-a@example.com", "analyst");
  viewerA = await addUser(tenantA, "viewer-a@example.com", "viewer");
  adminB = await addUser(tenantB, "admin-b@example.com", "admin");
  await addAlert(tenantA, "LGN-A-1");
  await addAlert(tenantB, "LGN-B-1");
});

// ---------------------------------------------------------------------------

describe("tenant isolation", () => {
  it("never returns another tenant's alerts in the list", async () => {
    const res = await request(app).get("/alerts").set(...asUser(adminA)).expect(200);
    const ids = res.body.map((a: { id: string }) => a.id);
    expect(ids).toContain("LGN-A-1");
    expect(ids).not.toContain("LGN-B-1");
  });

  it("404s on a direct fetch of another tenant's alert", async () => {
    await request(app).get("/alerts/LGN-B-1").set(...asUser(adminA)).expect(404);
  });

  it("refuses to change the status of another tenant's alert", async () => {
    await request(app)
      .patch("/alerts/LGN-B-1/status")
      .set(...asUser(analystA))
      .send({ status: "resolved" })
      .expect(404);
    const untouched = await store.getAlert(tenantB, "LGN-B-1");
    expect(untouched!.status).toBe("open");
  });

  it("keeps alert stats scoped to the caller's tenant", async () => {
    await addAlert(tenantB, "LGN-B-2");
    await addAlert(tenantB, "LGN-B-3");
    const res = await request(app).get("/alerts/stats").set(...asUser(adminA)).expect(200);
    expect(res.body.total).toBe(1);
  });

  it("scopes the user list to the caller's tenant", async () => {
    const res = await request(app).get("/users").set(...asUser(adminA)).expect(200);
    const emails = res.body.map((u: { email: string }) => u.email);
    expect(emails).toContain("admin-a@example.com");
    expect(emails).not.toContain("admin-b@example.com");
  });

  it("will not let an admin change a role in another tenant", async () => {
    await request(app)
      .patch(`/users/${adminB.id}/role`)
      .set(...asUser(adminA))
      .send({ role: "viewer" })
      .expect(404);
    expect((await reload(adminB)).role).toBe("admin");
  });

  it("scopes the audit log to the caller's tenant", async () => {
    await store.audit({
      tenant_id: tenantB, user_id: adminB.id, user_email: adminB.email,
      action: "secret.action", resource_type: null, resource_id: null,
      detail: null, ip_address: null,
    });
    const res = await request(app).get("/audit").set(...asUser(adminA)).expect(200);
    expect(res.body.every((r: { action: string }) => r.action !== "secret.action")).toBe(true);
  });

  it("lets two tenants use the same alert ID without colliding", async () => {
    // The alerts primary key is (tenant_id, id). A globally unique key would
    // let one tenant discover, or block, another tenant's alert IDs.
    await request(app)
      .post("/alerts")
      .set(...asUser(analystA))
      .send({ id: "SHARED-ID", title: "A's alert", severity: "low", agent: "Sentinel", summary: "a" })
      .expect(201);

    const analystB = await addUser(tenantB, "analyst-b@example.com", "analyst");
    await request(app)
      .post("/alerts")
      .set(...asUser(analystB))
      .send({ id: "SHARED-ID", title: "B's alert", severity: "low", agent: "Sentinel", summary: "b" })
      .expect(201);

    expect((await store.getAlert(tenantA, "SHARED-ID"))!.title).toBe("A's alert");
    expect((await store.getAlert(tenantB, "SHARED-ID"))!.title).toBe("B's alert");
  });
});

describe("role-based access control", () => {
  it("blocks a viewer from creating alerts", async () => {
    await request(app)
      .post("/alerts")
      .set(...asUser(viewerA))
      .send({ title: "x", severity: "low", agent: "Sentinel", summary: "y" })
      .expect(403);
  });

  it("lets an analyst create alerts", async () => {
    await request(app)
      .post("/alerts")
      .set(...asUser(analystA))
      .send({ title: "New finding", severity: "high", agent: "Hunter", summary: "detail" })
      .expect(201);
  });

  it("blocks an analyst from reading the team list", async () => {
    await request(app).get("/users").set(...asUser(analystA)).expect(403);
  });

  it("blocks an analyst from reading the audit log", async () => {
    await request(app).get("/audit").set(...asUser(analystA)).expect(403);
  });

  it("rejects unauthenticated requests", async () => {
    await request(app).get("/alerts").expect(401);
  });
});

describe("token_version revocation", () => {
  it("invalidates existing tokens when a role changes", async () => {
    const stale = tokenFor(analystA);
    await request(app).get("/alerts").set("Authorization", `Bearer ${stale}`).expect(200);

    await request(app)
      .patch(`/users/${analystA.id}/role`)
      .set(...asUser(adminA))
      .send({ role: "viewer" })
      .expect(200);

    await request(app).get("/alerts").set("Authorization", `Bearer ${stale}`).expect(401);
  });

  it("invalidates existing tokens when an account is deactivated", async () => {
    const stale = tokenFor(analystA);
    await request(app).delete(`/users/${analystA.id}`).set(...asUser(adminA)).expect(200);
    await request(app).get("/alerts").set("Authorization", `Bearer ${stale}`).expect(401);
    expect((await reload(analystA)).status).toBe("disabled");
  });
});

describe("team invitations", () => {
  const invite = (role: Role = "analyst", email = "newbie@example.com") =>
    request(app).post("/users/invite").set(...asUser(adminA)).send({ email, role });

  const invitedUser = () => store.findUserByEmail("newbie@example.com");
  /** The token from the link the API hands the inviting admin (development, no SMTP).
   *  The database only has its hash. */
  const tokenOf = (res: { body: { invite_url?: string } }) => new URL(res.body.invite_url!).searchParams.get("token")!;

  it("creates an invited user in the inviting admin's tenant", async () => {
    const res = await invite();
    expect(res.status).toBe(201);
    expect(res.body.status).toBe("invited");
    expect(res.body.tenant_id).toBe(tenantA);
    // Without SMTP the link is returned so local setup stays usable.
    expect(res.body.invite_url).toContain("/accept-invite?token=");
  });

  it("an address that already has an account gets a workspace invitation, answered like any other", async () => {
    const res = await request(app)
      .post("/users/invite")
      .set(...asUser(adminA))
      .send({ email: "admin-b@example.com", role: "viewer" })
      .expect(201);
    expect(res.body).toMatchObject({ status: "invited", tenant_id: tenantA, role: "viewer" });
    // Their account and home workspace are untouched until they accept.
    const account = (await store.findUserByEmail("admin-b@example.com"))!;
    expect(account).toMatchObject({ tenant_id: tenantB, role: "admin", status: "active" });
  });

  it("refuses to invite someone who is already a member here", async () => {
    await request(app)
      .post("/users/invite")
      .set(...asUser(adminA))
      .send({ email: "admin-a@example.com", role: "viewer" })
      .expect(400);
  });

  it("blocks non-admins from inviting", async () => {
    await request(app)
      .post("/users/invite")
      .set(...asUser(analystA))
      .send({ email: "x@example.com", role: "viewer" })
      .expect(403);
  });

  it("will not let an invited account log in before it is accepted", async () => {
    await invite();
    const invited = (await invitedUser())!;
    // Even with a usable hash present.
    await store.updateUser(invited.id, { password_hash: passwordHash });
    await request(app)
      .post("/auth/login")
      .send({ username: "newbie@example.com", password: PASSWORD })
      .expect(403);
  });

  it("previews the invitation without requiring auth", async () => {
    const token = tokenOf(await invite("viewer"));
    const res = await request(app).post("/auth/invite/preview").send({ token }).expect(200);
    expect(res.body).toMatchObject({
      email: "newbie@example.com", role: "viewer", tenant_name: "Tenant A",
    });
  });

  it("activates the account on accept and joins the existing tenant", async () => {
    const token = tokenOf(await invite("analyst"));

    await request(app)
      .post("/auth/accept-invite")
      .send({ token, password: "brand-new-password" })
      .expect(200);

    const accepted = (await invitedUser())!;
    expect(accepted.status).toBe("active");
    expect(accepted.invite_token_hash).toBeNull();
    expect(accepted.tenant_id).toBe(tenantA); // joined, did NOT create a tenant

    const tenantCount = await queryOne<{ count: number }>("SELECT count(*)::bigint AS count FROM tenants");
    expect(Number(tenantCount!.count)).toBe(2);

    await request(app)
      .post("/auth/login")
      .send({ username: "newbie@example.com", password: "brand-new-password" })
      .expect(200);
  });

  it("rejects a reused invitation token", async () => {
    const token = tokenOf(await invite());
    await request(app).post("/auth/accept-invite").send({ token, password: "first-password" }).expect(200);
    await request(app).post("/auth/accept-invite").send({ token, password: "second-password" }).expect(400);
  });

  it("rejects an expired invitation", async () => {
    const token = tokenOf(await invite());
    const invited = (await invitedUser())!;
    await store.updateUser(invited.id, { invite_expires: new Date(Date.now() - 1000).toISOString() });
    await request(app)
      .post("/auth/accept-invite")
      .send({ token, password: "whatever-password" })
      .expect(400);
  });

  it("invalidates the old link when an invite is resent", async () => {
    const firstToken = tokenOf(await invite());
    const invited = (await invitedUser())!;
    const firstHash = invited.invite_token_hash;
    const resent = await request(app).post(`/users/${invited.id}/resend-invite`).set(...asUser(adminA)).expect(200);
    expect(tokenOf(resent)).not.toBe(firstToken);
    expect((await invitedUser())!.invite_token_hash).not.toBe(firstHash);
    await request(app)
      .post("/auth/accept-invite")
      .send({ token: firstToken, password: "some-password" })
      .expect(400);
  });
});

describe("deactivation guards", () => {
  it("refuses to deactivate your own account", async () => {
    await request(app).delete(`/users/${adminA.id}`).set(...asUser(adminA)).expect(400);
  });

  it("refuses to remove the last admin", async () => {
    await request(app).delete(`/users/${adminB.id}`).set(...asUser(adminB)).expect(400);
    const second = await addUser(tenantB, "admin-b2@example.com", "admin");
    await request(app).delete(`/users/${adminB.id}`).set(...asUser(second)).expect(200);
  });

  it("refuses to demote the last admin", async () => {
    await request(app)
      .patch(`/users/${adminB.id}/role`)
      .set(...asUser(adminB))
      .send({ role: "viewer" })
      .expect(400);
  });

  it("ignores disabled accounts when counting remaining admins", async () => {
    await addUser(tenantA, "admin-a2@example.com", "admin", "disabled");
    await request(app)
      .patch(`/users/${adminA.id}/role`)
      .set(...asUser(adminA))
      .send({ role: "viewer" })
      .expect(400);
  });
});

describe("subscription enforcement", () => {
  it("allows a tenant inside its trial", async () => {
    await request(app).get("/alerts").set(...asUser(adminA)).expect(200);
  });

  it("blocks a tenant whose trial has expired and has never subscribed", async () => {
    await query("UPDATE tenants SET trial_ends_at = now() - interval '1 day' WHERE id = $1", [tenantA]);
    const res = await request(app).get("/alerts").set(...asUser(adminA)).expect(402);
    expect(res.body.access_state).toBe("blocked");
  });

  it("allows an active subscription after the trial ends", async () => {
    await query("UPDATE tenants SET trial_ends_at = now() - interval '1 day' WHERE id = $1", [tenantA]);
    await addSubscription(tenantA, "active");
    await request(app).get("/alerts").set(...asUser(adminA)).expect(200);
  });

  it("blocks a canceled subscription", async () => {
    await addSubscription(tenantA, "canceled");
    await request(app).get("/alerts").set(...asUser(adminA)).expect(402);
  });

  it("keeps past_due tenants read-only rather than dark", async () => {
    await addSubscription(tenantA, "past_due");
    // Existing findings stay visible...
    await request(app).get("/alerts").set(...asUser(adminA)).expect(200);
    // ...but no new work is accepted.
    await request(app)
      .post("/alerts")
      .set(...asUser(analystA))
      .send({ title: "x", severity: "low", agent: "Sentinel", summary: "y" })
      .expect(402);
  });

  it("always leaves the billing and auth paths reachable", async () => {
    await query("UPDATE tenants SET trial_ends_at = now() - interval '1 day' WHERE id = $1", [tenantA]);
    await request(app).get("/auth/me").set(...asUser(adminA)).expect(200);
    await request(app).post("/billing/checkout-context").set(...asUser(adminA)).expect(200);
  });

  it("reports the access state on /auth/me", async () => {
    await query("UPDATE tenants SET trial_ends_at = now() - interval '1 day' WHERE id = $1", [tenantA]);
    const res = await request(app).get("/auth/me").set(...asUser(adminA)).expect(200);
    expect(res.body.access_state).toBe("blocked");
    expect(res.body.tenant_name).toBe("Tenant A");
  });
});

describe("security event webhook", () => {

  const wazuhEvent = (id: string, level = 10, agentName = "web-01") => ({
    provider: "wazuh",
    event: {
      id,
      rule: { description: "Multiple authentication failures", level, mitre: { id: ["T1110"] } },
      agent: { name: agentName, ip: "10.0.0.5", os: { name: "Ubuntu 24.04" } },
      data: { srcip: "198.51.100.7" },
      full_log: "sshd: Failed password for invalid user",
    },
  });

  // Signed the way integrations/custom-legion.py signs (tests/webhook-auth
  // covers the forgeries); these tests are about what happens after. Tenant A's
  // own credential; the tenant is learned from it, not named by the request.
  let credA: TestCredential;
  beforeEach(async () => { credA = await issueCredential(tenantA); });
  const post = (_tenantId: string, body: unknown, opts: Parameters<typeof sendSigned>[3] = {}) => sendSigned(app, credA, body, opts);

  it("rejects a wrong signature", async () => {
    await post(tenantA, wazuhEvent("evt-1"), { signWithSecret: "whs_" + "x".repeat(43) }).expect(401);
  });

  it("rejects an unknown credential", async () => {
    await post(tenantA, wazuhEvent("evt-1"), { keyId: "whk_" + "A".repeat(22) }).expect(401);
  });

  it("ingests a valid event and registers the reporting asset", async () => {
    await post(tenantA, wazuhEvent("evt-1")).expect(202);

    const alerts = await store.listAlerts(tenantA, {});
    const alert = alerts.find((a) => a.target === "web-01");
    expect(alert).toBeDefined();
    expect(alert!.severity).toBe("high"); // level 10

    // The asset inventory is built from live sensor data, not a static seed.
    const assets = await store.listAssets(tenantA, {});
    const asset = assets.find((a) => a.name === "web-01");
    expect(asset).toBeDefined();
    expect(asset!.ip_address).toBe("10.0.0.5");
    expect(asset!.os).toBe("Ubuntu 24.04");
    expect(asset!.risk).toBe("high");
  });

  it("raises asset risk to match the worst recent alert", async () => {
    await post(tenantA, wazuhEvent("evt-low", 3, "db-01")).expect(202);
    expect((await store.listAssets(tenantA, {})).find((a) => a.name === "db-01")!.risk).toBe("low");

    await post(tenantA, wazuhEvent("evt-crit", 13, "db-01")).expect(202);
    expect((await store.listAssets(tenantA, {})).find((a) => a.name === "db-01")!.risk).toBe("critical");
  });

  it("deduplicates a replayed event", async () => {
    await post(tenantA, wazuhEvent("evt-dup")).expect(202);
    const before = (await store.listAlerts(tenantA, {})).length;
    const res = await post(tenantA, wazuhEvent("evt-dup")).expect(202);
    expect(res.body.reason).toBe("duplicate");
    expect((await store.listAlerts(tenantA, {})).length).toBe(before);
  });

  it("stays idempotent when the same event arrives concurrently", async () => {
    // Sensor retries can overlap; ON CONFLICT is what makes this safe, a
    // check-then-insert would let both pass.
    const results = await Promise.all([
      post(tenantA, wazuhEvent("evt-race")),
      post(tenantA, wazuhEvent("evt-race")),
      post(tenantA, wazuhEvent("evt-race")),
    ]);
    const ingested = results.filter((r) => r.body.status === "ingested");
    expect(ingested).toHaveLength(1);
  });

  it("keeps ingesting even when the tenant's subscription is blocked", async () => {
    // Losing telemetry over an unpaid invoice would leave a permanent hole in
    // the customer's security history.
    await addSubscription(tenantA, "canceled");
    await post(tenantA, wazuhEvent("evt-while-blocked")).expect(202);
    expect((await store.listAlerts(tenantA, {})).some((a) => a.id.startsWith("SEC-"))).toBe(true);
  });
});

describe("registration and passwords", () => {
  it("creates a tenant with a trial window", async () => {
    const res = await request(app)
      .post("/auth/register")
      .send({ email: "Founder@Example.com", password: "a-good-password", tenant_name: "Acme" })
      .expect(201);
    expect(res.body.email).toBe("founder@example.com"); // normalised
    const tenant = await queryOne<{ trial_ends_at: Date }>(
      "SELECT trial_ends_at FROM tenants WHERE name = 'Acme'"
    );
    expect(new Date(tenant!.trial_ends_at).getTime()).toBeGreaterThan(Date.now());
  });

  it("rejects a duplicate email", async () => {
    await request(app)
      .post("/auth/register")
      .send({ email: "admin-a@example.com", password: "a-good-password", tenant_name: "Dup" })
      .expect(400);
  });

  it("rejects a duplicate email regardless of case", async () => {
    await request(app)
      .post("/auth/register")
      .send({ email: "ADMIN-A@example.com", password: "a-good-password", tenant_name: "Dup" })
      .expect(400);
  });

  it("does not create duplicate accounts under concurrent registration", async () => {
    // Enforced by the unique index, not by an application-level check.
    const body = { email: "race@example.com", password: "a-good-password", tenant_name: "Race" };
    const results = await Promise.all([
      request(app).post("/auth/register").send(body),
      request(app).post("/auth/register").send(body),
      request(app).post("/auth/register").send(body),
    ]);
    expect(results.filter((r) => r.status === 201)).toHaveLength(1);
    const count = await queryOne<{ count: number }>(
      "SELECT count(*)::bigint AS count FROM users WHERE email = 'race@example.com'"
    );
    expect(Number(count!.count)).toBe(1);
  });

  it("leaves no orphan tenant when registration loses the race", async () => {
    const body = { email: "race2@example.com", password: "a-good-password", tenant_name: "RaceTenant" };
    await Promise.all([
      request(app).post("/auth/register").send(body),
      request(app).post("/auth/register").send(body),
    ]);
    // The tenant and its admin are inserted in one transaction, so a losing
    // request must roll the tenant back rather than stranding it.
    const count = await queryOne<{ count: number }>(
      "SELECT count(*)::bigint AS count FROM tenants WHERE name = 'RaceTenant'"
    );
    expect(Number(count!.count)).toBe(1);
  });

  it("does not reveal whether an address is registered", async () => {
    const known = await request(app).post("/auth/forgot-password").send({ email: "admin-a@example.com" });
    const unknown = await request(app).post("/auth/forgot-password").send({ email: "nobody@example.com" });
    expect(known.status).toBe(202);
    expect(unknown.status).toBe(202);
    expect(known.body).toEqual(unknown.body);
  });

  it("rejects an invalid reset token", async () => {
    await request(app)
      .post("/auth/reset-password")
      .send({ token: "x".repeat(43), new_password: "another-password" })
      .expect(400);
  });

  it("signs out other sessions when the password changes", async () => {
    const stale = tokenFor(adminA);
    await request(app)
      .post("/auth/change-password")
      .set("Authorization", `Bearer ${stale}`)
      .send({ current_password: PASSWORD, new_password: "a-fresh-password" })
      .expect(200);
    await request(app).get("/auth/me").set("Authorization", `Bearer ${stale}`).expect(401);
  });

  it("rejects a password change with the wrong current password", async () => {
    await request(app)
      .post("/auth/change-password")
      .set(...asUser(adminA))
      .send({ current_password: "not-the-password", new_password: "a-fresh-password" })
      .expect(400);
  });
});

describe("paddle webhook ordering", () => {
  it("ignores an event older than the one already applied", async () => {
    const newer = "2026-06-01T00:00:00.000Z";
    const older = "2026-05-01T00:00:00.000Z";

    await store.applySubscriptionEvent({
      tenant_id: tenantA, status: "active", paddle_customer_id: "ctm_1",
      paddle_subscription_id: "sub_order", paddle_price_id: "pri_1",
      current_period_end: null, cancel_at_period_end: false, last_event_at: newer,
    });

    const stale = await store.applySubscriptionEvent({
      tenant_id: tenantA, status: "canceled", paddle_customer_id: "ctm_1",
      paddle_subscription_id: "sub_order", paddle_price_id: "pri_1",
      current_period_end: null, cancel_at_period_end: true, last_event_at: older,
    });

    expect(stale).toBeNull();
    expect((await store.getSubscription(tenantA))!.status).toBe("active");
  });
});

describe("health", () => {
  it("reports database connectivity", async () => {
    const res = await request(app).get("/health").expect(200);
    expect(res.body.database).toBe("up");
  });
});
