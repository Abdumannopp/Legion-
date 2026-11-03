import request from "supertest";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { agentWithToken, as, auditRows, bearer, makeApp, resetDb, TENANT_A, TENANT_B, type TestApp } from "./helpers.js";

let t: TestApp;

beforeEach(async () => {
  if (t) await t.pool.end();
  t = await makeApp();
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  t.host.add("anna", TENANT_A, "analyst");
  t.host.add("vic", TENANT_A, "viewer");
  t.host.add("bob", TENANT_B, "admin");
});
afterAll(async () => { await t?.pool.end(); });

describe("creating an agent identity", () => {
  it("records every required attribute", async () => {
    const res = await request(t.app).post("/agents").set(as("alice"))
      .send({ name: "Triage bot", description: "Summarises new alerts", permissions: ["alerts:read", "alerts:comment"], ownerUserId: "anna" });
    expect(res.status).toBe(201);
    const a = res.body.identity;
    expect(a.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(a).toMatchObject({
      kind: "ai_agent",
      name: "Triage bot",
      tenantId: TENANT_A,
      ownerUserId: "anna",
      status: "active",
      permissions: ["alerts:read", "alerts:comment"],
      riskLevel: "medium",
      createdBy: "alice",
      lastActivityAt: null,
    });
    expect(new Date(a.createdAt).getTime()).toBeGreaterThan(Date.now() - 60_000);
  });

  it("returns the credential secret once and stores only its hash", async () => {
    const res = await request(t.app).post("/agents").set(as("alice")).send({ name: "x", permissions: [] });
    const secret: string = res.body.credential.secret;
    expect(secret).toMatch(/^lga_[0-9a-f]{32}_[A-Za-z0-9_-]{43}$/);

    const detail = await request(t.app).get(`/agents/${res.body.identity.id}`).set(as("alice"));
    expect(JSON.stringify(detail.body)).not.toContain(secret.slice(-43));

    const dump = await t.pool.query("SELECT row_to_json(c)::text AS j FROM machine_credentials c");
    expect(dump.rows.map((r) => r.j).join()).not.toContain(secret.slice(-43));
  });

  it("owner defaults to the creating administrator", async () => {
    const res = await request(t.app).post("/agents").set(as("alice")).send({ name: "x" });
    expect(res.body.identity.ownerUserId).toBe("alice");
  });

  it("audits creation, attributed to the human who did it", async () => {
    const res = await request(t.app).post("/agents").set(as("alice")).send({ name: "x", permissions: ["alerts:read"] });
    const rows = await auditRows(t.pool, "action = 'identity.created'");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      principal_type: "human", principal_id: "alice", tenant_id: TENANT_A,
      resource_type: "ai_agent", resource_id: res.body.identity.id, outcome: "success",
    });
    expect(JSON.stringify(rows[0].details)).not.toContain(res.body.credential.secret);
  });

  it("only administrators can create", async () => {
    expect((await request(t.app).post("/agents").set(as("anna")).send({ name: "x" })).status).toBe(403);
    expect((await request(t.app).post("/agents").set(as("vic")).send({ name: "x" })).status).toBe(403);
    expect((await request(t.app).post("/agents").send({ name: "x" })).status).toBe(401);
  });

  it("refuses administrative (tier 3) and unknown permissions", async () => {
    for (const perm of ["users:manage", "agents:manage", "settings:write", "*", "alerts:delete"]) {
      const res = await request(t.app).post("/agents").set(as("alice")).send({ name: "x", permissions: [perm] });
      expect(res.status, perm).toBe(400);
      expect(res.body.error.code).toBe("unknown_permission");
    }
  });

  it("cannot give an agent more than its owner's role allows", async () => {
    const res = await request(t.app).post("/agents").set(as("alice"))
      .send({ name: "x", ownerUserId: "vic", permissions: ["alerts:update_status"] });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("exceeds_owner_role");
  });

  it("owner must be an active user of the same tenant", async () => {
    t.host.add("gone", TENANT_A, "analyst", "disabled");
    for (const owner of ["bob", "gone", "nobody"]) {
      const res = await request(t.app).post("/agents").set(as("alice")).send({ name: "x", ownerUserId: owner });
      expect(res.status, owner).toBe(400);
      expect(res.body.error.code).toBe("invalid_owner");
    }
  });

  it("derives risk from permissions and never lets it be set lower", async () => {
    const hi = await request(t.app).post("/agents").set(as("alice")).send({ name: "a", permissions: ["alerts:update_status"] });
    expect(hi.body.identity.riskLevel).toBe("high");
    const low = await request(t.app).post("/agents").set(as("alice")).send({ name: "b", permissions: ["alerts:update_status"], riskLevel: "low" });
    expect(low.status).toBe(400);
    expect(low.body.error.code).toBe("risk_below_baseline");
    const raised = await request(t.app).post("/agents").set(as("alice")).send({ name: "c", permissions: [], riskLevel: "high" });
    expect(raised.body.identity.riskLevel).toBe("high");
  });

  it("names are unique per tenant among live identities", async () => {
    expect((await request(t.app).post("/agents").set(as("alice")).send({ name: "Bot" })).status).toBe(201);
    const dup = await request(t.app).post("/agents").set(as("alice")).send({ name: "bot" });
    expect(dup.status).toBe(409);
    expect((await request(t.app).post("/agents").set(as("bob")).send({ name: "Bot" })).status).toBe(201);
  });

  it("rejects unexpected fields instead of ignoring them", async () => {
    const res = await request(t.app).post("/agents").set(as("alice")).send({ name: "x", tenantId: TENANT_B });
    expect(res.status).toBe(400);
  });
});

describe("service accounts are a separate kind", () => {
  it("carry their own prefix and principal type", async () => {
    const res = await request(t.app).post("/service-accounts").set(as("alice")).send({ name: "backup-script", permissions: ["stats:read"] });
    expect(res.status).toBe(201);
    expect(res.body.identity.kind).toBe("service_account");
    expect(res.body.credential.secret).toMatch(/^lgs_/);
    const tok = await request(t.app).post("/agent/v1/token").set(bearer(res.body.credential.secret));
    expect(tok.body.principal.type).toBe("service_account");
    const me = await request(t.app).get("/agent/v1/me").set(bearer(tok.body.access_token));
    expect(me.body.principalType).toBe("service_account");
  });

  it("are not visible through the agents API, and vice versa", async () => {
    const sa = await request(t.app).post("/service-accounts").set(as("alice")).send({ name: "s" });
    expect((await request(t.app).get(`/agents/${sa.body.identity.id}`).set(as("alice"))).status).toBe(404);
    expect((await request(t.app).get("/agents").set(as("alice"))).body.identities).toHaveLength(0);
  });
});

describe("lifecycle", () => {
  it("suspension stops the agent at once and kills its tokens; resume needs a new token", async () => {
    const { agent, secret, token } = await agentWithToken(t, "alice");
    expect((await request(t.app).get("/agent/v1/me").set(bearer(token))).status).toBe(200);

    const s = await request(t.app).post(`/agents/${agent.id}/suspend`).set(as("alice")).send({ reason: "investigating" });
    expect(s.body.identity).toMatchObject({ status: "suspended", statusReason: "investigating" });
    const denied = await request(t.app).get("/agent/v1/me").set(bearer(token));
    expect(denied.status).toBe(401);
    expect((await request(t.app).post("/agent/v1/token").set(bearer(secret))).status).toBe(401);

    await request(t.app).post(`/agents/${agent.id}/resume`).set(as("alice")).send({});
    expect((await request(t.app).get("/agent/v1/me").set(bearer(token))).status).toBe(401); // old token stays dead
    const fresh = await request(t.app).post("/agent/v1/token").set(bearer(secret));
    expect((await request(t.app).get("/agent/v1/me").set(bearer(fresh.body.access_token))).status).toBe(200);
  });

  it("the owner can suspend their own agent but not resume it", async () => {
    const { agent } = await agentWithToken(t, "alice", { ownerUserId: "anna" });
    expect((await request(t.app).post(`/agents/${agent.id}/suspend`).set(as("anna")).send({})).status).toBe(200);
    expect((await request(t.app).post(`/agents/${agent.id}/resume`).set(as("anna")).send({})).status).toBe(403);
  });

  it("a non-owner analyst cannot suspend someone else's agent", async () => {
    const { agent } = await agentWithToken(t, "alice");
    expect((await request(t.app).post(`/agents/${agent.id}/suspend`).set(as("anna")).send({})).status).toBe(403);
  });

  it("revocation is final and kills credentials", async () => {
    const { agent, secret } = await agentWithToken(t, "alice");
    expect((await request(t.app).post(`/agents/${agent.id}/revoke`).set(as("alice")).send({})).status).toBe(200);
    expect((await request(t.app).post(`/agents/${agent.id}/resume`).set(as("alice")).send({})).status).toBe(409);
    expect((await request(t.app).patch(`/agents/${agent.id}`).set(as("alice")).send({ name: "y" })).status).toBe(409);
    expect((await request(t.app).post(`/agents/${agent.id}/credentials`).set(as("alice")).send({})).status).toBe(409);
    const tok = await request(t.app).post("/agent/v1/token").set(bearer(secret));
    expect(tok.status).toBe(401);
    expect(tok.body.error.code).toBe("credential_revoked");
  });

  it("update recalculates risk, re-checks the owner, and audits a diff", async () => {
    const { agent } = await agentWithToken(t, "alice", { ownerUserId: "vic" });
    const bad = await request(t.app).patch(`/agents/${agent.id}`).set(as("alice")).send({ permissions: ["assets:update"] });
    expect(bad.body.error.code).toBe("exceeds_owner_role");
    const ok = await request(t.app).patch(`/agents/${agent.id}`).set(as("alice"))
      .send({ ownerUserId: "anna", permissions: ["assets:update"] });
    expect(ok.body.identity).toMatchObject({ ownerUserId: "anna", riskLevel: "high", permissions: ["assets:update"] });
    const [row] = await auditRows(t.pool, "action = 'identity.updated'");
    expect(row.details.changes.permissions).toEqual({ from: ["alerts:read"], to: ["assets:update"] });
    expect(row.details.changes.riskLevel).toEqual({ from: "low", to: "high" });
  });

  it("an administrator can place an agent on risk hold by marking it critical", async () => {
    const { agent, secret, token } = await agentWithToken(t, "alice");
    await request(t.app).patch(`/agents/${agent.id}`).set(as("alice")).send({ riskLevel: "critical" });
    expect((await request(t.app).get("/agent/v1/me").set(bearer(token))).body.error.code).toBe("risk_hold");
    expect((await request(t.app).post("/agent/v1/token").set(bearer(secret))).body.error.code).toBe("risk_hold");
  });

  it("an expired identity cannot authenticate", async () => {
    const { agent, secret } = await agentWithToken(t, "alice");
    await t.pool.query("UPDATE machine_identities SET expires_at = now() - interval '1 second' WHERE id = $1", [agent.id]);
    expect((await request(t.app).post("/agent/v1/token").set(bearer(secret))).body.error.code).toBe("identity_expired");
  });
});

describe("credentials", () => {
  it("rotate without downtime: a second credential, then revoke the first", async () => {
    const { agent, secret, credentialId } = await agentWithToken(t, "alice");
    const second = await request(t.app).post(`/agents/${agent.id}/credentials`).set(as("alice")).send({});
    expect(second.status).toBe(201);
    expect((await request(t.app).post(`/agents/${agent.id}/credentials`).set(as("alice")).send({})).body.error.code)
      .toBe("too_many_credentials");

    expect((await request(t.app).post("/agent/v1/token").set(bearer(second.body.credential.secret))).status).toBe(200);
    expect((await request(t.app).delete(`/agents/${agent.id}/credentials/${credentialId}`).set(as("alice"))).status).toBe(204);
    expect((await request(t.app).post("/agent/v1/token").set(bearer(secret))).status).toBe(401);
    expect((await request(t.app).post("/agent/v1/token").set(bearer(second.body.credential.secret))).status).toBe(200);
  });

  it("revoking a credential also kills the tokens it issued", async () => {
    const { agent, token, credentialId } = await agentWithToken(t, "alice");
    await request(t.app).delete(`/agents/${agent.id}/credentials/${credentialId}`).set(as("alice"));
    expect((await request(t.app).get("/agent/v1/me").set(bearer(token))).status).toBe(401);
  });

  it("an expired credential is refused", async () => {
    const { secret, credentialId } = await agentWithToken(t, "alice");
    await t.pool.query("UPDATE machine_credentials SET expires_at = now() - interval '1 second' WHERE id = $1", [credentialId]);
    expect((await request(t.app).post("/agent/v1/token").set(bearer(secret))).body.error.code).toBe("credential_expired");
  });
});

describe("tenant isolation", () => {
  it("another tenant's administrator cannot see or touch an agent", async () => {
    const { agent } = await agentWithToken(t, "alice");
    for (const [method, path, body] of [
      ["get", `/agents/${agent.id}`, {}],
      ["patch", `/agents/${agent.id}`, { name: "hijack" }],
      ["post", `/agents/${agent.id}/suspend`, {}],
      ["post", `/agents/${agent.id}/revoke`, {}],
      ["post", `/agents/${agent.id}/credentials`, {}],
      ["get", `/agents/${agent.id}/activity`, {}],
    ] as const) {
      const res = await request(t.app)[method](path).set(as("bob")).send(body);
      expect(res.status, `${method} ${path}`).toBe(404);
    }
    expect((await request(t.app).get("/agents").set(as("bob"))).body.identities).toHaveLength(0);
    const still = await request(t.app).get(`/agents/${agent.id}`).set(as("alice"));
    expect(still.body.identity.status).toBe("active");
  });

  it("an agent's token carries its tenant and nothing else", async () => {
    const { token } = await agentWithToken(t, "alice");
    const res = await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    expect(res.body.calledBy.tenantId).toBe(TENANT_A);
  });

  it("activity is scoped to the tenant", async () => {
    await agentWithToken(t, "alice");
    const res = await request(t.app).get("/audit/principal-events").set(as("bob"));
    expect(res.body.events.every((e: { tenantId: string }) => e.tenantId === TENANT_B)).toBe(true);
  });
});
