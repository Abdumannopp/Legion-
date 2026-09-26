import request from "supertest";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { agentWithToken, as, auditRows, bearer, makeApp, resetDb, TENANT_A, type TestApp } from "./helpers.js";

let t: TestApp;

beforeEach(async () => {
  if (t) await t.pool.end();
  t = await makeApp();
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  t.host.add("anna", TENANT_A, "analyst");
});
afterAll(async () => { await t?.pool.end(); });

describe("every request is exactly one of four principal types", () => {
  it("human: a signed-in person", async () => {
    const res = await request(t.app).get("/whoami").set(as("alice"));
    expect(res.body.principal).toMatchObject({ type: "human", id: "alice", tenantId: TENANT_A, role: "admin" });
  });

  it("ai_agent: a registered agent with an access token", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    const res = await request(t.app).get("/whoami").set(bearer(token));
    expect(res.body.principal).toMatchObject({ type: "ai_agent", id: agent.id, tenantId: TENANT_A, ownerUserId: "alice" });
  });

  it("service_account: a registered non-AI machine", async () => {
    const sa = await request(t.app).post("/service-accounts").set(as("alice")).send({ name: "s" });
    const tok = await request(t.app).post("/agent/v1/token").set(bearer(sa.body.credential.secret));
    const res = await request(t.app).get("/whoami").set(bearer(tok.body.access_token));
    expect(res.body.principal.type).toBe("service_account");
  });

  it("external_system: anonymous callers and named integrations", async () => {
    expect((await request(t.app).get("/whoami")).body.principal).toMatchObject({ type: "external_system", id: "anonymous" });
    await request(t.app).post("/webhooks/wazuh").send({});
    const [row] = await auditRows(t.pool, "action = 'alert.ingest' AND outcome = 'attempt'");
    expect(row).toMatchObject({ principal_type: "external_system", principal_id: "wazuh-webhook" });
  });

  it("every response carries a request id that the audit trail also records", async () => {
    const { token } = await agentWithToken(t, "alice");
    const res = await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    const id = res.headers["x-request-id"];
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    await vi.waitFor(async () => {
      const rows = await auditRows(t.pool, "request_id = $1", [id]);
      expect(rows.map((r) => r.outcome)).toEqual(["attempt", "success"]);
    });
  });
});

describe("existing human authentication is unchanged", () => {
  it("signed-in and anonymous human routes behave exactly as before", async () => {
    expect((await request(t.app).get("/me").set(as("alice"))).body).toEqual({ user: "alice" });
    expect((await request(t.app).get("/me")).status).toBe(401);
    expect((await request(t.app).post("/auth/login").send({ email: "a@b.c" })).status).toBe(200);
    expect((await request(t.app).get("/health")).body).toEqual({ status: "ok" });
  });

  it("an ordinary browser is never mistaken for an agent", async () => {
    const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
    expect((await request(t.app).post("/auth/login").set("user-agent", ua).send({})).status).toBe(200);
  });

  it("a person's session does not work on the agent API", async () => {
    const res = await request(t.app).get("/agent/v1/me").set(as("alice"));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("machine_identity_required");
  });

  it("the health check never touches identity resolution", async () => {
    const before = t.host.calls;
    await request(t.app).get("/health").set("user-agent", "GPTBot/1.2");
    expect(t.host.calls).toBe(before);
  });
});

describe("an AI agent is never served as an anonymous client", () => {
  it.each([
    ["GPTBot user agent", { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)" }],
    ["ClaudeBot user agent", { "user-agent": "ClaudeBot/1.0" }],
    ["Claude-User user agent", { "user-agent": "Claude-User/1.0" }],
    ["x-legion-agent header", { "x-legion-agent": "my-agent" }],
    ["Signature-Agent header", { "signature-agent": '"https://agent.example"' }],
  ])("%s without an identity is refused and audited", async (_label, headers) => {
    const res = await request(t.app).post("/auth/login").set(headers).send({});
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("agent_identity_required");
    expect(t.seen).toHaveLength(0); // the route never ran
    const rows = await auditRows(t.pool, "action = 'auth.agent_identity_required'");
    expect(rows).toHaveLength(1);
    expect(rows[0].principal_type).toBe("external_system");
  });

  it("the same self-declared agent WITH a Legion identity is served, as itself", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    const res = await request(t.app).get("/whoami").set(bearer(token)).set("user-agent", "ClaudeBot/1.0");
    expect(res.status).toBe(200);
    expect(res.body.principal).toMatchObject({ type: "ai_agent", id: agent.id });
  });

  it("an agent cannot hide behind a human session (both at once is refused)", async () => {
    const { token } = await agentWithToken(t, "alice");
    const res = await request(t.app).get("/whoami").set(as("anna")).set(bearer(token));
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("ambiguous_principal");
    const [row] = await auditRows(t.pool, "action = 'principal.ambiguous'");
    expect(row).toMatchObject({ principal_type: "human", principal_id: "anna", outcome: "denied" });
  });

  it("long-lived credentials are accepted only by the token endpoint", async () => {
    const { secret } = await agentWithToken(t, "alice");
    const res = await request(t.app).get("/agent/v1/alerts").set(bearer(secret));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("credential_not_accepted");
  });

  it("agents cannot manage identities — not even their own", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    for (const [method, path] of [
      ["get", "/agents"],
      ["post", "/agents"],
      ["patch", `/agents/${agent.id}`],
      ["post", `/agents/${agent.id}/credentials`],
      ["post", `/agents/${agent.id}/resume`],
      ["get", "/audit/principal-events"],
    ] as const) {
      const res = await request(t.app)[method](path).set(bearer(token)).send({ name: "x", permissions: ["assets:update"] });
      expect(res.status, `${method} ${path}`).toBe(403);
    }
    const rows = await auditRows(t.pool, "action = 'identity.manage' AND outcome = 'denied'");
    expect(rows.length).toBe(6);
    expect(rows.every((r) => r.principal_type === "ai_agent" && r.principal_id === agent.id)).toBe(true);
  });
});

describe("token authentication failures", () => {
  it("unknown and malformed tokens get a generic answer", async () => {
    for (const tok of ["lgt_" + "A".repeat(43), "lgt_short", "lga_nothex_x"]) {
      const res = await request(t.app).get("/agent/v1/me").set(bearer(tok));
      expect(res.status, tok).toBe(401);
      expect(["invalid_token", "credential_not_accepted"]).toContain(res.body.error.code);
    }
  });

  it("an expired token is refused and the attempt is attributed to its agent", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    await t.pool.query("UPDATE machine_tokens SET expires_at = now() - interval '1 second'");
    const res = await request(t.app).get("/agent/v1/me").set(bearer(token));
    expect(res.body.error.code).toBe("token_expired");
    const [row] = await auditRows(t.pool, "action = 'auth.token'");
    expect(row).toMatchObject({ principal_type: "ai_agent", principal_id: agent.id, reason: "token_expired" });
  });

  it("a wrong secret for a real credential is recorded against that agent", async () => {
    const { agent, secret } = await agentWithToken(t, "alice");
    const forged = secret.slice(0, -43) + "B".repeat(43);
    const res = await request(t.app).post("/agent/v1/token").set(bearer(forged));
    expect(res.status).toBe(401);
    // Same answer as a credential that does not exist: no confirmation for a guesser…
    expect(res.body.error.code).toBe("invalid_credential");
    // …but the tenant's audit trail knows exactly which agent was targeted.
    const [row] = await auditRows(t.pool, "action = 'auth.credential'");
    expect(row).toMatchObject({ principal_type: "ai_agent", principal_id: agent.id, reason: "bad_secret", tenant_id: TENANT_A });
  });

  it("an agent credential relabelled as a service-account credential is refused", async () => {
    const { secret } = await agentWithToken(t, "alice");
    const res = await request(t.app).post("/agent/v1/token").set(bearer(secret.replace(/^lga_/, "lgs_")));
    expect(res.body.error.code).toBe("credential_kind_mismatch");
  });

  it("an agent can end its own session", async () => {
    const { token } = await agentWithToken(t, "alice");
    expect((await request(t.app).post("/agent/v1/token/revoke").set(bearer(token))).status).toBe(204);
    expect((await request(t.app).get("/agent/v1/me").set(bearer(token))).body.error.code).toBe("token_revoked");
  });

  it("high-risk agents get shorter-lived tokens", async () => {
    const low = await request(t.app).post("/agents").set(as("alice")).send({ name: "l", permissions: ["alerts:read"] });
    const high = await request(t.app).post("/agents").set(as("alice")).send({ name: "h", permissions: ["alerts:update_status"] });
    const a = await request(t.app).post("/agent/v1/token").set(bearer(low.body.credential.secret));
    const b = await request(t.app).post("/agent/v1/token").set(bearer(high.body.credential.secret));
    expect(a.body.expires_in).toBe(900);
    expect(b.body.expires_in).toBe(300);
    expect(a.headers["cache-control"]).toBe("no-store");
  });

  it("a flood of garbage tokens from one address writes a bounded number of audit rows", async () => {
    await Promise.all(Array.from({ length: 60 }, () =>
      request(t.app).get("/agent/v1/me").set(bearer("lgt_" + "Z".repeat(43)))));
    const rows = await auditRows(t.pool, "action = 'auth.token'");
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length).toBeLessThanOrEqual(20);
  });
});
