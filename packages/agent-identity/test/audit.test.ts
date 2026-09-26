import express from "express";
import pg from "pg";
import request from "supertest";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createAgentIdentity } from "../src/index.js";
import { migrate } from "../src/schema.js";
import { agentWithToken, as, auditRows, bearer, DATABASE_URL, FakeHost, makeApp, resetDb, TENANT_A, type TestApp } from "./helpers.js";

let t: TestApp;

beforeEach(async () => {
  if (t) await t.pool.end();
  t = await makeApp();
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  t.host.add("anna", TENANT_A, "analyst");
  t.host.add("vic", TENANT_A, "viewer");
});
afterAll(async () => { await t?.pool.end(); });

describe("every agent action is traceable to its identity", () => {
  it("an allowed action leaves an attempt and a result, naming agent, owner and credential", async () => {
    const { agent, credentialId, token } = await agentWithToken(t, "alice", { ownerUserId: "anna", permissions: ["alerts:update_status"] });
    const res = await request(t.app).post("/agent/v1/alerts/SEC-42/status").set(bearer(token)).send({ status: "closed" });
    expect(res.status).toBe(200);
    const rows = await vi.waitFor(async () => {
      const r = await auditRows(t.pool, "action = 'alerts:update_status'");
      expect(r.map((x) => x.outcome)).toEqual(["attempt", "success"]);
      return r;
    });
    for (const r of rows) {
      expect(r).toMatchObject({
        tenant_id: TENANT_A, principal_type: "ai_agent", principal_id: agent.id, principal_name: agent.name,
        on_behalf_of: "anna", credential_id: credentialId, resource_type: "alert", resource_id: "SEC-42",
      });
    }
    expect(rows[1].details).toMatchObject({ status: 200, decisionId: expect.stringMatching(/^[0-9a-f-]{36}$/) });
    // High-risk agent (20) + state-changing permission (20) + internal data (5) = 45 ≥ warnAt 40:
    // the action runs, but the firewall flags it.
    expect(res.headers["x-legion-firewall"]).toBe("warn");
  });

  it("a denied action is refused and recorded", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    const res = await request(t.app).post("/agent/v1/alerts/SEC-1/status").set(bearer(token)).send({});
    expect(res.status).toBe(403);
    const rows = await auditRows(t.pool, "action = 'alerts:update_status'");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ outcome: "denied", reason: "firewall: permission.not_granted", principal_id: agent.id });
    expect(res.body.error).toMatchObject({ code: "firewall_blocked", rules: ["permission.not_granted"] });
  });

  it("if the audit trail cannot be written, the action does not run", async () => {
    const logs: string[] = [];
    const pool = new pg.Pool({ connectionString: DATABASE_URL });
    const host = new FakeHost();
    host.add("alice", TENANT_A, "admin");
    const identity = createAgentIdentity({ pool, host, log: (m) => logs.push(m) });
    let ran = false;
    const app = express();
    app.use(express.json());
    app.use(identity.principal);
    app.use("/agent/v1", identity.agentApi);
    app.use("/agents", identity.agents);
    app.post("/agent/v1/act", identity.guards.requirePermission("alerts:read"), (_q, r) => { ran = true; r.json({}); });

    const created = await request(app).post("/agents").set(as("alice")).send({ name: "z", permissions: ["alerts:read"] });
    const tok = await request(app).post("/agent/v1/token").set(bearer(created.body.credential.secret));

    // Simulate the audit table becoming unwritable (disk full, permissions, …).
    await pool.query("ALTER TABLE principal_audit_log ADD CONSTRAINT audit_down CHECK (false) NOT VALID");
    try {
      const res = await request(app).post("/agent/v1/act").set(bearer(tok.body.access_token));
      expect(res.status).toBe(503);
      expect(res.body.error.code).toBe("audit_unavailable");
      expect(ran).toBe(false);
      expect(logs.some((l) => l.includes("audit unavailable"))).toBe(true);
    } finally {
      await pool.query("ALTER TABLE principal_audit_log DROP CONSTRAINT audit_down");
      await pool.end();
    }
  });

  it("humans using the same guarded route are recorded as humans", async () => {
    await request(t.app).get("/agent/v1/alerts").set(as("vic"));
    const [row] = await auditRows(t.pool, "action = 'alerts:read'");
    expect(row).toMatchObject({ principal_type: "human", principal_id: "vic", on_behalf_of: null });
  });

  it("anonymous callers cannot use guarded routes", async () => {
    expect((await request(t.app).get("/agent/v1/alerts")).status).toBe(401);
  });

  it("the activity endpoint shows what an agent did and what was done to it", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    await request(t.app).post(`/agents/${agent.id}/suspend`).set(as("alice")).send({ reason: "test" });
    const res = await request(t.app).get(`/agents/${agent.id}/activity`).set(as("anna"));
    const actions = res.body.events.map((e: { action: string }) => e.action);
    expect(actions).toEqual(expect.arrayContaining(["identity.created", "token.issued", "alerts:read", "identity.suspended"]));
    expect((await request(t.app).get(`/agents/${agent.id}/activity`).set(as("vic"))).status).toBe(403);
  });
});

describe("the owner's authority bounds the agent at every request", () => {
  it("demoting the owner shrinks the agent's effective permissions immediately", async () => {
    const { token } = await agentWithToken(t, "alice", { ownerUserId: "anna", permissions: ["alerts:read", "alerts:update_status"] });
    expect((await request(t.app).post("/agent/v1/alerts/A/status").set(bearer(token))).status).toBe(200);
    t.host.users.get("anna")!.role = "viewer";
    expect((await request(t.app).post("/agent/v1/alerts/A/status").set(bearer(token))).status).toBe(403);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(token))).status).toBe(200);
    const me = await request(t.app).get("/agent/v1/me").set(bearer(token));
    expect(me.body.grantedPermissions).toEqual(["alerts:read", "alerts:update_status"]);
    expect(me.body.effectivePermissions).toEqual(["alerts:read"]);
  });

  it("deactivating the owner stops the agent", async () => {
    const { token } = await agentWithToken(t, "alice", { ownerUserId: "anna" });
    t.host.users.get("anna")!.status = "disabled";
    const res = await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("owner_inactive");
  });
});

describe("last activity", () => {
  it("is set on use and written at most once a minute", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    const first = (await request(t.app).get(`/agents/${agent.id}`).set(as("alice"))).body.identity.lastActivityAt;
    expect(first).not.toBeNull();
    await t.pool.query("UPDATE machine_identities SET last_activity_at = now() - interval '5 minutes' WHERE id = $1", [agent.id]);
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    const second = (await request(t.app).get(`/agents/${agent.id}`).set(as("alice"))).body.identity.lastActivityAt;
    expect(new Date(second).getTime()).toBeGreaterThan(Date.now() - 10_000);
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    const third = (await request(t.app).get(`/agents/${agent.id}`).set(as("alice"))).body.identity.lastActivityAt;
    expect(third).toBe(second);
  });
});

describe("the audit log is tamper-evident", () => {
  it("verifies as intact after normal use", async () => {
    const { token } = await agentWithToken(t, "alice");
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    const res = await request(t.app).get("/audit/principal-events/verify").set(as("alice"));
    expect(res.body.ok).toBe(true);
    expect(res.body.rows).toBeGreaterThan(3);
  });

  it("refuses UPDATE, DELETE and TRUNCATE", async () => {
    await agentWithToken(t, "alice");
    await expect(t.pool.query("UPDATE principal_audit_log SET reason = 'x'")).rejects.toThrow(/append-only/);
    await expect(t.pool.query("DELETE FROM principal_audit_log")).rejects.toThrow(/append-only/);
    await expect(t.pool.query("TRUNCATE principal_audit_log")).rejects.toThrow(/append-only/);
  });

  it("detects a row edited behind the triggers' back", async () => {
    const { token } = await agentWithToken(t, "alice");
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    // Someone with superuser access disables the triggers and rewrites history.
    await t.pool.query("ALTER TABLE principal_audit_log DISABLE TRIGGER principal_audit_log_no_update");
    const target = (await auditRows(t.pool, "action = 'alerts:read'"))[0];
    await t.pool.query("UPDATE principal_audit_log SET principal_id = 'someone-else' WHERE seq = $1", [target.seq]);
    await t.pool.query("ALTER TABLE principal_audit_log ENABLE TRIGGER principal_audit_log_no_update");
    const res = await request(t.app).get("/audit/principal-events/verify").set(as("alice"));
    expect(res.body).toMatchObject({ ok: false, brokenAtSeq: String(target.seq) });
  });

  it("detects a deleted row", async () => {
    const { token } = await agentWithToken(t, "alice");
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    await t.pool.query("ALTER TABLE principal_audit_log DISABLE TRIGGER principal_audit_log_no_update");
    await t.pool.query("DELETE FROM principal_audit_log WHERE action = 'token.issued'");
    await t.pool.query("ALTER TABLE principal_audit_log ENABLE TRIGGER principal_audit_log_no_update");
    expect((await request(t.app).get("/audit/principal-events/verify").set(as("alice"))).body.ok).toBe(false);
  });

  it("stays linear under concurrent writes", async () => {
    const { token } = await agentWithToken(t, "alice");
    await Promise.all(Array.from({ length: 40 }, () => request(t.app).get("/agent/v1/alerts").set(bearer(token))));
    // Every attempt row is committed before its action runs…
    expect(await auditRows(t.pool, "action = 'alerts:read' AND outcome = 'attempt'")).toHaveLength(40);
    // …result rows follow the response asynchronously.
    await vi.waitFor(async () => {
      expect(await auditRows(t.pool, "action = 'alerts:read' AND outcome = 'success'")).toHaveLength(40);
    }, { timeout: 10_000 });
    expect((await t.identity.audit.verifyChain(TENANT_A)).ok).toBe(true);
  });

  it("filters by principal type", async () => {
    const { token } = await agentWithToken(t, "alice");
    await request(t.app).get("/agent/v1/alerts").set(bearer(token));
    const res = await request(t.app).get("/audit/principal-events?principalType=ai_agent").set(as("alice"));
    expect(res.body.events.length).toBeGreaterThan(0);
    expect(res.body.events.every((e: { principalType: string }) => e.principalType === "ai_agent")).toBe(true);
  });
});

describe("migration", () => {
  it("is idempotent and safe when several instances start at once", async () => {
    await Promise.all([migrate(t.pool), migrate(t.pool), migrate(t.pool)]);
    await migrate(t.pool);
    const r = await t.pool.query("SELECT count(*)::int AS n FROM information_schema.tables WHERE table_name LIKE 'machine_%' OR table_name = 'principal_audit_log'");
    expect(r.rows[0].n).toBe(4);
  });

  it("keeps existing data when re-run", async () => {
    const { agent } = await agentWithToken(t, "alice");
    await migrate(t.pool);
    expect((await request(t.app).get(`/agents/${agent.id}`).set(as("alice"))).status).toBe(200);
  });
});
