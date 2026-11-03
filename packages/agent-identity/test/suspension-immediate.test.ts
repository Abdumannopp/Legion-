/**
 * Requirement 3: when an agent is suspended, its old permissions stop working
 * immediately.
 *
 * Written independently of the module's own kill-switch tests, attacking the
 * places a suspension typically leaks: a token already in hand, a fresh token
 * requested at the same moment, an approval ticket issued just before, a
 * request that was authenticated before the switch, another server instance,
 * and the old token after the agent is later resumed.
 */
import request from "supertest";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import type { MachinePrincipal } from "../src/index.js";
import { agentWithToken, as, bearer, makeApp, resetDb, TENANT_A, type TestApp, withoutApprovals } from "./helpers.js";

let t: TestApp;

beforeEach(async () => {
  if (t) await t.pool.end();
  t = await makeApp();
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  await request(t.app).put("/firewall/policy").set(as("alice"))
    .send(withoutApprovals({ toolSecurity: { slack: { channels: { C0SECOPS1: "write" } } } })).expect(200);
});
afterAll(async () => { await t?.pool.end(); });

const suspend = (id: string, path = "agents") =>
  request(t.app).post(`/${path}/${id}/suspend`).set(as("alice")).send({ reason: "suspected compromise" }).expect(200);
const readAlerts = (token: string) => request(t.app).get("/agent/v1/alerts").set(bearer(token));
const SLACK = { kind: "slack", operation: "post_message", channel: "C0SECOPS1", text: "hello" };

describe("the token already in the agent's hands", () => {
  it("stops on the very next request", async () => {
    const a = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
    await readAlerts(a.token).expect(200);
    await suspend(a.agent.id);
    const res = await readAlerts(a.token);
    expect(res.status).toBe(401);
  });

  it("cannot be swapped for a new one with the long-lived credential", async () => {
    const a = await agentWithToken(t, "alice");
    await suspend(a.agent.id);
    const res = await request(t.app).post("/agent/v1/token").set(bearer(a.secret));
    expect(res.status).toBeGreaterThanOrEqual(401);
    expect(res.body.access_token).toBeUndefined();
  });

  it("stays dead after the agent is resumed — resuming does not bring old tokens back", async () => {
    const a = await agentWithToken(t, "alice");
    await suspend(a.agent.id);
    await request(t.app).post(`/agents/${a.agent.id}/resume`).set(as("alice")).send({ reason: "cleared" }).expect(200);
    await readAlerts(a.token).expect(401);
    // A new token is required, and works.
    const fresh = await request(t.app).post("/agent/v1/token").set(bearer(a.secret)).expect(200);
    await readAlerts(fresh.body.access_token).expect(200);
  });
});

describe("the race at the moment of suspension", () => {
  it("a token requested at the same instant is useless afterwards", async () => {
    const a = await agentWithToken(t, "alice");
    const [minted] = await Promise.all([
      request(t.app).post("/agent/v1/token").set(bearer(a.secret)),
      suspend(a.agent.id),
    ]);
    // Whichever way the race went, nothing the agent holds may work now.
    for (const token of [a.token, minted.body.access_token].filter(Boolean)) {
      await readAlerts(token as string).expect(401);
    }
  });
});

describe("approvals granted just before the switch", () => {
  it("a tool-call ticket issued before suspension is no longer honoured", async () => {
    const a = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    const auth = await request(t.app).post("/agent/v1/tools/authorize").set(bearer(a.token)).send({ call: SLACK }).expect(200);
    const ticket = auth.body.ticket as string;
    expect(ticket).toMatch(/^ltk_/);

    await suspend(a.agent.id);

    // The tool server (a service account) checks the ticket before acting.
    const created = await request(t.app).post("/service-accounts").set(as("alice"))
      .send({ name: "slack-bridge", permissions: ["alerts:read"] }).expect(201);
    const tok = await request(t.app).post("/agent/v1/token").set(bearer(created.body.credential.secret)).expect(200);
    const verify = await request(t.app).post("/agent/v1/tools/verify").set(bearer(tok.body.access_token)).send({ ticket, call: SLACK });
    expect(verify.status).toBe(403);
    expect(verify.body.valid).toBe(false);
  });
});

describe("a request that was already past the door", () => {
  it("is still stopped when it reaches the firewall", async () => {
    // Simulates an in-flight request (or another server instance) holding a
    // principal that was resolved before the suspension.
    const a = await agentWithToken(t, "alice", { permissions: ["alerts:read", "tool.slack:write"] });
    const principal = (await request(t.app).get("/agent/v1/whoami").set(bearer(a.token))).body.principal as MachinePrincipal;
    await suspend(a.agent.id);
    const auth = await t.identity.tools.authorize({ principal }, SLACK);
    expect(auth.decision.decision).toBe("BLOCK");
    expect(auth.ticket).toBeNull();
  });

  it("on a second server instance sharing the database", async () => {
    const other = await makeApp({ pool: t.pool });
    const a = await agentWithToken(t, "alice");
    await readAlerts(a.token).expect(200);
    await suspend(a.agent.id); // on instance one
    await request(other.app).get("/agent/v1/alerts").set(bearer(a.token)).expect(401); // instance two
  });
});

describe("service accounts", () => {
  it("are cut off the same way", async () => {
    const created = await request(t.app).post("/service-accounts").set(as("alice"))
      .send({ name: "ingest-bot", permissions: ["alerts:read"] }).expect(201);
    const tok = await request(t.app).post("/agent/v1/token").set(bearer(created.body.credential.secret)).expect(200);
    await readAlerts(tok.body.access_token).expect(200);
    await suspend(created.body.identity.id, "service-accounts");
    await readAlerts(tok.body.access_token).expect(401);
  });
});

describe("the owner loses access", () => {
  it("an agent whose owner is deactivated stops at once, without anyone suspending it", async () => {
    const a = await agentWithToken(t, "alice");
    t.host.add("carol", TENANT_A, "admin");
    const owned = await agentWithToken(t, "carol");
    await readAlerts(owned.token).expect(200);
    t.host.users.get("carol")!.status = "disabled";
    await readAlerts(owned.token).expect(401);
    await readAlerts(a.token).expect(200); // other owners' agents unaffected
  });
});
