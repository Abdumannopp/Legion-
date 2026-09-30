import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import pg from "pg";
import request from "supertest";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FirewallBlockedError, ToolAbortedError, ToolBlockedError, type AdminNotice, type AgentIdentityOptions, type MachinePrincipal } from "../src/index.js";
import { agentWithToken, as, auditRows, bearer, DATABASE_URL, makeApp, resetDb, TENANT_A, TENANT_B, type TestApp, withoutApprovals } from "./helpers.js";

let t: TestApp;
let dir: string;
let notices: AdminNotice[];
let logs: string[];
const others: TestApp[] = [];

async function start(extra: Partial<AgentIdentityOptions> = {}) {
  if (t) await t.pool.end();
  notices = [];
  logs = [];
  t = await makeApp({ logs, extra: { notifyAdmins: (n) => { notices.push(n); }, ...extra } });
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  t.host.add("anna", TENANT_A, "analyst");
  t.host.add("vic", TENANT_A, "viewer");
  t.host.add("bob", TENANT_B, "admin");
  await setPolicy({
    files: { roots: [{ path: dir, access: "readwrite" }] },
    toolSecurity: {
      shell: { commands: { sleep: { maxArgs: 1 }, echo: { maxArgs: 5 } } },
      slack: { channels: { C0SECOPS1: "write" } },
    },
  });
}

beforeEach(async () => {
  dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "legion-kill-")));
  await start();
});
afterEach(async () => {
  for (const o of others.splice(0)) await o.pool.end();
  await fs.rm(dir, { recursive: true, force: true });
});
afterAll(async () => { await t?.pool.end(); });

async function setPolicy(policy: Record<string, unknown>) {
  const res = await request(t.app).put("/firewall/policy").set(as("alice")).send(withoutApprovals(policy));
  if (res.status !== 200) throw new Error(JSON.stringify(res.body));
}
const kill = (id: string, body: Record<string, unknown> = { reason: "Exfiltration to an unknown host seen in egress logs", compromise: "suspected" }, user = "alice") =>
  request(t.app).post(`/kill-switch/agents/${id}`).set(as(user)).send(body);
const principalOf = async (token: string) =>
  (await request(t.app).get("/agent/v1/whoami").set(bearer(token))).body.principal as MachinePrincipal;
const SLACK_POST = { kind: "slack", operation: "post_message", channel: "C0SECOPS1", text: "Scan finished" };
const SLEEP = { kind: "shell", operation: "execute", command: "sleep", args: ["30"] };
const PERMS = ["alerts:read", "alerts:comment", "tool.slack:write", "tool.shell:execute", "tool.http:read"];

async function serviceAccount(name = "slack-proxy") {
  const sa = await request(t.app).post("/service-accounts").set(as("alice")).send({ name });
  const token = (await request(t.app).post("/agent/v1/token").set(bearer(sa.body.credential.secret))).body.access_token as string;
  return { id: sa.body.identity.id as string, token };
}
const verify = (saToken: string, ticket: string, call: unknown) =>
  request(t.app).post("/agent/v1/tools/verify").set(bearer(saToken)).send({ ticket, call });

/** Everything an agent could still hold at the moment it is stopped. */
async function armedAgent() {
  const a = await agentWithToken(t, "alice", { permissions: PERMS });
  const peer = await agentWithToken(t, "alice", { permissions: ["alerts:read"] });
  await setPolicy({
    toolSecurity: { shell: { commands: { sleep: { maxArgs: 1 }, echo: { maxArgs: 5 } } }, slack: { channels: { C0SECOPS1: "write" } } },
    agentMessages: { allow: [{ from: a.agent.id, to: peer.agent.id }] },
  });
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  const grant = await request(t.app).post("/firewall/delegations").set(as("anna")).send({ agentId: a.agent.id, permissions: ["alerts:read"], expiresAt });
  expect(grant.status).toBe(201);
  const auth = await request(t.app).post("/agent/v1/tools/authorize").set(bearer(a.token)).send({ call: SLACK_POST });
  expect(auth.body.ticket).toMatch(/^ltk_/);
  const msg = await request(t.app).post("/agent/v1/messages").set(bearer(a.token)).send({ toAgentId: peer.agent.id, requestedPermission: "alerts:read" });
  expect(msg.status).toBe(201);
  const principal = await principalOf(a.token);
  return { ...a, peer, ticket: auth.body.ticket as string, messageId: msg.body.messageId as string, principal };
}

/** Every way the stopped agent could try to act. None may succeed. */
async function expectNoPathLeft(a: Awaited<ReturnType<typeof armedAgent>>, sa: { token: string }) {
  // Its access token, on every agent route (guarded, traced, tools, messages, delegation).
  for (const [method, url] of [["get", "/agent/v1/alerts"], ["get", "/agent/v1/whoami"], ["get", "/agent/v1/me"],
    ["post", "/agent/v1/alerts/x1/status"], ["post", "/agent/v1/tools/authorize"], ["post", "/agent/v1/messages"],
    ["get", "/agent/v1/messages"], ["post", "/agent/v1/content/inspect"]] as const) {
    const res = await request(t.app)[method](url).set(bearer(a.token)).send({});
    expect(res.status, `${method} ${url}`).toBe(401);
  }
  expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.token)).set("x-legion-on-behalf-of", "anna")).status).toBe(401);
  // Outside the agent API too (people's routes, unguarded paths).
  for (const url of ["/agents", "/whoami", "/firewall/policy", "/kill-switch/events"]) {
    expect((await request(t.app).get(url).set(bearer(a.token))).status, url).toBe(401);
  }
  // Its credential cannot mint a new token.
  expect((await request(t.app).post("/agent/v1/token").set(bearer(a.secret))).status).toBe(401);
  // A tool ticket issued before the stop is refused by the tool server.
  expect((await verify(sa.token, a.ticket, SLACK_POST)).body).toEqual({ valid: false, reason: "agent_suspended" });
  // Its pending request to another agent is withdrawn: gone from the inbox, and unusable.
  const inbox = await request(t.app).get("/agent/v1/messages").set(bearer(a.peer.token));
  expect(inbox.body.messages.map((m: { id: string }) => m.id)).not.toContain(a.messageId);
  const relay = await request(t.app).get("/agent/v1/alerts").set(bearer(a.peer.token)).set("x-legion-message-id", a.messageId);
  expect(relay.status).toBe(403);
  // Library code still holding the principal resolved before the stop.
  const ctx = { principal: a.principal };
  const d = await t.identity.firewall.evaluate(ctx, { surface: "api", action: "alerts:read", permission: "alerts:read" });
  expect(d.decision).toBe("BLOCK");
  expect(d.hits.map((h) => h.id)).toContain("identity.not_active");
  await expect(t.identity.tools.runShell(ctx, { kind: "shell", operation: "execute", command: "echo", args: ["hi"] })).rejects.toBeInstanceOf(ToolBlockedError);
  await expect(t.identity.firewall.request(ctx, { url: "https://example.com/" })).rejects.toBeInstanceOf(FirewallBlockedError);
  await expect(t.identity.firewall.readFile(ctx, path.join(dir, "x.txt"), { permission: null })).rejects.toBeInstanceOf(FirewallBlockedError);
}

describe("who can pull the switch", () => {
  it("administrators only, with a reason and a compromise level", async () => {
    const { agent } = await agentWithToken(t, "alice");
    expect((await kill(agent.id, undefined, "anna")).status).toBe(403);
    expect((await kill(agent.id, undefined, "vic")).status).toBe(403);
    expect((await request(t.app).post(`/kill-switch/agents/${agent.id}`).send({ reason: "x".repeat(20), compromise: "suspected" })).status).toBe(401);
    expect((await kill(agent.id, { compromise: "suspected" })).status).toBe(400);
    expect((await kill(agent.id, { reason: "bad", compromise: "suspected" })).body.error.message).toMatch(/at least 10/);
    expect((await kill(agent.id, { reason: "Seen exfiltrating data", compromise: "maybe" })).status).toBe(400);
    expect((await kill(agent.id, { reason: "Seen exfiltrating data", compromise: "suspected", extra: 1 })).status).toBe(400);
    expect((await kill("00000000-0000-4000-8000-000000000000")).status).toBe(404);
    expect((await request(t.app).get(`/agents/${agent.id}`).set(as("alice"))).body.identity.status).toBe("active");
  });

  it("another organisation's administrator cannot stop (or even see) the agent", async () => {
    const { agent, token } = await agentWithToken(t, "alice");
    expect((await kill(agent.id, undefined, "bob")).status).toBe(404);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(token))).status).toBe(200);
  });

  it("no agent can use the switch, undo it, or resume itself", async () => {
    const victim = await agentWithToken(t, "alice");
    const other = await agentWithToken(t, "alice");
    expect((await request(t.app).post(`/kill-switch/agents/${victim.agent.id}`).set(bearer(other.token))
      .send({ reason: "an agent trying to kill another", compromise: "confirmed" })).status).toBe(403);
    expect((await kill(victim.agent.id)).status).toBe(200);
    // The stopped agent and its peers are machine identities: people's routes are closed to them.
    expect((await request(t.app).post(`/agents/${victim.agent.id}/resume`).set(bearer(other.token)).send({})).status).toBe(403);
    expect((await request(t.app).post(`/agents/${victim.agent.id}/resume`).set(bearer(victim.token)).send({})).status).toBe(401);
    // Resuming is an administrator's decision.
    expect((await request(t.app).post(`/agents/${victim.agent.id}/resume`).set(as("anna")).send({})).status).toBe(403);
    expect((await request(t.app).get(`/agents/${victim.agent.id}`).set(as("alice"))).body.identity.status).toBe("suspended");
  });
});

describe("stopping an agent closes every path", () => {
  it("tokens, credentials, tool tickets, relayed requests, delegation, library callers", async () => {
    const a = await armedAgent();
    const sa = await serviceAccount();
    // Before: everything works.
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.token))).status).toBe(200);

    const res = await kill(a.agent.id);
    expect(res.status).toBe(200);
    expect(res.body.affected).toEqual([expect.objectContaining({
      identityId: a.agent.id, previousStatus: "active", status: "suspended",
      cutOff: { tokens: 1, toolTickets: 1, messages: 1, credentials: 0, delegations: 0 },
    })]);
    await expectNoPathLeft(a, sa);
    // The rejected ticket is in the tool audit, attributed to the stopped agent.
    const rejected = (await t.pool.query("SELECT * FROM tool_call_audit WHERE phase = 'ticket_rejected'")).rows;
    expect(rejected[0]).toMatchObject({ rule_ids: ["ticket.agent_suspended"], outcome_detail: `agent ${a.agent.id}` });
  });

  it("the peer that received the request keeps working on its own", async () => {
    const a = await armedAgent();
    await kill(a.agent.id);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.peer.token))).status).toBe(200);
  });

  it("the stop holds when the identity is changed underneath (e.g. a permission edit)", async () => {
    const a = await armedAgent();
    await kill(a.agent.id);
    const patch = await request(t.app).patch(`/agents/${a.agent.id}`).set(as("alice")).send({ permissions: ["alerts:read"] });
    expect(patch.status).toBe(200);
    expect(patch.body.identity.status).toBe("suspended");
    expect((await request(t.app).post("/agent/v1/token").set(bearer(a.secret))).status).toBe(401);
  });
});

describe("stopping dangerous tool execution", () => {
  it("a running command is killed at once, and the stop is audited", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: PERMS });
    const ctx = { principal: await principalOf(token) };
    const started = Date.now();
    const run = t.identity.tools.runShell(ctx, SLEEP, { timeoutMs: 60_000 });
    run.catch(() => {});
    await vi.waitFor(() => expect(t.identity.tools.runningExecutions()).toHaveLength(1));

    const res = await kill(agent.id);
    expect(res.body.executionsAborted).toBe(1);
    const err = await run.then(() => null, (e) => e);
    expect(err).toBeInstanceOf(ToolAbortedError);
    expect(Date.now() - started).toBeLessThan(5_000); // not the 30 s the command asked for
    expect(t.identity.tools.runningExecutions()).toHaveLength(0);
    const [outcome] = (await t.pool.query("SELECT * FROM tool_call_audit WHERE phase = 'outcome'")).rows;
    expect(outcome).toMatchObject({ principal_id: agent.id, tool_kind: "shell", outcome: "aborted" });
  });

  it("on another Legion instance too, within its status check interval", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: PERMS });
    const ctx = { principal: await principalOf(token) };
    const second = await makeApp({ pool: new pg.Pool({ connectionString: DATABASE_URL, max: 5 }), extra: { killSwitchPollMs: 100 } });
    others.push(second);
    const started = Date.now();
    const run = second.identity.tools.runShell(ctx, SLEEP, { timeoutMs: 60_000 });
    run.catch(() => {});
    await vi.waitFor(() => expect(second.identity.tools.runningExecutions()).toHaveLength(1));

    const res = await kill(agent.id); // on the first instance
    expect(res.body.executionsAborted).toBe(0); // nothing ran here
    expect(await run.then(() => null, (e) => e)).toBeInstanceOf(ToolAbortedError);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("an executor that ignores the stop is cut loose: its result never reaches the agent", async () => {
    const { agent, token } = await agentWithToken(t, "alice", { permissions: PERMS });
    const ctx = { principal: await principalOf(token) };
    let finished = false;
    const run = t.identity.tools.execute(ctx, SLACK_POST, () => new Promise<{ output: string }>((r) => setTimeout(() => { finished = true; r({ output: "posted" }); }, 1_500)));
    run.catch(() => {});
    await vi.waitFor(() => expect(t.identity.tools.runningExecutions()).toHaveLength(1));
    await kill(agent.id);
    expect(await run.then(() => null, (e) => e)).toBeInstanceOf(ToolAbortedError);
    expect(finished).toBe(false);
  });

  it("other agents' executions keep running", async () => {
    const bad = await agentWithToken(t, "alice", { permissions: PERMS });
    const good = await agentWithToken(t, "alice", { permissions: PERMS });
    const run = t.identity.tools.runShell({ principal: await principalOf(good.token) },
      { kind: "shell", operation: "execute", command: "sleep", args: ["1"] }, { timeoutMs: 10_000 });
    await vi.waitFor(() => expect(t.identity.tools.runningExecutions()).toHaveLength(1));
    expect((await kill(bad.agent.id)).body.executionsAborted).toBe(0);
    expect((await run).data).toMatchObject({ exitCode: 0 });
  });
});

describe("suspected vs confirmed compromise", () => {
  it("suspected: short-lived access is withdrawn, the credential survives, so it can be resumed", async () => {
    const a = await armedAgent();
    await kill(a.agent.id);
    await request(t.app).post(`/agents/${a.agent.id}/resume`).set(as("alice")).send({ reason: "false alarm, reviewed" });
    const fresh = await request(t.app).post("/agent/v1/token").set(bearer(a.secret));
    expect(fresh.status).toBe(200);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(fresh.body.access_token))).status).toBe(200);
    // Nothing withdrawn comes back to life.
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.token))).status).toBe(401);
    const sa = await serviceAccount();
    expect((await verify(sa.token, a.ticket, SLACK_POST)).body.reason).toBe("agent_suspended");
  });

  it("confirmed: credentials and people's delegations are revoked too — resume alone does not bring it back", async () => {
    const a = await armedAgent();
    const res = await kill(a.agent.id, { reason: "Confirmed: credential found in a public paste", compromise: "confirmed" });
    expect(res.body.affected[0].cutOff).toEqual({ tokens: 1, toolTickets: 1, messages: 1, credentials: 1, delegations: 1 });
    await request(t.app).post(`/agents/${a.agent.id}/resume`).set(as("alice")).send({});
    expect((await request(t.app).post("/agent/v1/token").set(bearer(a.secret))).status).toBe(401);
    const grants = await t.pool.query("SELECT revoked_at, revoked_by FROM agent_delegations WHERE identity_id = $1", [a.agent.id]);
    expect(grants.rows[0]).toMatchObject({ revoked_at: expect.any(Date), revoked_by: "alice" });
    // An administrator must issue a new credential deliberately.
    const cred = await request(t.app).post(`/agents/${a.agent.id}/credentials`).set(as("alice")).send({});
    expect((await request(t.app).post("/agent/v1/token").set(bearer(cred.body.credential.secret))).status).toBe(200);
  });

  it("escalating an already-suspended agent to confirmed revokes what is left", async () => {
    const a = await armedAgent();
    await kill(a.agent.id);
    const second = await kill(a.agent.id, { reason: "Now confirmed by incident response", compromise: "confirmed" });
    expect(second.body.affected[0]).toMatchObject({ previousStatus: "suspended", cutOff: { tokens: 0, toolTickets: 0, messages: 0, credentials: 1, delegations: 1 } });
  });

  it("repeating the switch is harmless: nothing new to withdraw, no duplicate event or notice", async () => {
    const { agent } = await agentWithToken(t, "alice");
    expect((await kill(agent.id)).body.affected).toHaveLength(1);
    const again = await kill(agent.id);
    expect(again.status).toBe(200);
    expect(again.body).toMatchObject({ affected: [], unchanged: [{ identityId: agent.id, status: "suspended" }], notification: null });
    expect(await t.identity.killSwitch.events(TENANT_A)).toHaveLength(1);
    expect(notices).toHaveLength(1);
  });

  it("a revoked identity is already final", async () => {
    const { agent } = await agentWithToken(t, "alice");
    await request(t.app).post(`/agents/${agent.id}/revoke`).set(as("alice")).send({});
    expect((await kill(agent.id)).body).toMatchObject({ affected: [], unchanged: [{ identityId: agent.id, status: "revoked" }] });
  });
});

describe("the record: reason, security event, audit", () => {
  it("records who, why, how sure, and what was cut off — in a tamper-evident chain", async () => {
    const a = await armedAgent();
    await kill(a.agent.id, { reason: "Confirmed: credential found in a public paste", compromise: "confirmed" });
    const [event] = (await request(t.app).get("/kill-switch/events").set(as("anna"))).body.events;
    expect(event).toMatchObject({
      kind: "agent_killed", severity: "critical", tenantId: TENANT_A, identityId: a.agent.id, identityKind: "ai_agent",
      identityName: a.agent.name, actorType: "human", actorId: "alice", compromise: "confirmed",
      reason: "Confirmed: credential found in a public paste",
      details: { previousStatus: "active", status: "suspended", cutOff: { tokens: 1, toolTickets: 1, messages: 1, credentials: 1, delegations: 1 } },
    });
    const id = (await request(t.app).get(`/agents/${a.agent.id}`).set(as("alice"))).body.identity;
    expect(id.statusReason).toBe("Confirmed: credential found in a public paste");
    const [audit] = await auditRows(t.pool, "action = 'killswitch.activated'");
    expect(audit).toMatchObject({ principal_id: "alice", resource_id: a.agent.id, reason: "Confirmed: credential found in a public paste", outcome: "success" });
    expect((await request(t.app).get("/kill-switch/events/verify").set(as("alice"))).body).toEqual({ ok: true, rows: 1 });
    // Append-only: history cannot be edited or erased.
    await expect(t.pool.query("UPDATE security_events SET reason = 'nothing happened'")).rejects.toThrow(/append-only/);
    await expect(t.pool.query("DELETE FROM security_events")).rejects.toThrow(/append-only/);
    // Staff can read events; only administrators verify.
    expect((await request(t.app).get("/kill-switch/events/verify").set(as("anna"))).status).toBe(403);
    expect((await request(t.app).get("/kill-switch/events").set(as("vic"))).status).toBe(403);
    expect((await request(t.app).get("/kill-switch/events").set(as("bob"))).body.events).toEqual([]);
  });

  it("the security-event hook fires once per stopped identity", async () => {
    const seen: unknown[] = [];
    await start({ onSecurityEvent: (e) => { seen.push(e); } });
    const { agent } = await agentWithToken(t, "alice");
    await kill(agent.id);
    await vi.waitFor(() => expect(seen).toEqual([expect.objectContaining({ kind: "agent_killed", identityId: agent.id, severity: "high" })]));
  });
});

describe("notifying administrators", () => {
  it("a notice is sent at once with what happened", async () => {
    const { agent } = await agentWithToken(t, "alice", { name: "triage-bot" });
    const res = await kill(agent.id);
    expect(res.body.notification).toMatchObject({ status: "sent" });
    expect(notices).toEqual([expect.objectContaining({
      tenantId: TENANT_A, severity: "high", subject: '[Legion] Suspended AI agent "triage-bot" — suspected compromise',
      events: [expect.objectContaining({ identityId: agent.id, reason: "Exfiltration to an unknown host seen in egress logs", actorId: "alice" })],
    })]);
    const list = (await request(t.app).get("/kill-switch/notifications").set(as("alice"))).body.notifications;
    expect(list[0]).toMatchObject({ status: "sent", attempts: 1, eventIds: [res.body.affected[0].eventId] });
  });

  it("a failed delivery does not undo or delay the stop, and is retried", async () => {
    let fail = true;
    await start({ notifyAdmins: (n) => { if (fail) throw new Error("smtp down"); notices.push(n); } });
    const a = await armedAgent();
    const res = await kill(a.agent.id);
    expect(res.status).toBe(200);
    expect(res.body.notification.status).toBe("failed");
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.token))).status).toBe(401); // stopped regardless
    const [n] = (await request(t.app).get("/kill-switch/notifications").set(as("alice"))).body.notifications;
    expect(n).toMatchObject({ status: "failed", lastError: "smtp down", attempts: 1 });
    // Not due yet: backoff.
    expect((await request(t.app).post("/kill-switch/notifications/retry").set(as("alice"))).body).toEqual({ sent: 0, failed: 0, undeliverable: 0 });
    fail = false;
    await t.pool.query("UPDATE security_notifications SET next_attempt_at = now()");
    expect((await request(t.app).post("/kill-switch/notifications/retry").set(as("alice"))).body).toEqual({ sent: 1, failed: 0, undeliverable: 0 });
    expect(notices).toHaveLength(1);
    expect((await request(t.app).get("/kill-switch/notifications").set(as("alice"))).body.notifications[0]).toMatchObject({ status: "sent", attempts: 2 });
  });

  it("without a notifier, the gap is logged loudly and visible in the API", async () => {
    await start({ notifyAdmins: undefined });
    const { agent } = await agentWithToken(t, "alice");
    const res = await kill(agent.id);
    expect(res.body.notification.status).toBe("undeliverable");
    expect(logs.some((l) => l.startsWith("ADMIN NOTICE NOT DELIVERED"))).toBe(true);
    expect(logs.some((l) => l.startsWith("KILL SWITCH (agent_killed, suspected)"))).toBe(true);
  });

  it("two instances retrying at once send each notice once", async () => {
    let calls = 0;
    await start({ notifyAdmins: async () => { calls++; if (calls === 1) throw new Error("first attempt fails"); await new Promise((r) => setTimeout(r, 50)); } });
    const second = await makeApp({ pool: new pg.Pool({ connectionString: DATABASE_URL, max: 5 }), extra: { notifyAdmins: async () => { calls++; } } });
    others.push(second);
    const { agent } = await agentWithToken(t, "alice");
    await kill(agent.id);
    await t.pool.query("UPDATE security_notifications SET next_attempt_at = now()");
    const [x, y] = await Promise.all([t.identity.killSwitch.deliverPending(), second.identity.killSwitch.deliverPending()]);
    expect(x.sent + y.sent).toBe(1);
    expect(calls).toBe(2); // the failed first attempt + exactly one retry
  });
});

describe("tenant-wide emergency stop", () => {
  it("stops every active AI agent in the organisation, and nothing else", async () => {
    const a1 = await agentWithToken(t, "alice");
    const a2 = await agentWithToken(t, "alice");
    const a3 = await agentWithToken(t, "alice");
    await request(t.app).post(`/agents/${a3.agent.id}/suspend`).set(as("alice")).send({});
    const sa = await serviceAccount();
    t.host.add("bob", TENANT_B, "admin");
    const other = await agentWithToken(t, "bob");

    expect((await request(t.app).post("/kill-switch/all").set(as("alice")).send({ reason: "Supply-chain compromise of the agent runtime", compromise: "suspected" })).status).toBe(400);
    expect((await request(t.app).post("/kill-switch/all").set(as("anna")).send({ reason: "Supply-chain compromise of the agent runtime", compromise: "suspected", confirmAll: true })).status).toBe(403);
    const res = await request(t.app).post("/kill-switch/all").set(as("alice"))
      .send({ reason: "Supply-chain compromise of the agent runtime", compromise: "suspected", confirmAll: true });
    expect(res.status).toBe(200);
    expect(res.body.affected.map((x: { identityId: string }) => x.identityId).sort()).toEqual([a1.agent.id, a2.agent.id].sort());
    for (const a of [a1, a2]) expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.token))).status).toBe(401);
    // Service accounts (the tool servers) and other organisations keep running.
    expect((await request(t.app).get("/agent/v1/whoami").set(bearer(sa.token))).status).toBe(200);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(other.token))).status).toBe(200);
    // One notice for the whole stop.
    expect(notices.at(-1)).toMatchObject({ subject: "[Legion] Kill switch: 2 identities suspended — suspected compromise" });
    expect(notices.at(-1)!.events).toHaveLength(2);
  });

  it("with includeServiceAccounts, service accounts (tool servers, MCP bridges) are stopped too", async () => {
    const a1 = await agentWithToken(t, "alice");
    const sa = await serviceAccount();
    t.host.add("bob", TENANT_B, "admin");
    const other = await agentWithToken(t, "bob");
    const res = await request(t.app).post("/kill-switch/all").set(as("alice"))
      .send({ reason: "Organisation-wide compromise of the tool servers", compromise: "confirmed", confirmAll: true, includeServiceAccounts: true });
    expect(res.status).toBe(200);
    expect(res.body.affected.map((x: { identityId: string }) => x.identityId).sort()).toEqual([a1.agent.id, sa.id].sort());
    expect((await request(t.app).get("/agent/v1/whoami").set(bearer(sa.token))).status).toBe(401);
    expect((await request(t.app).get("/agent/v1/whoami").set(bearer(a1.token))).status).toBe(401);
    expect((await request(t.app).get("/agent/v1/alerts").set(bearer(other.token))).status).toBe(200);
  });
});

describe("every way of stopping an identity has the same effect", () => {
  const ways: [string, (id: string) => Promise<unknown>, string][] = [
    ["kill switch", (id) => kill(id), "agent_killed"],
    ["owner's routine suspension", (id) => request(t.app).post(`/agents/${id}/suspend`).set(as("alice")).send({ reason: "pausing it" }), "agent_suspended"],
    ["revocation", (id) => request(t.app).post(`/agents/${id}/revoke`).set(as("alice")).send({}), "agent_revoked"],
    ["library call (e.g. a SOAR playbook)", (id) => t.identity.killSwitch.activate({
      tenantId: TENANT_A, identityIds: [id], reason: "playbook: impossible travel", compromise: "suspected",
      actor: { type: "external_system", id: "soar-playbook", tenantId: TENANT_A, displayName: "SOAR" },
    }), "agent_killed"],
  ];
  for (const [name, stop, kind] of ways) {
    it(name, async () => {
      const a = await armedAgent();
      const sa = await serviceAccount();
      await stop(a.agent.id);
      await expectNoPathLeft(a, sa);
      const [event] = await t.identity.killSwitch.events(TENANT_A, { identityId: a.agent.id });
      expect(event).toMatchObject({ kind, identityId: a.agent.id });
      expect(notices.at(-1)!.events[0]).toMatchObject({ eventId: event!.eventId });
    });
  }

  it("a service account is stopped the same way", async () => {
    const sa = await serviceAccount("mcp-bridge");
    const checker = await serviceAccount("checker");
    const res = await kill(sa.id);
    expect(res.body.affected[0]).toMatchObject({ kind: "service_account", cutOff: expect.objectContaining({ tokens: 1 }) });
    expect((await request(t.app).get("/agent/v1/whoami").set(bearer(sa.token))).status).toBe(401);
    expect((await request(t.app).get("/agent/v1/whoami").set(bearer(checker.token))).status).toBe(200);
  });
});

describe("consistency under load", () => {
  it("concurrent stops of the same agent record exactly one event", async () => {
    const { agent } = await agentWithToken(t, "alice");
    const results = await Promise.all(Array.from({ length: 8 }, () => kill(agent.id)));
    expect(results.every((r) => r.status === 200)).toBe(true);
    expect(results.filter((r) => r.body.affected.length === 1)).toHaveLength(1);
    expect(await t.identity.killSwitch.events(TENANT_A)).toHaveLength(1);
  });

  it("a token minted while the stop is committing does not survive it", async () => {
    const { agent, secret } = await agentWithToken(t, "alice");
    const race = await Promise.all([
      ...Array.from({ length: 5 }, () => request(t.app).post("/agent/v1/token").set(bearer(secret))),
      kill(agent.id),
    ]);
    const minted = race.slice(0, 5).filter((r) => r.status === 200).map((r) => r.body.access_token as string);
    for (const tok of minted) expect((await request(t.app).get("/agent/v1/alerts").set(bearer(tok))).status).toBe(401);
  });

  it("the stop is repeatable across many agents and runs", async () => {
    for (let i = 0; i < 5; i++) {
      const a = await agentWithToken(t, "alice");
      expect((await kill(a.agent.id)).body.affected[0].cutOff.tokens).toBe(1);
      expect((await request(t.app).get("/agent/v1/alerts").set(bearer(a.token))).status).toBe(401);
      expect((await request(t.app).post("/agent/v1/token").set(bearer(a.secret))).status).toBe(401);
    }
    expect((await t.identity.killSwitch.verifyChain(TENANT_A))).toEqual({ ok: true, rows: 5 });
  });
});
