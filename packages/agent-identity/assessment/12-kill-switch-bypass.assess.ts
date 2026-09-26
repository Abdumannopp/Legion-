/*
 * Category: Kill switch bypass attempts — fresh angles beyond what
 * test/killswitch.test.ts already covers in depth (stale principals, tool
 * tickets, in-flight execution abort, relayed messages, the on-behalf-of
 * path, cross-instance watchdog, concurrent activations, races with token
 * minting — all independently regression-tested there).
 */
import request from "supertest";
import { describe } from "vitest";
import { as, bearer, TENANT_A, TENANT_B } from "../test/helpers.js";
import { mkAgent, useWorld } from "./setup.js";
import { defended, notDefended, partial, scenario } from "./harness.js";

const w = useWorld();

describe("Kill switch bypass attempts", () => {
  scenario({
    id: "KSB-1",
    category: "Kill switch bypass",
    title: "A confirmed kill must revoke every credential the agent holds, not only the one most recently used",
    attackPath: "An agent legitimately holds two active credentials at once (Legion allows up to two, for rotation). A confirmed-compromise kill switch is issued. The attacker, holding the *other* (not most-recently-used) credential, tries to mint a fresh token with it.",
    expectedDefense: "A confirmed compromise revokes every active credential belonging to the identity, not just one.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    const secondCred = await request(w.t.app).post(`/agents/${a.agent.id}/credentials`).set(as("alice")).send({});
    const secondSecret = secondCred.body.credential.secret as string;
    // Confirm the second credential works before the kill.
    const beforeKill = await request(w.t.app).post("/agent/v1/token").set(bearer(secondSecret));
    ev("secondCredentialWorksBeforeKill", { status: beforeKill.status });

    await request(w.t.app).post(`/kill-switch/agents/${a.agent.id}`).set(as("alice")).send({ reason: "Confirmed: credential leaked in a public repository", compromise: "confirmed" });
    const firstCredAfter = await request(w.t.app).post("/agent/v1/token").set(bearer(a.secret));
    const secondCredAfter = await request(w.t.app).post("/agent/v1/token").set(bearer(secondSecret));
    ev("firstCredentialAfterKill", { status: firstCredAfter.status });
    ev("secondCredentialAfterKill", { status: secondCredAfter.status });

    const bothRevoked = firstCredAfter.status === 401 && secondCredAfter.status === 401;
    return bothRevoked
      ? defended("Both credentials refused a new token after the confirmed kill.")
      : notDefended(JSON.stringify({ first: firstCredAfter.status, second: secondCredAfter.status }), "Critical", "A confirmed compromise must revoke every active credential belonging to the identity, not only the one used at kill time.");
  });

  scenario({
    id: "KSB-2",
    category: "Kill switch bypass",
    title: "A confirmed kill must revoke delegations from every person, not only whoever triggered it",
    attackPath: "Two different people (an analyst and an admin) each independently delegated permissions to the same agent. A confirmed kill is issued by the admin. The attacker, now controlling the agent's authority as far as the *analyst's* delegation is concerned, tries to act under that other grant.",
    expectedDefense: "Confirmed compromise revokes every active delegation to the identity, from every granting person, not only ones related to whoever issued the kill.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const grantFromAnna = await request(w.t.app).post("/firewall/delegations").set(as("anna")).send({ agentId: a.agent.id, permissions: ["alerts:read"], expiresAt });
    const grantFromAlice = await request(w.t.app).post("/firewall/delegations").set(as("alice")).send({ agentId: a.agent.id, permissions: ["alerts:read"], expiresAt });
    ev("grantsCreated", { fromAnna: grantFromAnna.status, fromAlice: grantFromAlice.status });

    await request(w.t.app).post(`/kill-switch/agents/${a.agent.id}`).set(as("alice")).send({ reason: "Confirmed: agent found exfiltrating alert data", compromise: "confirmed" });

    const bothGrants = await w.t.pool.query("SELECT user_id, revoked_at FROM agent_delegations WHERE identity_id = $1 ORDER BY user_id", [a.agent.id]);
    ev("delegationsAfterKill", bothGrants.rows);
    const allRevoked = bothGrants.rows.every((r) => r.revoked_at !== null);
    return allRevoked
      ? defended(`Both delegations (from anna and alice) revoked: ${JSON.stringify(bothGrants.rows)}.`)
      : notDefended(JSON.stringify(bothGrants.rows), "High", "Confirmed compromise must revoke every active delegation to the identity, regardless of who granted it or who triggered the kill.");
  });

  scenario({
    id: "KSB-3",
    category: "Kill switch bypass",
    title: "Library-level activate() call cannot affect another tenant's identities even with a mismatched actor claim",
    attackPath: "The kill switch is also a library API (KillSwitch.activate), meant to be called by trusted host code — e.g. a SOAR playbook — not only through the admin HTTP route. This checks whether that lower-level entry point itself still enforces tenant isolation on the identity ids it is given, as a defence-in-depth measure independent of whatever authorization the caller was supposed to have already done.",
    expectedDefense: "Even called directly with a tenantId that does not match where the target identity actually lives, the identity in the *other* tenant is not found and not affected — tenant scoping holds at the data layer itself, not only at the HTTP guard layer.",
  }, async (ev) => {
    w.t.host.add("bob", TENANT_B, "admin");
    const victimInTenantB = await mkAgent(w, ["alerts:read"], "tenant-b-agent", "bob");
    const result = await w.t.identity.killSwitch.activate({
      tenantId: TENANT_A, // wrong tenant on purpose
      identityIds: [victimInTenantB.agent.id],
      reason: "attempting cross-tenant activation via the library API directly",
      compromise: "confirmed",
      actor: { type: "human", id: "alice", tenantId: TENANT_A, role: "admin", displayName: "alice" },
    });
    ev("crossTenantLibraryActivation", result);
    const victimStillActive = await request(w.t.app).get("/agent/v1/whoami").set(bearer(victimInTenantB.token));
    ev("victimStillActive", { status: victimStillActive.status });
    const notFoundOrUnaffected = result.affected.length === 0 && victimStillActive.status === 200;
    return notFoundOrUnaffected
      ? defended(`The identity was not found under the wrong tenant (affected=[], notFound=${JSON.stringify(result.notFound)}); it kept working under its real tenant.`)
      : notDefended(JSON.stringify(result), "Critical", "KillSwitch.activate must scope its identity lookup to the given tenantId even when called directly as a library function.");
  });

  scenario({
    id: "KSB-4",
    category: "Kill switch bypass",
    title: "Acknowledging a behaviour finding does not silently resume a suspended agent",
    attackPath: "After an agent is suspended (by the kill switch or auto-suspension), someone calls the behaviour-acknowledge endpoint (a separate, narrower control meant to reset a behaviour *classification*, not identity status) — checking it isn't confused for, or does not accidentally act as, a resume.",
    expectedDefense: "Acknowledging behaviour only resets the behaviour classification; the identity remains suspended and still needs an explicit POST /agents/:id/resume.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    await request(w.t.app).post(`/kill-switch/agents/${a.agent.id}`).set(as("alice")).send({ reason: "suspected automation misuse, reviewing now", compromise: "suspected" });
    const ack = await request(w.t.app).post(`/behavior/agents/${a.agent.id}/acknowledge`).set(as("alice")).send({ reason: "reviewed the flagged activity, looks fine", learn: false });
    const identityAfterAck = await request(w.t.app).get(`/agents/${a.agent.id}`).set(as("alice"));
    const tokenAfterAck = await request(w.t.app).post("/agent/v1/token").set(bearer(a.secret));
    ev("acknowledgeStatus", ack.status);
    ev("identityStatusAfterAcknowledge", identityAfterAck.body?.identity?.status);
    ev("tokenAttemptAfterAcknowledge", { status: tokenAfterAck.status });
    const stillSuspended = identityAfterAck.body?.identity?.status === "suspended" && tokenAfterAck.status === 401;
    return stillSuspended
      ? defended("The identity remained suspended and its credential still refused a new token after the behaviour acknowledgement; resume was not implicitly granted.")
      : notDefended(`status=${identityAfterAck.body?.identity?.status}`, "High", "Behaviour acknowledgement must never change identity status; only an explicit resume should.");
  });

  scenario({
    id: "KSB-5",
    category: "Kill switch bypass",
    title: "Tenant-wide /kill-switch/all targets AI agents only — checking whether a compromised service account survives it",
    attackPath: "An administrator responds to a suspected organisation-wide compromise with POST /kill-switch/all. By this module's own design that route only suspends active ai_agent identities. This checks, factually, whether a compromised *service account* (the kind of identity a tool server or MCP bridge uses) is left running by that same call — a real path an attacker who specifically compromised a service account, rather than an AI agent, could rely on.",
    expectedDefense: "Reported factually either way. If service accounts are deliberately out of scope for the blanket tenant-wide stop, that is a real operational gap for administrators to know about (they would need POST /kill-switch/agents/:id per service account, or a future tenant-wide option covering both kinds), not an assumed protection.",
  }, async (ev) => {
    const agent = await mkAgent(w, ["alerts:read"]);
    const sa = await request(w.t.app).post("/service-accounts").set(as("alice")).send({ name: "compromised-tool-server" });
    const saToken = (await request(w.t.app).post("/agent/v1/token").set(bearer(sa.body.credential.secret))).body.access_token as string;

    const killAll = await request(w.t.app).post("/kill-switch/all").set(as("alice")).send({ reason: "suspected organisation-wide compromise", compromise: "confirmed", confirmAll: true });
    ev("killAllResult", { affectedCount: killAll.body?.affected?.length, affectedIds: killAll.body?.affected?.map((x: { identityId: string }) => x.identityId) });

    const agentAfter = await request(w.t.app).get("/agent/v1/whoami").set(bearer(agent.token));
    const saAfter = await request(w.t.app).get("/agent/v1/whoami").set(bearer(saToken));
    ev("aiAgentAfterKillAll", { status: agentAfter.status });
    ev("serviceAccountAfterKillAll", { status: saAfter.status });

    const agentStopped = agentAfter.status === 401;
    const saSurvived = saAfter.status === 200;
    if (agentStopped && saSurvived) {
      return partial(
        "POST /kill-switch/all correctly stopped the AI agent, but the service account (a plausible target for compromise — tool servers and MCP bridges authenticate as service accounts) was left completely unaffected and kept working normally.",
        "Medium",
        "Either extend /kill-switch/all with an option to include service accounts, or document prominently that a suspected organisation-wide incident requires separately auditing and, if needed, individually kill-switching every service account (GET /service-accounts, then POST /kill-switch/agents/:id per id).",
      );
    }
    return agentStopped
      ? notDefended(`Unexpected: service account status after kill-all was ${saAfter.status}.`, "Medium", "Re-verify /kill-switch/all's actual scope.")
      : notDefended("The AI agent itself was not stopped by /kill-switch/all.", "Critical", "/kill-switch/all must stop every active AI agent in the tenant.");
  });
});
