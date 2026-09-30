/*
 * Category: Cross-tenant access — an attacker in one organisation tries to
 * reach, act on, or learn about another organisation's agents, resources,
 * or evidence — across every surface, not only agent-to-agent messaging
 * (which is covered in detail in test/a2a.test.ts and re-touched briefly
 * here for completeness).
 */
import request from "supertest";
import { describe } from "vitest";
import { as, bearer, TENANT_B } from "../test/helpers.js";
import { authorize, brief, mkAgent, SLACK, useWorld, authorizeApproved, rules } from "./setup.js";
import { defended, notDefended, scenario } from "./harness.js";

const w = useWorld();

describe("Cross-tenant access", () => {
  scenario({
    id: "CT-1",
    category: "Cross-tenant access",
    title: "Agent tries to act on a resource explicitly tagged with another tenant",
    attackPath: "An agent in tenant A calls a route where the resource carries an explicit tenantId, set to tenant B's id (as if the agent's runtime were tricked into cross-tenant routing, or a bug elsewhere passed the wrong tenant along).",
    expectedDefense: "tenant.mismatch fires whenever a resource's declared tenant differs from the caller's own, regardless of how the mismatch arose.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    const ctx = { principal: await import("./setup.js").then((m) => m.principalOf(w, a)) };
    let outcome: unknown;
    try {
      const d = await w.t.identity.firewall.evaluate(ctx, { surface: "api", action: "alerts:read", permission: "alerts:read", resource: { type: "alert", id: "A1", tenantId: TENANT_B } });
      outcome = { decision: d.decision, rules: d.hits.map((h) => h.id) };
    } catch (e) {
      outcome = { threw: (e as Error).message };
    }
    ev("crossTenantResourceEvaluation", outcome);
    const blocked = typeof outcome === "object" && outcome !== null && (outcome as { rules?: string[] }).rules?.includes("tenant.mismatch");
    return blocked
      ? defended("Refused with tenant.mismatch.")
      : notDefended(JSON.stringify(outcome), "Critical", "Refuse any resource whose declared tenantId differs from the caller's own tenant.");
  });

  scenario({
    id: "CT-2",
    category: "Cross-tenant access",
    title: "Admin of one tenant tries to read another tenant's agent, audit trail, and firewall decisions by guessing IDs",
    attackPath: "An admin in tenant B, who happens to know (or brute-forces) a UUID belonging to an agent in tenant A, tries: GET /agents/:id, GET /agents/:id/activity, and GET /firewall/decisions?principalId=<tenant A's agent id> — all authenticated as a legitimate admin, just of the wrong organisation.",
    expectedDefense: "Every one of these is scoped to the caller's own tenant server-side; a tenant-B admin sees \"not found\" for tenant A's agent, and the decisions list is empty rather than showing another tenant's rows.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"], "tenant-a-secret-agent");
    await authorize(w, a, SLACK("C0SECOPS1")); // generate at least one decision to look for
    w.t.host.add("bob", TENANT_B, "admin");
    const getAgent = await request(w.t.app).get(`/agents/${a.agent.id}`).set(as("bob"));
    const getActivity = await request(w.t.app).get(`/agents/${a.agent.id}/activity`).set(as("bob"));
    const getDecisions = await request(w.t.app).get(`/firewall/decisions?principalId=${a.agent.id}`).set(as("bob"));
    ev("getAgentAsWrongTenant", { status: getAgent.status });
    ev("getActivityAsWrongTenant", { status: getActivity.status });
    ev("getDecisionsAsWrongTenant", { status: getDecisions.status, count: getDecisions.body?.decisions?.length });
    const isolated = getAgent.status === 404 && getActivity.status === 404 && (getDecisions.body?.decisions?.length ?? 0) === 0;
    return isolated
      ? defended("Agent record and activity both 404 for the wrong tenant; decisions list is empty rather than leaking tenant A's rows.")
      : notDefended(JSON.stringify({ agent: getAgent.status, activity: getActivity.status, decisionsCount: getDecisions.body?.decisions?.length }), "Critical", "Scope every by-id and by-principalId lookup to the caller's own tenant.");
  });

  scenario({
    id: "CT-3",
    category: "Cross-tenant access",
    title: "Tool ticket issued in one tenant is presented to a service account in another",
    attackPath: "A tool ticket generated for tenant A's agent (e.g. leaked, or the service account URL is shared across environments) is presented for verification by a service account belonging to tenant B.",
    expectedDefense: "The ticket is refused (as \"unknown\", not revealing that it exists in another tenant) because verification is scoped to the verifier's own tenant.",
  }, async (ev) => {
    const agentA = await mkAgent(w, ["tool.slack:write"]);
    const auth = await authorizeApproved(w, agentA, SLACK("C0SECOPS1"));
    const ticket = auth.body.ticket as string;
    w.t.host.add("bob", TENANT_B, "admin");
    const saB = await request(w.t.app).post("/service-accounts").set(as("bob")).send({ name: "tenant-b-verifier" });
    const saBToken = (await request(w.t.app).post("/agent/v1/token").set(bearer(saB.body.credential.secret))).body.access_token as string;
    const verifyAcrossTenant = await request(w.t.app).post("/agent/v1/tools/verify").set(bearer(saBToken)).send({ ticket, call: SLACK("C0SECOPS1") });
    ev("crossTenantTicketVerify", { status: verifyAcrossTenant.status, body: verifyAcrossTenant.body });
    return verifyAcrossTenant.status === 403 && verifyAcrossTenant.body.reason === "unknown"
      ? defended(`Refused as "unknown" (not "already_used" or any reason that would confirm the ticket exists elsewhere).`)
      : notDefended(JSON.stringify(verifyAcrossTenant.body), "High", "Scope ticket verification strictly to the verifier's own tenant and never distinguish \"exists in another tenant\" from \"doesn't exist\".");
  });

  scenario({
    id: "CT-4",
    category: "Cross-tenant access",
    title: "Admin of one tenant tries to kill-switch another tenant's agent by ID",
    attackPath: "An admin in tenant B, knowing tenant A's agent id, calls POST /kill-switch/agents/:id directly against it.",
    expectedDefense: "The kill switch is scoped to the caller's tenant; the call is refused as not found, and the tenant-A agent is left completely unaffected.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    w.t.host.add("bob", TENANT_B, "admin");
    const crossTenantKill = await request(w.t.app).post(`/kill-switch/agents/${a.agent.id}`).set(as("bob"))
      .send({ reason: "cross-tenant attack attempt on purpose", compromise: "confirmed" });
    const stillWorks = await request(w.t.app).get("/agent/v1/alerts").set(bearer(a.token));
    ev("crossTenantKillAttempt", { status: crossTenantKill.status, body: crossTenantKill.body });
    ev("victimAgentStillActive", { status: stillWorks.status });
    return crossTenantKill.status === 404 && stillWorks.status === 200
      ? defended("Refused as not found; the targeted agent's own tenant was unaffected and kept working.")
      : notDefended(JSON.stringify({ kill: crossTenantKill.status, stillWorks: stillWorks.status }), "Critical", "Scope the kill switch's identity lookup to the caller's own tenant.");
  });

  scenario({
    id: "CT-5",
    category: "Cross-tenant access",
    title: "Agent-to-agent messaging across tenants (spot check; full coverage in test/a2a.test.ts)",
    attackPath: "An agent in tenant A tries to send a request naming an agent id that actually belongs to tenant B.",
    expectedDefense: "Refused, and answered exactly like an id that exists nowhere (a2a.recipient_unknown), so the answer does not reveal that the id belongs to a real agent in another organisation.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    w.t.host.add("bob", TENANT_B, "admin");
    const foreignAgent = await mkAgent(w, ["alerts:read"], "tenant-b-target", "bob");
    const res = await request(w.t.app).post("/agent/v1/messages").set(bearer(a.token)).send({ toAgentId: foreignAgent.agent.id, requestedPermission: "alerts:read" });
    const ghost = await request(w.t.app).post("/agent/v1/messages").set(bearer(a.token)).send({ toAgentId: "00000000-0000-4000-8000-00000000beef", requestedPermission: "alerts:read" });
    ev("crossTenantMessage", brief(res));
    ev("nonexistentRecipient", brief(ghost));
    const refused = res.status === 403 && rules(res).includes("a2a.recipient_unknown");
    const indistinguishable = res.status === ghost.status && res.body?.error?.message === ghost.body?.error?.message
      && JSON.stringify(rules(res)) === JSON.stringify(rules(ghost));
    return refused && indistinguishable
      ? defended("Refused, and indistinguishable from an id that does not exist (no cross-tenant oracle).")
      : notDefended(JSON.stringify({ foreign: brief(res), ghost: brief(ghost) }), "High", "Refuse agent-to-agent messages whose recipient resolves to another tenant, answering exactly as for an unknown id.");
  });
});
