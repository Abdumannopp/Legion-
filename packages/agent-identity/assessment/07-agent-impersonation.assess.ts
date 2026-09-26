/*
 * Category: Agent impersonation — an attacker tries to be treated as an
 * agent (or a specific agent, or a trusted external system) without
 * holding that agent's actual credential/token.
 */
import request from "supertest";
import { describe } from "vitest";
import { bearer } from "../test/helpers.js";
import { authorize, mkAgent, useWorld } from "./setup.js";
import { defended, notDefended, partial, scenario } from "./harness.js";

const w = useWorld();

describe("Agent impersonation", () => {
  scenario({
    id: "IMP-1",
    category: "Agent impersonation",
    title: "Unauthenticated caller declares itself an AI agent via User-Agent, with no credential",
    attackPath: "A caller with no Authorization header sends a User-Agent string that matches Legion's known-AI-agent patterns (e.g. a GPTBot-style string) or an x-legion-agent header, hoping to be treated as an anonymous (unmonitored) client rather than triggering agent-identity requirements.",
    expectedDefense: "Self-declared AI callers without a registered identity are refused (401 agent_identity_required) rather than silently downgraded to an anonymous human-equivalent client.",
  }, async (ev) => {
    const viaUserAgent = await request(w.t.app).get("/agent/v1/whoami").set("user-agent", "Mozilla/5.0 (compatible; GPTBot/1.1; +https://openai.com/gptbot)");
    const viaHeader = await request(w.t.app).get("/agent/v1/whoami").set("x-legion-agent", "some-custom-agent");
    ev("viaUserAgentString", { status: viaUserAgent.status, body: viaUserAgent.body });
    ev("viaCustomHeader", { status: viaHeader.status, body: viaHeader.body });
    const bothRefused = viaUserAgent.status === 401 && viaHeader.status === 401
      && viaUserAgent.body?.error?.code === "agent_identity_required" && viaHeader.body?.error?.code === "agent_identity_required";
    return bothRefused
      ? defended("Both refused with 401 agent_identity_required.")
      : notDefended(JSON.stringify({ ua: viaUserAgent.status, header: viaHeader.status }), "Medium", "Refuse any self-declared AI caller without a registered credential.");
  });

  scenario({
    id: "IMP-2",
    category: "Agent impersonation",
    title: "Request presents both a human session and a machine token at once",
    attackPath: "A caller who has (or has stolen) both a person's session cookie and an agent's bearer token sends both together on the same request, hoping the server picks whichever grants more access, or that logging attributes the action to the wrong principal.",
    expectedDefense: "The request is refused outright (400 ambiguous_principal) rather than silently preferring one credential over the other.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    const res = await request(w.t.app).get("/agent/v1/whoami").set(bearer(a.token)).set("cookie", "session=alice");
    ev("bothCredentialsPresented", { status: res.status, body: res.body });
    return res.status === 400 && res.body?.error?.code === "ambiguous_principal"
      ? defended("Refused with 400 ambiguous_principal.")
      : notDefended(`status=${res.status} code=${res.body?.error?.code}`, "High", "Refuse any request carrying both a human session and a machine credential.");
  });

  scenario({
    id: "IMP-3",
    category: "Agent impersonation",
    title: "Agent tries to claim a different identity via a spoofable header while authenticating with its own (lesser) token",
    attackPath: "An agent holding only alerts:read authenticates normally with its own valid token, but adds headers naming a different, more privileged agent id (x-legion-agent-id, x-legion-principal, x-legion-owner), hoping the server trusts a client-supplied identity claim instead of deriving identity solely from the token.",
    expectedDefense: "The resolved principal (id, tenant, owner, permissions) is derived only from the database row the token hash resolves to; none of these headers change who whoami reports the caller as, or what it is allowed to do.",
  }, async (ev) => {
    const lowPriv = await mkAgent(w, ["alerts:read"], "low-priv-agent");
    const highPriv = await mkAgent(w, ["tool.shell:execute", "tool.cloud:write"], "high-priv-agent");
    const spoofed = await request(w.t.app).get("/agent/v1/whoami").set(bearer(lowPriv.token))
      .set("x-legion-agent-id", highPriv.agent.id)
      .set("x-legion-principal", highPriv.agent.id)
      .set("x-legion-owner", "alice");
    ev("spoofedIdentityHeaders", spoofed.body?.principal);
    const stillLowPriv = spoofed.body?.principal?.id === lowPriv.agent.id;
    const cannotUseHighPrivTool = (await authorize(w, lowPriv, { kind: "shell", operation: "execute", command: "echo", args: ["x"] })).status !== 200;
    ev("stillResolvesAsLowPrivAgent", stillLowPriv);
    ev("stillCannotUseHighPrivTool", cannotUseHighPrivTool);
    return stillLowPriv && cannotUseHighPrivTool
      ? defended("Identity headers had no effect; whoami and permission checks both resolved strictly from the token.")
      : notDefended(JSON.stringify({ resolvedId: spoofed.body?.principal?.id, expectedId: lowPriv.agent.id }), "Critical", "Never let any client-supplied header influence resolved principal identity or permissions.");
  });

  scenario({
    id: "IMP-4",
    category: "Agent impersonation",
    title: "Agent tries to forge its position in an agent-to-agent trust chain",
    attackPath: "An agent that has never been forwarded a request tries to set a custom header (x-legion-chain, x-legion-agent-chain) naming a highly-trusted agent as an upstream link, hoping to inherit relaxed rules that apply to requests forwarded through that chain.",
    expectedDefense: "The chain recorded against a decision is built exclusively server-side, from a verified x-legion-message-id lookup — never from any client-supplied chain header.",
  }, async (ev) => {
    const trusted = await mkAgent(w, ["alerts:read"], "trusted-upstream-agent");
    const attacker = await mkAgent(w, ["alerts:read"], "attacker-agent");
    const res = await request(w.t.app).get("/agent/v1/alerts").set(bearer(attacker.token))
      .set("x-legion-chain", trusted.agent.id)
      .set("x-legion-agent-chain", JSON.stringify([trusted.agent.id]));
    const decisionRow = (await w.t.pool.query("SELECT agent_chain FROM firewall_decisions WHERE principal_id = $1 ORDER BY seq DESC LIMIT 1", [attacker.agent.id])).rows[0];
    ev("responseStatus", res.status);
    ev("recordedAgentChain", decisionRow?.agent_chain);
    const chainEmpty = Array.isArray(decisionRow?.agent_chain) && decisionRow.agent_chain.length === 0;
    return chainEmpty
      ? defended("The recorded agent_chain is empty — the spoofed chain headers had no effect.")
      : notDefended(`recordedAgentChain=${JSON.stringify(decisionRow?.agent_chain)}`, "High", "Never derive the agent chain from any client-supplied header; build it only from verified relayed-message lookups.");
  });

  scenario({
    id: "IMP-5",
    category: "Agent impersonation",
    title: "Named external system labelling is an audit convenience, not an authentication check",
    attackPath: "Anyone (no credential at all) posts directly to a route mounted behind guards.externalSystem(\"wazuh-webhook\"), which by this module's own design labels any unauthenticated caller with that name for the audit trail — checking whether this module provides any origin verification (signature, shared secret) of its own, or whether that responsibility sits entirely with the specific webhook route/integration.",
    expectedDefense: "Reported factually either way: if the module verifies origin itself, that is confirmed with evidence; if it does not (by design — externalSystem() is documented as a label, not an authenticator), that scope boundary is stated plainly so integrators know they must add their own verification (HMAC/shared secret) before trusting the label.",
  }, async (ev) => {
    const res = await request(w.t.app).post("/webhooks/wazuh").send({ alert: "anything, from anyone" });
    ev("unauthenticatedWebhookPost", { status: res.status, body: res.body });
    const auditRow = (await w.t.pool.query(
      "SELECT principal_type, principal_id FROM principal_audit_log WHERE action = 'alert.ingest' ORDER BY seq DESC LIMIT 1",
    )).rows[0];
    ev("auditAttribution", auditRow);
    const accepted = res.status === 202;
    const labelledAsNamedSystemWithNoVerification = auditRow?.principal_type === "external_system" && auditRow?.principal_id === "wazuh-webhook";
    if (accepted && labelledAsNamedSystemWithNoVerification) {
      return partial(
        "A completely unauthenticated POST was accepted (202) and recorded in the audit trail as principal_type=external_system, principal_id=\"wazuh-webhook\" — with zero request-content verification. This matches the code's own documentation (externalSystem() \"labels a route's caller ... for the audit trail\"); it is not a broken authentication check, because none is claimed. But it means anyone who can reach the route can make the audit trail say \"this came from Wazuh\" for whatever alert.ingest actually does with the payload.",
        "Medium",
        "This module provides no HMAC/shared-secret verification for named external systems, and does not claim to. Document this loudly wherever externalSystem() is used, and require every real integration (the actual Wazuh webhook, any other external-system route) to verify a signature or shared secret in its own handler before Legion's guard runs, so the audit label reflects a verified source rather than an asserted one.",
      );
    }
    return notDefended(JSON.stringify({ status: res.status, auditRow }), "Medium", "Investigate: response/audit shape differs from what the code's documented design implies.");
  });
});
