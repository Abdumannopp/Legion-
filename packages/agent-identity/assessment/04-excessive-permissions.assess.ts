/*
 * Category: Excessive permissions — an agent ends up with, or keeps, more
 * authority than its owner's real role, or than its risk level implies.
 */
import request from "supertest";
import { describe } from "vitest";
import { as, bearer, TENANT_A } from "../test/helpers.js";
import { authorize, brief, mkAgent, SHELL_CALL, useWorld } from "./setup.js";
import { defended, notDefended, partial, scenario } from "./harness.js";

const w = useWorld();

describe("Excessive permissions", () => {
  scenario({
    id: "EP-1",
    category: "Excessive permissions",
    title: "Non-admin tries to create an agent directly",
    attackPath: "A signed-in analyst (not an admin) tries to create an AI agent with high-tier permissions directly via the management API.",
    expectedDefense: "Agent creation is admin-only; the analyst's attempt is refused regardless of what permissions they ask for.",
  }, async (ev) => {
    const res = await request(w.t.app).post("/agents").set(as("anna")).send({ name: "analyst-created-agent", permissions: ["tool.shell:execute", "tool.cloud:write"] });
    ev("analystCreateAttempt", { status: res.status, body: res.body });
    return res.status === 403
      ? defended(`Refused with 403 (${res.body?.error?.code}).`)
      : notDefended(`Status ${res.status}`, "Critical", "Agent creation must remain admin-only.");
  });

  scenario({
    id: "EP-2",
    category: "Excessive permissions",
    title: "Agent created with a risk level lower than its permissions warrant",
    attackPath: "An admin tries to create a shell-executing, cloud-writing agent but declares its risk level as \"low\" — hoping to keep it out of stricter behaviour-monitoring or review thresholds that key off risk level.",
    expectedDefense: "The declared risk level cannot fall below the floor implied by the granted permissions (baselineRisk); the request is refused or the risk is raised, never silently accepted as declared.",
  }, async (ev) => {
    const res = await request(w.t.app).post("/agents").set(as("alice")).send({ name: "sneaky-low-risk", permissions: ["tool.shell:execute", "tool.cloud:write"], riskLevel: "low" });
    ev("createWithMismatchedRisk", { status: res.status, body: res.body });
    const rejected = res.status === 400;
    const raisedAutomatically = res.status === 201 && (res.body?.identity?.riskLevel === "high" || res.body?.identity?.riskLevel === "critical");
    return rejected || raisedAutomatically
      ? defended(rejected ? `Refused: risk floor enforced (${res.body?.error?.code}).` : `Accepted but risk level was raised to "${res.body.identity.riskLevel}", not left at the requested "low".`)
      : notDefended(`Created with riskLevel=${res.body?.identity?.riskLevel}`, "High", "Enforce baselineRisk as a floor on every create/update, not just as a default.");
  });

  scenario({
    id: "EP-3",
    category: "Excessive permissions",
    title: "Agent tries to exercise a permission beyond what it was granted, and beyond its owner's current role",
    attackPath: "An agent authorised for tool.shell:execute tries a tool.cloud:write action it was never granted (simple over-reach). Separately, an agent's owner is demoted from admin to viewer after the agent was created; the agent — using its existing, already-issued token — then tries the same shell action it could do a moment ago.",
    expectedDefense: "The direct over-reach is refused (permission.not_granted). After the owner's demotion, effective permissions are recomputed live on every request from the owner's *current* role, so the previously-issued token immediately loses tier>0 access too — privilege does not outlive the human authority it rests on.",
  }, async (ev) => {
    const a = await mkAgent(w, ["tool.shell:execute"], "escalation-test-agent", "alice");
    const overReach = await authorize(w, a, { kind: "cloud", operation: "invoke", provider: "aws", account: "111122223333", action: "ec2:TerminateInstances" });
    const beforeDemotion = await authorize(w, a, SHELL_CALL("echo", ["hi"]));

    w.t.host.add("alice", TENANT_A, "viewer"); // demote the owner (FakeHost.add overwrites by id)
    const afterDemotion = await authorize(w, a, SHELL_CALL("echo", ["hi"]));
    const whoami = await request(w.t.app).get("/agent/v1/whoami").set(bearer(a.token));

    ev("directOverReach", brief(overReach));
    ev("beforeOwnerDemotion", brief(beforeDemotion));
    ev("afterOwnerDemotion", brief(afterDemotion));
    ev("effectivePermissionsAfterDemotion", whoami.body?.principal?.permissions);

    const overReachBlocked = overReach.status !== 200;
    const demotionShrankAccess = beforeDemotion.status === 200 && afterDemotion.status !== 200;
    if (overReachBlocked && demotionShrankAccess) {
      return defended("Direct over-reach refused; after the owner was demoted to viewer, the same already-issued token immediately lost tool.shell:execute (recomputed live from the owner's current role).");
    }
    return overReachBlocked
      ? partial("Direct over-reach is blocked, but an existing token kept tier>0 access after its owner was demoted.", "High", "Recompute effectivePermissions from the live owner role on every request, not only at token issuance.")
      : notDefended(`overReach=${overReach.status}`, "Critical", "Enforce granted permissions on every tool call.");
  });

  scenario({
    id: "EP-4",
    category: "Excessive permissions",
    title: "Delegation lets a non-admin hand tier-2 (write/execute) authority to an agent",
    attackPath: "An analyst (not an admin) uses the delegation endpoint to grant an agent tool.shell:execute and tool.cloud:write \"on their behalf\" — checking whether the module's role ceiling actually distinguishes analyst from admin for this purpose, since only admins can create agents but delegation is open to any signed-in role.",
    expectedDefense: "This is reported factually, whichever way it goes: either the delegation is capped below tier-2 for a non-admin role, or it is accepted — in which case that is a real design point administrators should know about, not assumed.",
  }, async (ev) => {
    const a = await mkAgent(w, ["tool.shell:execute", "tool.cloud:write"], "delegate-target", "alice");
    const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
    const delegation = await request(w.t.app).post("/firewall/delegations").set(as("anna"))
      .send({ agentId: a.agent.id, permissions: ["tool.shell:execute", "tool.cloud:write"], expiresAt });
    ev("analystDelegatesTier2", { status: delegation.status, body: delegation.body });

    if (delegation.status !== 201) {
      return defended(`Analyst's tier-2 delegation was refused (${delegation.status}, ${delegation.body?.error?.code}) — the module's role ceiling caps non-admin delegation below tier-2.`);
    }
    const actUnderGrant = await authorize(w, a, SHELL_CALL("echo", ["under-analyst-delegation"]), { "x-legion-on-behalf-of": "anna" });
    ev("actUnderAnalystGrant", brief(actUnderGrant));
    return partial(
      `An analyst (non-admin) role was able to delegate tool.shell:execute and tool.cloud:write to an agent, and the agent could act under that grant (status ${actUnderGrant.status}). This module's ROLE_CEILING treats "analyst" and "admin" identically (both get every permission tier) — only "viewer" is capped to tier 0. This may be intentional (Legion may consider "analyst" a fully trusted staff role for delegation purposes), but it means a compromised analyst account can hand full tool authority to an agent without any admin involvement.`,
      "Medium",
      "If analysts should not be able to delegate destructive/tier-2 tool authority (shell execute, cloud write) without admin approval, lower ROLE_CEILING for \"analyst\" below tier 2, or require admin co-signature for tier-2 delegations. If this is intentional, document it explicitly so operators don't assume delegation is admin-gated the way agent creation is.",
    );
  });
});
