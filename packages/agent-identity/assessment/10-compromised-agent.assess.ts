/*
 * Category: Compromised agent — an end-to-end incident, not just one
 * detection: an agent starts probing for weaknesses, the behaviour monitor
 * reaches CRITICAL from real (not synthetic) blocked attempts, automatic
 * containment engages through the kill switch, and the result is total,
 * auditable lockout — with the agent's established peer/owner unaffected.
 */
import request from "supertest";
import { describe } from "vitest";
import { as, bearer, TENANT_B } from "../test/helpers.js";
import { authorize, establishNormalBaseline, mkAgent, SHELL_CALL, SQL_CALL, setPolicy, useWorld, basePolicy } from "./setup.js";
import { defended, notDefended, partial, scenario } from "./harness.js";

const w = useWorld();

describe("Compromised agent", () => {
  scenario({
    id: "CA-1",
    category: "Compromised agent",
    title: "Boundary probing across several distinct attack indicators reaches CRITICAL from real, live-blocked attempts",
    attackPath: "A previously well-behaved triage agent (with an established baseline) starts probing in different directions: a foreign-tenant database query, a denied shell interpreter, a protected-table access, and a sensitive-file read — the pattern of an attacker exploring what a stolen credential can reach, not a single mistake.",
    expectedDefense: "Each probe is refused live (as tested throughout this assessment); recorded together, the behaviour monitor recognises the combined pattern as an intent-evidence attack, independent of any learned baseline, and reaches CRITICAL.",
  }, async (ev) => {
    // This scenario measures how the behaviour monitor classifies sustained
    // probing, so the agent must stay online to keep probing. With the
    // default policy it would not: the first foreign-tenant probe already
    // quarantines it (PE-4).
    await setPolicy(w, { ...basePolicy(w.dir), responses: { quarantineOn: [] } });
    const a = await mkAgent(w, ["alerts:read", "tool.shell:execute", "tool.database:read", "tool.files:read"]);
    await establishNormalBaseline(w, a.agent);
    const probes = [
      { name: "foreign-tenant SQL", res: await authorize(w, a, SQL_CALL("SELECT * FROM alerts WHERE tenant_id = $1", [TENANT_B])) },
      { name: "denied shell interpreter", res: await authorize(w, a, SHELL_CALL("python3", ["-c", "import os"])) },
      { name: "protected table", res: await authorize(w, a, SQL_CALL("SELECT * FROM machine_credentials")) },
      { name: "sensitive file path", res: await authorize(w, a, { kind: "files", operation: "read", path: "/etc/passwd" }) },
    ];
    // Repeat the pattern a few times: the monitor needs enough events in the window for confident classification.
    for (let round = 0; round < 3; round++) {
      for (const p of [SQL_CALL("SELECT * FROM alerts WHERE tenant_id = $1", [TENANT_B]), SHELL_CALL("python3", ["-c", "import os"]), SQL_CALL("SELECT * FROM machine_credentials"), { kind: "files", operation: "read", path: "/etc/passwd" }]) {
        await authorize(w, a, p);
      }
    }
    const assessment = await request(w.t.app).get(`/behavior/agents/${a.agent.id}`).set(as("anna"));
    ev("individualProbeResults", probes.map((p) => ({ name: p.name, status: p.res.status })));
    ev("assessment", { level: assessment.body.assessment?.level, score: assessment.body.assessment?.score, signals: assessment.body.assessment?.signals?.map((s: { id: string }) => s.id) });
    const allProbesRefused = probes.every((p) => p.res.status !== 200);
    const reachedCritical = assessment.body.assessment?.level === "CRITICAL";
    return allProbesRefused && reachedCritical
      ? defended(`All ${probes.length} probe types individually refused; combined pattern classified CRITICAL (score ${assessment.body.assessment.score}, signals: ${assessment.body.assessment.signals.map((s: { id: string }) => s.id).join(", ")}).`)
      : allProbesRefused
        ? partial(`All probes refused individually but combined classification was ${assessment.body.assessment?.level}, not CRITICAL.`, "Medium", "A sustained multi-indicator probing pattern should reach CRITICAL, independent of established baseline.")
        : notDefended(JSON.stringify(probes.map((p) => p.res.status)), "Critical", "Every probe type must be refused live regardless of behaviour classification.");
  });

  scenario({
    id: "CA-2",
    category: "Compromised agent",
    title: "CRITICAL with auto-suspend enabled contains the agent end-to-end: security event, notification, total lockout",
    attackPath: "Continuing from a CRITICAL classification, with autoSuspendOnCritical turned on, this verifies the full automatic response: the agent is actually suspended (not just labelled CRITICAL in a report), a tamper-evident security event exists, an administrator notification was queued, and every path the agent could use is now closed — while its peers and other tenants are untouched.",
    expectedDefense: "Automatic suspension actually happens, is fully audited (security event + notification), and results in the same total lockout as an administrator's manual kill switch — proven live, not assumed from the mechanism's existence.",
  }, async (ev) => {
    await setPolicy(w, { behavior: { autoSuspendOnCritical: true } });
    const a = await mkAgent(w, ["alerts:read", "tool.shell:execute", "tool.database:read"]);
    const peer = await mkAgent(w, ["alerts:read"], "unaffected-peer");
    await establishNormalBaseline(w, a.agent);
    for (let round = 0; round < 4; round++) {
      await authorize(w, a, SQL_CALL("SELECT * FROM alerts WHERE tenant_id = $1", [TENANT_B]));
      await authorize(w, a, SHELL_CALL("python3", ["-c", "import os"]));
      await authorize(w, a, SQL_CALL("SELECT * FROM machine_credentials"));
      await authorize(w, a, { kind: "files", operation: "read", path: "/etc/shadow" });
    }
    await request(w.t.app).get(`/behavior/agents/${a.agent.id}`).set(as("anna")); // force the transition to be assessed and acted on

    const identityRecord = await request(w.t.app).get(`/agents/${a.agent.id}`).set(as("alice"));
    const stillWorks = await request(w.t.app).get("/agent/v1/alerts").set(bearer(a.token));
    const securityEvents = await request(w.t.app).get("/kill-switch/events").set(as("anna"));
    const notifications = await request(w.t.app).get("/kill-switch/notifications").set(as("alice"));
    const peerUnaffected = await request(w.t.app).get("/agent/v1/alerts").set(bearer(peer.token));

    ev("identityStatus", { status: identityRecord.body?.identity?.status, reason: identityRecord.body?.identity?.statusReason });
    ev("agentTokenStillWorks", { status: stillWorks.status });
    ev("securityEventRecorded", securityEvents.body?.events?.[0]);
    ev("notificationQueued", notifications.body?.notifications?.[0]);
    ev("peerUnaffected", { status: peerUnaffected.status });

    const suspended = identityRecord.body?.identity?.status === "suspended";
    const lockedOut = stillWorks.status === 401;
    const eventRecorded = securityEvents.body?.events?.some((e: { identityId: string; kind: string }) => e.identityId === a.agent.id && e.kind === "agent_auto_suspended");
    const notificationExists = notifications.body?.notifications?.length > 0;
    const peerOk = peerUnaffected.status === 200;

    if (suspended && lockedOut && eventRecorded && notificationExists && peerOk) {
      return defended("Agent actually suspended; its own token immediately refused; a security event and an administrator notification both exist; the unrelated peer agent kept working.");
    }
    return notDefended(
      JSON.stringify({ suspended, lockedOut, eventRecorded, notificationExists, peerOk }),
      "Critical",
      "A CRITICAL classification with autoSuspendOnCritical must produce an actual, fully-audited, end-to-end suspension — not only a classification.",
    );
  });
});
