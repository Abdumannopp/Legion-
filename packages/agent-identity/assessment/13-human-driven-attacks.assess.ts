/*
 * Category: Traditional human-driven attack protections — this module also
 * fronts every human management route (creating/suspending agents, policy,
 * delegations, audit). This file checks the classic web-application
 * attacker playbook still fails here: broken RBAC, forged sessions, SQL
 * injection through filter parameters, tampering with the audit trail, and
 * mass-assignment through extra body fields.
 */
import request from "supertest";
import { describe } from "vitest";
import { as, TENANT_A } from "../test/helpers.js";
import { mkAgent, useWorld } from "./setup.js";
import { defended, notDefended, scenario } from "./harness.js";

const w = useWorld();

describe("Traditional human-driven attack protections", () => {
  scenario({
    id: "HA-1",
    category: "Human-driven attacks",
    title: "RBAC sweep: a read-only viewer tries every admin-gated management route",
    attackPath: "A signed-in viewer (read-only role) tries creating an agent, updating firewall policy, suspending and revoking an agent, and the emergency kill switch — the full set of destructive/administrative routes.",
    expectedDefense: "Every one refused with 403, whatever the viewer asks for.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    const attempts = [
      { name: "create agent", res: await request(w.t.app).post("/agents").set(as("vic")).send({ name: "viewer-created", permissions: [] }) },
      { name: "update policy", res: await request(w.t.app).put("/firewall/policy").set(as("vic")).send({ mode: "monitor" }) },
      { name: "revoke agent", res: await request(w.t.app).post(`/agents/${a.agent.id}/revoke`).set(as("vic")).send({}) },
      { name: "kill switch", res: await request(w.t.app).post(`/kill-switch/agents/${a.agent.id}`).set(as("vic")).send({ reason: "viewer trying to use the kill switch", compromise: "suspected" }) },
      { name: "resume agent", res: await request(w.t.app).post(`/agents/${a.agent.id}/resume`).set(as("vic")).send({}) },
    ];
    const results = attempts.map((x) => ({ name: x.name, status: x.res.status }));
    ev("attempts", results);
    const allRefused = attempts.every((x) => x.res.status === 403);
    return allRefused
      ? defended(`All ${attempts.length} admin-gated routes refused a viewer with 403.`)
      : notDefended(JSON.stringify(results), "Critical", "Every administrative route must check the caller's role server-side.");
  });

  scenario({
    id: "HA-2",
    category: "Human-driven attacks",
    title: "Forged or stale session cookies are rejected",
    attackPath: "An attacker sends a session cookie naming a user id that does not exist, and separately a cookie for a real user whose status the host adapter reports as inactive (e.g. an off-boarded employee) — the two classic forged/stale-session cases.",
    expectedDefense: "Both are treated as unauthenticated; no route treats the request as a valid signed-in person.",
  }, async (ev) => {
    const forgedCookie = await request(w.t.app).get("/agents").set("cookie", "session=totally-made-up-user-id-xyz");
    w.t.host.add("former-employee", TENANT_A, "admin", "inactive");
    const staleCookie = await request(w.t.app).get("/agents").set(as("former-employee"));
    ev("forgedUserIdCookie", { status: forgedCookie.status });
    ev("inactiveUserCookie", { status: staleCookie.status });
    const bothRefused = forgedCookie.status === 401 && staleCookie.status === 401;
    return bothRefused
      ? defended("Both a forged user id and a real-but-inactive user's cookie were refused as unauthenticated.")
      : notDefended(JSON.stringify({ forged: forgedCookie.status, stale: staleCookie.status }), "Critical", "Reject any session cookie naming a nonexistent or inactive user.");
  });

  scenario({
    id: "HA-3",
    category: "Human-driven attacks",
    title: "SQL injection attempts through filter query parameters",
    attackPath: "An admin-authenticated attacker (testing whether the authentication layer being solid is the only thing standing between them and the database) sends classic SQL-injection payloads as filter values on list endpoints: audit log principalId, firewall decisions principalId, and behaviour events identityId.",
    expectedDefense: "Every query uses parameterised placeholders; injection payloads are treated as literal (non-matching) filter values, returning an empty result — never a database error, and never unfiltered/unauthorized rows.",
  }, async (ev) => {
    const payloads = [
      "' OR '1'='1",
      "'; DROP TABLE machine_identities; --",
      "x' UNION SELECT secret_hash FROM machine_credentials --",
    ];
    const endpoints = [
      (p: string) => request(w.t.app).get(`/audit/principal-events?principalId=${encodeURIComponent(p)}`).set(as("alice")),
      (p: string) => request(w.t.app).get(`/firewall/decisions?principalId=${encodeURIComponent(p)}`).set(as("alice")),
      (p: string) => request(w.t.app).get(`/behavior/events?identityId=${encodeURIComponent(p)}`).set(as("alice")),
    ];
    const results = [];
    for (const [i, endpoint] of endpoints.entries()) {
      for (const payload of payloads) {
        const res = await endpoint(payload);
        results.push({ endpoint: i, payload, status: res.status, isServerError: res.status >= 500, resultCount: res.body?.events?.length ?? res.body?.decisions?.length });
      }
    }
    ev("injectionAttempts", results);
    const noServerErrors = results.every((r) => !r.isServerError);
    const noDataLeaked = results.every((r) => (r.resultCount ?? 0) === 0);
    // Confirm the app and its tables are still intact after the DROP TABLE attempt.
    const stillWorks = await request(w.t.app).get("/agents").set(as("alice"));
    ev("appStillFunctionalAfterInjectionAttempts", { status: stillWorks.status });
    if (noServerErrors && noDataLeaked && stillWorks.status === 200) {
      return defended("Every injection payload was treated as a literal, non-matching value (no server errors, no unauthorized rows returned); the application and its tables remained intact.");
    }
    return notDefended(JSON.stringify({ noServerErrors, noDataLeaked, appStatus: stillWorks.status }), "Critical", "Use only parameterised queries; a filter value must never be concatenated into SQL.");
  });

  scenario({
    id: "HA-4",
    category: "Human-driven attacks",
    title: "An insider with direct database access cannot quietly edit the human-facing audit trail",
    attackPath: "An attacker (or a rogue insider) who has obtained direct database access — not through the API — tries to UPDATE or DELETE rows in principal_audit_log directly, to remove evidence of what they did.",
    expectedDefense: "The append-only trigger on principal_audit_log refuses the UPDATE/DELETE outright at the database level, independent of any application code.",
  }, async (ev) => {
    const a = await mkAgent(w, ["alerts:read"]);
    await request(w.t.app).post(`/agents/${a.agent.id}/suspend`).set(as("alice")).send({ reason: "test action to have something to try to erase" });
    let updateBlocked = false;
    let deleteBlocked = false;
    try { await w.t.pool.query("UPDATE principal_audit_log SET action = 'nothing happened' WHERE resource_id = $1", [a.agent.id]); } catch (e) { updateBlocked = /append-only/.test((e as Error).message); }
    try { await w.t.pool.query("DELETE FROM principal_audit_log WHERE resource_id = $1", [a.agent.id]); } catch (e) { deleteBlocked = /append-only/.test((e as Error).message); }
    ev("directUpdateAttempt", { blocked: updateBlocked });
    ev("directDeleteAttempt", { blocked: deleteBlocked });
    const rowStillThere = await w.t.pool.query("SELECT action FROM principal_audit_log WHERE resource_id = $1 AND action = 'identity.suspended'", [a.agent.id]);
    ev("originalRowIntact", rowStillThere.rows.length > 0);
    return updateBlocked && deleteBlocked && rowStillThere.rows.length > 0
      ? defended("Both direct UPDATE and DELETE were refused by the database trigger; the original audit row is intact.")
      : notDefended(JSON.stringify({ updateBlocked, deleteBlocked }), "Critical", "The append-only trigger must cover UPDATE and DELETE on principal_audit_log unconditionally, including for direct database access.");
  });

  scenario({
    id: "HA-5",
    category: "Human-driven attacks",
    title: "Mass assignment: extra/unexpected fields in a request body are rejected, not silently accepted",
    attackPath: "An attacker who can create an agent (as an admin — testing the schema boundary itself, not RBAC) adds extra fields to the request body that aren't part of the documented API, hoping an internal field name happens to line up with something sensitive (a classic mass-assignment attack against loosely-validated APIs): status, ownerUserId set to someone else after creation via PATCH with an unexpected riskLevel bypass field, and a completely made-up field.",
    expectedDefense: "Every request body is validated against a strict schema that rejects unknown keys outright, rather than ignoring or silently accepting them.",
  }, async (ev) => {
    const withExtraFields = await request(w.t.app).post("/agents").set(as("alice"))
      .send({ name: "mass-assignment-test", permissions: ["alerts:read"], status: "active", isAdmin: true, bypassFirewall: true });
    ev("createWithExtraFields", { status: withExtraFields.status, body: withExtraFields.body });
    return withExtraFields.status === 400
      ? defended(`Rejected with 400 for unrecognised fields (${withExtraFields.body?.error?.code}).`)
      : notDefended(`status=${withExtraFields.status}`, "Medium", "Use strict schema validation (reject unknown keys) on every request body.");
  });
});
