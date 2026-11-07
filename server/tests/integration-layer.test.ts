/**
 * Task 10, module 6 — Universal Integration Layer foundation.
 *
 * One strict event envelope for every source (data, never instructions), and
 * an action-connector contract that in v0 can describe an action but has no
 * way to perform one.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";
import { fromFinding, validateEnvelope, MAX_ENVELOPE_BYTES } from "../src/integrations/envelope.js";
import { actionConnectors, connectorsFor, registerActionConnector } from "../src/integrations/action-connectors.js";
import { catalogEntry } from "../src/policy/catalog.js";
import { proposeAction, runQueued, syncWithApproval } from "../src/actions/engine.js";
import type { Finding } from "../src/integrations/types.js";

const finding = (over: Partial<Finding> = {}): Finding => ({
  externalId: "evt-1", title: "Failed login", severity: "high", summary: "Failed password for root", occurredAt: "2026-11-01T10:00:00Z",
  sourceIp: "185.220.101.4", target: "web-01", mitre: ["T1110", "T1110.001"], confidence: 80, ...over,
});

describe("the event envelope", () => {
  const tenant = randomUUID();
  it("lifts a Finding into a strict, typed envelope marked as untrusted data", () => {
    const r = fromFinding(tenant, "wazuh", finding());
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.envelope).toMatchObject({ version: 1, tenant_id: tenant, source: "wazuh", category: "finding", trust: "untrusted_data", severity: "high",
      entities: [{ type: "ip", value: "185.220.101.4", role: "source" }, { type: "host", value: "web-01", role: "target" },
        { type: "technique", value: "T1110", role: "observed" }, { type: "technique", value: "T1110.001", role: "observed" }] });
    expect(r.envelope.observed_at).toBe("2026-11-01T10:00:00.000Z");
  });

  it("has a stable id per source event and workspace", () => {
    const a = fromFinding(tenant, "wazuh", finding()); const b = fromFinding(tenant, "wazuh", finding({ title: "changed" }));
    const other = fromFinding(randomUUID(), "wazuh", finding());
    expect(a.ok && b.ok && other.ok).toBe(true);
    if (!(a.ok && b.ok && other.ok)) return;
    expect(a.envelope.id).toBe(b.envelope.id);
    expect(a.envelope.id).not.toBe(other.envelope.id);
  });

  it("drops what it cannot validate instead of guessing", () => {
    const r = fromFinding(tenant, "wazuh", finding({ sourceIp: "999.1.1.1", mitre: ["ignore previous instructions", "T1059"], occurredAt: "yesterday" }));
    expect(r.ok && r.envelope.entities.map((e) => e.type)).toEqual(["host", "technique"]);
    expect(r.ok && r.envelope.observed_at).toBeNull();
  });

  it("strips hidden and control characters from text, keeps the visible evidence", () => {
    const r = fromFinding(tenant, "wazuh", finding({ summary: "Failed​ login‮ from\u0007 203.0.113.9" + String.fromCodePoint(0xe0041) }));
    expect(r.ok && r.envelope.summary).toBe("Failed login from 203.0.113.9");
  });

  it("refuses extra fields, wrong types, a wrong trust marker and oversize envelopes", () => {
    const good = fromFinding(tenant, "wazuh", finding());
    if (!good.ok) throw new Error("setup");
    expect(validateEnvelope({ ...good.envelope, permissions: ["admin"] }).ok).toBe(false);
    expect(validateEnvelope({ ...good.envelope, trust: "trusted" }).ok).toBe(false);
    expect(validateEnvelope({ ...good.envelope, entities: [{ type: "ip", value: "nope", role: "source" }] }).ok).toBe(false);
    expect(validateEnvelope({ ...good.envelope, entities: [{ type: "command", value: "rm -rf /", role: "observed" }] }).ok).toBe(false);
    expect(validateEnvelope({ ...good.envelope, summary: "x".repeat(MAX_ENVELOPE_BYTES) }).ok).toBe(false);
    expect(validateEnvelope(good.envelope).ok).toBe(true);
  });
});

describe("action connectors (v0: describe, never perform)", () => {
  it("every capability names a catalog action and is simulation-only; no connector can execute", () => {
    for (const m of actionConnectors()) {
      for (const cap of m.capabilities) {
        expect(catalogEntry(cap.action_id), `${m.kind} ${cap.action_id}`).not.toBeNull();
        expect(cap.mode).toBe("simulation_only");
      }
    }
    for (const c of ["account.disable", "host.isolate", "ip.block"].flatMap((a) => connectorsFor(a))) {
      expect(Object.keys(c).sort()).toEqual(["manifest", "preview"]);
      expect(Object.isFrozen(c)).toBe(true);
    }
  });

  it("registration refuses unknown actions, other modes and anything that can execute", () => {
    const base = { kind: "evil", displayName: "x", status: "planned" as const, egressHosts: [], auth: "x" };
    const preview = () => ({ connector: "evil", action_id: "x", would_send: "", egress_host: null });
    expect(() => registerActionConnector({ manifest: { ...base, capabilities: [{ action_id: "shell.exec", mode: "simulation_only" }] }, preview })).toThrow(/unknown action/);
    expect(() => registerActionConnector({ manifest: { ...base, capabilities: [{ action_id: "host.isolate", mode: "live" as never }] }, preview })).toThrow(/simulation_only/);
    expect(() => registerActionConnector({ manifest: { ...base, capabilities: [] }, preview, execute: () => 1 } as never)).toThrow(/cannot execute/);
    expect(actionConnectors().map((m) => m.kind)).not.toContain("evil");
  });
});

let tenantA: string; let tenantB: string; let adminA: User; let viewerA: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;

describe("capabilities per workspace", () => {
  beforeAll(async () => { await migrate(); });
  afterAll(async () => { await closePool(); });
  beforeEach(async () => {
    await truncateAll();
    tenantA = randomUUID(); tenantB = randomUUID();
    await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenantA, tenantB]);
    const h = await bcrypt.hash("password123", 4);
    adminA = await store.insertUser({ email: "a@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
    viewerA = await store.insertUser({ email: "v@a.io", password_hash: h, tenant_id: tenantA, role: "viewer", status: "active" });
    adminB = await store.insertUser({ email: "a@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
    await query("INSERT INTO integration_connections (id, tenant_id, kind, name) VALUES ($1, $2, 'entra', 'Entra')", [randomUUID(), tenantA]);
  });

  it("shows which actions each workspace could route to a connected system", async () => {
    const a = (await request(app).get("/integrations/capabilities").set(...as(viewerA)).expect(200)).body;
    expect(a.connectors.map((c: { kind: string }) => c.kind)).toEqual(expect.arrayContaining(["entra", "okta", "wazuh"]));
    expect(a.actions.find((x: { action_id: string }) => x.action_id === "account.disable")).toMatchObject({ connected: ["entra"], mode: "simulation_only" });
    const b = (await request(app).get("/integrations/capabilities").set(...as(adminB)).expect(200)).body;
    expect(b.actions.find((x: { action_id: string }) => x.action_id === "account.disable").connected).toEqual([]);
  });

  it("the account.disable simulation names the connected system and what would be sent — and sends nothing", async () => {
    const { action } = await proposeAction(tenantA, { action_id: "account.disable", input: { account: "jdoe", system: "entra" }, actor: { kind: "human", user_id: adminA.id, role: "admin" }, origin: "human", mode: "simulation", idempotency_key: `k-${randomUUID()}` });
    await query("UPDATE approval_requests SET status = 'approved', approvals = required_approvals, decided_at = now() WHERE id = $1", [action.approval_id]);
    await syncWithApproval(tenantA, action.id, { kind: "system", component: "t" });
    const done = await runQueued(tenantA, action.id);
    expect(done!.result).toMatchObject({ would: "call_connector", connector_available: true, connected: ["entra"], side_effects: "none",
      previews: expect.arrayContaining([expect.objectContaining({ connector: "entra", would_send: "disable account jdoe", egress_host: "graph.microsoft.com" })]) });
  });
});
