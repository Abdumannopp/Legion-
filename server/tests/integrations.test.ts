/**
 * The integration framework (src/integrations): Wazuh as one adapter, the
 * shared ingestion path, pull connections and their worker, and the limits
 * every adapter runs under.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { createHmac, randomUUID } from "node:crypto";
import { z } from "zod";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import { findingAlertId, ingestFindings } from "../src/integrations/ingest.js";
import { wazuhAdapter } from "../src/integrations/wazuh.js";
import * as registry from "../src/integrations/registry.js";
import * as connections from "../src/integrations/connections.js";
import { adapterFetch, EgressRefused, hostAllowed } from "../src/integrations/fetch.js";
import type { Finding, PullAdapter } from "../src/integrations/types.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, adminB: User, analystA: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;

/** A pull adapter under test control: what the "vendor" returns, and what it saw. */
const vendor = { findings: [] as Finding[], fail: null as string | null, calls: [] as { cursor: unknown; secrets: Record<string, string>; config: Record<string, unknown> }[], delayMs: 0 };
const fake: PullAdapter = {
  manifest: { kind: "fakecloud", displayName: "Fake cloud", vendor: "Test", status: "available", plane: "data", inbound: "pull", outbound: [], egressHosts: ["api.fake.example"], summary: "test", auth: "api key" },
  configSchema: z.object({ account: z.string().regex(/^\d{12}$/) }),
  secretFields: ["api_key"],
  async poll(conn, cursor) {
    vendor.calls.push({ cursor, secrets: conn.secrets, config: conn.config });
    if (vendor.delayMs) await new Promise((r) => setTimeout(r, vendor.delayMs));
    if (vendor.fail) throw new Error(vendor.fail);
    return { findings: vendor.findings, cursor: { after: (Number((cursor as { after?: number } | null)?.after ?? 0)) + vendor.findings.length } };
  },
};
const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({
  externalId: id, title: `Finding ${id}`, severity: "high", summary: `detail ${id}`, occurredAt: null, sourceIp: null, target: "i-0abc",
  mitre: ["T1078"], confidence: 80, asset: null, ...extra,
});
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...bearer(u)).send(body);
const validBody = { kind: "fakecloud", name: "Prod account", config: { account: "123456789012" }, secrets: { api_key: "vendor-secret-key-123" } };

beforeAll(async () => { await migrate(); registry.register(fake); });
afterAll(async () => { registry.unregister("fakecloud"); await closePool(); });
beforeEach(async () => {
  await truncateAll();
  vendor.findings = []; vendor.fail = null; vendor.calls = []; vendor.delayMs = 0;
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@alpha.io", password_hash: hash, tenant_id: tA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
});

describe("Wazuh is one adapter", () => {
  const event = { id: "1727650000.123", timestamp: "2026-09-29T10:00:00.000+0000", rule: { level: 10, description: "sshd: brute force", mitre: { id: ["T1110"] } },
    agent: { name: "web-01", ip: "10.0.0.5", os: { name: "Ubuntu" } }, data: { srcip: "45.155.205.12" }, full_log: "Failed password for root" };

  it("maps an event to a finding exactly as the webhook always did, keeping the alert id", () => {
    const r = wazuhAdapter.normalize({ provider: "wazuh", event });
    expect(r.skipped).toBe(false);
    if (r.skipped) return;
    expect(r.source).toBe("wazuh");
    expect(r.findings[0]).toMatchObject({ externalId: "1727650000.123", title: "sshd: brute force", severity: "high", sourceIp: "45.155.205.12",
      target: "web-01", mitre: ["T1110"], confidence: 70, occurredAt: "2026-09-29T10:00:00.000Z", asset: { name: "web-01", ip: "10.0.0.5", os: "Ubuntu" } });
    // The id formula of the original handler, verbatim.
    const legacy = `SEC-${createHmac("sha256", config.webhookSecret || "legion-webhook-event-id").update(`${tA}:wazuh:1727650000.123`).digest("hex").slice(0, 16).toUpperCase()}`;
    expect(findingAlertId(tA, "wazuh", "1727650000.123")).toBe(legacy);
  });

  it("never throws on hostile input, and skips what is not an alert", () => {
    for (const junk of [null, 42, "x", [], {}, { event: null }, { rule: {} }, { event: { rule: { description: 7, level: "NaN" } } },
      { event: { rule: { description: "d" }, data: { srcip: "not-an-ip" }, agent: { name: "x".repeat(10_000) } } }]) {
      expect(() => wazuhAdapter.normalize(junk)).not.toThrow();
    }
    expect(wazuhAdapter.normalize({ event: { rule: {} } })).toEqual({ skipped: true, reason: "no rule description" });
    const r = wazuhAdapter.normalize({ event: { rule: { description: "d" }, data: { srcip: "not-an-ip" }, agent: { name: "x".repeat(10_000) } } });
    if (r.skipped) throw new Error("expected a finding");
    expect(r.findings[0]!.sourceIp).toBeNull();
    expect(r.findings[0]!.target!.length).toBeLessThanOrEqual(255);
  });

  it("the webhook still ingests through it, once", async () => {
    const cred = await issueCredential(tA);
    const first = await sendSigned(app, cred, { provider: "wazuh", event });
    expect(first.status).toBe(202);
    expect(first.body.alert_id).toBe(findingAlertId(tA, "wazuh", "1727650000.123"));
    expect((await sendSigned(app, cred, { provider: "wazuh", event })).body).toMatchObject({ status: "skipped", reason: "duplicate" });
    expect((await store.listAssets(tA)).map((a) => a.name)).toEqual(["web-01"]);
  });
});

describe("the catalogue", () => {
  it("lists Wazuh as available and the roadmap as contracts", async () => {
    const res = await request(app).get("/integrations/catalogue").set(...bearer(analystA));
    const byKind = Object.fromEntries(res.body.integrations.map((i: { kind: string }) => [i.kind, i]));
    expect(byKind.wazuh).toMatchObject({ status: "available", inbound: "push", plane: "data" });
    for (const k of ["aws", "azure", "gcp", "github", "m365", "slack"]) expect(byKind[k]).toMatchObject({ status: "planned" });
    expect(byKind.mcp).toMatchObject({ plane: "tool", status: "available" });
    expect(byKind.a2a).toMatchObject({ plane: "tool" });
  });
});

describe("pull connections", () => {
  it("are created by admins only; secrets are sealed and never returned", async () => {
    expect((await create(analystA, validBody)).status).toBe(403);
    const res = await create(adminA, validBody);
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ kind: "fakecloud", name: "Prod account", has_secrets: true, config: { account: "123456789012" } });
    expect(JSON.stringify(res.body)).not.toContain("vendor-secret-key-123");
    const row = (await query("SELECT secrets_enc FROM integration_connections WHERE id = $1", [res.body.id])).rows[0];
    expect(row.secrets_enc).not.toContain("vendor-secret-key-123");
    expect(JSON.stringify((await request(app).get("/integrations").set(...bearer(adminA))).body)).not.toContain("vendor-secret-key-123");
  });

  it("validate the kind, the adapter's config schema and the required secrets", async () => {
    expect((await create(adminA, { ...validBody, kind: "aws" })).status).toBe(400); // planned, not available
    expect((await create(adminA, { ...validBody, kind: "wazuh" })).status).toBe(400); // push, configured elsewhere
    expect((await create(adminA, { ...validBody, config: { account: "12" } })).status).toBe(400);
    expect((await create(adminA, { ...validBody, secrets: {} })).status).toBe(400);
  });

  it("are polled: findings ingested once, cursor kept, secrets opened only for the adapter", async () => {
    const c = (await create(adminA, validBody)).body;
    vendor.findings = [finding("f-1"), finding("f-2", { severity: "critical" })];
    const r1 = await connections.runDuePolls();
    expect(r1).toMatchObject({ claimed: 1, succeeded: 1, ingested: 2, duplicates: 0 });
    expect(vendor.calls[0]).toMatchObject({ cursor: null, secrets: { api_key: "vendor-secret-key-123" }, config: { account: "123456789012" } });
    const alerts = await store.listAlerts(tA);
    expect(alerts.map((a) => a.source)).toEqual(["fakecloud", "fakecloud"]);
    expect(await store.listAlerts(tB)).toEqual([]);
    // Not due again until poll_seconds have passed.
    expect((await connections.runDuePolls()).claimed).toBe(0);
    // Re-delivered after a "crash" (same findings, due again): duplicates, not new alerts.
    await query("UPDATE integration_connections SET next_poll_at = now(), cursor = NULL WHERE id = $1", [c.id]);
    expect(await connections.runDuePolls()).toMatchObject({ ingested: 0, duplicates: 2 });
    expect((await store.listAlerts(tA))).toHaveLength(2);
  });

  it("each due connection is polled by exactly one instance at a time", async () => {
    await create(adminA, validBody);
    vendor.findings = [finding("f-1")];
    vendor.delayMs = 150;
    const [a, b, c] = await Promise.all([
      connections.runDuePolls({ owner: "instance-a" }), connections.runDuePolls({ owner: "instance-b" }), connections.runDuePolls({ owner: "instance-c" }),
    ]);
    expect(a.claimed + b.claimed + c.claimed).toBe(1);
    expect(vendor.calls).toHaveLength(1);
  });

  it("a stalled instance cannot overwrite the result of the one that took over its lease", async () => {
    const c = (await create(adminA, validBody)).body;
    await query("UPDATE integration_connections SET lease_owner = 'someone-else', lease_until = now() + interval '1 minute' WHERE id = $1", [c.id]);
    // Our instance believes it holds it (stale), writes back — refused by the fence.
    await query("UPDATE integration_connections SET cursor = '{\"after\":99}' WHERE id = $1 AND lease_owner = 'stale-instance'", [c.id]);
    expect((await query("SELECT cursor FROM integration_connections WHERE id = $1", [c.id])).rows[0].cursor).toBeNull();
    expect((await connections.runDuePolls()).claimed).toBe(0); // leased elsewhere
  });

  it("failures back off, are visible, and park the connection after repeated errors", async () => {
    const c = (await create(adminA, validBody)).body;
    vendor.fail = "vendor said 403: access denied";
    expect(await connections.runDuePolls()).toMatchObject({ claimed: 1, failed: 1 });
    const row = (await query("SELECT failures, last_error, status, next_poll_at > now() AS later FROM integration_connections WHERE id = $1", [c.id])).rows[0];
    expect(row).toMatchObject({ failures: 1, last_error: "vendor said 403: access denied", status: "active", later: true });
    await query("UPDATE integration_connections SET failures = 9, next_poll_at = now() WHERE id = $1", [c.id]);
    await connections.runDuePolls();
    expect((await query("SELECT status FROM integration_connections WHERE id = $1", [c.id])).rows[0].status).toBe("error");
    // An admin resumes it (after fixing the cause): due immediately, count reset.
    vendor.fail = null;
    expect((await request(app).post(`/integrations/${c.id}/resume`).set(...bearer(adminA))).body).toMatchObject({ status: "active", failures: 0 });
    expect((await connections.runDuePolls()).succeeded).toBe(1);
  });

  it("belong to their workspace: another workspace can neither see nor change them", async () => {
    const c = (await create(adminA, validBody)).body;
    expect((await request(app).get("/integrations").set(...bearer(adminB))).body.connections).toEqual([]);
    for (const res of [
      await request(app).post(`/integrations/${c.id}/pause`).set(...bearer(adminB)),
      await request(app).delete(`/integrations/${c.id}`).set(...bearer(adminB)),
    ]) expect(res.status).toBe(404);
    expect((await request(app).get("/integrations").set(...bearer(adminA))).body.connections[0].status).toBe("active");
  });

  it("removal stops polling and forgets the credentials", async () => {
    const c = (await create(adminA, validBody)).body;
    expect((await request(app).delete(`/integrations/${c.id}`).set(...bearer(adminA))).status).toBe(200);
    expect((await query("SELECT status, secrets_enc FROM integration_connections WHERE id = $1", [c.id])).rows[0]).toEqual({ status: "disabled", secrets_enc: null });
    expect((await connections.runDuePolls()).claimed).toBe(0);
  });
});

describe("what an adapter may reach", () => {
  it("only HTTPS, only its declared vendor hosts, no redirects to elsewhere", async () => {
    const m = { egressHosts: ["api.fake.example", "securityhub.*.amazonaws.com"] };
    expect(hostAllowed(m, "api.fake.example")).toBe(true);
    expect(hostAllowed(m, "securityhub.eu-west-1.amazonaws.com")).toBe(true);
    for (const h of ["evil.example", "api.fake.example.evil.io", "securityhub.a.b.amazonaws.com", "169.254.169.254", "localhost"]) expect(hostAllowed(m, h)).toBe(false);
    await expect(adapterFetch(m, "http://api.fake.example/x")).rejects.toBeInstanceOf(EgressRefused);
    await expect(adapterFetch(m, "https://169.254.169.254/latest/meta-data")).rejects.toBeInstanceOf(EgressRefused);
    await expect(adapterFetch(m, "https://user:pw@api.fake.example/")).rejects.toBeInstanceOf(EgressRefused);
  });
});

describe("data residency", () => {
  it("a workspace in another region is not served here: API, webhook and worker", async () => {
    const cred = await issueCredential(tA);
    await create(adminA, validBody);
    await query("UPDATE tenants SET region = 'us-east' WHERE id = $1", [tA]);
    const api = await request(app).get("/alerts").set(...bearer(adminA));
    expect(api.status).toBe(421);
    expect(api.body).toMatchObject({ region: "us-east" });
    const hook = await sendSigned(app, cred, { event: { id: "x", rule: { description: "d", level: 3 } } });
    expect(hook.status).toBe(421);
    expect(await store.listAlerts(tA)).toEqual([]);
    expect((await connections.runDuePolls()).claimed).toBe(0);
    // Workspaces from before regions (NULL) belong to this deployment.
    expect((await request(app).get("/alerts").set(...bearer(adminB))).status).toBe(200);
  });

  it("ingestion is idempotent whatever the source, per workspace", async () => {
    const one = await ingestFindings(tA, "fakecloud", [finding("same")]);
    const two = await ingestFindings(tA, "fakecloud", [finding("same")]);
    const other = await ingestFindings(tB, "fakecloud", [finding("same")]);
    expect([one.ingested.length, two.duplicates.length, other.ingested.length]).toEqual([1, 1, 1]);
    expect(one.ingested[0]).not.toBe(other.ingested[0]);
  });
});
