/**
 * Outbound connectors (Slack notification, Jira ticket): delivery through the outbox, provider downtime,
 * tenant isolation, secrets, health, idempotent tickets, and the rule that they can only notify or ticket.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { ingestFindings } from "../src/integrations/ingest.js";
import { deliverDue } from "../src/outbox.js";
import * as registry from "../src/integrations/registry.js";
import * as connections from "../src/integrations/connections.js";
import type { Finding } from "../src/integrations/types.js";
import type { User } from "../src/types.js";

const HOOK = "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX";
let tA: string, tB: string, adminA: User, adminB: User, analystA: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({ externalId: id, title: `Alert ${id}`, severity: "high", summary: `detail ${id}`, occurredAt: null, sourceIp: "203.0.113.5", target: "web-1", mitre: [], confidence: 70, asset: null, ...extra });
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...bearer(u)).send(body);
const slackBody = { kind: "slack", name: "SOC channel", config: { min_severity: "high" }, secrets: { webhook_url: HOOK } };
const jiraBody = { kind: "jira", name: "SEC board", config: { site: "acme", project_key: "SEC", min_severity: "high" }, secrets: { email: "bot@acme.io", api_token: "jira-token-very-secret" } };
const due = () => query("UPDATE notification_outbox SET next_attempt_at = now() WHERE status = 'pending'");
const outbox = () => query<{ status: string; attempts: number; last_error: string | null; payload: Record<string, unknown>; recipient: string; tenant_id: string }>(
  "SELECT status, attempts, last_error, payload, recipient, tenant_id FROM notification_outbox WHERE kind = 'integration_message' ORDER BY created_at").then((r) => r.rows);

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[], respond: (c: Call) => { status: number; body?: string };
const realFetch = globalThis.fetch;
beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  analystA = await store.insertUser({ email: "analyst@alpha.io", password_hash: hash, tenant_id: tA, role: "analyst", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
  calls = []; respond = () => ({ status: 200, body: "ok" });
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const c: Call = { url: String(input), method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>)), body: String(init.body ?? "") };
    calls.push(c);
    const r = respond(c);
    return new Response(r.body ?? "", { status: r.status });
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; vi.restoreAllMocks(); });

describe("connections", () => {
  it("catalogue: Slack and Jira are available, notify/ticket only", () => {
    for (const k of ["slack", "jira"]) {
      const m = registry.catalogue().find((x) => x.kind === k)!;
      expect(m.status).toBe("available");
      expect(m.outbound).not.toContain("respond");
      expect(registry.outboundAdapter(k)).not.toBeNull();
    }
  });
  it("an administrator creates one; secrets are sealed and never returned", async () => {
    const r = await create(adminA, slackBody);
    expect(r.status).toBe(201);
    expect(JSON.stringify(r.body)).not.toContain("XXXXXXXX");
    expect(r.body.has_secrets).toBe(true);
    const rows = (await query<{ secrets_enc: string }>("SELECT secrets_enc FROM integration_connections")).rows;
    expect(rows[0]!.secrets_enc).not.toContain("hooks.slack.com");
    expect((await request(app).get("/integrations").set(...bearer(adminA))).text).not.toContain("XXXXXXXX");
  });
  it("an analyst cannot; bad config and a foreign Slack URL are refused", async () => {
    expect((await create(analystA, slackBody)).status).toBe(403);
    expect((await create(adminA, { ...slackBody, secrets: { webhook_url: "https://evil.example/services/x" } })).status).toBe(400);
    expect((await create(adminA, { ...jiraBody, config: { site: "acme.evil.com", project_key: "SEC" } })).status).toBe(400);
    expect((await create(adminA, { ...jiraBody, config: { site: "acme", project_key: "sec; DROP" } })).status).toBe(400);
  });
  it("the poll worker never claims an outbound connection", async () => {
    await create(adminA, slackBody);
    const r = await connections.runDuePolls({});
    expect(r.claimed).toBe(0);
  });
});

describe("Slack delivery", () => {
  it("an alert at or above min_severity becomes one Slack message, once", async () => {
    await create(adminA, slackBody);
    await ingestFindings(tA, "wazuh", [finding("a1"), finding("low1", { severity: "low" })]);
    await deliverDue({ kind: "integration_message" });
    // the low alert is queued but filtered by the adapter (no call)
    const slackCalls = calls.filter((c) => c.url === HOOK);
    expect(slackCalls).toHaveLength(1);
    const sent = JSON.parse(slackCalls[0]!.body);
    expect(sent.text).toContain("HIGH");
    expect(sent.text).toContain("Alert a1");
    // same finding again: no second message
    await ingestFindings(tA, "wazuh", [finding("a1")]);
    await deliverDue({ kind: "integration_message" });
    expect(calls.filter((c) => c.url === HOOK)).toHaveLength(1);
  });
  it("neutralises markup and mentions from untrusted alert text", async () => {
    await create(adminA, slackBody);
    await ingestFindings(tA, "wazuh", [finding("x", { title: "<!channel> *click* <https://evil.example|here>" })]);
    await deliverDue({ kind: "integration_message" });
    const text = JSON.parse(calls[0]!.body).text as string;
    expect(text).not.toContain("<!channel>");
    expect(text).not.toContain("<https");
  });
  it("provider downtime: retried with backoff, delivered when it is back, nothing lost", async () => {
    await create(adminA, slackBody);
    respond = () => ({ status: 503 });
    await ingestFindings(tA, "wazuh", [finding("d1")]);
    await deliverDue({ kind: "integration_message" });
    let [row] = await outbox();
    expect(row).toMatchObject({ status: "pending", attempts: 1 });
    respond = () => ({ status: 200, body: "ok" });
    await due(); await deliverDue({ kind: "integration_message" });
    [row] = await outbox();
    expect(row).toMatchObject({ status: "sent" });
  });
  it("429 is retried; a revoked webhook (404) is dead-lettered at once and shown in the connection's health", async () => {
    await create(adminA, slackBody);
    respond = () => ({ status: 429 });
    await ingestFindings(tA, "wazuh", [finding("r1")]);
    await deliverDue({ kind: "integration_message" });
    expect((await outbox())[0]!.status).toBe("pending");
    respond = () => ({ status: 404, body: "no_service" });
    await due(); await deliverDue({ kind: "integration_message" });
    expect((await outbox())[0]).toMatchObject({ status: "dead" });
    const list = (await request(app).get("/integrations").set(...bearer(adminA))).body;
    const conn = list.connections[0];
    expect(conn.failures).toBeGreaterThanOrEqual(1);
    expect(conn.last_error).toMatch(/Slack/);
    expect(JSON.stringify(conn)).not.toContain("XXXXXXXX");
  });
  it("a successful delivery clears the error and records last_success_at", async () => {
    await create(adminA, slackBody);
    respond = () => ({ status: 500 });
    await ingestFindings(tA, "wazuh", [finding("h1")]);
    await deliverDue({ kind: "integration_message" });
    respond = () => ({ status: 200, body: "ok" });
    await due(); await deliverDue({ kind: "integration_message" });
    const [c] = (await query<{ failures: number; last_error: string | null; last_success_at: string | null }>("SELECT failures, last_error, last_success_at FROM integration_connections")).rows;
    expect(c).toMatchObject({ failures: 0, last_error: null });
    expect(c!.last_success_at).not.toBeNull();
  });
  it("a paused connection receives nothing new; removing it drops pending messages quietly", async () => {
    const c = (await create(adminA, slackBody)).body;
    await request(app).post(`/integrations/${c.id}/pause`).set(...bearer(adminA));
    await ingestFindings(tA, "wazuh", [finding("p1")]);
    expect(await outbox()).toHaveLength(0);
    await request(app).post(`/integrations/${c.id}/resume`).set(...bearer(adminA));
    await ingestFindings(tA, "wazuh", [finding("p2")]);
    await connections.setStatus(tA, c.id, "disabled");
    await deliverDue({ kind: "integration_message" });
    expect(calls).toHaveLength(0);
    expect((await outbox())[0]!.status).toBe("sent");
  });
  it("never leaks a secret into the stored error, even if the provider echoes it", async () => {
    await create(adminA, slackBody);
    respond = () => { throw new Error(`boom ${HOOK} Bearer abc.def`); };
    await ingestFindings(tA, "wazuh", [finding("s1")]);
    await deliverDue({ kind: "integration_message" });
    const [row] = await outbox();
    expect(`${row!.last_error} ${(await query<{ last_error: string }>("SELECT last_error FROM integration_connections")).rows[0]!.last_error}`).not.toMatch(/XXXXXXXX|abc\.def/);
  });
});

describe("fan-out cost (audit A-5)", () => {
  it("queries per new alert do not grow with the number of connections, and every connection still gets its message once", async () => {
    const { enqueueIntegrationMessages } = await import("../src/integration-notify.js");
    const { pool } = await import("../src/db/pool.js");
    // Alerts are stored first, while no connection exists, so nothing is queued yet.
    await ingestFindings(tA, "wazuh", [finding("fan1"), finding("fan2")]);
    const alertOf = async (ext: string) => (await query<{ id: string }>("SELECT id FROM alerts WHERE tenant_id = $1 AND title = $2", [tA, `Alert ${ext}`])).rows[0]!.id;
    const measure = async (ext: string) => {
      const alert = (await store.getAlert(tA, await alertOf(ext)))!;
      let n = 0;
      const client = { query: (...a: unknown[]) => { n++; return pool.query(...(a as [string, unknown[]])); } };
      const queued = await enqueueIntegrationMessages(client as never, alert);
      return { n, queued, alert };
    };
    await create(adminA, slackBody);
    const one = await measure("fan1");
    for (let i = 0; i < 6; i++) expect((await create(adminA, { ...slackBody, name: `chan ${i}` })).status).toBe(201);
    const seven = await measure("fan2");
    expect(one.queued).toBe(1);
    expect(seven.queued).toBe(7);
    expect(seven.n).toBe(one.n);                 // constant: 3 queries either way
    expect(seven.n).toBeLessThanOrEqual(3);
    // the same alert again is a no-op
    expect((await measure("fan2")).queued).toBe(0);
  });
});

describe("tenant isolation", () => {
  it("workspace B's Slack never receives workspace A's alerts, and A cannot see or change B's connection", async () => {
    await create(adminA, slackBody);
    const b = (await create(adminB, { ...slackBody, secrets: { webhook_url: "https://hooks.slack.com/services/T9999999/B9999999/YYYYYYYYYYYYYYYYYYYYYYYY" } })).body;
    await ingestFindings(tA, "wazuh", [finding("iso1")]);
    await deliverDue({ kind: "integration_message" });
    expect(calls.map((c) => c.url)).toEqual([HOOK]);
    expect((await outbox()).every((r) => r.tenant_id === tA)).toBe(true);
    expect((await request(app).post(`/integrations/${b.id}/pause`).set(...bearer(adminA))).status).toBe(404);
    expect((await request(app).delete(`/integrations/${b.id}`).set(...bearer(adminA))).status).toBe(404);
  });
});

describe("Jira tickets", () => {
  const jiraRespond = (state: { exists: boolean; created: number }) => (c: Call) => {
    if (c.url.includes("/search/jql")) return { status: 200, body: JSON.stringify({ issues: state.exists ? [{ key: "SEC-7" }] : [] }) };
    if (c.url.endsWith("/rest/api/3/issue")) { state.created++; return { status: 201, body: JSON.stringify({ key: "SEC-8" }) }; }
    return { status: 404 };
  };
  it("opens one ticket per alert on acme.atlassian.net with Basic auth, and remembers the key", async () => {
    await create(adminA, jiraBody);
    const state = { exists: false, created: 0 }; respond = jiraRespond(state);
    await ingestFindings(tA, "wazuh", [finding("j1")]);
    await deliverDue({ kind: "integration_message" });
    expect(state.created).toBe(1);
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.url).toBe("https://acme.atlassian.net/rest/api/3/issue");
    expect(post.headers.authorization).toMatch(/^Basic /);
    expect(JSON.parse(post.body).fields.labels).toContain("severity-high");
    expect((await outbox())[0]).toMatchObject({ status: "sent", payload: { ticket: { key: "SEC-8", url: "https://acme.atlassian.net/browse/SEC-8" } } });
  });
  it("the alert page shows which ticket an alert became; another workspace gets 404", async () => {
    await create(adminA, jiraBody);
    respond = jiraRespond({ exists: false, created: 0 });
    await ingestFindings(tA, "wazuh", [finding("j9")]);
    await deliverDue({ kind: "integration_message" });
    const alertId = (await query<{ id: string }>("SELECT id FROM alerts WHERE tenant_id = $1", [tA])).rows[0]!.id;
    const r = await request(app).get(`/alerts/${alertId}/deliveries`).set(...bearer(analystA));
    expect(r.status).toBe(200);
    expect(r.body.deliveries).toEqual([expect.objectContaining({ connection: "SEC board", kind: "jira", status: "sent", ticket: { key: "SEC-8", url: "https://acme.atlassian.net/browse/SEC-8" } })]);
    expect(JSON.stringify(r.body)).not.toContain("jira-token");
    expect((await request(app).get(`/alerts/${alertId}/deliveries`).set(...bearer(adminB))).status).toBe(404);
    // the message links back to the real dashboard route
    expect(JSON.parse(calls.find((c) => c.method === "POST")!.body).fields.description.content.at(-1).content[0].text).toMatch(/\/incident\//);
  });
  it("a retry finds the existing ticket instead of creating a second one", async () => {
    await create(adminA, jiraBody);
    const state = { exists: true, created: 0 }; respond = jiraRespond(state);
    await ingestFindings(tA, "wazuh", [finding("j2")]);
    await deliverDue({ kind: "integration_message" });
    expect(state.created).toBe(0);
    expect((await outbox())[0]!.payload).toMatchObject({ ticket: { key: "SEC-7" } });
  });
  it("A-6: a create whose answer was lost is not repeated while Jira's index may not show it yet", async () => {
    await create(adminA, jiraBody);
    let created = 0, indexed = false;
    respond = (c) => {
      if (c.url.includes("/search/jql")) return { status: 200, body: JSON.stringify({ issues: indexed ? [{ key: "SEC-9" }] : [] }) };
      if (c.url.endsWith("/rest/api/3/issue")) { created++; return { status: 504 }; }   // Jira made the ticket, the answer was lost
      return { status: 404 };
    };
    await ingestFindings(tA, "wazuh", [finding("j6")]);
    await deliverDue({ kind: "integration_message" });
    expect(created).toBe(1);
    // an immediate retry: the search is still empty (index lag), but Legion must not create again
    await due(); await deliverDue({ kind: "integration_message" });
    await due(); await deliverDue({ kind: "integration_message" });
    expect(created).toBe(1);
    expect((await outbox())[0]!.last_error).toMatch(/waiting for Jira to index/);
    // waiting is not failing: the connection's health counts the lost answer once, not each wait
    expect((await query("SELECT failures, status FROM integration_connections WHERE tenant_id = $1", [tA])).rows[0]).toMatchObject({ failures: 1, status: "active" });
    // the index catches up: the retry finds the ticket and stops
    indexed = true;
    await query("UPDATE notification_outbox SET payload = jsonb_set(payload, '{createAttemptedAt}', to_jsonb((now() - interval '3 minutes')::text)) WHERE kind = 'integration_message'");
    await due(); await deliverDue({ kind: "integration_message" });
    expect(created).toBe(1);
    expect((await outbox())[0]).toMatchObject({ status: "sent", payload: { ticket: { key: "SEC-9" } } });
  });
  it("A-6: the new ticket key is stored at once; a retry after a crash reads that issue instead of searching", async () => {
    await create(adminA, jiraBody);
    let created = 0; const searches: string[] = [];
    respond = (c) => {
      if (c.url.includes("/search/jql")) { searches.push(c.url); return { status: 200, body: JSON.stringify({ issues: [] }) }; }   // index lag
      if (c.url.endsWith("/rest/api/3/issue")) { created++; return { status: 201, body: JSON.stringify({ key: "SEC-8" }) }; }
      if (c.url.includes("/rest/api/3/issue/SEC-8")) return { status: 200, body: "{}" };
      return { status: 404 };
    };
    await ingestFindings(tA, "wazuh", [finding("j7")]);
    await deliverDue({ kind: "integration_message" });
    expect(created).toBe(1);
    // simulate the worker dying before the row was marked sent
    await query("UPDATE notification_outbox SET status = 'pending', sent_at = NULL, next_attempt_at = now() WHERE kind = 'integration_message'");
    searches.length = 0;
    await deliverDue({ kind: "integration_message" });
    expect(created).toBe(1);
    expect(searches).toHaveLength(0);
    expect((await outbox())[0]).toMatchObject({ status: "sent", payload: { ticket: { key: "SEC-8" } } });
  });
  it("A-7: the ticket link stays on the alert after the delivered message is pruned", async () => {
    await create(adminA, jiraBody);
    const state = { exists: false, created: 0 }; respond = jiraRespond(state);
    await ingestFindings(tA, "wazuh", [finding("j8")]);
    await deliverDue({ kind: "integration_message" });
    const id = (await query<{ id: string }>("SELECT id FROM alerts WHERE tenant_id = $1 AND title = 'Alert j8'", [tA])).rows[0]!.id;
    const show = async (u: User) => (await request(app).get(`/alerts/${id}/deliveries`).set(...bearer(u))).body.deliveries;
    expect(await show(adminA)).toEqual([expect.objectContaining({ kind: "jira", ticket: { key: "SEC-8", url: "https://acme.atlassian.net/browse/SEC-8" } })]);
    // retention removes the delivered row (NOTIFY_RETENTION_DAYS)
    await query("DELETE FROM notification_outbox WHERE kind = 'integration_message'");
    const after = await show(adminA);
    expect(after).toHaveLength(1);
    expect(after[0]).toMatchObject({ connection: "SEC board", kind: "jira", status: "sent", ticket: { key: "SEC-8", url: "https://acme.atlassian.net/browse/SEC-8" } });
    // another workspace still cannot see it
    expect((await request(app).get(`/alerts/${id}/deliveries`).set(...bearer(adminB))).status).toBe(404);
    // a duplicated entry is shown once
    await query("UPDATE alerts SET tickets = tickets || tickets WHERE tenant_id = $1 AND id = $2", [tA, id]);
    expect(await show(adminA)).toHaveLength(1);
  });
  it("bad credentials (401) are not retried; a Jira outage is", async () => {
    await create(adminA, jiraBody);
    respond = () => ({ status: 401 });
    await ingestFindings(tA, "wazuh", [finding("j3")]);
    await deliverDue({ kind: "integration_message" });
    expect((await outbox())[0]!.status).toBe("dead");
    respond = () => ({ status: 503 });
    await ingestFindings(tA, "wazuh", [finding("j4")]);
    await deliverDue({ kind: "integration_message" });
    expect((await outbox())[1]!.status).toBe("pending");
  });
  it("the credentials never appear in any request URL or the stored rows", async () => {
    await create(adminA, jiraBody);
    respond = jiraRespond({ exists: false, created: 0 });
    await ingestFindings(tA, "wazuh", [finding("j5")]);
    await deliverDue({ kind: "integration_message" });
    expect(calls.map((c) => c.url).join(" ")).not.toContain("jira-token-very-secret");
    expect(JSON.stringify(await outbox())).not.toContain("jira-token-very-secret");
  });
});

describe("outbound connectors cannot act", () => {
  it("claim no response capability and import no response code", () => {
    for (const k of ["slack", "jira"]) {
      expect(registry.outboundAdapter(k)!.manifest.outbound.every((o) => o === "notify" || o === "ticket")).toBe(true);
      const src = readFileSync(new URL(`../src/integrations/${k}.ts`, import.meta.url), "utf8");
      expect(src).not.toMatch(/blocklist|actions\/|policy\/|approval/);
    }
    const glue = readFileSync(new URL("../src/integration-notify.ts", import.meta.url), "utf8");
    expect(glue).not.toMatch(/blocklist|actions\/engine|actions\/live/);
  });
});
