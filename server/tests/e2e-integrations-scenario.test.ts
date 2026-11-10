/**
 * Demonstration: an attack investigated end to end through the connectors (simulated providers).
 *
 *   Microsoft Defender XDR (pull) + firewall CEF (push) + Elastic alert (generic webhook) — one attacker
 *   → Legion correlates them into one campaign
 *   → Slack is told and a Jira ticket is opened (the ticket is visible on the alert)
 *   → the five agents investigate; Vanguard proposes blocking the address; a PERSON approves
 *   → the action is simulated, nothing real changes; the audit chain verifies.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { putPolicy } from "../src/policy/store.js";
import { flushShadow } from "../src/policy/shadow.js";
import { deliverDue } from "../src/outbox.js";
import * as connections from "../src/integrations/connections.js";
import { createAgents, investigate, verify } from "./helpers/soc-conductor.js";
import { issueCredential, sendSigned } from "./helpers/webhook.js";
import type { User } from "../src/types.js";

const ATTACKER = "45.155.205.66"; // public (documentation ranges like 203.0.113.0/24 are rightly "cannot block")
const HOOK = "https://hooks.slack.com/services/T0000000/B0000000/ZZZZZZZZZZZZZZZZZZZZZZZZ";
const savedMode = config.deploymentMode;
let tenant: string, admin: User;
const token = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });
const as = (u: User) => ["Authorization", `Bearer ${token(u)}`] as const;

type Call = { url: string; method: string; body: string };
let calls: Call[]; let jiraCreated: number;
const realFetch = globalThis.fetch;
const now = () => new Date(Date.now() - 60_000).toISOString();

beforeAll(async () => { await migrate(); config.deploymentMode = "self-hosted"; });
afterAll(async () => { await flushShadow(); config.deploymentMode = savedMode; await closePool(); });
beforeEach(async () => {
  await flushShadow(); await truncateAll();
  config.policyEngineMode = "shadow"; config.orchestratorAutoMode = "off";
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'Acme', 'business')", [tenant]);
  admin = await store.insertUser({ email: "soc@acme.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenant, role: "admin", status: "active" });
  calls = []; jiraCreated = 0;
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const c: Call = { url: String(input), method: String(init.method ?? "GET"), body: String(init.body ?? "") };
    calls.push(c);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
    if (c.url.includes("login.microsoftonline.com")) return json(200, { access_token: "t" });
    if (c.url.includes("graph.microsoft.com")) return json(200, { value: [{
      id: "da-1", title: "Suspicious PowerShell on laptop-7", severity: "high", description: "Encoded PowerShell", createdDateTime: now(), lastUpdateDateTime: now(),
      mitreTechniques: ["T1059.001"], evidence: [{ "@odata.type": "#microsoft.graph.security.ipEvidence", ipAddress: ATTACKER }, { "@odata.type": "#microsoft.graph.security.deviceEvidence", deviceDnsName: "laptop-7" }],
    }] });
    if (c.url.startsWith("https://hooks.slack.com/")) return new Response("ok", { status: 200 });
    if (c.url.includes("/search/jql")) return json(200, { issues: [] });
    if (c.url.endsWith("/rest/api/3/issue")) { jiraCreated++; return json(201, { key: `SEC-${jiraCreated}` }); }
    return new Response("", { status: 404 });
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

describe("attack investigation through the connectors", () => {
  it("three sources, one campaign, Slack + Jira told, investigated, a person approves, simulated, audited", async () => {
    await putPolicy(tenant, { schema: 1, rules: [], default_autonomy: "ASSIST" } as never, { expectedVersion: 0, userId: admin.id });
    const post = (body: Record<string, unknown>) => request(app).post("/integrations").set(...as(admin)).send(body).expect(201);
    await post({ kind: "slack", name: "SOC", config: { min_severity: "high" }, secrets: { webhook_url: HOOK } });
    await post({ kind: "jira", name: "SEC", config: { site: "acme", project_key: "SEC", min_severity: "high" }, secrets: { email: "bot@acme.io", api_token: "token-xyz-123" } });
    await post({ kind: "m365", name: "Defender", config: { directory_id: randomUUID(), client_id: randomUUID() }, secrets: { client_secret: "secret-abc-123" } });
    const cred = await issueCredential(tenant);

    // 1. Three different products report the same attacker, each with a different technique.
    expect(await connections.runDuePolls({})).toMatchObject({ succeeded: 1, ingested: 1 });
    await sendSigned(app, cred, `CEF:0|Acme|Firewall|1|100|Port scan from ${ATTACKER}|8|src=${ATTACKER} dhost=web-1 cs1=T1046 externalId=fw-1`, { path: "/security-events/webhook/cef", contentType: "text/plain" }).expect(202);
    await sendSigned(app, cred, { "kibana.alert.rule.name": "SSH brute force", "kibana.alert.severity": "high", "kibana.alert.uuid": "k-1", source: { ip: ATTACKER }, host: { name: "web-1" }, mitre: "T1110" }, { path: "/security-events/webhook/generic" }).expect(202);
    const alerts = (await query<{ id: string; source: string }>("SELECT id, source FROM alerts WHERE tenant_id = $1 AND source_ip = $2 AND source <> 'legion-correlation' ORDER BY created_at", [tenant, ATTACKER])).rows;
    expect(alerts.map((a) => a.source).sort()).toEqual(["cef", "generic_webhook", "m365"]);

    // 2. Legion correlates them: one address, three techniques in minutes.
    const campaigns = (await request(app).get("/security/campaigns").set(...as(admin)).expect(200)).body.campaigns as Array<{ rule: string; subject: string }>;
    // …and announces it as an alert of its own.
    expect((await query("SELECT 1 FROM alerts WHERE tenant_id = $1 AND source = 'legion-correlation'", [tenant])).rowCount).toBeGreaterThanOrEqual(1);
    expect(campaigns).toEqual(expect.arrayContaining([expect.objectContaining({ rule: "rapid_chain", subject: ATTACKER })]));

    // 3. People are told: Slack messages and Jira tickets; the ticket is shown on the alert.
    await deliverDue({ kind: "integration_message" });
    expect(calls.filter((c) => c.url === HOOK).length).toBeGreaterThanOrEqual(3);
    expect(jiraCreated).toBeGreaterThanOrEqual(3);
    const deliveries = (await request(app).get(`/alerts/${alerts[0]!.id}/deliveries`).set(...as(admin)).expect(200)).body.deliveries;
    expect(deliveries).toEqual(expect.arrayContaining([expect.objectContaining({ connection: "SEC", status: "sent", ticket: expect.objectContaining({ url: expect.stringMatching(/^https:\/\/acme\.atlassian\.net\/browse\/SEC-\d+$/) }) })]));

    // 4. The agents investigate; Vanguard proposes; policy asks a person.
    const agents = await createAgents(admin, token(admin));
    const inv = await investigate({ tenantId: tenant, alertId: alerts[0]!.id, sourceIp: ATTACKER, asset: "web-1", agents });
    expect(inv.candidate).toMatchObject({ ip: ATTACKER });
    expect(inv.action).toMatchObject({ status: "awaiting_approval", execution_mode: "simulation" });
    expect((await query("SELECT count(*)::int AS n FROM ip_blocks WHERE tenant_id = $1", [tenant])).rows[0].n).toBe(0);

    // 5. A person approves exactly what was proposed; it is simulated; nothing real changes; the audit verifies.
    const approval = (await request(app).get(`/approvals/${inv.action!.approval_id}`).set(...as(admin)).expect(200)).body;
    const decided = await request(app).post(`/approvals/${approval.id}/decision`).set(...as(admin)).send({ decision: "approve", action_digest: approval.action_digest }).expect(200);
    expect(decided.body.action.status).toBe("simulated");
    const v = await verify(inv.trace, tenant, inv.action!.id, ATTACKER);
    expect(v).toMatchObject({ status: "simulated", blocks: 0, chain: { ok: true } });
    expect((await request(app).get("/soc/audit/verify").set(...as(admin)).expect(200)).body.ok).toBe(true);
    // None of the connectors acted on anything: only notify/ticket calls and read calls left Legion.
    expect(calls.every((c) => /hooks\.slack\.com|atlassian\.net\/rest\/api\/3\/(issue|search\/jql)|login\.microsoftonline\.com|graph\.microsoft\.com\/v1\.0\/security\/alerts_v2/.test(c.url))).toBe(true);
  });
});
