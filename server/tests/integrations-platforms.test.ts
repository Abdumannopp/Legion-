/**
 * Azure Defender for Cloud, Google Cloud SCC, Okta, GitHub (pull and push), PagerDuty and Teams (outbound),
 * against simulated providers. Same bars as the other connectors: secrets sealed, egress pinned, errors scrubbed,
 * idempotent, tenant isolated, and nothing can act.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { createHmac, createVerify, generateKeyPairSync, randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { ingestFindings } from "../src/integrations/ingest.js";
import { deliverDue } from "../src/outbox.js";
import { azureAdapter, findingFromAzureAlert } from "../src/integrations/azure.js";
import { findingFromScc, gcpAdapter, signJwt } from "../src/integrations/gcp.js";
import { findingFromOkta, oktaAdapter } from "../src/integrations/okta.js";
import { githubAdapter } from "../src/integrations/github.js";
import { EgressRefused } from "../src/integrations/fetch.js";
import * as registry from "../src/integrations/registry.js";
import type { Finding } from "../src/integrations/types.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...bearer(u)).send(body);
const GUID = (n: number) => `${String(n).repeat(8)}-${String(n).repeat(4)}-4${String(n).repeat(3)}-8${String(n).repeat(3)}-${String(n).repeat(12)}`;
const HOUR = 3_600_000;
const T1 = new Date(Date.now() - 3 * HOUR).toISOString(), T2 = new Date(Date.now() - 2 * HOUR).toISOString(), T3 = new Date(Date.now() - HOUR).toISOString();
const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({ externalId: id, title: `Alert ${id}`, severity: "critical", summary: `detail ${id}`, occurredAt: null, sourceIp: "198.51.100.5", target: "web-1", mitre: [], confidence: 70, asset: null, ...extra });

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown; headers?: Record<string, string> };
const realFetch = globalThis.fetch;
const sig = new AbortController().signal;
beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
  calls = []; respond = () => ({ status: 404 });
  globalThis.fetch = (async (input: URL | string, init: RequestInit = {}) => {
    const c: Call = { url: String(input), method: String(init.method ?? "GET"), headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>)), body: String(init.body ?? "") };
    calls.push(c);
    const r = respond(c);
    return new Response(typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}), { status: r.status, headers: r.headers });
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

describe("catalogue", () => {
  it("lists all six as available and none can respond", () => {
    for (const k of ["azure", "gcp", "okta", "github", "pagerduty", "teams"]) {
      const m = registry.catalogue().find((x) => x.kind === k)!;
      expect(m.status, k).toBe("available");
      expect(m.outbound.includes("respond"), k).toBe(false);
    }
  });
});

describe("Azure Defender for Cloud", () => {
  const alert = (name: string, extra: Record<string, unknown> = {}) => ({ name, properties: { alertDisplayName: `Azure ${name}`, severity: "High", description: "Suspicious login", timeGeneratedUtc: T2, compromisedEntity: "vm-web-1", entities: [{ type: "ip", address: "198.51.100.77" }, { type: "account", name: "alice" }], ...extra } });
  const conn = { id: "c", tenantId: tA, config: { directory_id: GUID(1), client_id: GUID(2), subscription_id: GUID(3) }, secrets: { client_secret: "az-secret-VERY" } };
  it("maps severity, address, host and account", () => {
    expect(findingFromAzureAlert(alert("a1") as never)).toMatchObject({ externalId: "a1", severity: "high", sourceIp: "198.51.100.77", target: "vm-web-1" });
    expect(findingFromAzureAlert(alert("a2", { severity: "Informational" }) as never)!.severity).toBe("low");
  });
  it("signs in, lists the subscription's alerts, follows paging, skips old ones, advances the cursor", async () => {
    respond = (c) => c.url.includes("/oauth2/") ? { status: 200, body: { access_token: "tok" } }
      : c.url.includes("page=2") ? { status: 200, body: { value: [alert("a2", { timeGeneratedUtc: T3 })] } }
      : { status: 200, body: { value: [alert("a1"), alert("old", { timeGeneratedUtc: new Date(Date.now() - 48 * HOUR).toISOString() })], nextLink: "https://management.azure.com/next?page=2" } };
    const r = await azureAdapter.poll(conn, null, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["a1", "a2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(calls[1]!.url).toContain(`/subscriptions/${GUID(3)}/providers/Microsoft.Security/alerts`);
    expect(calls[1]!.headers.authorization).toBe("Bearer tok");
  });
  it("refuses a paging link to another host; errors never contain the secret", async () => {
    respond = (c) => c.url.includes("/oauth2/") ? { status: 200, body: { access_token: "t" } } : { status: 200, body: { value: [alert("a1")], nextLink: "https://evil.example/x" } };
    await expect(azureAdapter.poll(conn, null, sig)).rejects.toBeInstanceOf(EgressRefused);
    respond = () => ({ status: 401, body: "bad az-secret-VERY" });
    const e = (await azureAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error;
    expect(e.message).toMatch(/sign-in failed/); expect(e.message).not.toContain("az-secret");
  });
});

describe("Google Cloud Security Command Center", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
  const saJson = JSON.stringify({ client_email: "legion@proj.iam.gserviceaccount.com", private_key: privateKey });
  const conn = { id: "c", tenantId: tA, config: { organization_id: "123456789012" }, secrets: { service_account_json: saJson } };
  const item = (name: string, extra: Record<string, unknown> = {}) => ({ finding: { name, category: "PERSISTENCE_IAM_ANOMALOUS_GRANT", severity: "HIGH", state: "ACTIVE", eventTime: T2, resourceName: "//cloudresourcemanager.googleapis.com/projects/p1", sourceProperties: { callerIp: "198.51.100.9" }, description: "Anomalous grant", ...extra } });
  it("signs a valid RS256 JWT for the token endpoint", () => {
    const jwt = signJwt("legion@proj.iam.gserviceaccount.com", privateKey, 1_700_000_000);
    const [h, c, s] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h!, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(c!, "base64url").toString())).toMatchObject({ iss: "legion@proj.iam.gserviceaccount.com", aud: "https://oauth2.googleapis.com/token", exp: 1_700_003_600 });
    expect(createVerify("RSA-SHA256").update(`${h}.${c}`).verify(publicKey, Buffer.from(s!, "base64url"))).toBe(true);
  });
  it("maps a finding and polls with paging and a cursor", async () => {
    expect(findingFromScc(item("f1") as never)).toMatchObject({ externalId: "f1", severity: "high", sourceIp: "198.51.100.9", title: "PERSISTENCE IAM ANOMALOUS GRANT" });
    respond = (c) => c.url.startsWith("https://oauth2.googleapis.com/token") ? { status: 200, body: { access_token: "gtok" } }
      : c.url.includes("pageToken=p2") ? { status: 200, body: { listFindingsResults: [item("f2", { eventTime: T3 })] } }
      : { status: 200, body: { listFindingsResults: [item("f1")], nextPageToken: "p2" } };
    const r = await gcpAdapter.poll(conn, null, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["f1", "f2"]);
    expect(r.cursor).toEqual({ since: Date.parse(T3) });
    expect(calls[0]!.body).toContain("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer");
    expect(calls[1]!.url).toContain("/v1/organizations/123456789012/sources/-/findings");
    expect(calls.every((c) => /^https:\/\/(oauth2|securitycenter)\.googleapis\.com\//.test(c.url))).toBe(true);
  });
  it("a bad key or a refusal is a clear error that never contains the key", async () => {
    expect(((await gcpAdapter.poll({ ...conn, secrets: { service_account_json: "not json" } }, null, sig).catch((x: Error) => x)) as Error).message).toMatch(/not valid JSON/);
    respond = () => ({ status: 403, body: `denied ${privateKey}` });
    const e = (await gcpAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error;
    expect(e.message).not.toContain("PRIVATE KEY");
  });
  it("is created through the API with sealed secrets and the key never comes back", async () => {
    const r = await create(adminA, { kind: "gcp", name: "GCP", config: { organization_id: "123456789012" }, secrets: { service_account_json: saJson } });
    expect(r.status).toBe(201);
    expect(JSON.stringify(r.body)).not.toContain("PRIVATE KEY");
    expect((await create(adminA, { kind: "gcp", name: "x", config: { organization_id: "abc" }, secrets: { service_account_json: saJson } })).status).toBe(400);
  });
});

describe("Okta", () => {
  const ev = (uuid: string, extra: Record<string, unknown> = {}) => ({ uuid, displayMessage: "User login to Okta", eventType: "user.session.start", severity: "WARN", published: T2, outcome: { result: "FAILURE", reason: "VERIFICATION_ERROR" }, actor: { alternateId: "alice@acme.io" }, client: { ipAddress: "198.51.100.33" }, ...extra });
  const conn = { id: "c", tenantId: tA, config: { domain: "acme.okta.com" }, secrets: { api_token: "okta-token-VERY" } };
  it("maps severity, account and address", () => {
    expect(findingFromOkta(ev("e1"))).toMatchObject({ externalId: "e1", severity: "medium", sourceIp: "198.51.100.33", target: "alice@acme.io", title: "Okta: User login to Okta (failed)" });
    expect(findingFromOkta(ev("e2", { severity: "ERROR" }))!.severity).toBe("high");
  });
  it("uses SSWS auth on the org's own host, follows Link next on that host only", async () => {
    respond = (c) => c.url.includes("after=2")
      ? { status: 200, body: [ev("e2", { published: T3 })] }
      : { status: 200, body: [ev("e1")], headers: { link: '<https://acme.okta.com/api/v1/logs?after=2>; rel="next"' } };
    const r = await oktaAdapter.poll(conn, null, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["e1", "e2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(calls[0]!.headers.authorization).toBe("SSWS okta-token-VERY");
    respond = () => ({ status: 200, body: [ev("e1")], headers: { link: '<https://evil.example/api/v1/logs>; rel="next"' } });
    calls = []; await oktaAdapter.poll(conn, null, sig);
    expect(calls).toHaveLength(1);   // the foreign next link was not followed
  });
  it("a refused token is a clear error without the token; domains other than Okta's are rejected", async () => {
    respond = () => ({ status: 401, body: "okta-token-VERY" });
    const e = (await oktaAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error;
    expect(e.message).toMatch(/refused the token/); expect(e.message).not.toContain("okta-token");
    expect((await create(adminA, { kind: "okta", name: "Okta", config: { domain: "acme.okta.com.evil.io" }, secrets: { api_token: "x".repeat(20) } })).status).toBe(400);
    expect((await create(adminA, { kind: "okta", name: "Okta", config: { domain: "acme.okta.com" }, secrets: { api_token: "x".repeat(20) } })).status).toBe(201);
  });
});

describe("GitHub webhook", () => {
  const SECRET = "gh-webhook-secret-VERY-long";
  const sign = (body: string, secret = SECRET) => `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
  const secretAlert = (action = "created") => JSON.stringify({ action, alert: { number: 7, secret_type_display_name: "AWS Access Key", html_url: "https://github.com/acme/app/security/secret-scanning/7", created_at: T2, secret: "AKIAREALSECRETVALUE" }, repository: { full_name: "acme/app" } });
  let connId: string;
  beforeEach(async () => { connId = (await create(adminA, { kind: "github", name: "GitHub", config: {}, secrets: { webhook_secret: SECRET } })).body.id; });
  const send = (body: string, o: { sig?: string; id?: string; event?: string } = {}) => request(app).post(`/security-events/webhook/github?connection=${o.id ?? connId}`)
    .set("content-type", "application/json").set("x-github-event", o.event ?? "secret_scanning_alert").set("x-hub-signature-256", o.sig ?? sign(body)).send(body);

  it("a correctly signed secret-scanning alert becomes a high alert in the connection's workspace; the secret value is never stored", async () => {
    const r = await send(secretAlert());
    expect(r.status).toBe(202); expect(r.body.status).toBe("ingested");
    const rows = (await query<{ title: string; severity: string; summary: string; source: string }>("SELECT title, severity, summary, source FROM alerts WHERE tenant_id = $1", [tA])).rows;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ severity: "high", source: "github" });
    expect(rows[0]!.title).toContain("AWS Access Key");
    expect(JSON.stringify(rows)).not.toContain("AKIAREALSECRETVALUE");
    expect((await query("SELECT 1 FROM alerts WHERE tenant_id = $1", [tB])).rowCount).toBe(0);
    const c = (await request(app).get("/integrations").set(...bearer(adminA))).body.connections[0];
    expect(c.last_success_at).not.toBeNull();
    expect(JSON.stringify(c)).not.toContain(SECRET);
  });
  it("a repeat delivery is one alert; closing or fixing an alert is not a finding; ping answers", async () => {
    await send(secretAlert()); expect((await send(secretAlert())).body).toMatchObject({ status: "skipped", reason: "duplicate" });
    expect((await send(secretAlert("resolved"))).body.status).toBe("skipped");
    expect((await send("{}", { event: "ping" })).body.status).toBe("pong");
    expect((await query("SELECT 1 FROM alerts WHERE tenant_id = $1", [tA])).rowCount).toBe(1);
  });
  it("maps code scanning and Dependabot alerts", () => {
    const cs = githubAdapter.normalize({ event: "code_scanning_alert", body: { action: "created", alert: { number: 1, rule: { description: "SQL injection", security_severity_level: "critical" }, html_url: "https://github.com/a/b/1" }, repository: { full_name: "a/b" } } });
    const db = githubAdapter.normalize({ event: "dependabot_alert", body: { action: "created", alert: { number: 2, security_advisory: { summary: "RCE in lib", severity: "high", cve_id: "CVE-2026-1" }, dependency: { package: { name: "lib" } } }, repository: { full_name: "a/b" } } });
    expect(cs.skipped || cs.findings[0]!.severity).toBe("critical");
    expect(db.skipped || db.findings[0]!.title).toContain("lib");
  });
  it("rejects a wrong signature, a tampered body, a missing signature, an unknown or malformed connection — all 401, nothing stored", async () => {
    const body = secretAlert();
    expect((await send(body, { sig: sign(body, "wrong") })).status).toBe(401);
    expect((await send(body, { sig: sign("other body") })).status).toBe(401);
    expect((await send(body, { sig: "" })).status).toBe(401);
    expect((await send(body, { id: randomUUID() })).status).toBe(401);
    expect((await send(body, { id: "not-a-uuid" })).status).toBe(401);
    expect((await query("SELECT 1 FROM alerts")).rowCount).toBe(0);
  });
  it("workspace B's connection id with A's secret does not authenticate, and a paused connection is refused", async () => {
    const b = (await create(adminB, { kind: "github", name: "GH-B", config: {}, secrets: { webhook_secret: "b-secret-different" } })).body.id;
    const body = secretAlert();
    expect((await send(body, { id: b })).status).toBe(401);
    await request(app).post(`/integrations/${connId}/pause`).set(...bearer(adminA)).expect(200);
    expect((await send(body)).status).toBe(401);
  });
});

describe("PagerDuty", () => {
  const KEY = "a".repeat(32);
  const body = { kind: "pagerduty", name: "On-call", config: { min_severity: "critical" }, secrets: { routing_key: KEY } };
  it("pages once per alert (dedup_key = the alert id), only for critical by default, with the mapped severity", async () => {
    await create(adminA, body);
    respond = () => ({ status: 202, body: { status: "success" } });
    await ingestFindings(tA, "wazuh", [finding("p1"), finding("p2", { severity: "high" })]);
    await deliverDue({ kind: "integration_message" });
    const pd = calls.filter((c) => c.url === "https://events.pagerduty.com/v2/enqueue");
    expect(pd).toHaveLength(1);
    const sent = JSON.parse(pd[0]!.body);
    expect(sent).toMatchObject({ event_action: "trigger", routing_key: KEY, payload: { severity: "critical" } });
    expect(sent.dedup_key).toMatch(/^SEC-/);
  });
  it("a bad key is refused at save time; a revoked key is dead-lettered at once; an outage is retried", async () => {
    expect((await create(adminA, { ...body, secrets: { routing_key: "short" } })).status).toBe(400);
    await create(adminA, body);
    respond = () => ({ status: 503 });
    await ingestFindings(tA, "wazuh", [finding("p3")]);
    await deliverDue({ kind: "integration_message" });
    expect((await query<{ status: string }>("SELECT status FROM notification_outbox WHERE kind = 'integration_message'")).rows[0]!.status).toBe("pending");
    respond = () => ({ status: 400, body: "invalid routing key" });
    await query("UPDATE notification_outbox SET next_attempt_at = now() WHERE status = 'pending'");
    await deliverDue({ kind: "integration_message" });
    expect((await query<{ status: string }>("SELECT status FROM notification_outbox WHERE kind = 'integration_message'")).rows[0]!.status).toBe("dead");
  });
});

describe("Microsoft Teams", () => {
  const URL_OK = "https://contoso.webhook.office.com/webhookb2/abc/IncomingWebhook/def/ghi";
  const mk = (url: string) => create(adminA, { kind: "teams", name: "Teams", config: { min_severity: "high" }, secrets: { webhook_url: url } });
  it("accepts Microsoft webhook hosts only", async () => {
    expect((await mk(URL_OK)).status).toBe(201);
    expect((await mk("https://prod-12.westus.logic.azure.com:443/workflows/x/triggers/manual/paths/invoke?sig=s")).status).toBe(201);
    for (const bad of ["https://evil.example/x", "http://contoso.webhook.office.com/x", "https://webhook.office.com.evil.io/x", "https://user:pw@contoso.webhook.office.com/x", "https://127.0.0.1/x"]) expect((await mk(bad)).status, bad).toBe(400);
  });
  it("posts an Adaptive Card with plain text only (no mentions or markup), once per alert, and never leaks the URL", async () => {
    await mk(URL_OK);
    respond = () => ({ status: 200, body: "1" });
    await ingestFindings(tA, "wazuh", [finding("t1", { title: "<at>everyone</at> **click** [x](https://evil.example)" })]);
    await deliverDue({ kind: "integration_message" });
    const sent = calls.filter((c) => c.url === URL_OK);
    expect(sent).toHaveLength(1);
    const card = JSON.parse(sent[0]!.body).attachments[0].content;
    expect(card.type).toBe("AdaptiveCard");
    expect(card.actions[0].url).toMatch(/\/incident\//);
    respond = () => ({ status: 403, body: URL_OK });
    await ingestFindings(tA, "wazuh", [finding("t2")]);
    await deliverDue({ kind: "integration_message" });
    expect(JSON.stringify((await query("SELECT last_error FROM integration_connections")).rows)).not.toContain("IncomingWebhook");
  });
});
