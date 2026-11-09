/**
 * CrowdStrike Falcon, SentinelOne, Microsoft Sentinel, AWS Security Hub, Elastic Cloud, Splunk Cloud, Cloudflare,
 * Google Workspace (pull), ServiceNow and Opsgenie (outbound), and the vendor-update rule (audit A-9) — against
 * simulated providers built from the vendors' API documentation. Same bars as the other connectors: secrets sealed,
 * egress pinned to the vendor, errors scrubbed, idempotent, tenant isolated, and none of them can act.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { findingAlertId, ingestFindings } from "../src/integrations/ingest.js";
import { deliverDue } from "../src/outbox.js";
import * as connections from "../src/integrations/connections.js";
import * as registry from "../src/integrations/registry.js";
import { crowdstrikeAdapter, findingFromFalcon } from "../src/integrations/crowdstrike.js";
import { findingFromS1Threat, sentineloneAdapter } from "../src/integrations/sentinelone.js";
import { findingFromSentinelIncident, msentinelAdapter } from "../src/integrations/msentinel.js";
import { findingFromAsff, securityhubAdapter } from "../src/integrations/securityhub.js";
import { elasticAdapter, findingFromElasticAlert } from "../src/integrations/elastic.js";
import { findingFromSplunk, splunkAdapter } from "../src/integrations/splunk.js";
import { cloudflareAdapter, findingsFromCloudflare } from "../src/integrations/cloudflare.js";
import { findingsFromWorkspaceActivity, gworkspaceAdapter } from "../src/integrations/gworkspace.js";
import { cursorSince } from "../src/integrations/shared.js";
import type { Finding } from "../src/integrations/types.js";
import type { User } from "../src/types.js";

let tA: string, tB: string, adminA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const create = (u: User, body: Record<string, unknown>) => request(app).post("/integrations").set(...bearer(u)).send(body);
const GUID = (n: number) => `${String(n).repeat(8)}-${String(n).repeat(4)}-4${String(n).repeat(3)}-8${String(n).repeat(3)}-${String(n).repeat(12)}`;
const HOUR = 3_600_000;
const T1 = new Date(Date.now() - 3 * HOUR).toISOString(), T2 = new Date(Date.now() - 2 * HOUR).toISOString(), T3 = new Date(Date.now() - HOUR).toISOString();
const finding = (id: string, extra: Partial<Finding> = {}): Finding => ({ externalId: id, title: `Alert ${id}`, severity: "medium", summary: `detail ${id}`, occurredAt: null, sourceIp: "198.51.100.5", target: "web-1", mitre: [], confidence: 70, asset: null, ...extra });

type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown; headers?: Record<string, string> };
const realFetch = globalThis.fetch;
const sig = new AbortController().signal;
const hostsCalled = () => [...new Set(calls.map((c) => new URL(c.url).host))];
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
  it("all ten are available, read or notify/ticket only, and pinned to their vendor's hosts", () => {
    for (const k of ["crowdstrike", "sentinelone", "msentinel", "securityhub", "elastic", "splunk", "cloudflare", "gworkspace", "servicenow", "opsgenie"]) {
      const m = registry.catalogue().find((x) => x.kind === k)!;
      expect(m, k).toBeDefined();
      expect(m.status, k).toBe("available");
      expect(m.outbound.includes("respond"), k).toBe(false);
      expect(m.egressHosts.length, k).toBeGreaterThan(0);
      expect(m.egressHosts.every((h) => !h.startsWith("*") || h.split(".").length >= 3), k).toBe(true); // never a bare "*"
    }
  });
  it("a cursor is only ever a strict UTC timestamp (it is put into vendor query languages)", () => {
    expect(cursorSince({ since: "2026-01-01T00:00:00.000Z" })).toBe("2026-01-01T00:00:00.000Z");
    for (const bad of [{ since: "2026-01-01' OR 1=1" }, { since: "x" }, { since: 5 }, null, { since: new Date(Date.now() + 10 * HOUR).toISOString() }]) {
      const s = cursorSince(bad);
      expect(Date.now() - Date.parse(s)).toBeGreaterThan(23 * HOUR);
    }
  });
});

describe("CrowdStrike Falcon", () => {
  const alert = (id: string, extra: Record<string, unknown> = {}) => ({ composite_id: id, display_name: "Credential dumping", description: "lsass memory read", severity: 70, severity_name: "High", technique_id: "T1003", tactic_id: "TA0006", device: { hostname: "ws-12", external_ip: "203.0.113.9", local_ip: "10.0.0.12", platform_name: "Windows" }, user_name: "alice", updated_timestamp: T2, timestamp: T1, ...extra });
  const conn = { id: "c", tenantId: tA, config: { cloud: "eu-1", client_id: "a".repeat(32) }, secrets: { client_secret: "cs-secret-VERY-long" } };
  it("maps severity, host, address, user and MITRE", () => {
    expect(findingFromFalcon(alert("cid:1") as never)).toMatchObject({ externalId: "cid:1", severity: "high", target: "ws-12", sourceIp: "203.0.113.9", mitre: expect.arrayContaining(["T1003"]), asset: { name: "ws-12", os: "Windows" } });
    expect(findingFromFalcon(alert("cid:2", { severity_name: "Informational" }) as never)!.severity).toBe("low");
    expect(findingFromFalcon(alert("cid:3", { severity_name: undefined, severity: 95 }) as never)!.severity).toBe("critical");
    expect(findingFromFalcon({ composite_id: "x" } as never)).toBeNull();
  });
  it("signs in on the chosen cloud only, queries by update time, fetches details, advances the cursor", async () => {
    respond = (c) => c.url.endsWith("/oauth2/token") ? { status: 201, body: { access_token: "tok" } }
      : c.url.includes("/alerts/queries/") ? { status: 200, body: { resources: ["cid:1", "cid:2"] } }
      : c.url.includes("/alerts/entities/") ? { status: 200, body: { resources: [alert("cid:1"), alert("cid:2", { updated_timestamp: T3 })] } }
      : { status: 404 };
    const r = await crowdstrikeAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["cid:1", "cid:2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(hostsCalled()).toEqual(["api.eu-1.crowdstrike.com"]);
    const q = calls.find((c) => c.url.includes("/alerts/queries/"))!;
    expect(decodeURIComponent(q.url)).toContain(`updated_timestamp:>='${T1}'`);
    expect(q.headers.authorization).toBe("Bearer tok");
    expect(JSON.parse(calls.find((c) => c.url.includes("/entities/"))!.body)).toEqual({ composite_ids: ["cid:1", "cid:2"] });
  });
  it("bad credentials and outages give clear errors without the secret", async () => {
    respond = () => ({ status: 401, body: { errors: [{ message: "access denied cs-secret-VERY-long" }] } });
    const e = (await crowdstrikeAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error;
    expect(e.message).toMatch(/sign-in failed \(401\)/);
    expect(e.message).not.toContain("cs-secret");
    respond = (c) => c.url.endsWith("/oauth2/token") ? { status: 201, body: { access_token: "t" } } : { status: 403 };
    expect(((await crowdstrikeAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error).message).toMatch(/Alerts: Read/);
  });
  it("the config only accepts a known cloud (no URL)", async () => {
    expect((await create(adminA, { kind: "crowdstrike", name: "f", config: { cloud: "evil.example", client_id: "a".repeat(32) }, secrets: { client_secret: "s" } })).status).toBe(400);
    expect((await create(adminA, { kind: "crowdstrike", name: "f", config: { cloud: "us-2", client_id: "a".repeat(32) }, secrets: { client_secret: "s" } })).status).toBe(201);
  });
});

describe("SentinelOne", () => {
  const threat = (id: string, info: Record<string, unknown> = {}) => ({ id, threatInfo: { threatName: "mimikatz.exe", confidenceLevel: "malicious", mitigationStatus: "not_mitigated", classification: "Hacktool", filePath: "C:\\tmp\\m.exe", sha1: "a".repeat(40), updatedAt: T2, createdAt: T1, ...info }, agentRealtimeInfo: { agentComputerName: "ws-7", agentOsName: "Windows 11" }, agentDetectionInfo: { agentIpV4: "10.0.0.7", externalIp: "198.51.100.33", agentLastLoggedInUserName: "bob" }, indicators: [{ tactics: [{ name: "Credential Access", techniques: [{ name: "T1003", link: "https://attack.mitre.org/techniques/T1003/" }] }] }] });
  const conn = { id: "c", tenantId: tA, config: { console: "usea1-acme" }, secrets: { api_token: "s1-token-VERY-long" } };
  it("derives severity from the verdict and mitigation", () => {
    expect(findingFromS1Threat(threat("1") as never)).toMatchObject({ severity: "critical", target: "ws-7", sourceIp: "198.51.100.33", mitre: ["T1003"] });
    expect(findingFromS1Threat(threat("2", { mitigationStatus: "mitigated" }) as never)!.severity).toBe("high");
    expect(findingFromS1Threat(threat("3", { confidenceLevel: "suspicious" }) as never)!.severity).toBe("medium");
  });
  it("uses the ApiToken header on the named console only, pages by cursor, advances by updatedAt", async () => {
    respond = (c) => c.url.includes("cursor=next1") ? { status: 200, body: { data: [threat("2", { updatedAt: T3 })], pagination: { nextCursor: null } } }
      : { status: 200, body: { data: [threat("1")], pagination: { nextCursor: "next1" } } };
    const r = await sentineloneAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["1", "2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(hostsCalled()).toEqual(["usea1-acme.sentinelone.net"]);
    expect(calls[0]!.headers.authorization).toBe("ApiToken s1-token-VERY-long");
    expect(new URL(calls[0]!.url).searchParams.get("updatedAt__gte")).toBe(T1);
  });
  it("refuses a console that is not a plain name", async () => {
    for (const bad of ["evil.com/x", "a.b", "-x"]) expect((await create(adminA, { kind: "sentinelone", name: "s", config: { console: bad }, secrets: { api_token: "t" } })).status, bad).toBe(400);
  });
});

describe("Microsoft Sentinel", () => {
  const incident = (name: string, p: Record<string, unknown> = {}) => ({ name, properties: { title: "Multistage attack", description: "Brute force then T1078 sign-in", severity: "High", status: "New", incidentNumber: 42, lastModifiedTimeUtc: T2, firstActivityTimeUtc: T1, additionalData: { alertsCount: 3, alertProductNames: ["Azure Active Directory Identity Protection"], tactics: ["InitialAccess"] }, ...p } });
  const conn = { id: "c", tenantId: tA, config: { directory_id: GUID(1), client_id: GUID(2), subscription_id: GUID(3), resource_group: "soc-rg", workspace: "soc-law" }, secrets: { client_secret: "ms-secret-VERY" } };
  it("maps incidents and skips closed ones", () => {
    expect(findingFromSentinelIncident(incident(GUID(4)) as never)).toMatchObject({ externalId: GUID(4), severity: "high", title: "Sentinel incident #42: Multistage attack", mitre: ["T1078"] });
    expect(findingFromSentinelIncident(incident(GUID(5), { status: "Closed" }) as never)).toBeNull();
    expect(findingFromSentinelIncident(incident(GUID(6), { severity: "Informational" }) as never)!.severity).toBe("low");
  });
  it("reads the named workspace by last change, on Microsoft hosts only", async () => {
    respond = (c) => c.url.includes("/oauth2/") ? { status: 200, body: { access_token: "tok" } } : { status: 200, body: { value: [incident(GUID(4)), incident(GUID(5), { lastModifiedTimeUtc: T3 })] } };
    const r = await msentinelAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings).toHaveLength(2);
    expect(r.cursor).toEqual({ since: T3 });
    expect(hostsCalled().sort()).toEqual(["login.microsoftonline.com", "management.azure.com"]);
    const list = calls.find((c) => c.url.includes("SecurityInsights"))!;
    expect(list.url).toContain("/resourceGroups/soc-rg/providers/Microsoft.OperationalInsights/workspaces/soc-law/");
    expect(new URL(list.url).searchParams.get("$filter")).toBe(`properties/lastModifiedTimeUtc ge ${T1}`);
  });
});

describe("AWS Security Hub", () => {
  const asff = (id: string, extra: Record<string, unknown> = {}) => ({ Id: id, Title: "S3 bucket allows public read", Description: "Bucket is public", ProductName: "Config", Severity: { Label: "HIGH", Normalized: 70 }, UpdatedAt: T2, AwsAccountId: "123456789012", Region: "eu-west-1", Types: ["Software and Configuration Checks/AWS Security Best Practices"], Resources: [{ Type: "AwsS3Bucket", Id: "arn:aws:s3:::data" }], ...extra });
  const conn = { id: "c", tenantId: tA, config: { regions: ["eu-west-1"], include_guardduty: false }, secrets: { access_key_id: "AKIAIOSFODNN7EXAMPLE", secret_access_key: "sh-secret-VERY" } };
  it("maps ASFF", () => {
    expect(findingFromAsff(asff("arn:1") as never)).toMatchObject({ severity: "high", title: "Config: S3 bucket allows public read", target: "arn:aws:s3:::data" });
    expect(findingFromAsff(asff("arn:2", { Severity: { Label: "INFORMATIONAL" } }) as never)!.severity).toBe("low");
    expect(findingFromAsff(asff("arn:3", { Severity: { Normalized: 95 } }) as never)!.severity).toBe("critical");
  });
  it("signs with SigV4 for securityhub, filters active new findings and skips GuardDuty's own, pages, advances", async () => {
    respond = (c) => JSON.parse(c.body).NextToken ? { status: 200, body: { Findings: [asff("arn:2", { UpdatedAt: T3 })] } } : { status: 200, body: { Findings: [asff("arn:1")], NextToken: "n1" } };
    const r = await securityhubAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["arn:1", "arn:2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(hostsCalled()).toEqual(["securityhub.eu-west-1.amazonaws.com"]);
    expect(calls[0]!.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\/\d{8}\/eu-west-1\/securityhub\/aws4_request/);
    const body = JSON.parse(calls[0]!.body);
    expect(body.Filters.RecordState).toEqual([{ Value: "ACTIVE", Comparison: "EQUALS" }]);
    expect(body.Filters.ProductName).toEqual([{ Value: "GuardDuty", Comparison: "NOT_EQUALS" }]);
    expect(body.Filters.UpdatedAt[0].Start).toBe(T1);
  });
  it("a 403 says to check the policy and that Security Hub is enabled", async () => {
    respond = () => ({ status: 403 });
    expect(((await securityhubAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error).message).toMatch(/IAM policy.*enabled/);
  });
});

describe("Elastic Security (Elastic Cloud)", () => {
  const hit = (id: string, ts: string, flat = true) => ({ _id: id, sort: [Date.parse(ts), id], _source: flat
    ? { "@timestamp": ts, "kibana.alert.rule.name": "Potential credential access via LSASS", "kibana.alert.severity": "high", "kibana.alert.risk_score": 73, "kibana.alert.reason": "process event on ws-3", "host.name": "ws-3", "source.ip": "198.51.100.40", "user.name": "carol", "kibana.alert.rule.threat": [{ technique: [{ id: "T1003", subtechnique: [{ id: "T1003.001" }] }] }] }
    : { "@timestamp": ts, kibana: { alert: { rule: { name: "Nested rule" }, severity: "critical" } }, host: { name: "ws-4" } } });
  const conn = { id: "c", tenantId: tA, config: { kibana_host: "soc.kb.us-central1.gcp.cloud.es.io", space: "default" }, secrets: { api_key: "el-key-VERY" } };
  it("reads flat and nested alert documents", () => {
    expect(findingFromElasticAlert("e1", hit("e1", T2)._source as never)).toMatchObject({ severity: "high", target: "ws-3", sourceIp: "198.51.100.40", mitre: ["T1003", "T1003.001"] });
    expect(findingFromElasticAlert("e2", hit("e2", T2, false)._source as never)).toMatchObject({ severity: "critical", target: "ws-4" });
  });
  it("posts to the detection engine with ApiKey and kbn-xsrf, open alerts only, advances", async () => {
    respond = () => ({ status: 200, body: { hits: { hits: [hit("e1", T2), hit("e2", T3, false)] } } });
    const r = await elasticAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["e1", "e2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(calls[0]!.url).toBe("https://soc.kb.us-central1.gcp.cloud.es.io/api/detection_engine/signals/search");
    expect(calls[0]!.headers).toMatchObject({ authorization: "ApiKey el-key-VERY", "kbn-xsrf": "legion" });
    expect(JSON.stringify(JSON.parse(calls[0]!.body).query)).toContain('"kibana.alert.workflow_status":"open"');
  });
  it("only Elastic Cloud Kibana hosts are accepted (no internal or typed address)", async () => {
    for (const bad of ["169.254.169.254", "kibana.internal.corp", "soc.kb.us-central1.gcp.cloud.es.io.evil.com", "localhost"]) {
      expect((await create(adminA, { kind: "elastic", name: "e", config: { kibana_host: bad }, secrets: { api_key: "k" } })).status, bad).toBe(400);
    }
    expect((await create(adminA, { kind: "elastic", name: "e", config: { kibana_host: "SOC.kb.eu-west-1.aws.elastic-cloud.com" }, secrets: { api_key: "k" } })).status).toBe(201);
  });
});

describe("Splunk Cloud", () => {
  const line = (r: Record<string, unknown>, preview = false) => JSON.stringify({ preview, result: r });
  const conn = { id: "c", tenantId: tA, config: { stack: "acme", index: "notable" }, secrets: { token: "sp-token-VERY" } };
  it("maps notable events (urgency, src, dest, user)", () => {
    expect(findingFromSplunk({ event_id: "ev1", rule_name: "Brute Force Access Behavior Detected", urgency: "high", src: "198.51.100.60", dest: "srv-1", user: "dave", _time: T2 })).toMatchObject({ externalId: "ev1", severity: "high", sourceIp: "198.51.100.60", target: "srv-1" });
    const noId = findingFromSplunk({ search_name: "x", _raw: "raw", _time: T2 })!;
    expect(noId.externalId).toMatch(/^[a-f0-9]{40}$/);
    expect(findingFromSplunk({ search_name: "x", _raw: "raw", _time: T2 })!.externalId).toBe(noId.externalId);
  });
  it("searches the index by index time on port 8089 with a Bearer token, skips previews, moves the cursor to the end of the window", async () => {
    respond = () => ({ status: 200, body: [line({ event_id: "ev1", rule_name: "R1", urgency: "critical", legion_indextime: String(Date.parse(T2) / 1000) }), line({ event_id: "p", rule_name: "P" }, true), line({ event_id: "ev2", rule_name: "R2", urgency: "low" }), "not json"].join("\n") });
    const before = Date.now();
    const r = await splunkAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings.map((f) => f.externalId)).toEqual(["ev1", "ev2"]);
    expect(Date.parse((r.cursor as { since: string }).since)).toBeGreaterThanOrEqual(before - 1000);
    expect(calls[0]!.url).toBe("https://acme.splunkcloud.com:8089/services/search/v2/jobs/export");
    expect(calls[0]!.headers.authorization).toBe("Bearer sp-token-VERY");
    const form = new URLSearchParams(calls[0]!.body);
    expect(form.get("search")).toMatch(/^search index=notable /);
    expect(Number(form.get("index_earliest"))).toBe(Date.parse(T1) / 1000);
  });
  it("the index name cannot carry SPL", async () => {
    for (const bad of ["notable | delete", "main OR index=*", "a b"]) expect((await create(adminA, { kind: "splunk", name: "s", config: { stack: "acme", index: bad }, secrets: { token: "t" } })).status, bad).toBe(400);
  });
});

describe("Cloudflare", () => {
  const zone = "f".repeat(32);
  const conn = { id: "c", tenantId: tA, config: { zone_id: zone, min_events: 50 }, secrets: { api_token: "cf-token-VERY" } };
  it("one alert per address per hour, with the count; below the threshold nothing", () => {
    const out = findingsFromCloudflare(zone, "2026-01-01T10:00:00.000Z", [
      { count: 600, dimensions: { clientIP: "198.51.100.70", clientCountryName: "XX", clientRequestHTTPHost: "shop.example" } },
      { count: 100, dimensions: { clientIP: "198.51.100.70", clientCountryName: "XX", clientRequestHTTPHost: "api.example" } },
      { count: 10, dimensions: { clientIP: "198.51.100.71" } },
      { count: 99, dimensions: { clientIP: "not-an-ip" } },
    ], 50);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ externalId: `${zone}:2026-01-01T10:00:00.000Z:198.51.100.70`, severity: "medium", sourceIp: "198.51.100.70", title: "Cloudflare blocked 700 requests from 198.51.100.70 to shop.example" });
  });
  it("reads complete hours only, at most 24, then resumes from the current hour", async () => {
    respond = () => ({ status: 200, body: { data: { viewer: { zones: [{ firewallEventsAdaptiveGroups: [{ count: 80, dimensions: { clientIP: "198.51.100.80" } }] }] } } } });
    const current = Math.floor(Date.now() / HOUR) * HOUR;
    const r = await cloudflareAdapter.poll(conn, { next_hour: current - 3 * HOUR }, sig);
    expect(calls).toHaveLength(3);
    expect(r.findings).toHaveLength(3);
    expect(r.cursor).toEqual({ next_hour: current });
    expect(hostsCalled()).toEqual(["api.cloudflare.com"]);
    const v = JSON.parse(calls[0]!.body).variables;
    expect(v).toEqual({ zone, start: new Date(current - 3 * HOUR).toISOString(), end: new Date(current - 2 * HOUR).toISOString() });
    calls = [];
    expect((await cloudflareAdapter.poll(conn, { next_hour: current - 100 * HOUR }, sig)).findings).toHaveLength(24);
    calls = [];
    expect((await cloudflareAdapter.poll(conn, { next_hour: current }, sig)).findings).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });
  it("a GraphQL error is reported, not swallowed", async () => {
    respond = () => ({ status: 200, body: { data: null, errors: [{ message: "zone not authorized" }] } });
    expect(((await cloudflareAdapter.poll(conn, null, sig).catch((x: Error) => x)) as Error).message).toMatch(/zone not authorized/);
  });
});

describe("Google Workspace", () => {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
  const key = JSON.stringify({ client_email: "legion@acme.iam.gserviceaccount.com", private_key: privateKey });
  const activity = (time: string, name: string, extra: Record<string, unknown> = {}) => ({ id: { time, uniqueQualifier: "-123", applicationName: "login" }, actor: { email: "eve@acme.io" }, ipAddress: "198.51.100.90", events: [{ type: "login", name, parameters: [{ name: "login_type", value: "google_password" }] }], ...extra });
  const conn = { id: "c", tenantId: tA, config: { admin_email: "admin@acme.io" }, secrets: { service_account_json: key } };
  it("keeps the security events, skips ordinary sign-ins", () => {
    expect(findingsFromWorkspaceActivity(activity(T2, "suspicious_login") as never)).toMatchObject([{ severity: "high", target: "eve@acme.io", sourceIp: "198.51.100.90" }]);
    expect(findingsFromWorkspaceActivity(activity(T2, "gov_attack_warning") as never)[0]!.severity).toBe("critical");
    expect(findingsFromWorkspaceActivity(activity(T2, "login_success") as never)).toEqual([]);
    expect(findingsFromWorkspaceActivity(activity(T2, "logout") as never)).toEqual([]);
  });
  it("acts as the administrator with the read-only audit scope, reads the login report, advances", async () => {
    respond = (c) => c.url.startsWith("https://oauth2.googleapis.com/") ? { status: 200, body: { access_token: "tok" } }
      : { status: 200, body: { items: [activity(T2, "login_failure"), activity(T3, "account_disabled_hijacked"), activity(T3, "login_success")] } };
    const r = await gworkspaceAdapter.poll(conn, { since: T1 }, sig);
    expect(r.findings.map((f) => f.severity)).toEqual(["low", "high"]);
    expect(r.cursor).toEqual({ since: T3 });
    const assertion = new URLSearchParams(calls[0]!.body).get("assertion")!;
    const claim = JSON.parse(Buffer.from(assertion.split(".")[1]!, "base64url").toString());
    expect(claim).toMatchObject({ iss: "legion@acme.iam.gserviceaccount.com", sub: "admin@acme.io", scope: "https://www.googleapis.com/auth/admin.reports.audit.readonly" });
    expect(calls[1]!.url).toContain("https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?");
    expect(new URL(calls[1]!.url).searchParams.get("startTime")).toBe(T1);
  });
});

describe("end to end through the worker", () => {
  it("a CrowdStrike connection: sealed secret, alerts in the right workspace, duplicates on re-poll", async () => {
    const created = await create(adminA, { kind: "crowdstrike", name: "Falcon", config: { cloud: "us-1", client_id: "b".repeat(32) }, secrets: { client_secret: "e2e-secret-VERY-long" } });
    expect(created.status).toBe(201);
    expect(JSON.stringify(created.body)).not.toContain("e2e-secret");
    const a = { composite_id: "cid:e2e", display_name: "Ransomware", severity_name: "Critical", device: { hostname: "fs-1" }, updated_timestamp: T2 };
    respond = (c) => c.url.endsWith("/oauth2/token") ? { status: 201, body: { access_token: "tok" } } : c.url.includes("/queries/") ? { status: 200, body: { resources: ["cid:e2e"] } } : { status: 200, body: { resources: [a] } };
    expect(await connections.runDuePolls({})).toMatchObject({ succeeded: 1, ingested: 1 });
    expect((await query("SELECT severity FROM alerts WHERE tenant_id = $1 AND source = 'crowdstrike'", [tA])).rows).toEqual([{ severity: "critical" }]);
    expect((await query("SELECT 1 FROM alerts WHERE tenant_id = $1", [tB])).rowCount).toBe(0);
    await query("UPDATE integration_connections SET next_poll_at = now()");
    expect(await connections.runDuePolls({})).toMatchObject({ ingested: 0, duplicates: 1 });
  });
});

describe("audit A-9: a vendor raising an alert's severity raises the Legion alert", () => {
  it("raises (never lowers), notes it in the text, audits it, and keeps the status", async () => {
    await ingestFindings(tA, "crowdstrike", [finding("v1", { severity: "medium" })]);
    const id = findingAlertId(tA, "crowdstrike", "v1");
    await query("UPDATE alerts SET status = 'investigating' WHERE tenant_id = $1 AND id = $2", [tA, id]);
    const seq0 = (await query("SELECT seq FROM alerts WHERE id = $1", [id])).rows[0].seq;
    const r = await ingestFindings(tA, "crowdstrike", [finding("v1", { severity: "critical" })]);
    expect(r).toMatchObject({ ingested: [], duplicates: [id], escalated: [id] });
    const row = (await query("SELECT severity, status, summary, seq FROM alerts WHERE id = $1", [id])).rows[0];
    expect(row).toMatchObject({ severity: "critical", status: "investigating" });
    expect(row.summary).toMatch(/The source raised the severity to critical/);
    expect(Number(row.seq)).toBeGreaterThan(Number(seq0)); // dashboards see the change
    expect((await query("SELECT 1 FROM audit_log WHERE tenant_id = $1 AND action = 'alert.severity_raised_by_source' AND resource_id = $2", [tA, id])).rowCount).toBe(1);
    // lower or equal: nothing changes
    expect((await ingestFindings(tA, "crowdstrike", [finding("v1", { severity: "low" })])).escalated).toBeUndefined();
    expect((await ingestFindings(tA, "crowdstrike", [finding("v1", { severity: "critical" })])).escalated).toBeUndefined();
    expect((await query("SELECT severity FROM alerts WHERE id = $1", [id])).rows[0].severity).toBe("critical");
  });
  it("only within the same workspace: another workspace's same vendor id is a different alert", async () => {
    await ingestFindings(tA, "crowdstrike", [finding("v2", { severity: "low" })]);
    await ingestFindings(tB, "crowdstrike", [finding("v2", { severity: "critical" })]);
    expect((await query("SELECT severity FROM alerts WHERE tenant_id = $1", [tA])).rows).toEqual([{ severity: "low" }]);
  });
});

describe("ServiceNow", () => {
  const body = { kind: "servicenow", name: "SN", config: { instance: "acme", min_severity: "high" }, secrets: { username: "legion.int", password: "sn-pass-VERY-secret" } };
  const SYS = "a".repeat(32);
  it("opens one incident per alert on the named instance with correlation_id, and remembers the number", async () => {
    expect((await create(adminA, body)).status).toBe(201);
    let created = 0;
    respond = (c) => c.method === "GET" ? { status: 200, body: { result: [] } } : (created++, { status: 201, body: { result: { number: "INC0010001", sys_id: SYS } } });
    await ingestFindings(tA, "wazuh", [finding("sn1", { severity: "critical" }), finding("sn-low", { severity: "low" })]);
    await deliverDue({ kind: "integration_message" });
    expect(created).toBe(1);
    expect(hostsCalled()).toEqual(["acme.service-now.com"]);
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.headers.authorization).toBe(`Basic ${Buffer.from("legion.int:sn-pass-VERY-secret").toString("base64")}`);
    const sent = JSON.parse(post.body);
    expect(sent).toMatchObject({ impact: "1", urgency: "1", correlation_display: "Legion" });
    expect(sent.correlation_id).toMatch(/^legion-SEC-[A-F0-9]{16}$/);
    expect(new URL(calls.find((c) => c.method === "GET")!.url).searchParams.get("sysparm_query")).toBe(`correlation_id=${sent.correlation_id}`);
    const id = findingAlertId(tA, "wazuh", "sn1");
    const d = (await request(app).get(`/alerts/${id}/deliveries`).set(...bearer(adminA))).body.deliveries;
    expect(d).toEqual([expect.objectContaining({ kind: "servicenow", status: "sent", ticket: { key: "INC0010001", url: `https://acme.service-now.com/nav_to.do?uri=incident.do%3Fsys_id%3D${SYS}` } })]);
  });
  it("a retry finds the incident by correlation_id instead of opening a second", async () => {
    await create(adminA, body);
    let created = 0;
    respond = (c) => c.method === "GET" ? { status: 200, body: { result: [{ number: "INC0010002", sys_id: SYS }] } } : (created++, { status: 201, body: {} });
    await ingestFindings(tA, "wazuh", [finding("sn2", { severity: "high" })]);
    await deliverDue({ kind: "integration_message" });
    expect(created).toBe(0);
  });
  it("bad credentials are not retried; an outage is; the password never reaches the stored error", async () => {
    await create(adminA, body);
    respond = () => ({ status: 401, body: `{"error":"User Not Authenticated sn-pass-VERY-secret"}` });
    await ingestFindings(tA, "wazuh", [finding("sn3", { severity: "high" })]);
    await deliverDue({ kind: "integration_message" });
    const row = (await query("SELECT status, last_error FROM notification_outbox WHERE kind = 'integration_message'")).rows[0];
    expect(row.status).toBe("dead");
    expect(row.last_error).not.toContain("sn-pass");
  });
  it("the instance is a name, never a URL", async () => {
    for (const bad of ["evil.com", "acme.service-now.com", "http://x"]) expect((await create(adminA, { ...body, config: { instance: bad } })).status, bad).toBe(400);
  });
});

describe("Opsgenie", () => {
  const KEY = "12345678-1234-1234-1234-123456789abc";
  const body = { kind: "opsgenie", name: "On-call", config: { region: "eu", min_severity: "high" }, secrets: { api_key: KEY } };
  it("creates an alert with alias legion-<id> and priority, on the region's host, with GenieKey", async () => {
    expect((await create(adminA, body)).status).toBe(201);
    respond = () => ({ status: 202, body: { result: "Request will be processed", requestId: "r" } });
    await ingestFindings(tA, "wazuh", [finding("og1", { severity: "critical" }), finding("og-low", { severity: "medium" })]);
    await deliverDue({ kind: "integration_message" });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://api.eu.opsgenie.com/v2/alerts");
    expect(calls[0]!.headers.authorization).toBe(`GenieKey ${KEY}`);
    expect(JSON.parse(calls[0]!.body)).toMatchObject({ alias: `legion-${findingAlertId(tA, "wazuh", "og1")}`, priority: "P1", source: "Legion" });
  });
  it("a key that is not an Opsgenie key is refused when saving", async () => {
    expect((await create(adminA, { ...body, secrets: { api_key: "nope" } })).status).toBe(400);
  });
});

describe("tenant isolation", () => {
  it("workspace B cannot see, pause or remove workspace A's new connections", async () => {
    const ids: string[] = [];
    for (const b of [
      { kind: "sentinelone", name: "S1", config: { console: "acme" }, secrets: { api_token: "t" } },
      { kind: "cloudflare", name: "CF", config: { zone_id: "e".repeat(32) }, secrets: { api_token: "t" } },
      { kind: "servicenow", name: "SN", config: { instance: "acme" }, secrets: { username: "u", password: "p" } },
    ]) { const r = await create(adminA, b); expect(r.status, b.kind).toBe(201); ids.push(r.body.id); }
    expect((await request(app).get("/integrations").set(...bearer(adminB))).body.connections).toHaveLength(0);
    for (const id of ids) {
      expect((await request(app).post(`/integrations/${id}/pause`).set(...bearer(adminB))).status).toBe(404);
      expect((await request(app).delete(`/integrations/${id}`).set(...bearer(adminB))).status).toBe(404);
    }
  });
});
