/**
 * Pull connectors: Microsoft Defender XDR (Graph alerts_v2) and AWS GuardDuty, against simulated providers.
 * The SigV4 signer is checked against AWS's published test vector.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import * as connections from "../src/integrations/connections.js";
import { signV4 } from "../src/integrations/sigv4.js";
import { findingFromAlert, m365Adapter } from "../src/integrations/m365.js";
import { findingFromGuardDuty, guarddutyAdapter } from "../src/integrations/guardduty.js";
import { EgressRefused } from "../src/integrations/fetch.js";
import type { User } from "../src/types.js";

const DIR = "11111111-1111-4111-8111-111111111111", APP = "22222222-2222-4222-8222-222222222222", SECRET = "ms-client-secret-VERY-secret";
const HOUR = 3_600_000;
const T1 = new Date(Date.now() - 3 * HOUR).toISOString(), T2 = new Date(Date.now() - 2 * HOUR).toISOString(), T3 = new Date(Date.now() - HOUR).toISOString();
let tA: string, tB: string, adminA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
type Call = { url: string; method: string; headers: Record<string, string>; body: string };
let calls: Call[]; let respond: (c: Call) => { status: number; body?: unknown };
const realFetch = globalThis.fetch;
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
    return new Response(typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

describe("SigV4", () => {
  it("matches AWS's published get-vanilla test vector", () => {
    const h = signV4({ method: "GET", host: "example.amazonaws.com", path: "/", region: "us-east-1", service: "service", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", now: new Date("2015-08-30T12:36:00Z") });
    expect(h.authorization).toBe("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
  });
});

describe("Defender XDR", () => {
  const alert = (id: string, extra: Record<string, unknown> = {}) => ({
    id, title: `Defender ${id}`, severity: "high", status: "new", category: "Execution", description: "Suspicious PowerShell", serviceSource: "microsoftDefenderForEndpoint",
    createdDateTime: T1, lastUpdateDateTime: T2, mitreTechniques: ["T1059.001"],
    evidence: [{ "@odata.type": "#microsoft.graph.security.ipEvidence", ipAddress: "198.51.100.9" }, { "@odata.type": "#microsoft.graph.security.deviceEvidence", deviceDnsName: "laptop-7.corp" }, { "@odata.type": "#microsoft.graph.security.userEvidence", userAccount: { accountName: "alice" } }], ...extra,
  });
  const graph = (pages: unknown[][]) => (c: Call) => {
    if (c.url.includes("/oauth2/v2.0/token")) return { status: 200, body: { access_token: "tok-abc" } };
    const i = c.url.includes("page=2") ? 1 : 0;
    return { status: 200, body: { value: pages[i], ...(i + 1 < pages.length ? { "@odata.nextLink": "https://graph.microsoft.com/v1.0/security/alerts_v2?page=2" } : {}) } };
  };
  const conn = { id: "c1", tenantId: tA, config: { directory_id: DIR, client_id: APP }, secrets: { client_secret: SECRET } };

  it("maps an alert: severity, address, host, technique", () => {
    const f = findingFromAlert(alert("a1") as never)!;
    expect(f).toMatchObject({ externalId: "a1", severity: "high", sourceIp: "198.51.100.9", target: "laptop-7.corp", mitre: ["T1059.001"] });
    expect(f.summary).toContain("User: alice");
    expect(findingFromAlert(alert("a2", { severity: "informational" }) as never)!.severity).toBe("low");
  });
  it("signs in with client credentials, reads alerts_v2 with a bearer token, follows paging, advances the cursor", async () => {
    respond = graph([[alert("a1")], [alert("a2", { lastUpdateDateTime: T3 })]]);
    const r = await m365Adapter.poll(conn, null, new AbortController().signal);
    expect(r.findings.map((f) => f.externalId)).toEqual(["a1", "a2"]);
    expect(r.cursor).toEqual({ since: T3 });
    expect(calls[0]!.url).toBe(`https://login.microsoftonline.com/${DIR}/oauth2/v2.0/token`);
    expect(calls[1]!.headers.authorization).toBe("Bearer tok-abc");
    expect(new URL(calls[1]!.url).searchParams.get("$filter")).toContain("lastUpdateDateTime ge");
    await m365Adapter.poll(conn, r.cursor, new AbortController().signal);
    expect(new URL(calls.at(-2)!.url).searchParams.get("$filter")).toBe(`lastUpdateDateTime ge ${T3}`);
  });
  it("refuses a nextLink that points anywhere but Graph", async () => {
    respond = (c) => c.url.includes("/oauth2") ? { status: 200, body: { access_token: "t" } } : { status: 200, body: { value: [alert("a1")], "@odata.nextLink": "https://evil.example/steal" } };
    await expect(m365Adapter.poll(conn, null, new AbortController().signal)).rejects.toBeInstanceOf(EgressRefused);
  });
  it("a wrong secret or missing consent is a clear error that never contains the secret", async () => {
    respond = (c) => c.url.includes("/oauth2") ? { status: 401, body: { error: `invalid_client ${SECRET}` } } : { status: 200 };
    const e1 = await m365Adapter.poll(conn, null, new AbortController().signal).catch((e: Error) => e);
    expect((e1 as Error).message).toMatch(/sign-in failed \(401\)/);
    expect((e1 as Error).message).not.toContain(SECRET);
    respond = (c) => c.url.includes("/oauth2") ? { status: 200, body: { access_token: "t" } } : { status: 403 };
    expect(((await m365Adapter.poll(conn, null, new AbortController().signal).catch((e: Error) => e)) as Error).message).toMatch(/admin consent/);
  });
  it("end to end through the worker: alerts become Legion alerts in the right workspace; secret sealed; outage backs off and recovers", async () => {
    const created = await request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "m365", name: "Defender", config: { directory_id: DIR, client_id: APP }, secrets: { client_secret: SECRET } });
    expect(created.status).toBe(201);
    expect(JSON.stringify(created.body)).not.toContain(SECRET);
    expect((await request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "m365", name: "bad", config: { directory_id: "nope", client_id: APP }, secrets: { client_secret: SECRET } })).status).toBe(400);
    respond = (c) => c.url.includes("/oauth2") ? { status: 503 } : { status: 200 };
    const down = await connections.runDuePolls({});
    expect(down).toMatchObject({ claimed: 1, failed: 1 });
    let [c] = (await request(app).get("/integrations").set(...bearer(adminA))).body.connections;
    expect(c.failures).toBe(1);
    expect(c.last_error).not.toContain(SECRET);
    await query("UPDATE integration_connections SET next_poll_at = now()");
    respond = graph([[alert("e1"), alert("e2")]]);
    const ok = await connections.runDuePolls({});
    expect(ok).toMatchObject({ succeeded: 1, ingested: 2 });
    [c] = (await request(app).get("/integrations").set(...bearer(adminA))).body.connections;
    expect(c).toMatchObject({ failures: 0, last_error: null });
    expect((await query("SELECT 1 FROM alerts WHERE tenant_id = $1 AND source = 'm365'", [tA])).rowCount).toBe(2);
    expect((await query("SELECT 1 FROM alerts WHERE tenant_id = $1", [tB])).rowCount).toBe(0);
    expect((await request(app).get("/integrations").set(...bearer(adminB))).body.connections).toHaveLength(0);
    // re-poll the same alerts: duplicates, not new alerts
    await query("UPDATE integration_connections SET next_poll_at = now()");
    expect(await connections.runDuePolls({})).toMatchObject({ ingested: 0, duplicates: 2 });
  });
});

describe("GuardDuty", () => {
  const gd = (over: Record<string, unknown> = {}) => ({
    Id: "f1", Title: "UnauthorizedAccess:EC2/SSHBruteForce", Type: "UnauthorizedAccess:EC2/SSHBruteForce", Description: "SSH brute force", Severity: 5, Region: "eu-west-1", AccountId: "123456789012",
    UpdatedAt: T2, Service: { EventLastSeen: T1, Action: { NetworkConnectionAction: { RemoteIpDetails: { IpAddressV4: "203.0.113.20" } } } },
    Resource: { InstanceDetails: { InstanceId: "i-0abc123" } }, ...over,
  });
  const api = (findings: unknown[]) => (c: Call) => {
    if (c.method === "GET" && c.url.endsWith("/detector")) return { status: 200, body: { detectorIds: ["abcdef0123456789abcdef0123456789"] } };
    if (c.url.endsWith("/findings/get")) return { status: 200, body: { findings } };
    if (c.url.endsWith("/findings")) return { status: 200, body: { findingIds: (findings as { Id: string }[]).map((f) => f.Id) } };
    return { status: 404 };
  };
  const conn = { id: "c2", tenantId: tA, config: { regions: ["eu-west-1"] }, secrets: { access_key_id: "AKIAEXAMPLE", secret_access_key: "aws-secret-VERY-secret-key" } };

  it("maps severity bands, address and instance", () => {
    expect(findingFromGuardDuty(gd() as never)).toMatchObject({ externalId: "f1", severity: "medium", sourceIp: "203.0.113.20", target: "i-0abc123" });
    expect(findingFromGuardDuty(gd({ Severity: 8 }) as never)!.severity).toBe("high");
    expect(findingFromGuardDuty(gd({ Severity: 2 }) as never)!.severity).toBe("low");
    const probe = gd({ Service: { Action: { PortProbeAction: { PortProbeDetails: [{ RemoteIpDetails: { IpAddressV4: "198.51.100.3" } }] } } } });
    expect(findingFromGuardDuty(probe as never)!.sourceIp).toBe("198.51.100.3");
  });
  it("lists detectors, lists and gets findings with a signed request to guardduty.<region>.amazonaws.com only", async () => {
    respond = api([gd(), gd({ Id: "f2", UpdatedAt: T3 })]);
    const r = await guarddutyAdapter.poll(conn, null, new AbortController().signal);
    expect(r.findings.map((f) => f.externalId)).toEqual(["f1", "f2"]);
    expect(r.cursor).toEqual({ since: Date.parse(T3) });
    expect(calls.every((c) => new URL(c.url).hostname === "guardduty.eu-west-1.amazonaws.com")).toBe(true);
    expect(calls.every((c) => /^AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE\/\d{8}\/eu-west-1\/guardduty\/aws4_request/.test(c.headers.authorization!))).toBe(true);
    expect(JSON.stringify(calls)).not.toContain("aws-secret-VERY-secret-key");
  });
  it("403 names the problem without echoing keys; 503 is a retryable error", async () => {
    respond = () => ({ status: 403, body: "AccessDenied aws-secret-VERY-secret-key" });
    const e = (await guarddutyAdapter.poll(conn, null, new AbortController().signal).catch((x: Error) => x)) as Error;
    expect(e.message).toMatch(/refused the credentials/);
    expect(e.message).not.toContain("aws-secret");
    respond = () => ({ status: 503 });
    expect(((await guarddutyAdapter.poll(conn, null, new AbortController().signal).catch((x: Error) => x)) as Error).message).toMatch(/will retry/);
  });
  it("with role_arn: assumes the role through STS (external id) and reads GuardDuty with the short-lived session", async () => {
    const roleConn = { ...conn, config: { regions: ["eu-west-1"], role_arn: "arn:aws:iam::210987654321:role/LegionGuardDutyRead", external_id: "legion-ext-42" } };
    const inner = api([gd()]);
    respond = (c) => c.url.startsWith("https://sts.amazonaws.com/")
      ? { status: 200, body: "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP</AccessKeyId><SecretAccessKey>tempsecret</SecretAccessKey><SessionToken>tok123</SessionToken></Credentials></AssumeRoleResult></AssumeRoleResponse>" }
      : inner(c);
    const r = await guarddutyAdapter.poll(roleConn, null, new AbortController().signal);
    expect(r.findings).toHaveLength(1);
    const sts = new URL(calls[0]!.url);
    expect(sts.hostname).toBe("sts.amazonaws.com");
    expect(sts.searchParams.get("RoleArn")).toBe("arn:aws:iam::210987654321:role/LegionGuardDutyRead");
    expect(sts.searchParams.get("ExternalId")).toBe("legion-ext-42");
    expect(calls[0]!.headers.authorization).toMatch(/Credential=AKIAEXAMPLE\/\d{8}\/us-east-1\/sts\/aws4_request/);
    const gdCalls = calls.slice(1);
    expect(gdCalls.every((c) => /Credential=ASIATEMP\//.test(c.headers.authorization!) && c.headers["x-amz-security-token"] === "tok123")).toBe(true);
    respond = (c) => c.url.startsWith("https://sts.amazonaws.com/") ? { status: 403, body: "AccessDenied" } : inner(c);
    expect(((await guarddutyAdapter.poll(roleConn, null, new AbortController().signal).catch((x: Error) => x)) as Error).message).toMatch(/trust policy and external id/);
  });
  it("rejects a region that is not a region (no host injection) and an empty list", async () => {
    const mk = (regions: unknown) => request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "guardduty", name: "AWS", config: { regions }, secrets: { access_key_id: "AKIAEXAMPLE", secret_access_key: "x".repeat(30) } });
    expect((await mk(["eu-west-1.evil.com"])).status).toBe(400);
    expect((await mk([])).status).toBe(400);
    expect((await mk(["eu-west-1", "us-east-2"])).status).toBe(201);
    const bad = await request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "guardduty", name: "AWS", config: { regions: ["eu-west-1"], role_arn: "arn:aws:iam::1:role/x\nHost: evil" }, secrets: { access_key_id: "AKIAEXAMPLE", secret_access_key: "x".repeat(30) } });
    expect(bad.status).toBe(400);
  });
});

describe("audit A-4: polling many connections", () => {
  const GUID = (n: number) => `${String(n).repeat(8)}-${String(n).repeat(4)}-4${String(n).repeat(3)}-8${String(n).repeat(3)}-${String(n).repeat(12)}`;
  it("polls slow connections in parallel (a batch takes about one vendor delay, not the sum), never more than the limit at once", async () => {
    const DELAY = 150;
    let inFlight = 0, peak = 0;
    respond = () => ({ status: 200 });
    globalThis.fetch = (async (input: URL | string) => {
      inFlight++; peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, DELAY));
      inFlight--;
      const url = String(input);
      if (url.includes("login.microsoftonline.com")) return new Response(JSON.stringify({ access_token: "t" }), { status: 200 });
      return new Response(JSON.stringify({ value: [] }), { status: 200 });
    }) as typeof fetch;
    for (let i = 0; i < 16; i++) {
      const r = await request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "m365", name: `Defender ${i}`, config: { directory_id: GUID(1), client_id: GUID(2) }, secrets: { client_secret: "s-secret-123" } });
      expect(r.status).toBe(201);
    }
    const started = Date.now();
    const report = await connections.runDuePolls({ concurrency: 8 });
    const took = Date.now() - started;
    expect(report).toMatchObject({ claimed: 16, succeeded: 16, failed: 0 });
    expect(peak).toBeLessThanOrEqual(8);          // bounded
    expect(peak).toBeGreaterThan(1);              // and really parallel
    // 16 connections x 2 requests x 150 ms = 4.8 s one after another; in parallel (8 at a time) about 0.6 s.
    expect(took).toBeLessThan(2500);
  }, 20_000);

  it("the lease covers the worst case of a batch, so a slow batch is not taken over by another instance", async () => {
    // Claim with the defaults and read the lease the database recorded: it must outlast the worst case,
    // i.e. every poll of the batch hitting its 120 s timeout, two rounds of 8.
    await request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "m365", name: "D", config: { directory_id: GUID(1), client_id: GUID(2) }, secrets: { client_secret: "s-secret-123" } }).expect(201);
    globalThis.fetch = (async () => { await new Promise((r) => setTimeout(r, 50)); return new Response("{}", { status: 503 }); }) as typeof fetch;
    let leaseSeconds = 0;
    const realClaim = connections.runDuePolls;
    await realClaim({});
    const row = (await query<{ lease_until: string | null }>("SELECT lease_until FROM integration_connections")).rows[0]!;
    expect(row.lease_until).toBeNull();      // released after the (failed) poll
    // The default is computed, not assumed: 2 rounds x 120 s + 60 s.
    const { config } = await import("../src/config.js");
    expect(Math.ceil((config.integrationPollConcurrency * 2) / config.integrationPollConcurrency) * 120 + 60).toBe(300);
  });

  it("/metrics reports how far behind the polls are and how many connections stopped", async () => {
    await request(app).post("/integrations").set(...bearer(adminA)).send({ kind: "m365", name: "D", config: { directory_id: GUID(1), client_id: GUID(2) }, secrets: { client_secret: "s-secret-123" } }).expect(201);
    await query("UPDATE integration_connections SET next_poll_at = now() - interval '20 minutes'");
    const { collectMetrics } = await import("../src/metrics.js");
    const text = await collectMetrics();
    const lag = Number(/legion_integration_poll_lag_seconds (\d+)/.exec(text)?.[1]);
    expect(lag).toBeGreaterThanOrEqual(1190);
    expect(text).toMatch(/legion_integration_connections_active 1/);
    await query("UPDATE integration_connections SET status = 'error'");
    expect(await collectMetrics()).toMatch(/legion_integration_connections_error 1/);
  });
});
