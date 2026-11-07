/**
 * Push integrations beyond Wazuh: the generic JSON webhook (also Elastic Security and Splunk payloads)
 * and Syslog/CEF text. Same authentication as the Wazuh webhook, so the security cases are repeated here.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { genericWebhookAdapter } from "../src/integrations/generic.js";
import { cefAdapter, parseExtension } from "../src/integrations/cef.js";
import * as registry from "../src/integrations/registry.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

const GEN = "/security-events/webhook/generic";
const CEF = "/security-events/webhook/cef";
let tA: string, tB: string, credA: TestCredential;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  credA = await issueCredential(tA);
});
const alertsOf = (t: string) => query<{ id: string; title: string; severity: string; source: string; source_ip: string | null; target: string | null; occurred_at: string | null }>(
  "SELECT id, title, severity, source, source_ip, target, occurred_at FROM alerts WHERE tenant_id = $1 ORDER BY title", [t]).then((r) => r.rows);

describe("catalogue", () => {
  it("lists both as available push integrations", () => {
    const c = registry.catalogue();
    for (const kind of ["generic_webhook", "cef"]) {
      const m = c.find((x) => x.kind === kind);
      expect(m).toMatchObject({ status: "available", inbound: "push", plane: "data" });
      expect(registry.pushAdapter(kind)).not.toBeNull();
    }
  });
});

describe("generic JSON webhook", () => {
  it("stores one event, normalised, in the credential's workspace only", async () => {
    const r = await sendSigned(app, credA, { title: "Impossible travel", severity: "High", source_ip: "203.0.113.9", host: "web-1", id: "evt-1", timestamp: "2026-11-01T10:00:00Z" }, { path: GEN });
    expect(r.status).toBe(202);
    expect(r.body.status).toBe("ingested");
    const rows = await alertsOf(tA);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ title: "Impossible travel", severity: "high", source: "generic_webhook", source_ip: "203.0.113.9", target: "web-1" });
    expect(await alertsOf(tB)).toHaveLength(0);
  });
  it("is idempotent: the same event twice is one alert", async () => {
    await sendSigned(app, credA, { title: "X", id: "same" }, { path: GEN });
    const r = await sendSigned(app, credA, { title: "X", id: "same" }, { path: GEN });
    expect(r.body).toMatchObject({ status: "skipped", reason: "duplicate" });
    expect(await alertsOf(tA)).toHaveLength(1);
  });
  it("without an id, identical content is one alert and different content is another", async () => {
    await sendSigned(app, credA, { title: "A", host: "h" }, { path: GEN });
    await sendSigned(app, credA, { title: "A", host: "h" }, { path: GEN });
    await sendSigned(app, credA, { title: "A", host: "h2" }, { path: GEN });
    expect(await alertsOf(tA)).toHaveLength(2);
  });
  it("takes a batch (array and {events})", async () => {
    const r = await sendSigned(app, credA, { events: [{ title: "one", id: "1" }, { title: "two", id: "2" }, { nope: true }] }, { path: GEN });
    expect(r.status).toBe(202);
    expect(r.body.ingested).toBe(2);
    expect(await alertsOf(tA)).toHaveLength(2);
  });
  it("reads an Elastic Security (Kibana) alert document", async () => {
    const doc = { "kibana.alert.rule.name": "Suspicious PowerShell", "kibana.alert.severity": "critical", "kibana.alert.uuid": "k-1", "kibana.alert.reason": "process powershell.exe -enc on host-9", "@timestamp": "2026-11-01T10:00:00.000Z", host: { name: "host-9", ip: ["10.0.0.9"] }, source: { ip: "198.51.100.7" }, "kibana.alert.rule.threat.technique.id": ["T1059"] };
    const r = await sendSigned(app, credA, doc, { path: GEN });
    expect(r.status).toBe(202);
    const [a] = await alertsOf(tA);
    expect(a).toMatchObject({ title: "Suspicious PowerShell", severity: "critical", source_ip: "198.51.100.7", target: "host-9" });
  });
  it("reads a Splunk webhook alert action", async () => {
    const r = await sendSigned(app, credA, { sid: "scheduler_admin_1", search_name: "Brute force on sshd", result: { src_ip: "192.0.2.44", host: "bastion", _raw: "Failed password for root", severity: "high" } }, { path: GEN });
    expect(r.status).toBe(202);
    const [a] = await alertsOf(tA);
    expect(a).toMatchObject({ title: "Brute force on sshd", severity: "high", source_ip: "192.0.2.44", target: "bastion" });
  });
  it("skips events with no title, and requests over 200 events, without storing anything", async () => {
    expect((await sendSigned(app, credA, { foo: "bar" }, { path: GEN })).body.status).toBe("skipped");
    const many = Array.from({ length: 201 }, (_, i) => ({ title: `e${i}`, id: String(i) }));
    expect((await sendSigned(app, credA, many, { path: GEN })).body.status).toBe("skipped");
    expect(await alertsOf(tA)).toHaveLength(0);
  });
  it("treats hostile text as bounded data", () => {
    const r = genericWebhookAdapter.normalize({ title: "ok\u0000‮" + "x".repeat(5000), summary: "y".repeat(9000), source_ip: "not an ip; DROP TABLE", severity: { a: 1 }, host: "h\u0007" });
    if (r.skipped) throw new Error("skipped");
    const f = r.findings[0]!;
    expect(f.title.length).toBeLessThanOrEqual(300);
    expect(f.title).not.toMatch(/[\u0000‮]/);
    expect(f.summary.length).toBeLessThanOrEqual(4000);
    expect(f.sourceIp).toBeNull();
    expect(f.severity).toBe("medium"); // unknown severity never hides an event
    expect(f.target).toBe("h");
  });
  it("never throws on odd input", () => {
    for (const body of [null, 1, "x", [], [null, 3, "a"], { events: "no" }, { title: { a: { b: 1 } } }]) expect(() => genericWebhookAdapter.normalize(body)).not.toThrow();
  });
});

describe("Syslog / CEF", () => {
  const cefLine = "CEF:0|Acme|Firewall|1.0|100|Port scan detected|8|src=203.0.113.50 dst=10.0.0.5 dhost=db-1 msg=Many ports probed in 5 seconds rt=1793527200000 externalId=fw-77";
  const send = (text: string, opts = {}) => sendSigned(app, credA, text, { path: CEF, contentType: "text/plain", ...opts });

  it("stores a CEF event, with and without a syslog header", async () => {
    const r1 = await send(cefLine);
    expect(r1.status).toBe(202);
    expect(r1.body.status).toBe("ingested");
    await send(`<134>Nov  1 10:00:00 fw01 ${cefLine.replace("fw-77", "fw-78").replace("Port scan", "Port sweep")}`);
    const rows = await alertsOf(tA);
    expect(rows.map((x) => x.title)).toEqual(["Port scan detected", "Port sweep detected"]);
    expect(rows[0]).toMatchObject({ severity: "high", source: "cef", source_ip: "203.0.113.50", target: "db-1" });
  });
  it("is idempotent on externalId, and on identical lines without one", async () => {
    await send(cefLine); await send(cefLine);
    const bare = "CEF:0|A|B|1|1|Thing|5|src=198.51.100.1";
    await send(bare); await send(bare);
    expect(await alertsOf(tA)).toHaveLength(2);
  });
  it("maps severity 0–10", () => {
    const sev = (n: number) => { const r = cefAdapter.normalize(`CEF:0|A|B|1|1|T|${n}|x=1`); if (r.skipped) throw new Error("skipped"); return r.findings[0]!.severity; };
    expect([sev(0), sev(3), sev(4), sev(6), sev(7), sev(8), sev(9), sev(10)]).toEqual(["low", "low", "medium", "medium", "high", "high", "critical", "critical"]);
  });
  it("handles escaped pipes in the header and escaped equals in values", () => {
    const r = cefAdapter.normalize("CEF:0|Ac\\|me|P|1|1|Name with \\| pipe|5|msg=a\\=b and more src=198.51.100.2");
    if (r.skipped) throw new Error("skipped");
    expect(r.findings[0]!.title).toBe("Name with | pipe");
    expect(r.findings[0]!.summary).toContain("a=b and more");
    expect(r.findings[0]!.sourceIp).toBe("198.51.100.2");
    expect(parseExtension("a=1 b=two words c=3")).toEqual({ a: "1", b: "two words", c: "3" });
  });
  it("keeps error-or-worse syslog lines and skips routine ones", async () => {
    const r = await send("<11>Nov  1 10:00:00 host sshd[1]: error: maximum authentication attempts exceeded from 203.0.113.77\n<14>Nov  1 10:00:01 host cron[2]: job ran\nnot syslog at all");
    expect(r.body.status).toBe("ingested");
    const rows = await alertsOf(tA);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ severity: "medium", source_ip: "203.0.113.77" });
  });
  it("skips a request with nothing usable, and more than 200 lines", async () => {
    expect((await send("hello\nworld")).body.status).toBe("skipped");
    expect((await send(Array.from({ length: 201 }, (_, i) => `CEF:0|A|B|1|1|T${i}|5|x=1`).join("\n"))).body.status).toBe("skipped");
    expect(await alertsOf(tA)).toHaveLength(0);
  });
  it("never throws on hostile lines", () => {
    const lines = ["CEF:", "CEF:0|", "CEF:0|a|b|c|d|e|f|", "CEF:0|" + "|".repeat(5000), "x".repeat(100_000), "\u0000\u0001<999>", "CEF:0|a|b|c|d|e|99999999999|" + "k=".repeat(3000)];
    for (const l of lines) expect(() => cefAdapter.normalize(l)).not.toThrow();
  });
});

describe("authentication (same as the Wazuh webhook)", () => {
  it("rejects a bad signature, a tampered body, an unknown key and a replayed nonce on both routes", async () => {
    for (const [path, ct, body] of [[GEN, "application/json", { title: "t" }], [CEF, "text/plain", "CEF:0|A|B|1|1|T|5|x=1"]] as const) {
      expect((await sendSigned(app, credA, body, { path, contentType: ct, signWithSecret: "wrong-secret" })).status).toBe(401);
      expect((await sendSigned(app, credA, body, { path, contentType: ct, signBody: "something else" })).status).toBe(401);
      expect((await sendSigned(app, credA, body, { path, contentType: ct, keyId: "lw_00000000000000000000000000" })).status).toBe(401);
      const nonce = "replayNonce" + "x".repeat(path.length);
      expect((await sendSigned(app, credA, body, { path, contentType: ct, nonce })).status).toBe(202);
      expect((await sendSigned(app, credA, body, { path, contentType: ct, nonce })).status).toBe(401);
    }
  });
  it("does not parse or store anything for an unauthenticated sender", async () => {
    const r = await request(app).post(GEN).set("content-type", "application/json").send({ title: "x" });
    expect(r.status).toBe(401);
    expect(await alertsOf(tA)).toHaveLength(0);
  });
  it("a credential of workspace A never writes into workspace B, even with B's id in a header", async () => {
    await sendSigned(app, credA, { title: "mine", id: "1" }, { path: GEN, tenantHeader: tB });
    expect(await alertsOf(tB)).toHaveLength(0);
  });
  it("the CEF route refuses JSON and the generic route refuses text (no body is read)", async () => {
    const a = await sendSigned(app, credA, "CEF:0|A|B|1|1|T|5|x=1", { path: CEF, contentType: "application/json" });
    const b = await sendSigned(app, credA, "plain", { path: GEN, contentType: "text/plain" });
    expect([a.status, b.status].every((s) => s === 401 || s === 400 || s === 415)).toBe(true);
    expect(await alertsOf(tA)).toHaveLength(0);
  });
});
