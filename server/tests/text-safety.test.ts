/**
 * A NUL character (U+0000) cannot be stored by PostgreSQL. Anywhere text can
 * reach the database it must not become a 500: a sensor would re-send the same
 * event forever, holding back everything queued behind it.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { stripNul } from "../src/text.js";
import type { User } from "../src/types.js";
import { issueCredential, sendSigned, type TestCredential } from "./helpers/webhook.js";

const savedMode = config.deploymentMode;
let tenant: string;
let admin: User;
let cred: TestCredential;
const NUL = "a\u0000b";
const bearer = () => `Bearer ${mint({ sub: admin.id, tenant_id: tenant, token_version: admin.token_version }, { expiresIn: "1h" })}`;
const pay = { action: "payment-check", beneficiary: { account: "DE89370400440532013000", name: "N" }, amount: 10, currency: "EUR" };
const wazuh = (id: string, event: Record<string, unknown>) => ({ provider: "wazuh", event: { id, rule: { description: "d", level: 5 }, ...event } });

beforeAll(async () => { await migrate(); config.deploymentMode = "self-hosted"; });
afterAll(async () => { config.deploymentMode = savedMode; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Z')", [tenant]);
  admin = await store.insertUser({ email: "a@z.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tenant, role: "admin", status: "active" });
  cred = await issueCredential(tenant);
});

describe("sensor text with a NUL character is cleaned and kept, never a 500", () => {
  it.each([
    ["rule description", wazuh("n1", { rule: { description: `Brute${NUL}force`, level: 5 } })],
    ["full log", wazuh("n2", { full_log: `Failed password${NUL}for root` })],
    ["agent name and address", wazuh("n3", { agent: { name: NUL, ip: NUL, os: { name: NUL } } })],
    ["MITRE id", wazuh("n4", { rule: { description: "d", level: 5, mitre: { id: [NUL] } } })],
    ["event id", wazuh(NUL, {})],
    ["data", wazuh("n5", { data: { srcip: NUL, srcuser: NUL, office365: { x: NUL } } })],
  ])("%s", async (_name, body) => {
    await sendSigned(app, cred, body).expect(202);
    // Stored, so the sensor does not retry it.
    expect(Number((await query("SELECT count(*) AS n FROM alerts WHERE tenant_id = $1", [tenant])).rows[0].n)).toBe(1);
  });

  it("the stored text has no NUL, and the rest of it is intact", async () => {
    await sendSigned(app, cred, wazuh("n6", { rule: { description: `Brute${NUL}force`, level: 5 }, full_log: `Failed password${NUL} for root`, agent: { name: `web${NUL}01` } })).expect(202);
    const a = (await query("SELECT title, summary, target FROM alerts WHERE tenant_id = $1", [tenant])).rows[0];
    // NUL is "a\0b": only the NUL goes, the letters around it stay.
    expect(a).toEqual({ title: "Bruteabforce", summary: "Failed passwordab for root", target: "webab01" });
  });

  it("a poison event does not hold back the ones behind it", async () => {
    await sendSigned(app, cred, wazuh("p1", { full_log: NUL })).expect(202);
    await sendSigned(app, cred, wazuh("p2", { full_log: "normal" })).expect(202);
    expect(Number((await query("SELECT count(*) AS n FROM alerts WHERE tenant_id = $1", [tenant])).rows[0].n)).toBe(2);
  });

  it("stripNul only removes NUL", () => {
    expect(stripNul("a\u0000b\u0000")).toBe("ab");
    expect(stripNul("plain ünïcode 😀\n\t")).toBe("plain ünïcode 😀\n\t");
  });
});

describe("text typed into the API is refused with a clear answer, never a 500", () => {
  const send = (body: unknown) => sendSigned(app, cred, body, { path: "/security-events/payment-check" });

  it.each([
    ["account", { ...pay, beneficiary: { account: NUL + "cdef" } }],
    ["name", { ...pay, beneficiary: { account: "DE89370400440532013000", name: NUL } }],
    ["requested by", { ...pay, requestedBy: NUL }],
    ["reference", { ...pay, reference: NUL }],
  ])("payment check: %s", async (_name, body) => {
    await send(body).expect(400);
  });

  it("a payment with a hidden character is not 'the same account' as without it", async () => {
    await send({ ...pay, beneficiary: { account: "DE89\u0000370400440532013000" } }).expect(400);
    expect(Number((await query("SELECT count(*) AS n FROM payment_checks WHERE tenant_id = $1", [tenant])).rows[0].n)).toBe(0);
  });

  it("block reason", async () => {
    const r = await request(app).post("/security/blocks").set("Authorization", bearer()).send({ ip: "45.155.205.12", reason: NUL });
    expect(r.status).toBe(400); // the whole API refuses NUL before the route runs (see below)
  });
});

describe("the whole API refuses a NUL character with a 400 before any route runs", () => {
  const auth = () => ["Authorization", bearer()] as const;

  it.each([
    ["alerts query", () => request(app).get("/alerts?severity=%00").set(...auth())],
    ["alerts feed query", () => request(app).get("/alerts/feed?since=%00").set(...auth())],
    ["assets query", () => request(app).get("/assets?search=a%00b").set(...auth())],
    ["alert id in the path", () => request(app).get("/alerts/%00").set(...auth())],
    ["explain, id in the path", () => request(app).post("/alerts/a%00b/explain").set(...auth())],
    ["password reset, before sign-in", () => request(app).post("/auth/forgot-password").send({ email: NUL })],
    ["resend verification, before sign-in", () => request(app).post("/auth/resend-verification").send({ email: NUL })],
    ["connection key label", () => request(app).post("/security-events/credentials").set(...auth()).send({ label: NUL })],
    ["a NUL in a JSON key", () => request(app).post("/auth/login").send({ ["a\u0000"]: 1, email: "x@y.z", password: "p" })],
    ["a NUL deep in a body", () => request(app).post("/auth/login").send({ email: "x@y.z", password: "p", extra: { a: [{ b: NUL }] } })],
    ["a NUL in a cookie", () => request(app).get("/alerts").set("Cookie", "legion_refresh=a%00b")],
  ])("%s", async (_name, call) => {
    const r = await call();
    expect(r.status).toBe(400);
    expect(r.body.detail).toBe("Invalid request");
  });

  it("a form-encoded body is checked too", async () => {
    const r = await request(app).post("/auth/forgot-password").type("form").send("email=a%00b");
    expect(r.status).toBe(400);
  });

  it("answers in the person's language", async () => {
    const r = await request(app).post("/auth/forgot-password").set("Accept-Language", "uz").send({ email: NUL });
    expect(r.status).toBe(400);
    expect(r.body.detail).not.toBe("Invalid request");
  });

  it("ordinary requests, and the sensor routes (raw bodies), are unaffected", async () => {
    await request(app).get("/alerts?severity=high").set(...auth()).expect(200);
    await request(app).get("/health").expect(200);
    await sendSigned(app, cred, wazuh("ok1", { full_log: "fine" })).expect(202);
    // A sensor body with a NUL is cleaned and stored, not refused by this rule.
    await sendSigned(app, cred, wazuh("ok2", { full_log: NUL })).expect(202);
  });

  it("the NUL cannot be smuggled in as a percent-encoded character in a place that is later decoded", async () => {
    for (const path of ["/alerts/%00", "/alerts/%2500x", "/%00"]) {
      const r = await request(app).get(path).set(...auth());
      expect(r.status, path).toBeLessThan(500);
    }
  });
});
