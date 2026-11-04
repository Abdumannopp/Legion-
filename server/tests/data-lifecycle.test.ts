/**
 * Data lifecycle: what is kept, for how long, and what a customer can take with
 * them. The privacy text promises these; each one is tested here.
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
import { prunePaymentChecks, pseudonymiseAudit } from "../src/retention.js";
import { pruneAlertsByPlan } from "../src/plan-limits.js";
import type { Role, User } from "../src/types.js";

const savedMode = config.deploymentMode;
let hash = "";
let tA: string, tB: string;
let adminA: User, analystA: User, adminB: User;
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { algorithm: "HS256", expiresIn: "1h" })}`] as const;
const tenant = async (name: string, extra = "") => {
  const id = randomUUID();
  await query(`INSERT INTO tenants (id, name, trial_ends_at${extra ? ", legal_hold" : ""}) VALUES ($1, $2, now() + interval '14 days'${extra ? ", true" : ""})`, [id, name]);
  return id;
};
const user = (t: string, role: Role, email?: string) => store.insertUser({ email: email ?? `${role}-${randomUUID().slice(0, 8)}@example.com`, password_hash: hash, tenant_id: t, role, status: "active" });
const hexHash = "a".repeat(64);
const pay = (t: string, id: string, monthsAgo: number) => query(
  `INSERT INTO payment_checks (tenant_id, id, beneficiary_hash, beneficiary_hint, amount, currency, decision, reasons, created_at)
   VALUES ($1, $2, $3, '0000', 5, 'EUR', 'allow', '{}', now() - make_interval(months => $4))`, [t, id, hexHash, monthsAgo]);
const audit = (t: string, id: string, monthsAgo: number, email: string | null, detail: string | null) => query(
  `INSERT INTO audit_log (id, tenant_id, user_email, action, detail, ip_address, created_at)
   VALUES ($1, $2, $3, 'user.invited', $4, '203.0.113.5', now() - make_interval(months => $5))`, [id, t, email, detail, monthsAgo]);

beforeAll(async () => { await migrate(); hash = await bcrypt.hash("password123", 4); });
afterAll(async () => { (config as { deploymentMode: string }).deploymentMode = savedMode; await closePool(); });
beforeEach(async () => {
  await truncateAll();
  (config as { deploymentMode: string }).deploymentMode = "saas";
  tA = await tenant("A"); tB = await tenant("B");
  adminA = await user(tA, "admin", "boss@a.example"); analystA = await user(tA, "analyst"); adminB = await user(tB, "admin", "boss@b.example");
});

describe("payment checks are deleted after 24 months", () => {
  it("only old ones, in every workspace; a workspace on legal hold keeps everything", async () => {
    const held = await tenant("Held", "hold");
    await pay(tA, "PAY-OLD-A", 25); await pay(tA, "PAY-NEW-A", 3); await pay(tB, "PAY-OLD-B", 30); await pay(held, "PAY-OLD-H", 40);
    expect(await prunePaymentChecks(24)).toBe(2);
    const left = (await query("SELECT id FROM payment_checks ORDER BY id")).rows.map((r) => r.id);
    expect(left).toEqual(["PAY-NEW-A", "PAY-OLD-H"]);
  });
  it("0 keeps everything, and a self-hosted installation is never pruned", async () => {
    await pay(tA, "PAY-OLD", 40);
    expect(await prunePaymentChecks(0)).toBe(0);
    (config as { deploymentMode: string }).deploymentMode = "self-hosted";
    expect(await prunePaymentChecks(24)).toBe(0);
    expect((await query("SELECT count(*)::int AS n FROM payment_checks")).rows[0].n).toBe(1);
  });
});

describe("old audit entries lose their personal data, not their existence", () => {
  it("removes email, IP and addresses inside the detail text after 24 months; recent entries are untouched", async () => {
    await audit(tA, randomUUID(), 25, "boss@a.example", "dana@acme.example as analyst");
    await audit(tA, randomUUID(), 2, "boss@a.example", "kim@acme.example as viewer");
    expect(await pseudonymiseAudit(24)).toBe(1);
    const rows = (await query("SELECT user_email, ip_address, detail, action FROM audit_log WHERE tenant_id = $1 ORDER BY created_at", [tA])).rows;
    expect(rows).toHaveLength(2);                                                   // nothing was deleted
    expect(rows[0]).toMatchObject({ user_email: null, ip_address: null, detail: "[removed] as analyst", action: "user.invited" });
    expect(rows[1]).toMatchObject({ user_email: "boss@a.example", ip_address: "203.0.113.5", detail: "kim@acme.example as viewer" });
  });

  it("is idempotent, skips a legal hold and self-hosted, and the log stays append-only afterwards", async () => {
    const held = await tenant("Held", "hold");
    await audit(held, randomUUID(), 40, "x@h.example", "y@h.example");
    await audit(tA, randomUUID(), 40, "x@a.example", null);
    expect(await pseudonymiseAudit(24)).toBe(1);
    expect(await pseudonymiseAudit(24)).toBe(0);
    expect((await query("SELECT user_email FROM audit_log WHERE tenant_id = $1", [held])).rows[0].user_email).toBe("x@h.example");
    (config as { deploymentMode: string }).deploymentMode = "self-hosted";
    await audit(tB, randomUUID(), 40, "x@b.example", null);
    expect(await pseudonymiseAudit(24)).toBe(0);
    await expect(query("UPDATE audit_log SET action = 'x' WHERE tenant_id = $1", [tA])).rejects.toThrow(/append-only/);
  });
});

describe("a legal hold stops the other retention too", () => {
  it("resolved alerts on a held workspace are kept past their plan's period", async () => {
    const held = await tenant("Held", "hold");
    await store.applySubscriptionEvent({ tenant_id: held, status: "active", paddle_customer_id: "c", paddle_subscription_id: "sub_h", paddle_price_id: null, current_period_end: null, cancel_at_period_end: false, last_event_at: new Date().toISOString(), plan: "starter", addons: [] });
    await query(`INSERT INTO alerts (id, tenant_id, title, severity, agent, status, summary, confidence, source, created_at) VALUES ('OLD', $1, 't', 'low', 'Sentinel', 'resolved', 's', 50, 'wazuh', now() - interval '400 days')`, [held]);
    expect(await pruneAlertsByPlan()).toBe(0);
    expect((await query("SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1", [held])).rows[0].n).toBe(1);
  });
});

describe("the workspace export", () => {
  const get = (u: User) => request(app).get("/workspace/export").set(...bearer(u)).buffer(true).parse((res, cb) => { let d = ""; res.on("data", (c) => (d += c)); res.on("end", () => cb(null, d)); });

  it("is this workspace's data only, as one JSON file, with no secrets", async () => {
    await store.insertAlert({ id: "A-1", tenant_id: tA, title: "Brute force", severity: "high", agent: "Hunter", status: "open", summary: "s", confidence: 80, ai_explanation: null, explained_at: null, source_ip: "198.51.100.1", target: "web-01", mitre_technique: "T1110", source: "wazuh" } as never);
    await store.insertAlert({ id: "B-1", tenant_id: tB, title: "B secret", severity: "low", agent: "Hunter", status: "open", summary: "s", confidence: 80, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" } as never);
    await pay(tA, "PAY-1", 1); await pay(tB, "PAY-B", 1);
    const r = await get(adminA).expect(200);
    expect(r.headers["content-type"]).toMatch(/application\/json/);
    expect(r.headers["content-disposition"]).toMatch(/attachment; filename="legion-workspace-\d{4}-\d{2}-\d{2}\.json"/);
    const body = JSON.parse(r.body as unknown as string);
    expect(body.format).toBe("legion-workspace-export/1");
    expect(body.workspace.name).toBe("A");
    expect(body.members.map((m: { email: string }) => m.email).sort()).toEqual([adminA.email, analystA.email].sort());
    expect(body.alerts.map((a: { id: string }) => a.id)).toEqual(["A-1"]);
    expect(body.payment_checks.map((p: { id: string }) => p.id)).toEqual(["PAY-1"]);
    expect(body.counts).toMatchObject({ alerts: 1, payment_checks: 1, members: 2 });
    const text = r.body as unknown as string;
    // Nothing of workspace B, and no secret of workspace A.
    for (const marker of ["B-1", "B secret", "PAY-B", tB, adminB.email]) expect(text, marker).not.toContain(marker);
    for (const secret of [hash, hexHash, "password_hash", "token_version", "mfa", "invite_token", "reset_token"]) expect(text, secret).not.toContain(secret);
  });

  it("is complete across batch boundaries (2,500 alerts, no duplicates, none missing)", async () => {
    await query(`INSERT INTO alerts (id, tenant_id, title, severity, agent, status, summary, confidence, source)
                 SELECT 'E-' || lpad(g::text, 5, '0'), $1, 't', 'low', 'Sentinel', 'open', 's', 50, 'wazuh' FROM generate_series(1, 2500) g`, [tA]);
    const body = JSON.parse((await get(adminA).expect(200)).body as unknown as string);
    expect(body.alerts).toHaveLength(2500);
    expect(new Set(body.alerts.map((a: { id: string }) => a.id)).size).toBe(2500);
  });

  it("is for administrators only, rate-limited, audited, and works while the workspace is locked", async () => {
    expect((await request(app).get("/workspace/export").set(...bearer(analystA))).status).toBe(403);
    expect((await request(app).get("/workspace/export")).status).toBe(401);
    await query("UPDATE tenants SET trial_ends_at = now() - interval '1 day' WHERE id = $1", [tA]);       // locked
    expect((await request(app).get("/alerts").set(...bearer(adminA))).status).toBe(402);
    await get(adminA).expect(200);                                                                          // still allowed
    await get(adminA).expect(200); await get(adminA).expect(200);
    await new Promise((r) => setTimeout(r, 150));                                                           // audit is written after the stream ends
    expect((await query("SELECT detail FROM audit_log WHERE tenant_id = $1 AND action = 'workspace.exported'", [tA])).rowCount).toBe(3);
    const limited = await request(app).get("/workspace/export").set(...bearer(adminA));
    expect(limited.status).toBe(429);
  });
});
