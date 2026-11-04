/**
 * Task 10, module 2 — Approval Engine v0.
 *
 * Bound to an exact action (digest); no self-approval; critical actions need
 * two different people with fresh second-factor codes; requests expire; an
 * approval is consumed at most once; decisions are serialised; every
 * workspace sees only its own requests; only the action engine creates them.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import * as OTPAuth from "otpauth";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, pool, query, transaction } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import type { User } from "../src/types.js";
import { consumeApproval, createApproval, type NewApproval } from "../src/approvals/engine.js";
import { digestOf } from "../src/policy/canonical.js";

let tenantA: string; let tenantB: string;
let admin1: User; let admin2: User; let analyst: User; let viewer: User; let adminB: User;
const bearer = (u: User) => `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`;
const as = (u: User) => ["Authorization", bearer(u)] as const;
const reload = async (u: User) => (await store.findUserById(u.id))!;

function codeFor(secret: string, email: string): string {
  return new OTPAuth.TOTP({ issuer: config.mfaIssuer, label: email, algorithm: "SHA1", digits: 6, period: 30, secret: OTPAuth.Secret.fromBase32(secret) }).generate();
}
async function enroll(u: User): Promise<{ user: User; secret: string }> {
  const secret: string = (await request(app).post("/auth/mfa/setup").set(...as(u)).expect(200)).body.secret;
  await request(app).post("/auth/mfa/enable").set(...as(u)).send({ code: codeFor(secret, u.email) }).expect(200);
  await query("DELETE FROM mfa_used_counters WHERE user_id = $1", [u.id]);
  return { user: await reload(u), secret };
}

const digest = digestOf({ action_id: "ip.block", input: { ip: "203.0.113.5", minutes: 60 } });
const proposal = (over: Partial<NewApproval> = {}): NewApproval => ({
  subject_id: randomUUID(), action_id: "ip.block", risk_class: "R3", action_digest: digest, summary: "Block 203.0.113.5 for 60 minutes",
  requested_by: { kind: "agent", agent: "Vanguard" }, ...over,
});
const create = (tenant: string, over: Partial<NewApproval> = {}) => transaction((c) => createApproval(c, tenant, proposal(over)));
const decide = (u: User, id: string, body: Record<string, unknown>) => request(app).post(`/approvals/${id}/decision`).set(...as(u)).send(body);

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tenantA = randomUUID(); tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  admin1 = await store.insertUser({ email: "a1@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  admin2 = await store.insertUser({ email: "a2@a.io", password_hash: h, tenant_id: tenantA, role: "admin", status: "active" });
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tenantA, role: "analyst", status: "active" });
  viewer = await store.insertUser({ email: "v@a.io", password_hash: h, tenant_id: tenantA, role: "viewer", status: "active" });
  adminB = await store.insertUser({ email: "a@b.io", password_hash: h, tenant_id: tenantB, role: "admin", status: "active" });
});

describe("creating requests (action engine only)", () => {
  it("R3: one approver, no second factor, expires within hours", async () => {
    const a = await create(tenantA);
    expect(a).toMatchObject({ status: "pending", required_approvals: 1, require_mfa: false, approvals: 0, requester_user_id: null });
    const hours = (Date.parse(a.expires_at) - Date.parse(a.created_at)) / 3_600_000;
    expect(hours).toBeGreaterThan(3.9); expect(hours).toBeLessThan(4.1);
  });
  it("R4: two approvers with a second factor — and the database refuses anything weaker", async () => {
    const a = await create(tenantA, { action_id: "payment.release", risk_class: "R4" });
    expect(a).toMatchObject({ required_approvals: 2, require_mfa: true });
    await expect(query(
      `INSERT INTO approval_requests (tenant_id, id, subject_type, subject_id, action_id, risk_class, action_digest, summary, requested_by, required_approvals, require_mfa, expires_at)
       VALUES ($1, $2, 'action_request', $3, 'payment.release', 'R4', $4, 's', '{}', 1, false, now() + interval '1 hour')`,
      [tenantA, randomUUID(), randomUUID(), digest],
    )).rejects.toThrow(/check constraint/);
  });
  it("one approval request per action", async () => {
    const subject = randomUUID();
    await create(tenantA, { subject_id: subject });
    await expect(create(tenantA, { subject_id: subject })).rejects.toThrow(/duplicate key/);
  });
  it("no route and no module outside the action engine can create one", () => {
    const src = join(__dirname, "..", "src");
    const users = (readdirSync(src, { recursive: true }) as string[])
      .filter((f) => f.endsWith(".ts") && /\bcreateApproval\b/.test(readFileSync(join(src, f), "utf8")))
      .map((f) => f.replace(/\\/g, "/"));
    expect(users.filter((f) => f !== "approvals/engine.ts" && !f.startsWith("actions/"))).toEqual([]);
    expect(readFileSync(join(src, "soc-routes.ts"), "utf8")).not.toMatch(/createApproval/);
  });
});

describe("deciding", () => {
  it("needs approvals:read to look and approvals:decide (admin) to decide", async () => {
    const a = await create(tenantA);
    await request(app).get("/approvals").set(...as(viewer)).expect(403);
    expect((await request(app).get("/approvals").set(...as(analyst)).expect(200)).body.approvals).toHaveLength(1);
    await decide(analyst, a.id, { decision: "approve", action_digest: digest }).expect(403);
    const ok = await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(200);
    expect(ok.body).toMatchObject({ settled: "approved", approval: { status: "approved", approvals: 1 } });
    const audit = (await query("SELECT action, resource_id FROM audit_log WHERE tenant_id = $1 AND action LIKE 'approval.%'", [tenantA])).rows;
    expect(audit).toEqual([{ action: "approval.approved", resource_id: a.id }]);
  });

  it("validates the body strictly", async () => {
    const a = await create(tenantA);
    await decide(admin1, a.id, { decision: "maybe", action_digest: digest }).expect(422);
    await decide(admin1, a.id, { decision: "approve", action_digest: "nope" }).expect(422);
    await decide(admin1, a.id, { decision: "approve", action_digest: digest, approvals: 5 }).expect(422);
    await decide(admin1, "not-a-uuid", { decision: "approve", action_digest: digest }).expect(404);
  });

  it("is bound to the exact action: a different digest is refused", async () => {
    const a = await create(tenantA);
    const other = digestOf({ action_id: "ip.block", input: { ip: "203.0.113.99", minutes: 60 } });
    expect((await decide(admin1, a.id, { decision: "approve", action_digest: other }).expect(409)).body.code).toBe("digest_mismatch");
  });

  it("the person who asked cannot approve it", async () => {
    const a = await create(tenantA, { requested_by: { kind: "human", user_id: admin1.id, role: "admin" } });
    expect((await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(403)).body.code).toBe("self_approval");
    await decide(admin2, a.id, { decision: "approve", action_digest: digest }).expect(200);
  });

  it("a settled request takes no more decisions; a rejection settles at once", async () => {
    const a = await create(tenantA);
    await decide(admin1, a.id, { decision: "reject", reason: "false positive", action_digest: digest }).expect(200);
    expect((await decide(admin2, a.id, { decision: "approve", action_digest: digest }).expect(409)).body.code).toBe("already_settled");
    const got = (await request(app).get(`/approvals/${a.id}`).set(...as(analyst)).expect(200)).body;
    expect(got).toMatchObject({ status: "rejected", decisions: [{ user_id: admin1.id, decision: "reject", reason: "false positive" }] });
  });

  it("critical: two different people, each with a fresh second-factor code", async () => {
    const a = await create(tenantA, { action_id: "payment.release", risk_class: "R4" });
    expect((await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(403)).body.code).toBe("mfa_required");
    const e1 = await enroll(admin1); const e2 = await enroll(admin2);
    expect((await decide(e1.user, a.id, { decision: "approve", action_digest: digest, mfa_code: "000000" }).expect(403)).body.code).toBe("mfa_required");
    const first = await decide(e1.user, a.id, { decision: "approve", action_digest: digest, mfa_code: codeFor(e1.secret, e1.user.email) }).expect(200);
    expect(first.body).toMatchObject({ settled: null, approval: { status: "pending", approvals: 1 } });
    // The same person cannot count twice.
    await query("DELETE FROM mfa_used_counters WHERE user_id = $1", [e1.user.id]);
    expect((await decide(e1.user, a.id, { decision: "approve", action_digest: digest, mfa_code: codeFor(e1.secret, e1.user.email) }).expect(409)).body.code).toBe("already_decided");
    const second = await decide(e2.user, a.id, { decision: "approve", action_digest: digest, mfa_code: codeFor(e2.secret, e2.user.email) }).expect(200);
    expect(second.body).toMatchObject({ settled: "approved", approval: { status: "approved", approvals: 2 } });
  });

  it("a request past its deadline is expired and cannot be decided", async () => {
    const a = await create(tenantA);
    await query("UPDATE approval_requests SET created_at = now() - interval '5 hours', expires_at = now() - interval '1 minute' WHERE id = $1", [a.id]);
    expect((await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(410)).body.code).toBe("expired");
    expect((await request(app).get("/approvals?status=expired").set(...as(analyst)).expect(200)).body.approvals.map((x: { id: string }) => x.id)).toEqual([a.id]);
  });

  it("two admins approving at the same moment: exactly one decision counts", async () => {
    const a = await create(tenantA);
    const [r1, r2] = await Promise.all([
      decide(admin1, a.id, { decision: "approve", action_digest: digest }),
      decide(admin2, a.id, { decision: "approve", action_digest: digest }),
    ]);
    expect([r1.status, r2.status].sort()).toEqual([200, 409]);
    expect((await query("SELECT approvals FROM approval_requests WHERE id = $1", [a.id])).rows[0].approvals).toBe(1);
    expect((await query("SELECT count(*)::int AS n FROM approval_decisions WHERE approval_id = $1", [a.id])).rows[0].n).toBe(1);
  });

  it("decisions are append-only", async () => {
    const a = await create(tenantA);
    await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(200);
    await expect(query("UPDATE approval_decisions SET decision = 'reject' WHERE approval_id = $1", [a.id])).rejects.toThrow(/append-only/);
    await expect(query("DELETE FROM approval_decisions WHERE approval_id = $1", [a.id])).rejects.toThrow(/append-only/);
  });

  it("another workspace can neither see nor decide it", async () => {
    const a = await create(tenantA);
    await request(app).get(`/approvals/${a.id}`).set(...as(adminB)).expect(404);
    expect((await request(app).get("/approvals").set(...as(adminB)).expect(200)).body.approvals).toEqual([]);
    await decide(adminB, a.id, { decision: "approve", action_digest: digest }).expect(404);
    expect((await query("SELECT status FROM approval_requests WHERE id = $1", [a.id])).rows[0].status).toBe("pending");
  });
});

describe("consuming", () => {
  const consume = (tenant: string, id: string, d = digest) => transaction((c) => consumeApproval(c, tenant, id, d));

  it("only an approved, unexpired request for the same digest, and only once", async () => {
    const a = await create(tenantA);
    expect(await consume(tenantA, a.id)).toBe(false); // still pending
    await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(200);
    expect(await consume(tenantB, a.id)).toBe(false); // other workspace
    expect(await consume(tenantA, a.id, "0".repeat(64))).toBe(false); // other action
    expect(await consume(tenantA, a.id)).toBe(true);
    expect(await consume(tenantA, a.id)).toBe(false); // used up
    expect((await query("SELECT status, consumed_at FROM approval_requests WHERE id = $1", [a.id])).rows[0]).toMatchObject({ status: "consumed", consumed_at: expect.any(Date) });
  });

  it("an approval that expired before use cannot be consumed", async () => {
    const a = await create(tenantA);
    await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(200);
    await query("UPDATE approval_requests SET created_at = now() - interval '5 hours', expires_at = now() - interval '1 second' WHERE id = $1", [a.id]);
    expect(await consume(tenantA, a.id)).toBe(false);
  });

  it("concurrent consumers: exactly one succeeds", async () => {
    const a = await create(tenantA);
    await decide(admin1, a.id, { decision: "approve", action_digest: digest }).expect(200);
    const results = await Promise.all(Array.from({ length: 5 }, () => consume(tenantA, a.id)));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(pool.totalCount).toBeGreaterThan(0);
  });
});
