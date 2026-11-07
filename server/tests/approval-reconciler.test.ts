/**
 * K-8 / R-6: an expired approval used to be noticed only when someone read it, so its action could
 * wait in awaiting_approval forever. The worker now reconciles once a minute, per workspace.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { runOnce } from "../src/runtime/worker.js";
import type { User } from "../src/types.js";

let tA: string; let tB: string; let adminA: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const status = async (id: string) => (await query("SELECT status FROM action_requests WHERE id = $1", [id])).rows[0].status as string;
const approvalStatus = async (id: string) => (await query("SELECT status FROM approval_requests WHERE id = $1", [id])).rows[0].status as string;
/** Puts an approval's deadline in the past (created_at moves too: the table requires expires_at > created_at). */
const overdue = (approvalId: string) => query("UPDATE approval_requests SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' WHERE id = $1", [approvalId]);

async function critical(u: User) {
  const r = await request(app).post("/actions").set(...as(u))
    .send({ action_id: "account.disable", input: { account: "jdoe", system: "entra" }, mode: "simulation", idempotency_key: randomUUID() });
  expect(r.status).toBe(201);
  expect(r.body.action.status).toBe("awaiting_approval");
  return r.body.action as { id: string; approval_id: string };
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "a@a.io", password_hash: h, tenant_id: tA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "b@b.io", password_hash: h, tenant_id: tB, role: "admin", status: "active" });
});

describe("approval reconciler", () => {
  it("expires an overdue approval and its action without anyone reading them, and records why", async () => {
    const a = await critical(adminA);
    await overdue(a.approval_id);
    expect(await status(a.id)).toBe("awaiting_approval");   // before: nothing changes on its own

    const report = await runOnce({ reconcile: true });
    expect(report.reconciled).toBe(1);
    expect(await approvalStatus(a.approval_id)).toBe("expired");
    expect(await status(a.id)).toBe("expired");
    const ev = (await query("SELECT from_status, to_status FROM action_events WHERE action_id = $1 ORDER BY at DESC LIMIT 1", [a.id])).rows[0];
    expect(ev).toMatchObject({ from_status: "awaiting_approval", to_status: "expired" });
    // Running again changes nothing (idempotent).
    expect((await runOnce({ reconcile: true })).reconciled).toBe(0);
  });

  it("leaves approvals still inside their deadline alone, in every workspace", async () => {
    const a = await critical(adminA);
    const b = await critical(adminB);
    await overdue(b.approval_id);
    await runOnce({ reconcile: true });
    expect(await status(a.id)).toBe("awaiting_approval");
    expect(await approvalStatus(a.approval_id)).toBe("pending");
    expect(await status(b.id)).toBe("expired");
  });

  it("does not run more than once a minute unless asked", async () => {
    await runOnce({ reconcile: true });
    const a = await critical(adminA);
    await overdue(a.approval_id);
    expect((await runOnce()).reconciled).toBe(0);           // throttled: the last pass was just now
    expect(await status(a.id)).toBe("awaiting_approval");
    expect((await runOnce({ reconcile: true })).reconciled).toBe(1);
  });
});
