/**
 * F-09: the incident lifecycle is recorded and reopening needs a reason.
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
import type { User } from "../src/types.js";

let tA: string; let tB: string; let analyst: User; let viewer: User; let other: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const setStatus = (u: User, id: string, body: Record<string, unknown>) => request(app).patch(`/alerts/${id}/status`).set(...as(u)).send(body);

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  analyst = await store.insertUser({ email: "an@a.io", password_hash: h, tenant_id: tA, role: "analyst", status: "active" });
  viewer = await store.insertUser({ email: "v@a.io", password_hash: h, tenant_id: tA, role: "viewer", status: "active" });
  other = await store.insertUser({ email: "an@b.io", password_hash: h, tenant_id: tB, role: "analyst", status: "active" });
  await store.insertAlert({ id: "SEC-L", tenant_id: tA, title: "t", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
});

describe("alert lifecycle", () => {
  it("records acknowledgement once, resolution with who, and a reopen with its reason", async () => {
    const fresh = (await store.getAlert(tA, "SEC-L"))!;
    expect(fresh).toMatchObject({ acknowledged_at: null, resolved_at: null, resolved_by: null, reopened_count: 0 });

    const inv = (await setStatus(analyst, "SEC-L", { status: "investigating" }).expect(200)).body;
    expect(inv.acknowledged_at).toEqual(expect.any(String));
    const res = (await setStatus(analyst, "SEC-L", { status: "resolved" }).expect(200)).body;
    expect(res).toMatchObject({ status: "resolved", acknowledged_at: inv.acknowledged_at, resolved_by: `user:${analyst.id}` });
    expect(res.resolved_at).toEqual(expect.any(String));

    // The same status again changes nothing (the original resolution is kept).
    const again = (await setStatus(analyst, "SEC-L", { status: "resolved" }).expect(200)).body;
    expect(again.resolved_at).toBe(res.resolved_at);

    // Reopening needs a reason, and is counted; the resolution is cleared.
    expect((await setStatus(analyst, "SEC-L", { status: "open" }).expect(422)).body.code).toBe("reason_required");
    await setStatus(analyst, "SEC-L", { status: "investigating", reason: "  " }).expect(422);   // a blank reason is no reason
    const reopened = (await setStatus(analyst, "SEC-L", { status: "investigating", reason: "Same host attacked again" }).expect(200)).body;
    expect(reopened).toMatchObject({ status: "investigating", resolved_at: null, resolved_by: null, reopened_count: 1, acknowledged_at: inv.acknowledged_at });
    const audit = (await query("SELECT detail FROM audit_log WHERE tenant_id = $1 AND action = 'alert.status_updated' ORDER BY created_at", [tA])).rows.map((r) => r.detail);
    expect(audit.at(-1)).toBe("investigating: Same host attacked again");
  });

  it("a system resolution names the component; only analysts change status; other workspaces get 404", async () => {
    const r = (await store.updateAlertStatus(tA, "SEC-L", "resolved", { by: "system:sensor_monitor" }))!;
    expect(r.resolved_by).toBe("system:sensor_monitor");
    await expect(store.updateAlertStatus(tA, "SEC-L", "open")).rejects.toBeInstanceOf(store.AlertTransitionError);
    await setStatus(viewer, "SEC-L", { status: "open", reason: "x" }).expect(403);
    await setStatus(other, "SEC-L", { status: "open", reason: "x" }).expect(404);
    expect((await store.getAlert(tA, "SEC-L"))!.status).toBe("resolved");
  });
});
