/**
 * K-6 / K-1: the chain alone cannot see events cut from its END (what remains is still a valid chain).
 * An off-host checkpoint can. These tests prove the gap and that the checkpoint closes it.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query, transaction } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import { appendAuditEventNow, auditCheckpoints } from "../src/audit/events.js";
import type { User } from "../src/types.js";

let tA: string; let tB: string; let admin: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const ev = (t: string, n: number) => appendAuditEventNow(t, { category: "controls", event: "checkpoint.test", actor: { kind: "system" }, detail: { n } });
const verify = (u: User, q = "") => request(app).get(`/soc/audit/verify${q}`).set(...as(u));
const erase = (sql: string, params: unknown[]) => transaction(async (c) => {
  await c.query("SELECT set_config('legion.audit_erasure', 'on', true)");
  await c.query(sql, params);
});

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  await query("DELETE FROM chain_prune_anchors WHERE table_name = 'soc_audit_events'");
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  admin = await store.insertUser({ email: "a@a.io", password_hash: h, tenant_id: tA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "b@b.io", password_hash: h, tenant_id: tB, role: "admin", status: "active" });
});

describe("off-host audit checkpoint", () => {
  it("lists the head of every workspace's chain", async () => {
    for (let i = 0; i < 3; i++) await ev(tA, i);
    await ev(tB, 0);
    const heads = await auditCheckpoints();
    expect(heads.find((h) => h.tenant === tA)).toMatchObject({ seq: 3, hash: expect.stringMatching(/^[0-9a-f]{64}$/) });
    expect(heads.find((h) => h.tenant === tB)).toMatchObject({ seq: 1 });
  });

  it("an event cut from the end passes the plain verify — the checkpoint catches it", async () => {
    for (let i = 0; i < 5; i++) await ev(tA, i);
    const cp = (await auditCheckpoints()).find((h) => h.tenant === tA)!;
    const q = `?checkpoint_seq=${cp.seq}&checkpoint_hash=${cp.hash}`;
    expect((await verify(admin, q)).body).toMatchObject({ ok: true, checkpoint: { seq: 5, status: "match" } });

    await erase("DELETE FROM soc_audit_events WHERE tenant_id = $1 AND seq >= 4", [tA]);
    expect((await verify(admin)).body).toMatchObject({ ok: true, events: 3 });                       // the gap
    expect((await verify(admin, q)).body).toMatchObject({ ok: false, checkpoint: { status: "missing" } });  // closed
  });

  it("a different hash at the checkpoint position is a mismatch; other workspaces' checkpoints are not readable", async () => {
    for (let i = 0; i < 2; i++) await ev(tA, i);
    const cp = (await auditCheckpoints()).find((h) => h.tenant === tA)!;
    expect((await verify(admin, `?checkpoint_seq=${cp.seq}&checkpoint_hash=${"a".repeat(64)}`)).body)
      .toMatchObject({ ok: false, checkpoint: { status: "mismatch" } });
    // Workspace B has no event 2: B's admin learns nothing about A's chain, only that B's is shorter.
    await ev(tB, 0);
    expect((await verify(adminB, `?checkpoint_seq=${cp.seq}&checkpoint_hash=${cp.hash}`)).body.checkpoint.status).toBe("missing");
  });

  it("refuses malformed checkpoints and needs audit:read", async () => {
    await ev(tA, 0);
    expect((await verify(admin, "?checkpoint_seq=0&checkpoint_hash=" + "a".repeat(64))).status).toBe(422);
    expect((await verify(admin, "?checkpoint_seq=1&checkpoint_hash=xyz")).status).toBe(422);
    expect((await verify(admin, "?checkpoint_seq=1")).status).toBe(422);
    const viewer = await store.insertUser({ email: "v@a.io", password_hash: await bcrypt.hash("password123", 4), tenant_id: tA, role: "viewer", status: "active" });
    expect((await verify(viewer)).status).toBe(403);
  });
});
