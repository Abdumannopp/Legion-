/**
 * Erasing a workspace: complete, deliberate, provable, and replayable after a restore.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import { autoDeleteExpired, deleteTenant, expiredWorkspaces, planDeletion, replayLedger } from "../src/tenant-deletion.js";
import type { Role, User } from "../src/types.js";

// The mail server is replaced: what would be sent is recorded, and "no mail server" can be simulated.
const mail = vi.hoisted(() => ({ on: true, fail: false, sent: [] as Array<{ to: string; subject: string; text: string; html?: string }> }));
vi.mock("../src/mailer.js", async (orig) => ({
  ...(await orig<typeof import("../src/mailer.js")>()),
  mailEnabled: () => mail.on,
  sendMail: async (m: { to: string; subject: string; text: string; html?: string }) => {
    if (mail.fail) return { sent: false, reason: "send_failed" };
    mail.sent.push(m);
    return { sent: true };
  },
}));

const savedMode = config.deploymentMode;
let hash = "";
let tA: string, tB: string;
let adminA: User, adminB: User;
const dir = mkdtempSync(join(tmpdir(), "legion-ledger-"));
const bearer = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { algorithm: "HS256", expiresIn: "1h" })}`] as const;
const tenant = async (name: string) => { const id = randomUUID(); await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, $2, now() + interval '14 days')", [id, name]); return id; };
const user = (t: string, role: Role) => store.insertUser({ email: `${role}-${randomUUID().slice(0, 8)}@example.com`, password_hash: hash, tenant_id: t, role, status: "active" });
const count = async (table: string, t: string) => Number((await query(`SELECT count(*)::int AS n FROM ${table} WHERE tenant_id::text = $1`, [t])).rows[0].n);
const subscribe = (t: string, status: string, endedDaysAgo?: number) => store.applySubscriptionEvent({
  tenant_id: t, status: status as "active", paddle_customer_id: "c", paddle_subscription_id: `sub_${t.slice(0, 8)}`, paddle_price_id: null,
  current_period_end: endedDaysAgo === undefined ? null : new Date(Date.now() - endedDaysAgo * 86_400_000).toISOString(),
  cancel_at_period_end: false, last_event_at: new Date().toISOString(), plan: "professional", addons: [] });

/** A workspace with a bit of everything, including the agent layer (no foreign keys) and its append-only logs. */
async function populate(t: string, admin: User) {
  await store.insertAlert({ id: `AL-${t.slice(0, 6)}`, tenant_id: t, title: "x", severity: "low", agent: "Sentinel", status: "open", summary: "s", confidence: 50, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" } as never);
  await store.audit({ tenant_id: t, user_id: admin.id, user_email: admin.email, action: "user.login", resource_type: null, resource_id: null, detail: null, ip_address: "203.0.113.9" });
  await query(`INSERT INTO payment_checks (tenant_id, id, beneficiary_hash, beneficiary_hint, amount, currency, decision, reasons) VALUES ($1, $2, $3, '0000', 1, 'EUR', 'allow', '{}')`, [t, `PAY-${t.slice(0, 6)}`, "b".repeat(64)]);
  const agent = await request(app).post("/agents").set(...bearer(admin)).send({ name: `bot-${t.slice(0, 4)}`, permissions: ["alerts:read"] });
  expect(agent.status, JSON.stringify(agent.body)).toBe(201);
}

beforeAll(async () => { await migrate(); hash = await bcrypt.hash("password123", 4); });
afterAll(async () => { (config as { deploymentMode: string }).deploymentMode = savedMode; await closePool(); });
beforeEach(async () => {
  mail.on = true; mail.fail = false; mail.sent.length = 0;
  await truncateAll();
  await query("TRUNCATE machine_identities, principal_audit_log, tenant_deletions CASCADE").catch(async () => {
    await query("SET LOCAL legion.audit_erasure = 'on'").catch(() => {});
  });
  (config as { deploymentMode: string }).deploymentMode = "saas";
  tA = await tenant("Acme Security"); tB = await tenant("Bravo");
  adminA = await user(tA, "admin"); adminB = await user(tB, "admin");
});

describe("erasing a workspace", () => {
  it("removes everything of this workspace, the agent layer and its append-only logs included, and nothing of another", async () => {
    await populate(tA, adminA); await populate(tB, adminB);
    const before = { ident: await count("machine_identities", tA), audit: await count("principal_audit_log", tA) };
    expect(before.ident).toBeGreaterThan(0); expect(before.audit).toBeGreaterThan(0);

    const r = await deleteTenant(tA, { by: "test", confirmName: "Acme Security", ledgerFile: null });
    expect(r.counts).toMatchObject({ alerts: 1, payment_checks: 1, users: 1 });

    for (const table of ["alerts", "assets", "audit_log", "payment_checks", "machine_identities", "principal_audit_log", "workspace_memberships", "users"]) {
      expect(await count(table, tA), table).toBe(0);
    }
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(0);
    // Workspace B is untouched.
    for (const table of ["alerts", "audit_log", "payment_checks", "machine_identities", "principal_audit_log", "users"]) expect(await count(table, tB), table).toBeGreaterThan(0);
    // The agent audit log is still append-only for everyone else, and rewriting a row is never allowed.
    await expect(query("DELETE FROM principal_audit_log WHERE tenant_id = $1", [tB])).rejects.toThrow(/append-only/);
    await expect(query("UPDATE principal_audit_log SET action = 'x' WHERE tenant_id = $1", [tB])).rejects.toThrow(/append-only/);
  });

  it("leaves proof with no personal data", async () => {
    await populate(tA, adminA);
    await deleteTenant(tA, { by: "operator", reason: "customer request", confirmName: "Acme Security", ledgerFile: null });
    const row = (await query("SELECT * FROM tenant_deletions WHERE tenant_id = $1", [tA])).rows[0];
    expect(row).toMatchObject({ deleted_by: "operator", reason: "customer request" });
    expect(row.counts.alerts).toBe(1);
    const text = JSON.stringify(row);
    for (const secret of ["Acme", adminA.email, "203.0.113.9"]) expect(text, secret).not.toContain(secret);
  });

  it("needs the exact name, and refuses a hold, a paid subscription and shared people", async () => {
    await expect(deleteTenant(tA, { by: "t", confirmName: "acme security", ledgerFile: null })).rejects.toThrow(/does not match/);
    await query("UPDATE tenants SET legal_hold = true WHERE id = $1", [tA]);
    await expect(deleteTenant(tA, { by: "t", confirmName: "Acme Security", ledgerFile: null })).rejects.toThrow(/legal hold/);
    await query("UPDATE tenants SET legal_hold = false WHERE id = $1", [tA]);
    await subscribe(tA, "active");
    await expect(deleteTenant(tA, { by: "t", confirmName: "Acme Security", ledgerFile: null })).rejects.toThrow(/active subscription/);
    await subscribe(tA, "canceled", 1);
    await query("INSERT INTO workspace_memberships (tenant_id, user_id, role, status) VALUES ($1, $2, 'viewer', 'active')", [tB, adminA.id]);
    const plan = await planDeletion(tA);
    expect(plan.blockers.join()).toMatch(/belong to other workspaces/);
    await expect(deleteTenant(tA, { by: "t", confirmName: "Acme Security", ledgerFile: null })).rejects.toThrow(/Refused/);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(1);   // nothing happened
    expect(await count("users", tA)).toBe(1);
  });

  it("is all or nothing: a failure part-way leaves the workspace intact", async () => {
    await populate(tA, adminA);
    await query("CREATE OR REPLACE FUNCTION boom() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'boom'; END $$");
    await query("CREATE TRIGGER boom_t BEFORE DELETE ON tenants FOR EACH ROW EXECUTE FUNCTION boom()");
    try {
      await expect(deleteTenant(tA, { by: "t", confirmName: "Acme Security", ledgerFile: null })).rejects.toThrow(/boom/);
    } finally { await query("DROP TRIGGER boom_t ON tenants"); }
    expect(await count("alerts", tA)).toBe(1);
    expect(await count("machine_identities", tA)).toBeGreaterThan(0);
    expect(await count("users", tA)).toBe(1);
    expect((await query("SELECT 1 FROM tenant_deletions WHERE tenant_id = $1", [tA])).rowCount).toBe(0);
  });
});

describe("the ledger: a restored backup brings deleted workspaces back, the replay erases them again", () => {
  it("appends a line outside the database, and replays after a 'restore'", async () => {
    const ledger = join(dir, "ledger.jsonl");
    await deleteTenant(tA, { by: "operator", confirmName: "Acme Security", ledgerFile: ledger });
    expect(JSON.parse(readFileSync(ledger, "utf8").trim())).toMatchObject({ tenant_id: tA, by: "operator" });

    // A restore from an older backup: the workspace is back.
    await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'Acme Security', now() + interval '1 day')", [tA]);
    await subscribe(tA, "active");                                          // it was paying in the old backup
    expect(await replayLedger(ledger, { dryRun: true })).toEqual([tA]);     // dry run changes nothing
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(1);
    expect(await replayLedger(ledger)).toEqual([tA]);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(0);
    expect(await replayLedger(ledger)).toEqual([]);                         // nothing left to do
    // B was never in the ledger.
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tB])).rowCount).toBe(1);
  });

  it("skips damaged lines and refuses a missing file", async () => {
    const f = join(dir, "damaged.jsonl");
    writeFileSync(f, `not json\n{"tenant_id":"../../etc"}\n{"tenant_id":"${tA}"}\n`);
    expect(await replayLedger(f, { dryRun: true })).toEqual([tA]);
    await expect(replayLedger(join(dir, "nope.jsonl"))).rejects.toThrow(/No such ledger/);
  });
});

describe("workspaces locked for a long time", () => {
  it("lists the ones locked longer than N days; never a paying one, a held one or a recent one", async () => {
    const canceledOld = await tenant("Old canceled"); await subscribe(canceledOld, "canceled", 60);
    const canceledNew = await tenant("New canceled"); await subscribe(canceledNew, "canceled", 5);
    const paying = await tenant("Paying"); await subscribe(paying, "active");
    const held = await tenant("Held"); await subscribe(held, "canceled", 90); await query("UPDATE tenants SET legal_hold = true WHERE id = $1", [held]);
    const trialOld = await tenant("Old trial"); await query("UPDATE tenants SET trial_ends_at = now() - interval '45 days' WHERE id = $1", [trialOld]);
    expect((await expiredWorkspaces(30)).map((w) => w.name).sort()).toEqual(["Old canceled", "Old trial"]);
    expect(await expiredWorkspaces(0)).toEqual([]);
  });

  it("is off by default, and never runs on a self-hosted installation", async () => {
    const old = await tenant("Old canceled"); await subscribe(old, "canceled", 60);
    await user(old, "admin");
    expect(await autoDeleteExpired(0)).toEqual([]);
    (config as { deploymentMode: string }).deploymentMode = "self-hosted";
    expect(await autoDeleteExpired(30)).toEqual([]);
    expect(mail.sent).toHaveLength(0);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [old])).rowCount).toBe(1);
  });

  it("warns first, deletes later: the admins are e-mailed, nothing is erased until the date has passed", async () => {
    const old = await tenant("Acme Ltd"); await subscribe(old, "canceled", 60);
    const boss = await user(old, "admin"); const second = await user(old, "admin"); await user(old, "viewer");
    const notices: string[] = [];
    expect(await autoDeleteExpired(30, (id) => notices.push(id))).toEqual([]);
    expect(notices).toEqual([old]);
    expect(mail.sent.map((m) => m.to).sort()).toEqual([boss.email, second.email].sort());      // admins only, not the viewer
    expect(mail.sent[0]!.subject).toContain("Acme Ltd");
    expect(mail.sent[0]!.text).toMatch(/permanently erased/);
    const row = (await query("SELECT deletion_notice_at, deletion_scheduled_for FROM tenants WHERE id = $1", [old])).rows[0];
    expect(row.deletion_notice_at).toBeTruthy();
    const days = (new Date(row.deletion_scheduled_for).getTime() - new Date(row.deletion_notice_at).getTime()) / 86_400_000;
    expect(days).toBeGreaterThanOrEqual(config.tenantDeleteNoticeDays - 0.01);
    expect(days).toBeGreaterThanOrEqual(7);

    // The next runs before the date: no second e-mail, no deletion.
    expect(await autoDeleteExpired(30)).toEqual([]);
    expect(mail.sent).toHaveLength(2);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [old])).rowCount).toBe(1);

    // The date arrives: erased, and the tombstone says it was warned.
    await query("UPDATE tenants SET deletion_scheduled_for = now() - interval '1 minute' WHERE id = $1", [old]);
    expect(await autoDeleteExpired(30)).toEqual([old]);
    const stone = (await query("SELECT deleted_by, reason FROM tenant_deletions WHERE tenant_id = $1", [old])).rows[0];
    expect(stone.deleted_by).toBe("auto");
    expect(stone.reason).toMatch(/warned/);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(1);        // the others live
  });

  it("cancels itself when the workspace is subscribed again or put on a legal hold", async () => {
    const back = await tenant("Came back"); await subscribe(back, "canceled", 60); await user(back, "admin");
    const held = await tenant("Held later"); await subscribe(held, "canceled", 60); await user(held, "admin");
    await autoDeleteExpired(30);
    expect((await query("SELECT count(*)::int AS n FROM tenants WHERE deletion_notice_at IS NOT NULL")).rows[0].n).toBe(2);
    await query("UPDATE tenants SET deletion_scheduled_for = now() - interval '1 day'");
    await subscribe(back, "active");
    await query("UPDATE tenants SET legal_hold = true WHERE id = $1", [held]);
    expect(await autoDeleteExpired(30)).toEqual([]);                                             // even with the date passed
    expect((await query("SELECT count(*)::int AS n FROM tenants WHERE deletion_notice_at IS NOT NULL")).rows[0].n).toBe(0);
    expect((await query("SELECT count(*)::int AS n FROM tenants WHERE id = ANY($1::uuid[])", [[back, held]])).rows[0].n).toBe(2);
  });

  it("never deletes a workspace it could not warn: no mail server, a failing one, or nobody to tell", async () => {
    const old = await tenant("Unwarned"); await subscribe(old, "canceled", 60);
    const lonely = await tenant("No admin"); await subscribe(lonely, "canceled", 60); await user(lonely, "viewer");
    await user(old, "admin");
    mail.on = false;
    expect(await autoDeleteExpired(30)).toEqual([]);
    mail.on = true; mail.fail = true;
    expect(await autoDeleteExpired(30)).toEqual([]);
    mail.fail = false;
    expect(await autoDeleteExpired(30)).toEqual([]);                                             // "Unwarned" is warned now; "No admin" cannot be
    expect((await query("SELECT id FROM tenants WHERE deletion_notice_at IS NOT NULL")).rows.map((r) => r.id)).toEqual([old]);
    await query("UPDATE tenants SET deletion_scheduled_for = now() - interval '1 day' WHERE id = $1", [old]);
    await autoDeleteExpired(30);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [lonely])).rowCount).toBe(1);    // never warned, never deleted
  });

  it("two instances running at once send one warning", async () => {
    const old = await tenant("Race"); await subscribe(old, "canceled", 60); await user(old, "admin");
    await Promise.all([autoDeleteExpired(30), autoDeleteExpired(30)]);
    expect(mail.sent).toHaveLength(1);
  });
});

describe("the operator tool", () => {
  const run = (...args: string[]) => spawnSync("npx", ["tsx", "src/scripts/tenant-data.ts", ...args], { encoding: "utf8", timeout: 90_000, env: { ...process.env, NODE_ENV: "test" } });

  it("plans without changing anything, holds, releases, and refuses a wrong confirmation", async () => {
    const plan = run("plan", "--tenant", tA);
    expect(plan.status).toBe(0);
    expect(JSON.parse(plan.stdout).counts.users).toBe(1);
    expect(run("hold", "--tenant", tA).stdout).toMatch(/Legal hold set/);
    expect((await query("SELECT legal_hold FROM tenants WHERE id = $1", [tA])).rows[0].legal_hold).toBe(true);
    expect(run("plan", "--tenant", tA).status).toBe(1);                              // blocked while held
    expect(run("release", "--tenant", tA).stdout).toMatch(/released/);
    expect(run("delete", "--tenant", tA, "--confirm", "wrong").status).not.toBe(0);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(1);
    expect(run("delete", "--tenant", tA, "--confirm", "Acme Security").stdout).toMatch(/Erased workspace/);
    expect((await query("SELECT 1 FROM tenants WHERE id = $1", [tA])).rowCount).toBe(0);
    expect(existsSync(dir)).toBe(true);
  });
});
