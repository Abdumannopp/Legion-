/**
 * Protection modes: Legion acts on its own only because an administrator said so, and only within what
 * they said. These tests prove the chain end to end, against a real PostgreSQL:
 *
 *   settings (who may change them, what it takes) → the policy decision → the action engine → the
 *   executor's own re-check → the audit trail and the administrators' notice;
 *
 * and everything that must NOT happen: nothing live in manual mode, nothing for a critical or AI-produced
 * action without a person, nothing for an address that must never be blocked, nothing after the emergency
 * stop, nothing twice, nothing when the outcome of a crashed attempt is unknown.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import * as blocklist from "../src/blocklist.js";
import * as outbox from "../src/outbox.js";
import { config } from "../src/config.js";
import type { User } from "../src/types.js";
import { putPolicy } from "../src/policy/store.js";
import { catalogList, LIVE_ACTION_IDS } from "../src/policy/catalog.js";
import { ActionError, failLiveUnknown, getAction, proposeAction, runQueued, setPaused, syncWithApproval, type Proposal } from "../src/actions/engine.js";
import { decide } from "../src/approvals/engine.js";
import { EXECUTOR_IDS } from "../src/actions/live.js";
import { PROTECTION_NOTICE_VERSION, getProtection, wantsLiveResponse } from "../src/protection.js";
import { runOnce } from "../src/runtime/worker.js";
import { addMemory } from "../src/memory/store.js";
import { pruneSocHistory, SOC_TERMINAL_ACTIONS } from "../src/retention.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { transaction } from "../src/db/pool.js";

let tA: string; let tStarter: string; let admin: User; let admin2: User; let analyst: User; let viewer: User; let adminStarter: User;
const now = () => Math.floor(Date.now() / 1000);
const tok = (u: User, authTime: number | null = now()) =>
  `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version, auth_time: authTime ?? undefined }, { expiresIn: "1h" })}`;
const as = (u: User) => ["Authorization", tok(u)] as const;
const stale = (u: User) => ["Authorization", tok(u, now() - 3600)] as const;
const key = () => `k-${randomUUID()}`;
const agent = (action_id: string, input: unknown, over: Partial<Proposal> = {}): Proposal =>
  ({ action_id, input, actor: { kind: "agent", agent: "Vanguard" }, origin: "agent", mode: "live", idempotency_key: key(), ...over });
const block = (ip: string, over: Partial<Proposal> = {}) => agent("ip.block", { ip, minutes: 60 }, over);
const put = (u: User, body: Record<string, unknown>, h: readonly [string, string] = as(u)) => request(app).put("/soc/protection").set(...h).send(body);
const blocks = async () => (await query("SELECT ip, created_by FROM ip_blocks WHERE tenant_id = $1 AND revoked_at IS NULL ORDER BY ip", [tA])).rows;
const status = async (id: string) => (await query("SELECT status, error FROM action_requests WHERE id = $1", [id])).rows[0] as { status: string; error: string | null };

/** What an administrator does in the dashboard: accept the notice and pick a mode. */
async function enable(mode: "hybrid" | "automatic", auto: string[] = ["ip.block"]) {
  await put(admin, { mode, auto_actions: auto, acknowledge: true }).expect(200);
}

const savedSmtp = config.smtpHost; const savedCap = config.socLiveActionsPerHour;
beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
afterEach(() => { config.smtpHost = savedSmtp; config.socLiveActionsPerHour = savedCap; });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tStarter = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'S', 'starter')", [tA, tStarter]);
  const h = await bcrypt.hash("password123", 4);
  const mk = (email: string, tenant: string, role: "admin" | "analyst" | "viewer") =>
    store.insertUser({ email, password_hash: h, tenant_id: tenant, role, status: "active" });
  admin = await mk("a1@a.io", tA, "admin"); admin2 = await mk("a2@a.io", tA, "admin");
  analyst = await mk("an@a.io", tA, "analyst"); viewer = await mk("v@a.io", tA, "viewer");
  adminStarter = await mk("s@s.io", tStarter, "admin");
  await query("UPDATE users SET email_verified_at = now()");
  await store.insertAlert({ id: "SEC-1", tenant_id: tA, title: "Brute force", severity: "high", agent: "Sentinel", status: "open", summary: "s", confidence: 80,
    ai_explanation: null, explained_at: null, source_ip: "185.220.101.4", target: "web-01", mitre_technique: null, source: "wazuh" });
});

// ------------------------------------------------------------------------------------------------

describe("manual is the default, and nothing runs for real in it", () => {
  it("a new workspace is in manual mode, and says what it could be", async () => {
    const r = await request(app).get("/soc/protection").set(...as(analyst)).expect(200);
    expect(r.body.protection).toMatchObject({ mode: "manual", effective_mode: "manual", acknowledged: false, auto_actions: [] });
    expect(r.body.live_actions.map((a: { id: string }) => a.id).sort()).toEqual([...LIVE_ACTION_IDS].sort());
    expect(r.body.notice.version).toBe(PROTECTION_NOTICE_VERSION);
    expect(r.body.plan_allows).toBe(true);
    expect((await request(app).get("/soc/protection").set(...as(viewer))).status).toBe(403);   // actions:read is analyst
  });

  it("a live proposal is refused by the policy — from an agent, from an administrator, and from the workflow route", async () => {
    const { action } = await proposeAction(tA, block("185.220.101.50"));
    expect(action).toMatchObject({ status: "denied", policy_decision: "DENY" });
    const viaRoute = await request(app).post("/actions").set(...as(admin)).send({ action_id: "ip.block", input: { ip: "185.220.101.51", minutes: 30 }, mode: "live", idempotency_key: key() });
    expect(viaRoute.body.action).toMatchObject({ status: "denied" });
    const wf = await request(app).post("/workflows/alert_response/runs").set(...as(admin)).send({ alert_id: "SEC-1", mode: "live" });
    expect(wf.status).toBe(409);
    expect(wf.body.code).toBe("protection_off");
    expect(await blocks()).toEqual([]);
    expect((await query("SELECT count(*)::int AS n FROM action_requests WHERE status IN ('queued','running','executed')")).rows[0].n).toBe(0);
  });

  it("an analyst cannot ask for a live action at all", async () => {
    const r = await request(app).post("/actions").set(...as(analyst)).send({ action_id: "ip.block", input: { ip: "185.220.101.52", minutes: 30 }, mode: "live", idempotency_key: key() });
    expect(r.status).toBe(403);
    expect((await request(app).post("/workflows/alert_response/runs").set(...as(analyst)).send({ alert_id: "SEC-1", mode: "live" })).status).toBe(403);
  });
});

describe("turning protection on takes an administrator who just proved who they are, and a written acceptance", () => {
  it("the notice must be accepted; a plan without automatic protection is refused; unknown actions are refused", async () => {
    const noAck = await put(admin, { mode: "hybrid", auto_actions: ["ip.block"] });
    expect(noAck.status).toBe(400); expect(noAck.body.code).toBe("acknowledgement_required");
    const starter = await put(adminStarter, { mode: "hybrid", acknowledge: true });
    expect(starter.status).toBe(402); expect(starter.body.code).toBe("plan_feature");
    for (const bad of ["account.disable", "host.isolate", "payment.release", "alert.set_status", "shell.exec"]) {
      const r = await put(admin, { mode: "hybrid", auto_actions: [bad], acknowledge: true });
      expect(r.status, bad).toBe(422); expect(r.body.code, bad).toBe("unknown_action");
    }
    expect((await getProtection(tA)).mode).toBe("manual");
  });

  it("an administrator is required, with a recent password confirmation — except to switch OFF", async () => {
    expect((await put(analyst, { mode: "hybrid", acknowledge: true })).status).toBe(403);
    const old = await put(admin, { mode: "hybrid", auto_actions: ["ip.block"], acknowledge: true }, stale(admin));
    expect(old.status).toBe(403); expect(old.body.code).toBe("reauth_required");
    expect((await getProtection(tA)).mode).toBe("manual");

    await enable("hybrid");
    expect(await getProtection(tA)).toMatchObject({ mode: "hybrid", effective_mode: "hybrid", acknowledged: true, acknowledged_by: "a1@a.io", auto_actions: ["ip.block"] });
    // Widening needs the confirmation again; switching off never does.
    expect((await put(admin, { auto_actions: ["ip.block", "notify.admins"] }, stale(admin))).status).toBe(403);
    expect((await put(admin, { mode: "manual" }, stale(admin))).status).toBe(200);
    expect((await getProtection(tA)).effective_mode).toBe("manual");
  });

  it("every change is in the audit trail (chained and plain), naming who and what", async () => {
    await enable("hybrid");
    await put(admin, { mode: "manual" }).expect(200);
    const chain = (await query("SELECT detail FROM soc_audit_events WHERE tenant_id = $1 AND event = 'protection.changed' ORDER BY seq", [tA])).rows;
    expect(chain.map((r) => r.detail)).toEqual([
      { from: "manual", to: "hybrid", auto_actions: ["ip.block"], acknowledged: true },
      { from: "hybrid", to: "manual", auto_actions: ["ip.block"], acknowledged: false },
    ]);
    const plain = (await query("SELECT user_email FROM audit_log WHERE tenant_id = $1 AND action = 'protection.changed'", [tA])).rows;
    expect(plain).toHaveLength(2);
    expect(plain.every((r) => r.user_email === "a1@a.io")).toBe(true);
  });

  it("a new version of the notice puts the workspace back in manual until it is accepted again", async () => {
    await enable("automatic");
    await query("UPDATE tenants SET protection_ack_version = 'older' WHERE id = $1", [tA]);
    expect(await getProtection(tA)).toMatchObject({ mode: "automatic", acknowledged: false, effective_mode: "manual" });
    expect((await proposeAction(tA, block("185.220.101.60"))).action.status).toBe("denied");
  });

  it("the database refuses what the code must not do: protection without an acceptance, or an action with no executor", async () => {
    await expect(query("UPDATE tenants SET protection_mode = 'automatic' WHERE id = $1", [tA])).rejects.toThrow(/check constraint/);
    await enable("hybrid");
    await expect(query("UPDATE tenants SET protection_auto_actions = ARRAY['account.disable'] WHERE id = $1", [tA])).rejects.toThrow(/check constraint/);
  });

  it("the three lists agree: catalog, executors and the database CHECK", async () => {
    expect([...EXECUTOR_IDS].sort()).toEqual([...LIVE_ACTION_IDS].sort());
    const def = (await query("SELECT pg_get_constraintdef(oid) AS d FROM pg_constraint WHERE conrelid = 'tenants'::regclass AND pg_get_constraintdef(oid) LIKE '%protection_auto_actions%'")).rows[0].d as string;
    for (const id of LIVE_ACTION_IDS) expect(def).toContain(`'${id}'`);
    expect(def.match(/'[a-z]+\.[a-z_]+'/g)).toHaveLength(LIVE_ACTION_IDS.length);
    // Every live-capable action exists in the catalog, and none is critical.
    for (const id of LIVE_ACTION_IDS) expect(catalogList().find((c) => c.id === id)?.class).not.toBe("R4");
  });
});

describe("hybrid: what the administrator pre-authorised runs on its own; everything else asks", () => {
  beforeEach(async () => { await enable("hybrid", ["ip.block"]); });

  it("a pre-authorised block is done at once, by Legion, and is recorded everywhere", async () => {
    config.smtpHost = "smtp.test.invalid";
    const { action } = await proposeAction(tA, block("185.220.101.70", { reason: "brute force campaign" }));
    expect(action).toMatchObject({ status: "queued", policy_decision: "ALLOW", execution_mode: "live", approval_id: null });
    const done = (await runQueued(tA, action.id))!;
    expect(done).toMatchObject({ status: "executed", result: { did: "block", ip: "185.220.101.70", minutes: 60 }, attempts: 1 });
    // Really done: the blocklist (which the Wazuh sync and the dashboard read) has it, marked automatic.
    expect(await blocks()).toEqual([{ ip: "185.220.101.70", created_by: null }]);
    expect((await blocklist.activeEntries(tA)).map((e) => e.ip)).toEqual(["185.220.101.70"]);
    // Audited twice over: the action trail and the ordinary audit log.
    const events = (await query("SELECT to_status FROM action_events WHERE tenant_id = $1 AND action_id = $2 ORDER BY seq", [tA, action.id])).rows.map((r) => r.to_status);
    expect(events).toEqual(["queued", "running", "executed"]);
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE tenant_id = $1 AND action = 'security.auto_block'", [tA])).rows[0].n).toBe(1);
    // …and the administrators were told, in the same commit: one mail each, saying what and why.
    const mails = (await query("SELECT recipient, payload FROM notification_outbox WHERE tenant_id = $1 AND kind = 'protection_email' ORDER BY recipient", [tA])).rows;
    expect(mails.map((m) => m.recipient)).toEqual(["a1@a.io", "a2@a.io"]);
    expect(mails[0].payload.subject).toContain("Legion acted on its own");
    expect(mails[0].payload.text).toContain("185.220.101.70");
    expect(mails[0].payload.text).toContain("brute force campaign");
  });

  it("running it again changes nothing: no second block, no second mail, no second audit entry", async () => {
    config.smtpHost = "smtp.test.invalid";
    const { action } = await proposeAction(tA, block("185.220.101.71"));
    await runQueued(tA, action.id);
    const again = await runQueued(tA, action.id);
    expect(again?.status).toBe("executed"); expect(again?.attempts).toBe(1);
    const replay = await proposeAction(tA, { ...block("185.220.101.71"), idempotency_key: action.idempotency_key });
    expect(replay.replayed).toBe(true);
    expect(await blocks()).toHaveLength(1);
    expect((await query("SELECT count(*)::int AS n FROM notification_outbox WHERE kind = 'protection_email'")).rows[0].n).toBe(2);
    expect((await query("SELECT count(*)::int AS n FROM audit_log WHERE action = 'security.auto_block'")).rows[0].n).toBe(1);
  });

  it("an action that was not pre-authorised asks first: the administrators are told, nothing is done until one approves", async () => {
    config.smtpHost = "smtp.test.invalid";
    const { action } = await proposeAction(tA, agent("notify.admins", { subject: "Critical alert SEC-1", alert_id: "SEC-1" }, { actor: { kind: "agent", agent: "Sentinel" } }));
    expect(action).toMatchObject({ status: "awaiting_approval", policy_decision: "REQUIRE_APPROVAL" });
    expect((await runQueued(tA, action.id))?.status).toBe("awaiting_approval");
    const ask = (await query("SELECT payload FROM notification_outbox WHERE tenant_id = $1 AND kind = 'protection_email'", [tA])).rows;
    expect(ask).toHaveLength(2);
    expect(ask[0].payload.subject).toContain("needs your decision");
    // A person approves → it is queued → it runs, once.
    await decide(tA, action.approval_id!, { userId: admin2.id, decision: "approve", actionDigest: action.action_digest, mfaVerified: true });
    const queued = (await syncWithApproval(tA, action.id, { kind: "system", component: "test" }))!;
    expect(queued.status).toBe("queued");
    expect((await runQueued(tA, action.id))?.status).toBe("executed");
  });

  it("a policy RULE can refuse or require approval, but never grant what the administrator did not", async () => {
    await putPolicy(tA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [{ id: "grant", effect: "ALLOW", actions: ["notify.admins"] }] }, { expectedVersion: 0, userId: admin.id });
    const granted = await proposeAction(tA, agent("notify.admins", { subject: "x", alert_id: "SEC-1" }, { actor: { kind: "agent", agent: "Sentinel" } }));
    expect(granted.action.status).toBe("awaiting_approval");
    await putPolicy(tA, { schema: 1, default_autonomy: "AUTONOMOUS", rules: [{ id: "no", effect: "DENY", actions: ["ip.block"] }] }, { expectedVersion: 1, userId: admin.id });
    expect((await proposeAction(tA, block("185.220.101.72"))).action.status).toBe("denied");
    expect(await blocks()).toEqual([]);
  });

  it("an administrator can run a live action by hand (HUMAN_DIRECT), and it is theirs in the record", async () => {
    const r = await request(app).post("/actions").set(...as(admin)).send({ action_id: "ip.block", input: { ip: "185.220.101.73", minutes: 30 }, mode: "live", idempotency_key: key() });
    expect(r.status).toBe(201);
    expect(r.body.action).toMatchObject({ status: "executed", actor: { kind: "human" } });
    expect(await blocks()).toEqual([{ ip: "185.220.101.73", created_by: null }]);
  });
});

describe("automatic: everything Legion can really do and that is not critical — and still never what needs a person", () => {
  beforeEach(async () => { await enable("automatic", []); });

  it("runs the actions it has an executor for", async () => {
    const { action } = await proposeAction(tA, block("185.220.101.80"));
    expect((await runQueued(tA, action.id))?.status).toBe("executed");
    const mail = await proposeAction(tA, agent("notify.admins", { subject: "Heads up", alert_id: "SEC-1" }, { actor: { kind: "agent", agent: "Sentinel" } }));
    expect(mail.action.status).toBe("queued");
    expect((await runQueued(tA, mail.action.id))?.status).toBe("executed");
  });

  it("never does what it cannot do for real: critical and money actions stay simulation-only, whoever asks", async () => {
    for (const [id, input] of [["account.disable", { account: "jdoe", system: "entra" }], ["host.isolate", { host: "web-01" }], ["payment.release", { payment_id: "PAY-0123456789ABCDEF" }], ["ip.unblock", { ip: "185.220.101.4" }]] as const) {
      const a = (await proposeAction(tA, agent(id, input))).action;
      expect(a.status, id).toBe("denied");
      const h = await request(app).post("/actions").set(...as(admin)).send({ action_id: id, input, mode: "live", idempotency_key: key() });
      expect(h.body.action.status, id).toBe("denied");
    }
  });

  it("anything an AI model produced waits for a person, even here", async () => {
    const { action } = await proposeAction(tA, block("185.220.101.81", { origin: "llm", actor: { kind: "agent", agent: "Vanguard" } }));
    expect(action.status).toBe("awaiting_approval");
    expect(await blocks()).toEqual([]);
  });

  it("the hourly ceiling hands the next ones to a person instead of doing them", async () => {
    config.socLiveActionsPerHour = 2;
    const results = [];
    for (let i = 0; i < 4; i++) results.push((await proposeAction(tA, block(`185.220.101.${90 + i}`))).action);
    expect(results.map((a) => a.status)).toEqual(["queued", "queued", "awaiting_approval", "awaiting_approval"]);
    const d = (await query("SELECT reason_codes FROM policy_decisions WHERE tenant_id = $1 ORDER BY created_at DESC, id LIMIT 4", [tA])).rows.flatMap((r) => r.reason_codes);
    expect(d).toContain("LIVE_RATE_LIMIT");
  });
});

describe("at the moment of doing it, the facts are checked again", () => {
  beforeEach(async () => { await enable("automatic", []); });

  it("a private or internal address, an allowlisted one, and a smaller plan are refused with nothing done", async () => {
    for (const ip of ["10.0.0.5", "192.168.1.9", "127.0.0.1"]) {
      const { action } = await proposeAction(tA, block(ip));
      expect(await runQueued(tA, action.id), ip).toMatchObject({ status: "failed" });
      expect((await status(action.id)).error, ip).toMatch(/refused: Not a public/);
    }
    await blocklist.updateSettings(tA, { allowlist: "185.220.101.100" });
    const listed = (await proposeAction(tA, block("185.220.101.100"))).action;
    expect(await runQueued(tA, listed.id)).toMatchObject({ status: "failed" });
    expect((await status(listed.id)).error).toMatch(/allowlist/);
    await query("UPDATE tenants SET plan_override = 'professional' WHERE id = $1", [tA]);
    const small = (await proposeAction(tA, block("185.220.101.101"))).action;
    expect(await runQueued(tA, small.id)).toMatchObject({ status: "failed" });
    expect((await status(small.id)).error).toMatch(/plan/);
    expect(await blocks()).toEqual([]);
  });

  it("turning protection off after an action was queued stops it", async () => {
    const { action } = await proposeAction(tA, block("185.220.101.102"));
    expect(action.status).toBe("queued");
    await put(admin, { mode: "manual" }).expect(200);
    expect(await runQueued(tA, action.id)).toMatchObject({ status: "cancelled" });
    expect((await status(action.id)).error).toMatch(/turned off/);
    expect(await blocks()).toEqual([]);
  });

  it("narrowing the authorisation after it was queued stops it too", async () => {
    await put(admin, { mode: "hybrid", auto_actions: ["notify.admins"], acknowledge: true }).expect(200);
    const { action } = await proposeAction(tA, agent("notify.admins", { subject: "s", alert_id: "SEC-1" }, { actor: { kind: "agent", agent: "Sentinel" } }));
    expect(action.status).toBe("queued");
    await put(admin, { auto_actions: [] }).expect(200);
    expect(await runQueued(tA, action.id)).toMatchObject({ status: "cancelled" });
    expect((await status(action.id)).error).toMatch(/no longer authorized/);
  });

  it("the emergency stop refuses new live actions and holds queued ones until it is lifted", async () => {
    const { action } = await proposeAction(tA, block("185.220.101.103"));
    await setPaused(tA, true, admin.id, "test");
    await expect(proposeAction(tA, block("185.220.101.104"))).rejects.toMatchObject({ status: 423, code: "paused" } satisfies Partial<ActionError>);
    expect((await runQueued(tA, action.id))?.status).toBe("queued");
    expect(await blocks()).toEqual([]);
    await setPaused(tA, false, admin.id);
    expect((await runQueued(tA, action.id))?.status).toBe("executed");
    expect(await blocks()).toHaveLength(1);
  });
});

describe("a crashed attempt is never repeated blind", () => {
  beforeEach(async () => { await enable("automatic", []); });

  it("a live action left running by a dead worker is not taken over: it is marked 'outcome unknown' and the administrators are told", async () => {
    config.smtpHost = "smtp.test.invalid";
    const { action } = await proposeAction(tA, block("185.220.101.110"));
    await query("UPDATE action_requests SET status = 'running', attempts = 1, updated_at = now() - interval '5 minutes' WHERE id = $1", [action.id]);
    const after = await runQueued(tA, action.id);
    expect(after).toMatchObject({ status: "running", attempts: 1 });          // not re-executed
    expect(await blocks()).toEqual([]);
    expect(await failLiveUnknown(tA, action.id)).toBe(true);
    expect(await status(action.id)).toMatchObject({ status: "failed", error: expect.stringMatching(/outcome unknown/) });
    expect(await failLiveUnknown(tA, action.id)).toBe(false);
    const mails = (await query("SELECT payload FROM notification_outbox WHERE kind = 'protection_email'")).rows;
    expect(mails).toHaveLength(2);
    expect(mails[0].payload.subject).toContain("could not");
    // A fresh running one is left alone.
    const fresh = (await proposeAction(tA, block("185.220.101.111"))).action;
    await query("UPDATE action_requests SET status = 'running', attempts = 1 WHERE id = $1", [fresh.id]);
    expect(await failLiveUnknown(tA, fresh.id)).toBe(false);
  });

  it("the worker does the same, from the job queue", async () => {
    const { action } = await proposeAction(tA, block("185.220.101.112"));
    await query("UPDATE action_requests SET status = 'running', attempts = 1, updated_at = now() - interval '5 minutes' WHERE id = $1", [action.id]);
    await query("UPDATE soc_jobs SET run_after = now() WHERE tenant_id = $1", [tA]);
    await runOnce({ reconcile: false });
    expect((await status(action.id)).status).toBe("failed");
    expect(await blocks()).toEqual([]);
  });
});

describe("from a real alert to a real block, without anyone clicking", () => {
  const newAlert = (id: string, over: Record<string, unknown> = {}) => ({
    id, tenant_id: tA, title: "SSH brute force", severity: "high" as const, agent: "Sentinel" as const, status: "open" as const, summary: "s", confidence: 90,
    ai_explanation: null, explained_at: null, source_ip: "185.220.101.120", target: "web-01", mitre_technique: "T1110", source: "wazuh", ...over,
  });
  const queuedLive = async () => (await query("SELECT count(*)::int AS n FROM soc_jobs WHERE tenant_id = $1 AND kind = 'workflow.run' AND payload->>'mode' = 'live'", [tA])).rows[0].n as number;

  it("manual: no live job is even queued", async () => {
    await outbox.insertAlertAndNotify(newAlert("SEC-M1") as never);
    expect(await queuedLive()).toBe(0);
  });

  it("hybrid with the block pre-authorised: a high alert from a sensor ends with the attacker blocked, and the people told", async () => {
    config.smtpHost = "smtp.test.invalid";
    await enable("hybrid", ["ip.block"]);
    await outbox.insertAlertAndNotify(newAlert("SEC-H1") as never);
    expect(await queuedLive()).toBe(1);
    await runOnce({ reconcile: false });
    expect(await blocks()).toEqual([{ ip: "185.220.101.120", created_by: null }]);
    const run = (await query("SELECT mode, status, steps FROM workflow_runs WHERE tenant_id = $1 AND mode = 'live'", [tA])).rows[0];
    expect(run).toMatchObject({ mode: "live", status: "completed" });
    expect(run.steps.map((s: { name: string; action_status: string | null }) => `${s.name}:${s.action_status}`)).toEqual(["triage:simulated", "contain_source:executed", "notify:null"]);
    expect((await query("SELECT count(*)::int AS n FROM notification_outbox WHERE kind = 'protection_email'")).rows[0].n).toBe(2);
  });

  it("a critical alert also e-mails the administrators only if that was pre-authorised; otherwise it asks", async () => {
    await enable("hybrid", ["ip.block"]);
    await outbox.insertAlertAndNotify(newAlert("SEC-C1", { severity: "critical", source_ip: "185.220.101.121" }) as never);
    await runOnce({ reconcile: false });
    const steps = (await query("SELECT steps FROM workflow_runs WHERE tenant_id = $1 AND mode = 'live'", [tA])).rows[0].steps;
    expect(steps.find((s: { name: string }) => s.name === "contain_source").action_status).toBe("executed");
    expect(steps.find((s: { name: string }) => s.name === "notify").action_status).toBe("awaiting_approval");
  });

  it("test alerts, samples, the demo and Legion's own monitors never start anything", async () => {
    await enable("automatic", []);
    for (const [i, source] of ["legion-test", "mock", "demo", "legion-monitor", "legion-agent-security"].entries()) {
      await outbox.insertAlertAndNotify(newAlert(`SEC-T${i}`, { source }) as never);
    }
    expect(await queuedLive()).toBe(0);
    expect(await blocks()).toEqual([]);
    await transaction(async (c) => { expect(await wantsLiveResponse(c, tA, "wazuh")).toBe(true); expect(await wantsLiveResponse(c, tA, "mock")).toBe(false); });
  });

  it("an address a person marked harmless, and a private source, are not blocked", async () => {
    await enable("automatic", []);
    await outbox.insertAlertAndNotify(newAlert("SEC-P1", { source_ip: "10.1.1.1" }) as never);
    await addMemory(tA, { kind: "false_positive", subject_type: "ip", subject_key: "185.220.101.122", content: "our scanner", source: "human", created_by: admin.id, ttl_days: 30 });
    await outbox.insertAlertAndNotify(newAlert("SEC-P2", { source_ip: "185.220.101.122" }) as never);
    await runOnce({ reconcile: false });
    expect(await blocks()).toEqual([]);
  });
});

describe("the report: what Legion did, in one place", () => {
  it("counts what ran on its own, what a person approved, what a person did, what is waiting and what failed", async () => {
    await enable("hybrid", ["ip.block"]);
    const auto = (await proposeAction(tA, block("185.220.101.130"))).action; await runQueued(tA, auto.id);
    const asked = (await proposeAction(tA, agent("notify.admins", { subject: "s", alert_id: "SEC-1" }, { actor: { kind: "agent", agent: "Sentinel" } }))).action;
    const waiting = (await proposeAction(tA, agent("notify.admins", { subject: "t", alert_id: "SEC-1" }, { actor: { kind: "agent", agent: "Sentinel" } }))).action;
    await decide(tA, asked.approval_id!, { userId: admin2.id, decision: "approve", actionDigest: asked.action_digest, mfaVerified: true });
    await syncWithApproval(tA, asked.id, { kind: "system", component: "test" }); await runQueued(tA, asked.id);
    await request(app).post("/actions").set(...as(admin)).send({ action_id: "ip.block", input: { ip: "185.220.101.131", minutes: 30 }, mode: "live", idempotency_key: key() }).expect(201);
    const bad = (await proposeAction(tA, block("10.9.9.9"))).action; await runQueued(tA, bad.id);

    const r = await request(app).get("/soc/protection/report?days=7").set(...as(analyst)).expect(200);
    expect(r.body.totals).toEqual({ automatic: 1, approved_by_person: 1, by_person: 1, awaiting_approval: 1, failed: 1, refused_or_cancelled: 0 });
    expect(r.body.by_action).toEqual([{ action_id: "ip.block", executed: 2, failed: 1 }, { action_id: "notify.admins", executed: 1, failed: 0 }]);
    expect(r.body.recent.find((x: { id: string }) => x.id === waiting.id)).toMatchObject({ status: "awaiting_approval", by: "Sentinel" });
    expect(r.body.recent.find((x: { id: string }) => x.id === bad.id)).toMatchObject({ status: "failed", error: expect.stringContaining("refused") });
    expect(r.body.changes[0]).toMatchObject({ by: "a1@a.io" });
    expect((await request(app).get("/soc/protection/report").set(...as(viewer))).status).toBe(403);
  });
});

describe("old history of what Legion did is pruned like the rest, and nothing else is", () => {
  it("executed and failed live actions go with the retention period; pending ones never do; both lists agree", async () => {
    await enable("automatic", []);
    const old = (await proposeAction(tA, block("185.220.101.150"))).action; await runQueued(tA, old.id);
    const fresh = (await proposeAction(tA, block("185.220.101.151"))).action; await runQueued(tA, fresh.id);
    const pending = (await proposeAction(tA, block("185.220.101.152", { origin: "llm" }))).action;
    await query("UPDATE action_requests SET created_at = now() - interval '500 days' WHERE id = ANY($1)", [[old.id, pending.id]]);
    await query("UPDATE approval_requests SET created_at = now() - interval '500 days', expires_at = now() + interval '1 day' WHERE id = $1", [pending.approval_id]).catch(() => {});
    await pruneSocHistory(365);
    expect((await query("SELECT id FROM action_requests WHERE tenant_id = $1 AND execution_mode = 'live' ORDER BY id", [tA])).rows.map((r) => r.id).sort()).toEqual([fresh.id, pending.id].sort());
    // The list in the database function (migration 0012) is the list in code.
    const sql = readFileSync(join(__dirname, "..", "src", "db", "migrations", "0012_protection_modes.sql"), "utf8");
    const inSql = /terminal text\[\] := ARRAY\[([^\]]+)\]/.exec(sql)![1]!.match(/'([a-z]+)'/g)!.map((x) => x.replace(/'/g, "")).sort();
    expect(inSql).toEqual([...SOC_TERMINAL_ACTIONS].sort());
  });
});

describe("one workspace's settings never reach another", () => {
  it("authorising in A leaves B (and its actions) in manual", async () => {
    await enable("automatic", []);
    expect((await getProtection(tStarter)).mode).toBe("manual");
    const other = await proposeAction(tStarter, block("185.220.101.140"));
    expect(other.action.status).toBe("denied");
    expect((await query("SELECT count(*)::int AS n FROM ip_blocks WHERE tenant_id = $1", [tStarter])).rows[0].n).toBe(0);
    expect((await getAction(tStarter, (await proposeAction(tA, block("185.220.101.141"))).action.id))).toBeNull();
  });
});
