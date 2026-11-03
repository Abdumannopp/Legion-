/**
 * Workspaces: one person, several organisations (src/workspaces.ts).
 *
 * The properties that matter: a membership is the only thing that lets an
 * access token act in a workspace, and it is checked on every request; a
 * workspace can change or end only its own membership, never the account or
 * another workspace; invitations of existing accounts are accepted by
 * signing in, never by setting a password; switching never mixes data.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app, socketGrantsStillValid } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import * as store from "../src/store.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import type { User } from "../src/types.js";

const PASSWORD = "correct horse battery staple";
let tA: string, tB: string;
let adminA: User, adminB: User, dana: User;

const bearer = (t: string) => ["Authorization", `Bearer ${t}`] as const;
const tokenFor = (u: User, tenantId = u.tenant_id) => mint({ sub: u.id, tenant_id: tenantId, token_version: u.token_version }, { expiresIn: "1h" });
const cookieOf = (res: request.Response, name: string) =>
  ((res.headers["set-cookie"] as unknown as string[] | undefined) ?? []).find((c) => c.startsWith(`${name}=`))?.split(";")[0]?.split("=").slice(1).join("=");
const login = async (email: string) => {
  const res = await request(app).post("/auth/login").send({ username: email, password: PASSWORD });
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  return { access: res.body.access_token as string, refresh: cookieOf(res, "legion_refresh")! };
};
const invite = async (admin: User, email: string, role = "analyst") => {
  const res = await request(app).post("/users/invite").set(...bearer(tokenFor(admin))).send({ email, role });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return new URL(res.body.invite_url).searchParams.get("token")!;
};
const alertIn = (tenantId: string, id: string) => store.insertAlert({
  id, tenant_id: tenantId, title: `${id} title`, severity: "high", agent: "Sentinel", status: "open", summary: id,
  confidence: 80, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh",
});
/** Dana: an analyst of A, invited to B as a viewer, accepted. */
async function danaInBoth() {
  const token = await invite(adminB, dana.email, "viewer");
  const { access } = await login(dana.email);
  expect((await request(app).post("/workspaces/invitations/accept").set(...bearer(access)).send({ token })).status).toBe(200);
  return access;
}
const switchTo = async (access: string, workspaceId: string) => {
  const res = await request(app).post("/workspaces/switch").set(...bearer(access)).send({ workspace_id: workspaceId });
  return { res, access: res.body.access_token as string, refresh: cookieOf(res, "legion_refresh") };
};

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'Alpha'), ($2, 'Bravo')", [tA, tB]);
  const hash = await bcrypt.hash(PASSWORD, 4);
  adminA = await store.insertUser({ email: "admin@alpha.io", password_hash: hash, tenant_id: tA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "admin@bravo.io", password_hash: hash, tenant_id: tB, role: "admin", status: "active" });
  dana = await store.insertUser({ email: "dana@alpha.io", password_hash: hash, tenant_id: tA, role: "analyst", status: "active" });
  await alertIn(tA, "ALPHA-1");
  await alertIn(tB, "BRAVO-1");
});

describe("memberships", () => {
  it("every existing account has its home membership (backfill + trigger)", async () => {
    const rows = (await query("SELECT tenant_id, user_id, role, status FROM workspace_memberships ORDER BY role")).rows;
    expect(rows).toHaveLength(3);
    expect(rows.find((r) => r.user_id === dana.id)).toMatchObject({ tenant_id: tA, role: "analyst", status: "active" });
    // A token issued before workspaces (tenant = home) keeps working.
    expect((await request(app).get("/alerts").set(...bearer(tokenFor(dana)))).status).toBe(200);
  });

  it("a token for a workspace the person is not a member of is refused", async () => {
    const forged = tokenFor(dana, tB);
    expect((await request(app).get("/alerts").set(...bearer(forged))).status).toBe(401);
    expect((await request(app).get("/auth/me").set(...bearer(forged))).status).toBe(401);
  });
});

describe("inviting someone who already has an account", () => {
  it("is accepted by signing in — the invitation link can never set their password", async () => {
    const token = await invite(adminB, dana.email, "viewer");
    const preview = await request(app).post("/auth/invite/preview").send({ token });
    expect(preview.body).toMatchObject({ email: dana.email, tenant_name: "Bravo", existing_account: true });
    // The new-account path refuses it and changes nothing.
    const takeover = await request(app).post("/auth/accept-invite").send({ token, password: "attacker-chosen-password-1" });
    expect(takeover.status).toBe(409);
    expect((await store.findUserById(dana.id))!.password_hash).toBe(dana.password_hash);
    // Someone else, signed in, cannot accept it.
    expect((await request(app).post("/workspaces/invitations/accept").set(...bearer(tokenFor(adminA))).send({ token })).status).toBe(400);
    // Dana can, once.
    const { access } = await login(dana.email);
    expect((await request(app).post("/workspaces/invitations/accept").set(...bearer(access)).send({ token })).body).toMatchObject({ workspace_id: tB, role: "viewer" });
    expect((await request(app).post("/workspaces/invitations/accept").set(...bearer(access)).send({ token })).status).toBe(400);
    // Her account and home workspace are as they were.
    expect(await store.findUserById(dana.id)).toMatchObject({ tenant_id: tA, role: "analyst", status: "active" });
  });

  it("before acceptance the invitation grants nothing", async () => {
    await invite(adminB, dana.email);
    const { access } = await login(dana.email);
    expect((await switchTo(access, tB)).res.status).toBe(404);
    expect((await request(app).get("/alerts").set(...bearer(tokenFor(dana, tB)))).status).toBe(401);
    const list = (await request(app).get("/workspaces").set(...bearer(access))).body.workspaces;
    expect(list.map((w: { id: string; status: string }) => [w.id, w.status])).toEqual(expect.arrayContaining([[tA, "active"], [tB, "invited"]]));
  });
});

describe("switching workspace", () => {
  it("issues a session for the other workspace; data never mixes; the first session is unchanged", async () => {
    const inA = await danaInBoth();
    const { res, access: inB, refresh } = await switchTo(inA, tB);
    expect(res.status).toBe(200);
    expect(res.body.workspace).toMatchObject({ id: tB, name: "Bravo", role: "viewer" });
    const idsIn = async (t: string) => (await request(app).get("/alerts").set(...bearer(t))).body.map((a: { id: string }) => a.id);
    expect(await idsIn(inB)).toEqual(["BRAVO-1"]);
    expect(await idsIn(inA)).toEqual(["ALPHA-1"]);
    expect((await request(app).get("/alerts/ALPHA-1").set(...bearer(inB))).status).toBe(404);
    // The role is the workspace's: analyst in A, viewer in B.
    expect((await request(app).get("/auth/me").set(...bearer(inB))).body).toMatchObject({ role: "viewer", tenant_id: tB, workspace: { id: tB }, home_workspace_id: tA });
    expect((await request(app).patch("/alerts/BRAVO-1/status").set(...bearer(inB)).send({ status: "resolved" })).status).toBe(403);
    // Refreshing the B session stays in B.
    const refreshed = await request(app).post("/auth/refresh").set("Cookie", `legion_refresh=${refresh}`);
    expect(refreshed.status).toBe(200);
    expect(await idsIn(refreshed.body.access_token)).toEqual(["BRAVO-1"]);
  });

  it("a sign-in lands in the chosen default workspace", async () => {
    const inA = await danaInBoth();
    expect((await request(app).put("/workspaces/default").set(...bearer(inA)).send({ workspace_id: tB })).status).toBe(200);
    const { access } = await login(dana.email);
    expect((await request(app).get("/auth/me").set(...bearer(access))).body.tenant_id).toBe(tB);
    // Not a member: refused, and nothing changes.
    const other = randomUUID();
    expect((await request(app).put("/workspaces/default").set(...bearer(inA)).send({ workspace_id: other })).status).toBe(404);
  });
});

describe("a workspace changes only its own membership", () => {
  it("B deactivating Dana ends her B sessions at once; her A access and account are untouched", async () => {
    const inA = await danaInBoth();
    const { access: inB, refresh: refreshB } = await switchTo(inA, tB);
    const loginA = await login(dana.email);
    const res = await request(app).delete(`/users/${dana.id}`).set(...bearer(tokenFor(adminB)));
    expect(res.status).toBe(200);
    expect((await request(app).get("/alerts").set(...bearer(inB))).status).toBe(401);
    expect((await request(app).post("/auth/refresh").set("Cookie", `legion_refresh=${refreshB}`)).status).toBe(401);
    // A: same token, same refresh session, same account.
    expect((await request(app).get("/alerts").set(...bearer(inA))).status).toBe(200);
    expect((await request(app).post("/auth/refresh").set("Cookie", `legion_refresh=${loginA.refresh}`)).status).toBe(200);
    expect(await store.findUserById(dana.id)).toMatchObject({ status: "active", role: "analyst", token_version: dana.token_version });
  });

  it("B changing Dana's role changes it in B only", async () => {
    await danaInBoth();
    expect((await request(app).patch(`/users/${dana.id}/role`).set(...bearer(tokenFor(adminB))).send({ role: "admin" })).status).toBe(200);
    const roles = (await query("SELECT tenant_id, role FROM workspace_memberships WHERE user_id = $1", [dana.id])).rows;
    expect(Object.fromEntries(roles.map((r) => [r.tenant_id, r.role]))).toEqual({ [tA]: "analyst", [tB]: "admin" });
    expect((await store.findUserById(dana.id))!.role).toBe("analyst");
  });

  it("B's user list shows its members only, with B's roles", async () => {
    await danaInBoth();
    const list = (await request(app).get("/users").set(...bearer(tokenFor(adminB)))).body as { id: string; role: string; tenant_id: string }[];
    expect(list.map((u) => [u.id, u.role, u.tenant_id]).sort()).toEqual([[adminB.id, "admin", tB], [dana.id, "viewer", tB]].sort());
    expect(JSON.stringify(list)).not.toContain("admin@alpha.io");
  });

  it("A (Dana's home) deactivating her disables the account everywhere, as before workspaces", async () => {
    const inA = await danaInBoth();
    const { access: inB } = await switchTo(inA, tB);
    expect((await request(app).delete(`/users/${dana.id}`).set(...bearer(tokenFor(adminA)))).status).toBe(200);
    expect((await request(app).get("/alerts").set(...bearer(inB))).status).toBe(401);
    expect((await request(app).post("/auth/login").send({ username: dana.email, password: PASSWORD })).status).not.toBe(200);
  });
});

describe("leaving and creating workspaces", () => {
  it("a member can leave; the home workspace and the last admin cannot", async () => {
    const inA = await danaInBoth();
    expect((await request(app).post("/workspaces/leave").set(...bearer(inA)).send({ workspace_id: tA })).status).toBe(400);
    expect((await request(app).post("/workspaces/leave").set(...bearer(inA)).send({ workspace_id: tB })).status).toBe(200);
    expect((await switchTo(inA, tB)).res.status).toBe(404);
    // Admin B, invited to A and made its only admin? A keeps adminA, so check B's last admin instead:
    const tokenB = tokenFor(adminB);
    const tokenForA = await invite(adminA, adminB.email, "admin");
    await request(app).post("/workspaces/invitations/accept").set(...bearer(tokenB)).send({ token: tokenForA });
    expect((await request(app).delete(`/users/${adminA.id}`).set(...bearer(tokenFor(adminB, tA)))).status).toBe(200);
    expect((await request(app).post("/workspaces/leave").set(...bearer(tokenB)).send({ workspace_id: tA })).body.detail).toMatch(/at least one admin/);
  });

  it("creates a workspace in this region with its creator as admin, up to a cap", async () => {
    const access = tokenFor(adminA);
    const res = await request(app).post("/workspaces").set(...bearer(access)).send({ name: "Charlie", currency: "EUR", timezone: "Europe/Berlin" });
    expect(res.status).toBe(201);
    const t = await store.getTenant(res.body.id);
    expect(t).toMatchObject({ name: "Charlie", region: config.region, currency: "EUR", timezone: "Europe/Berlin" });
    expect(t!.trial_ends_at).not.toBeNull();
    const { access: inC } = await switchTo(access, res.body.id);
    expect((await request(app).get("/users").set(...bearer(inC))).body.map((u: { email: string; role: string }) => [u.email, u.role])).toEqual([["admin@alpha.io", "admin"]]);
    expect((await request(app).post("/workspaces").set(...bearer(access)).send({ name: "X", currency: "JPY" })).status).toBe(422);
    expect((await request(app).post("/workspaces").set(...bearer(access)).send({ name: "X", timezone: "Mars/Olympus" })).status).toBe(422);
    const cap = config.maxWorkspacesPerUser;
    try {
      (config as { maxWorkspacesPerUser: number }).maxWorkspacesPerUser = 2;
      expect((await request(app).post("/workspaces").set(...bearer(access)).send({ name: "Delta" })).status).toBe(429);
    } finally {
      (config as { maxWorkspacesPerUser: number }).maxWorkspacesPerUser = cap;
    }
  });
});

describe("realtime", () => {
  it("a socket's grant is re-checked against the membership of ITS workspace", async () => {
    await danaInBoth();
    const grant = { userId: dana.id, tokenVersion: dana.token_version, expiresAt: Date.now() + 60_000, tokenHash: "x" };
    const before = await socketGrantsStillValid([{ tenantId: tA, ...grant }, { tenantId: tB, ...grant }]);
    expect(before.size).toBe(2);
    await request(app).delete(`/users/${dana.id}`).set(...bearer(tokenFor(adminB)));
    const after = await socketGrantsStillValid([{ tenantId: tA, ...grant }, { tenantId: tB, ...grant }]);
    expect(after.size).toBe(1);
  });
});
