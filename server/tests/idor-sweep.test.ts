/**
 * PR-7: an IDOR sweep generated from the route table. For every route registered on the app with a
 * path parameter, a resource of that kind is created in workspace A, then the route is called by an
 * ADMINISTRATOR of workspace B with A's id. Every answer must be a refusal (never 2xx), must not carry
 * A's data, and A's resource must be unchanged afterwards.
 *
 * A new route with a path parameter fails this test until it has a fixture below — so a future route
 * cannot skip the check by accident.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import request from "supertest";
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../src/index.js";
import { mint } from "./helpers/tokens.js";
import { issueCredential } from "./helpers/webhook.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import * as store from "../src/store.js";
import * as blocklist from "../src/blocklist.js";
import { checkPayment } from "../src/payments.js";
import type { User } from "../src/types.js";

let tA: string; let tB: string; let adminA: User; let adminA2: User; let adminB: User;
const as = (u: User) => ["Authorization", `Bearer ${mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" })}`] as const;
const ALERT = "SEC-IDOR-A";

interface Fixture {
  /** Creates the resource in workspace A; returns the path params to call with and a fingerprint of A's state. */
  make: () => Promise<{ params: Record<string, string>; body?: Record<string, unknown>; snapshot: () => Promise<unknown> }>;
}

const row = (sql: string, params: unknown[]) => async () => (await query(sql, params)).rows;

const FIXTURES: Record<string, Fixture> = {
  "GET /alerts/:id": { make: async () => ({ params: { id: ALERT }, snapshot: row("SELECT status FROM alerts WHERE tenant_id = $1 AND id = $2", [tA, ALERT]) }) },
  "PATCH /alerts/:id/status": { make: async () => ({ params: { id: ALERT }, body: { status: "resolved" }, snapshot: row("SELECT status, resolved_at FROM alerts WHERE tenant_id = $1 AND id = $2", [tA, ALERT]) }) },
  "POST /alerts/:id/explain": { make: async () => ({ params: { id: ALERT }, snapshot: row("SELECT ai_explanation FROM alerts WHERE tenant_id = $1 AND id = $2", [tA, ALERT]) }) },
  "POST /users/:id/resend-invite": { make: async () => ({ params: { id: adminA2.id }, snapshot: row("SELECT status, role FROM users WHERE id = $1", [adminA2.id]) }) },
  "PATCH /users/:id/role": { make: async () => ({ params: { id: adminA2.id }, body: { role: "viewer" }, snapshot: row("SELECT role FROM workspace_memberships WHERE user_id = $1 AND tenant_id = $2", [adminA2.id, tA]) }) },
  "DELETE /users/:id": { make: async () => ({ params: { id: adminA2.id }, snapshot: row("SELECT status FROM workspace_memberships WHERE user_id = $1 AND tenant_id = $2", [adminA2.id, tA]) }) },
  "POST /notifications/deliveries/:id/retry": {
    make: async () => {
      const id = randomUUID();
      await query(`INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, status, max_attempts)
                   VALUES ($1, $2, 'alert_email', $3, 'soc@a.io', '{"title":"x"}', 'dead', 8)`, [id, tA, randomUUID()]);
      return { params: { id }, snapshot: row("SELECT status, attempts FROM notification_outbox WHERE id = $1", [id]) };
    },
  },
  "POST /security-events/credentials/:id/rotate": {
    make: async () => { const c = await issueCredential(tA, "idor"); return { params: { id: c.keyId }, snapshot: row("SELECT * FROM webhook_credentials WHERE key_id = $1", [c.keyId]) }; },
  },
  "DELETE /security-events/credentials/:id": {
    make: async () => { const c = await issueCredential(tA, "idor"); return { params: { id: c.keyId }, snapshot: row("SELECT * FROM webhook_credentials WHERE key_id = $1", [c.keyId]) }; },
  },
  "DELETE /security/blocks/:ip": {
    make: async () => {
      await blocklist.addBlock(tA, "185.220.101.77", { minutes: 60, reason: "idor test", userId: adminA.id });
      return { params: { ip: "185.220.101.77" }, snapshot: row("SELECT ip, revoked_at FROM ip_blocks WHERE tenant_id = $1", [tA]) };
    },
  },
  "POST /security/payments/:id/release": {
    make: async () => {
      const r = await checkPayment(tA, { beneficiary: { account: "DE89370400440532013000", name: "X" }, amount: 10, currency: "EUR" } as never);
      return { params: { id: r.check.id }, snapshot: row("SELECT resolution FROM payment_checks WHERE tenant_id = $1 AND id = $2", [tA, r.check.id]) };
    },
  },
  "POST /security/payments/:id/reject": {
    make: async () => {
      const r = await checkPayment(tA, { beneficiary: { account: "GB82WEST12345698765432", name: "Y" }, amount: 11, currency: "EUR" } as never);
      return { params: { id: r.check.id }, snapshot: row("SELECT resolution FROM payment_checks WHERE tenant_id = $1 AND id = $2", [tA, r.check.id]) };
    },
  },
  ...Object.fromEntries(["POST /integrations/:id/pause", "POST /integrations/:id/resume", "DELETE /integrations/:id"].map((k) => [k, {
    make: async () => {
      const id = randomUUID();
      await query("INSERT INTO integration_connections (id, tenant_id, kind, name, status) VALUES ($1, $2, 'fakecloud', 'A cloud', 'active')", [id, tA]);
      return { params: { id }, snapshot: row("SELECT status FROM integration_connections WHERE id = $1", [id]) };
    },
  }])),
  ...Object.fromEntries(["GET /actions/:id", "POST /actions/:id/cancel"].map((k) => [k, {
    make: async () => {
      const r = await request(app).post("/actions").set(...as(adminA)).send({ action_id: "account.disable", input: { account: "jdoe", system: "entra" }, mode: "simulation", idempotency_key: randomUUID() });
      expect(r.status).toBe(201);
      return { params: { id: r.body.action.id }, snapshot: row("SELECT status FROM action_requests WHERE id = $1", [r.body.action.id]) };
    },
  }])),
  ...Object.fromEntries(["GET /approvals/:id", "POST /approvals/:id/decision"].map((k) => [k, {
    make: async () => {
      const r = await request(app).post("/actions").set(...as(adminA)).send({ action_id: "account.disable", input: { account: "jdoe2", system: "entra" }, mode: "simulation", idempotency_key: randomUUID() });
      const a = r.body.action;
      return { params: { id: a.approval_id }, body: { decision: "approve", action_digest: a.action_digest }, snapshot: row("SELECT status FROM approval_requests WHERE id = $1", [a.approval_id]) };
    },
  }])),
  "GET /workflows/runs/:id": {
    make: async () => {
      const r = await request(app).post("/workflows/alert_response/runs").set(...as(adminA)).send({ alert_id: ALERT, mode: "shadow" });
      expect(r.status).toBeLessThan(300);
      const id = r.body.run?.id ?? r.body.id;
      return { params: { id }, snapshot: row("SELECT status FROM workflow_runs WHERE id = $1", [id]) };
    },
  },
  // :name is a workflow name, not a resource; the resource is the alert in the body.
  "POST /workflows/:name/runs": {
    make: async () => ({ params: { name: "alert_response" }, body: { alert_id: ALERT, mode: "shadow" }, snapshot: row("SELECT count(*)::int n FROM workflow_runs WHERE tenant_id = $1", [tA]) }),
  },
  "DELETE /memory/:id": {
    make: async () => {
      const r = await request(app).post("/memory").set(...as(adminA)).send({ kind: "note", subject_type: "host", subject_key: "web-01", content: "A's private note" });
      expect(r.status).toBe(201);
      const id = r.body.memory?.id ?? r.body.id;
      return { params: { id }, snapshot: row("SELECT content FROM soc_memory WHERE id = $1", [id]) };
    },
  },
};

function paramRoutes(): string[] {
  const out: string[] = [];
  for (const l of (app as any).router.stack) {
    if (!l.route || !/:/.test(l.route.path)) continue;
    for (const m of Object.keys(l.route.methods)) out.push(`${m.toUpperCase()} ${l.route.path}`);
  }
  return out;
}

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'enterprise'), ($2, 'B', 'enterprise')", [tA, tB]);
  const h = await bcrypt.hash("password123", 4);
  adminA = await store.insertUser({ email: "a1@a.io", password_hash: h, tenant_id: tA, role: "admin", status: "active" });
  adminA2 = await store.insertUser({ email: "a2@a.io", password_hash: h, tenant_id: tA, role: "admin", status: "active" });
  adminB = await store.insertUser({ email: "b@b.io", password_hash: h, tenant_id: tB, role: "admin", status: "active" });
  await store.insertAlert({ id: ALERT, tenant_id: tA, title: "A-only secret title", severity: "high", agent: "Sentinel", status: "open", summary: "A-only summary", confidence: 60, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "wazuh" });
});

describe("IDOR sweep over every parameterised route", () => {
  it("every route with a path parameter has a fixture (a new route must add one)", () => {
    const missing = paramRoutes().filter((r) => !FIXTURES[r]);
    expect(missing).toEqual([]);
  });

  for (const key of Object.keys(FIXTURES)) {
    it(`${key}: workspace B's administrator cannot read or change workspace A's resource`, async () => {
      const [method, path] = key.split(" ") as [string, string];
      const f = await FIXTURES[key]!.make();
      const before = JSON.stringify(await f.snapshot());
      const url = path.replace(/:([a-z_]+)/gi, (_, p: string) => encodeURIComponent(f.params[p]!));
      const r = await (request(app) as any)[method.toLowerCase()](url).set(...as(adminB)).send(f.body ?? {});
      expect(r.status, `${key} answered ${r.status}: ${JSON.stringify(r.body).slice(0, 200)}`).toBeGreaterThanOrEqual(400);
      expect(r.status).not.toBe(500);
      const text = JSON.stringify(r.body);
      for (const leak of ["A-only secret title", "A-only summary", "A's private note", "a2@a.io"]) expect(text).not.toContain(leak);
      expect(JSON.stringify(await f.snapshot())).toBe(before);
    });
  }
});

describe("the sweep itself", () => {
  it("catches a deliberately broken route that forgets the workspace", async () => {
    // A route that looks the alert up by id alone — the bug this sweep exists to catch.
    (app as any).get("/zz-idor-probe/:id", async (req: any, res: any) => {
      const r = await query("SELECT title FROM alerts WHERE id = $1", [req.params.id]);
      res.json(r.rows[0] ?? {});
    });
    // Registered last it would sit behind the 404 handler; move it to the front so it is reachable.
    const layers = (app as any).router.stack as unknown[];
    layers.unshift(layers.pop());
    try {
      const r = await request(app).get(`/zz-idor-probe/${ALERT}`).set(...as(adminB));
      // What the sweep asserts for every real route — and what this broken one violates.
      expect(r.status).toBeLessThan(400);
      expect(JSON.stringify(r.body)).toContain("A-only secret title");
      expect(paramRoutes()).toContain("GET /zz-idor-probe/:id");
      expect(paramRoutes().filter((x) => !FIXTURES[x])).toEqual(["GET /zz-idor-probe/:id"]);   // and it has no fixture
    } finally {
      const stack = (app as any).router.stack as Array<{ route?: { path: string } }>;
      const i = stack.findIndex((l) => l.route?.path === "/zz-idor-probe/:id");
      if (i >= 0) stack.splice(i, 1);
    }
  });
});
