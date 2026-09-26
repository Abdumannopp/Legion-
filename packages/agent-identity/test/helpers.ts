import express, { type Express, type Request } from "express";
import pg from "pg";
import request from "supertest";
import { createAgentIdentity, type AgentIdentity, type HostAdapter, type HostUser, type HumanRole } from "../src/index.js";

export const DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgresql://legion:legion-test@127.0.0.1:55432/legion_test";

export const TENANT_A = "11111111-1111-4111-8111-111111111111";
export const TENANT_B = "22222222-2222-4222-8222-222222222222";

/**
 * Stand-in for Legion's existing login: a person is signed in when the
 * request carries `cookie: session=<userId>`, exactly the kind of check the
 * real cookie/JWT middleware makes. The module only ever calls this.
 */
export class FakeHost implements HostAdapter {
  users = new Map<string, HostUser>();
  calls = 0;

  add(id: string, tenantId: string, role: HumanRole, status = "active"): HostUser {
    const u = { id, tenantId, role, status, displayName: id };
    this.users.set(id, u);
    return u;
  }

  async authenticateHuman(req: Request) {
    this.calls++;
    const m = /(?:^|;\s*)session=([^;]+)/.exec(req.get("cookie") ?? "");
    const u = m ? this.users.get(m[1]!) : undefined;
    if (!u || u.status !== "active") return null;
    return { userId: u.id, tenantId: u.tenantId, role: u.role, displayName: u.displayName };
  }

  async getUser(tenantId: string, userId: string) {
    const u = this.users.get(userId);
    return u && u.tenantId === tenantId ? { ...u } : null;
  }
}

export interface TestApp {
  app: Express;
  host: FakeHost;
  identity: AgentIdentity;
  pool: pg.Pool;
  /** What each "existing" human route saw, to prove humans are untouched. */
  seen: unknown[];
}

export async function resetDb(pool: pg.Pool) {
  await pool.query(`
    DROP TABLE IF EXISTS tool_call_audit, tool_call_tickets, content_ingestion_log, content_risk_acknowledgements,
      agent_messages, agent_delegations, firewall_decisions, firewall_policies,
      principal_audit_log, machine_tokens, machine_credentials, machine_identities CASCADE;
    DROP FUNCTION IF EXISTS principal_audit_log_append_only() CASCADE;
  `);
}

export async function makeApp(opts: { pool?: pg.Pool; logs?: string[] } = {}): Promise<TestApp> {
  const pool = opts.pool ?? new pg.Pool({ connectionString: DATABASE_URL, max: 20 });
  const host = new FakeHost();
  const identity = createAgentIdentity({
    pool,
    host,
    log: (msg) => opts.logs?.push(msg),
  });
  await identity.migrate();

  const app = express();
  app.set("trust proxy", false);
  app.use(express.json());
  const seen: unknown[] = [];

  // An endpoint that exists before the module — the health check — is exempt.
  app.get("/health", (_req, res) => { res.json({ status: "ok" }); });

  app.use(identity.principal);
  app.use("/agent/v1", identity.agentApi);
  app.use("/agents", identity.agents);
  app.use("/service-accounts", identity.serviceAccounts);
  app.use("/audit/principal-events", identity.auditApi);
  app.use("/firewall", identity.firewallApi);
  app.use("/prompt-guard", identity.promptGuardApi);
  app.use("/tools", identity.toolsApi);

  // Stand-ins for existing human routes: they keep their own auth and see
  // exactly what they saw before (plus req.principal, which they ignore).
  app.post("/auth/login", (req, res) => {
    seen.push({ route: "login", principal: req.principal?.type });
    res.json({ ok: true });
  });
  app.get("/me", async (req, res) => {
    const s = await host.authenticateHuman(req);
    if (!s) return res.status(401).json({ error: "not signed in" });
    seen.push({ route: "me", principal: req.principal?.type });
    res.json({ user: s.userId });
  });

  // Agent-callable actions guarded by the module.
  app.get("/agent/v1/alerts", identity.guards.requirePermission("alerts:read", { resource: () => ({ type: "alert" }) }),
    (req, res) => { res.json({ alerts: [], calledBy: req.principal }); });
  app.post("/agent/v1/alerts/:id/status", identity.guards.requirePermission("alerts:update_status", {
    resource: (req) => ({ type: "alert", id: String(req.params.id) }),
  }), (_req, res) => { res.json({ ok: true }); });
  app.get("/whoami", (req, res) => { res.json({ principal: req.principal }); });
  app.get("/agent/v1/whoami", identity.guards.traced("test:whoami"), (req, res) => { res.json({ principal: req.principal }); });
  // Deliberately missing a guard: the firewall must flag it.
  app.get("/agent/v1/unguarded", (_req, res) => { res.json({ oops: true }); });
  app.post("/webhooks/wazuh", identity.guards.externalSystem("wazuh-webhook"),
    identity.guards.traced("alert.ingest"), (_req, res) => { res.status(202).json({ ok: true }); });

  return { app, host, identity, pool, seen };
}

export const as = (userId: string) => ({ cookie: `session=${userId}` });
export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** Creates an agent as `adminId` and exchanges its credential for an access token. */
export async function agentWithToken(t: TestApp, adminId: string, body: Record<string, unknown> = {}) {
  const created = await request(t.app).post("/agents").set(as(adminId))
    .send({ name: `agent-${Math.random().toString(36).slice(2, 8)}`, permissions: ["alerts:read"], ...body });
  if (created.status !== 201) throw new Error(`create failed: ${created.status} ${JSON.stringify(created.body)}`);
  const secret: string = created.body.credential.secret;
  const tok = await request(t.app).post("/agent/v1/token").set(bearer(secret));
  if (tok.status !== 200) throw new Error(`token failed: ${tok.status} ${JSON.stringify(tok.body)}`);
  return { agent: created.body.identity, secret, token: tok.body.access_token as string, credentialId: created.body.credential.id as string };
}

export async function auditRows(pool: pg.Pool, where = "true", args: unknown[] = []) {
  const r = await pool.query(`SELECT * FROM principal_audit_log WHERE ${where} ORDER BY seq`, args);
  return r.rows;
}
