/** Shared setup for the Task 11 end-to-end suites (test harness, not production code). */
import bcrypt from "bcryptjs";
import { randomUUID } from "node:crypto";
import { app } from "../../src/index.js";
import { mint } from "./tokens.js";
import { query } from "../../src/db/pool.js";
import { truncateAll } from "../../src/seed.js";
import { config } from "../../src/config.js";
import * as store from "../../src/store.js";
import type { Agent, User } from "../../src/types.js";
import { putPolicy } from "../../src/policy/store.js";
import { flushShadow } from "../../src/policy/shadow.js";
import { createAgents, type AgentSession } from "./soc-conductor.js";
import { issueCredential, sendSigned, type TestCredential } from "./webhook.js";

export const ATTACKER = "45.155.205.12";
export const tokenOf = (u: User) => mint({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, { expiresIn: "1h" });
export const as = (u: User) => ["Authorization", `Bearer ${tokenOf(u)}`] as const;

let n = 0;
export const wazuh = (o: { ip?: string; host?: string; mitre?: string[]; level?: number; log?: string; desc?: string; groups?: string[] } = {}) => ({
  provider: "wazuh",
  event: {
    id: `wz-${++n}-${randomUUID()}`,
    rule: { description: o.desc ?? "sshd: brute force attempt", level: o.level ?? 12, mitre: { id: o.mitre ?? ["T1110"] }, groups: o.groups ?? ["sshd"] },
    agent: { name: o.host ?? "web-01", ip: "10.0.0.5" },
    data: { srcip: o.ip ?? ATTACKER },
    full_log: o.log ?? `sshd[812]: Failed password for root from ${o.ip ?? ATTACKER} port 22 ssh2`,
  },
});
export const sendWazuh = (cred: TestCredential, body: unknown) => sendSigned(app, cred, body).expect(202);

export async function attack(cred: TestCredential, ip = ATTACKER, host = "web-01") {
  await sendWazuh(cred, wazuh({ ip, host, mitre: ["T1595"], desc: "Port scan detected", groups: ["recon"], level: 7 }));
  for (let i = 0; i < 4; i++) await sendWazuh(cred, wazuh({ ip, host, mitre: ["T1110"] }));
  await sendWazuh(cred, wazuh({ ip, host, mitre: ["T1059"], desc: "Suspicious command execution after login", level: 13, log: `sudo: www-data : COMMAND=/bin/bash; from ${ip}` }));
}

export const alertsFor = async (tenant: string, ip = ATTACKER) =>
  (await query("SELECT id, severity, title FROM alerts WHERE tenant_id = $1 AND source_ip = $2 AND source = 'wazuh' ORDER BY created_at", [tenant, ip])).rows as Array<{ id: string; severity: string; title: string }>;
export const worstAlert = async (tenant: string, ip = ATTACKER) => (await alertsFor(tenant, ip)).slice(-1)[0]!;

export interface SocEnv {
  tenantA: string; tenantB: string;
  admin: User; approver2: User; analyst: User; adminB: User;
  credA: TestCredential; credB: TestCredential;
  agentsA: Record<Agent, AgentSession>; agentsB: Record<Agent, AgentSession>;
}

export async function resetEnv(): Promise<SocEnv> {
  await flushShadow();
  await truncateAll();
  config.socAuditKey = ""; config.policyEngineMode = "shadow"; config.orchestratorAutoMode = "off"; config.openrouterApiKey = "";
  const tenantA = randomUUID(); const tenantB = randomUUID();
  await query("INSERT INTO tenants (id, name, plan_override) VALUES ($1, 'A', 'business'), ($2, 'B', 'business')", [tenantA, tenantB]);
  const h = await bcrypt.hash("password123", 4);
  const mk = (email: string, tenant_id: string, role: "admin" | "analyst") => store.insertUser({ email, password_hash: h, tenant_id, role, status: "active" });
  const admin = await mk("admin@a.io", tenantA, "admin"); const approver2 = await mk("admin2@a.io", tenantA, "admin");
  const analyst = await mk("analyst@a.io", tenantA, "analyst"); const adminB = await mk("admin@b.io", tenantB, "admin");
  return {
    tenantA, tenantB, admin, approver2, analyst, adminB,
    credA: await issueCredential(tenantA), credB: await issueCredential(tenantB),
    agentsA: await createAgents(admin, tokenOf(admin)), agentsB: await createAgents(adminB, tokenOf(adminB)),
  };
}

export const setPolicy = (tenant: string, by: User, d: Record<string, unknown>, expectedVersion = 0) =>
  putPolicy(tenant, { schema: 1, rules: [], ...d } as never, { expectedVersion, userId: by.id });
