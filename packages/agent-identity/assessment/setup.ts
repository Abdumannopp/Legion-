/*
 * Shared setup for the security assessment. Every scenario file imports
 * this: a real Express app + PostgreSQL 16, one tenant scenario per test,
 * reset between tests. Attacks are made the way an attacker would make
 * them — over HTTP with an agent's bearer token, or through the library
 * calls a host's agent runtime makes — never by calling internal code that
 * bypasses the firewall.
 */
import { randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import request from "supertest";
import { beforeEach } from "vitest";
import { hashToolDefinition, type MachinePrincipal } from "../src/index.js";
import { DecisionLog } from "../src/firewall/log.js";
import { agentWithToken, as, bearer, makeApp, resetDb, TENANT_A, TENANT_B, type TestApp } from "../test/helpers.js";

export const MCP_DEF = { name: "create_ticket", description: "Create a ticket in the service desk.", inputSchema: { type: "object", properties: { title: { type: "string" } } } };

export function basePolicy(dir: string) {
  return {
    egress: { allowedHosts: ["api.partner.example", "rebind.partner.example"] },
    files: { roots: [{ path: dir, access: "readwrite" }] },
    database: { tables: { alerts: ["select", "update"] } },
    toolSecurity: {
      shell: { commands: { git: {}, ls: {}, cat: {}, echo: {}, sleep: { maxArgs: 1 } } },
      slack: { channels: { C0SECOPS1: "write" } },
      email: { allowedRecipientDomains: ["corp.example"] },
      github: { repos: { "acme/soc-runbooks": "write" } },
      cloud: { accounts: [{ provider: "aws", account: "111122223333", regions: ["eu-west-1"], access: "write" }] },
    },
    mcp: { servers: { servicedesk: { tools: { create_ticket: { permission: "tool.mcp:write", sideEffects: "internal", sha256: hashToolDefinition(MCP_DEF) } } } } },
  };
}

/** One hostname is deliberately rebound to an internal address, to test DNS-rebinding defence without real network access. */
export const fakeDns = async (host: string) =>
  host === "rebind.partner.example" ? [{ address: "10.0.0.7", family: 4 }] : [{ address: "203.0.113.10", family: 4 }];

export interface World {
  t: TestApp;
  dir: string;
  outside: string;
}

export async function setPolicy(w: World, policy: Record<string, unknown>, user = "alice") {
  const res = await request(w.t.app).put("/firewall/policy").set(as(user)).send(policy);
  if (res.status !== 200) throw new Error(`policy rejected: ${JSON.stringify(res.body)}`);
}

export type Agent = Awaited<ReturnType<typeof agentWithToken>>;
export const mkAgent = (w: World, permissions: string[], name?: string, owner = "alice") =>
  agentWithToken(w.t, owner, { name: name ?? `agent-${randomUUID().slice(0, 6)}`, permissions });

export const principalOf = async (w: World, a: Agent) =>
  (await request(w.t.app).get("/agent/v1/whoami").set(bearer(a.token))).body.principal as MachinePrincipal;

export const authorize = (w: World, a: Agent, call: unknown, headers: Record<string, string> = {}) =>
  request(w.t.app).post("/agent/v1/tools/authorize").set(bearer(a.token)).set(headers).send({ call });

/**
 * A legitimate call, let through the way the product lets it through: tool
 * permissions that act on the world need a person's approval per action by
 * default (policy responses.confirm), so the agent asks, an administrator
 * approves that exact call, and the agent retries citing the approval.
 * Scenarios use this for their "legitimate baseline" steps.
 */
export async function authorizeApproved(w: World, a: Agent, call: unknown): Promise<request.Response> {
  const first = await authorize(w, a, call);
  if (first.body?.decision !== "CONFIRM" || !first.body?.approval?.id) return first;
  const id: string = first.body.approval.id;
  const ok = await request(w.t.app).post(`/firewall/approvals/${id}/approve`).set(as("alice")).send({ reason: "assessment: legitimate baseline" });
  if (ok.status !== 200) return first;
  return authorize(w, a, call, { "x-legion-approval-id": id });
}

export const rules = (res: request.Response): string[] => res.body?.error?.rules ?? [];
export const brief = (res: request.Response) => ({ status: res.status, decision: res.body?.decision, rules: rules(res) });
export const isDenied = (res: request.Response) => [400, 401, 403, 404].includes(res.status);

export const SLACK = (channel: string, text = "Scan finished") => ({ kind: "slack", operation: "post_message", channel, text });
export const HTTP_CALL = (url: string, method = "POST", body?: string) => ({ kind: "http", operation: "request", method, url, ...(body ? { body } : {}) });
export const SHELL_CALL = (command: string, args: string[], cwd?: string) => ({ kind: "shell", operation: "execute", command, args, ...(cwd ? { cwd } : {}) });
export const SQL_CALL = (sql: string, params: unknown[] = []) => ({ kind: "database", operation: "query", sql, params });

interface Seed {
  action: string;
  surface?: string;
  resourceType?: string;
  destination?: string;
  sensitivity?: string;
  decision?: "ALLOW" | "WARN" | "BLOCK";
  ruleIds?: string[];
}

/**
 * Writes past decisions directly into the decision log to establish an
 * agent's behaviour baseline (what behaviour monitoring learns from).
 * Establishing history is a legitimate test input, not the attack itself —
 * every attack in this file is still performed live, against the running
 * firewall/route, after the baseline exists.
 */
export async function seedHistory(w: World, agent: { id: string; name: string }, items: (Seed & { minutesAgo: number })[]) {
  const log = new DecisionLog(w.t.pool);
  for (const it of items) {
    await log.record({
      decisionId: randomUUID(), occurredAt: new Date(Date.now() - it.minutesAgo * 60_000).toISOString(),
      tenantId: TENANT_A, principalType: "ai_agent", principalId: agent.id, principalName: agent.name, ownerUserId: "alice",
      credentialId: null, tokenId: null, delegatedUser: null, delegationId: null, agentChain: [], viaMessageId: null,
      surface: it.surface ?? "api", action: it.action, permission: null, resourceType: it.resourceType ?? "alert", resourceId: null,
      sensitivity: (it.sensitivity ?? "internal") as never, destination: it.destination ?? "api:alert", decision: it.decision ?? "ALLOW",
      wouldBlock: false, mode: "enforce", riskScore: 0, riskFactors: [],
      ruleHits: (it.ruleIds ?? []).map((id) => ({ id, effect: "BLOCK" as const, hard: true, reason: "seeded" })),
      advisor: [], policyVersion: 1, inputDigest: "0".repeat(64), inputPreview: {}, requestId: null, ip: null,
    });
  }
}

export const SLACK_KNOWN = { action: "tool:slack.post_message", surface: "tool_call", resourceType: "tool:slack", destination: "slack:C0SECOPS1" };

/** Five days of a triage agent's normal work: reading alerts and posting to one channel, spread over every hour. */
export async function establishNormalBaseline(w: World, agent: { id: string; name: string }) {
  const items = Array.from({ length: 160 }, (_, i) => ({
    ...(i % 4 === 0 ? SLACK_KNOWN : { action: "alerts:read" }),
    minutesAgo: 90 + i * 43, // 43-minute steps: ~5 days, every hour of the day
  }));
  await seedHistory(w, agent, items);
}

/**
 * Boots a fresh app + tenants for one test. Call inside `beforeEach` in each
 * scenario file (each file gets its own `World` object so files can run in
 * parallel processes later if wanted; the shared Postgres server serialises
 * actual DB access via fileParallelism: false).
 */
export function useWorld(extraOpts: Record<string, unknown> = {}): World {
  const w = {} as World;
  beforeEach(async () => {
    w.dir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "legion-assess-root-")));
    w.outside = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "legion-assess-outside-")));
    if (w.t) await w.t.pool.end();
    w.t = await makeApp({ extra: { dnsLookup: fakeDns, killSwitchPollMs: 200, ...extraOpts } });
    await resetDb(w.t.pool);
    await w.t.identity.migrate();
    w.t.host.add("alice", TENANT_A, "admin");
    w.t.host.add("anna", TENANT_A, "analyst");
    w.t.host.add("vic", TENANT_A, "viewer");
    w.t.host.add("bob", TENANT_B, "admin");
    await setPolicy(w, basePolicy(w.dir));
  });
  return w;
}
