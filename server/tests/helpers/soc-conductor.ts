/**
 * TEST HARNESS for Task 11 — not production code.
 *
 * Plays the SOC investigation the way the five agents would, using only
 * Legion's real interfaces: the signed Wazuh webhook, the agent API with each
 * agent's own least-privilege token and assigned skills, then the policy,
 * approval, action and audit engines. Every step is timed and recorded in a
 * trace. The conductor itself holds no authority: Vanguard's proposal goes
 * through proposeAction like any other request.
 *
 * (Today no production component chains Hunter and Guardian into a workflow —
 * the orchestrator's alert_response workflow uses Oracle, Vanguard and
 * Sentinel steps only. That gap is reported in E2E-REPORT.md.)
 */
import request from "supertest";
import { app } from "../../src/index.js";
import { query } from "../../src/db/pool.js";
import { proposeAction, type ActionRequest } from "../../src/actions/engine.js";
import { verifyAuditChain } from "../../src/audit/events.js";
import { randomUUID } from "node:crypto";
import type { User } from "../../src/types.js";
import type { Agent } from "../../src/types.js";

export interface TraceStep { n: number; ms: number; agent: Agent | "Legion" | "Human"; step: string; ok: boolean; summary: string }
export type AgentSession = { id: string; token: string; agent: Agent };

const bearer = (t: string) => ["Authorization", `Bearer ${t}`] as const;

/** Each agent gets only what its skills read. */
export const AGENT_SETUP: Record<Agent, { permissions: string[]; skills: string[] }> = {
  Sentinel: { permissions: ["alerts:read"], skills: ["threat_detection"] },
  Hunter: { permissions: ["alerts:read", "assets:read"], skills: ["attack_investigation"] },
  Guardian: { permissions: ["alerts:read", "assets:read", "vulnerabilities:read"], skills: ["vulnerability_analysis", "exposure_review"] },
  Oracle: { permissions: ["alerts:read", "assets:read"], skills: ["alert_analysis"] },
  Vanguard: { permissions: ["alerts:read"], skills: ["containment_candidates"] },
};

export async function createAgents(admin: User, adminToken: string): Promise<Record<Agent, AgentSession>> {
  const out = {} as Record<Agent, AgentSession>;
  for (const agent of Object.keys(AGENT_SETUP) as Agent[]) {
    const cfg = AGENT_SETUP[agent];
    const created = await request(app).post("/agents").set(...bearer(adminToken)).send({ name: `${agent.toLowerCase()}-${randomUUID().slice(0, 6)}`, permissions: cfg.permissions });
    if (created.status !== 201) throw new Error(`agent ${agent}: ${created.status} ${JSON.stringify(created.body)}`);
    for (const skill of cfg.skills) {
      const a = await request(app).post("/skills/assignments").set(...bearer(adminToken)).send({ identityId: created.body.identity.id, skill });
      if (a.status !== 201) throw new Error(`assign ${skill}: ${a.status} ${JSON.stringify(a.body)}`);
    }
    const tok = await request(app).post("/agent/v1/token").set(...bearer(created.body.credential.secret));
    if (tok.status !== 200) throw new Error(`token ${agent}: ${tok.status}`);
    out[agent] = { id: created.body.identity.id, token: tok.body.access_token, agent };
  }
  void admin;
  return out;
}

export class Trace {
  readonly steps: TraceStep[] = [];
  private t0 = performance.now();
  async step<T>(agent: TraceStep["agent"], step: string, fn: () => Promise<T>, summarize: (v: T) => string): Promise<T> {
    const t = performance.now();
    try {
      const v = await fn();
      this.steps.push({ n: this.steps.length + 1, ms: Math.round((performance.now() - t) * 10) / 10, agent, step, ok: true, summary: summarize(v) });
      return v;
    } catch (e) {
      this.steps.push({ n: this.steps.length + 1, ms: Math.round((performance.now() - t) * 10) / 10, agent, step, ok: false, summary: String(e instanceof Error ? e.message : e).slice(0, 200) });
      throw e;
    }
  }
  get totalMs() { return Math.round((performance.now() - this.t0) * 10) / 10; }
}

export async function invoke(a: AgentSession, skill: string, input: Record<string, unknown>) {
  const r = await request(app).post(`/agent/v1/skills/${skill}/invoke`).set(...bearer(a.token)).send({ input });
  if (r.status !== 200) throw Object.assign(new Error(`${a.agent}.${skill}: ${r.status} ${JSON.stringify(r.body).slice(0, 200)}`), { status: r.status, body: r.body });
  return r.body.output as Record<string, any>;
}

export interface Investigation {
  alertId: string;
  trace: Trace;
  sentinel: { patterns: string[]; score: number };
  hunter: { chains: number; stages: string[]; events: number };
  guardian: { findings: number; exposure: string };
  oracle: { severity: string; summary: string };
  /** Disagreement between agents, resolved towards the higher risk. */
  conflict: { detected: boolean; reasons: string[] };
  risk: "low" | "medium" | "high" | "critical";
  candidate: { ip: string; score: number; reasons: string[] } | null;
  action: ActionRequest | null;
}

const RANK = { low: 0, medium: 1, high: 2, critical: 3 } as const;

export async function investigate(opts: {
  tenantId: string; alertId: string; sourceIp: string; asset: string; agents: Record<Agent, AgentSession>;
  mode?: "shadow" | "simulation"; origin?: "agent" | "llm"; key?: string;
}): Promise<Investigation> {
  const { agents, alertId, sourceIp, asset, tenantId } = opts;
  const trace = new Trace();

  const wz = await trace.step("Legion", "wazuh event stored as alert", async () => (await query("SELECT id, severity, title FROM alerts WHERE tenant_id = $1 AND id = $2", [tenantId, alertId])).rows[0],
    (r) => (r ? `${r.id} [${r.severity}] ${String(r.title).slice(0, 60)}` : "missing"));
  if (!wz) throw new Error("alert not found in tenant");

  const sd = await trace.step("Sentinel", "threat_detection", () => invoke(agents.Sentinel, "threat_detection", { eventIds: [alertId] }),
    (o) => `${o.findings?.length ?? 0} finding(s); top patterns ${JSON.stringify(o.findings?.[0]?.patterns ?? [])}`);
  const sf = sd.findings?.[0];

  const hunt = await trace.step("Hunter", "attack_investigation", () => invoke(agents.Hunter, "attack_investigation", { sourceIp }),
    (o) => `${o.eventsAnalyzed} event(s), ${o.chains?.length ?? 0} chain(s)`);

  const vul = await trace.step("Guardian", "vulnerability_analysis", () => invoke(agents.Guardian, "vulnerability_analysis", { asset }),
    (o) => `${o.findings?.length ?? 0} vulnerability finding(s); evidence ${o.evidence}`);
  const exp = await trace.step("Guardian", "exposure_review", () => invoke(agents.Guardian, "exposure_review", {}),
    (o) => `${o.assets?.length ?? 0} asset(s) ranked`);

  const oracle = await trace.step("Oracle", "alert_analysis", () => invoke(agents.Oracle, "alert_analysis", { alertId, includeRelated: true }),
    (o) => `severity ${o.alert?.severity}; ${String(o.summary).slice(0, 70)}`);

  const cand = await trace.step("Vanguard", "containment_candidates", () => invoke(agents.Vanguard, "containment_candidates", { minEvents: 3 }),
    (o) => `${o.candidates?.length ?? 0} candidate(s); cannot-block ${o.cannotBlock?.length ?? 0}`);

  // Reconcile: when agents disagree the HIGHER risk wins, and the disagreement is recorded.
  const chainsN = hunt.chains?.length ?? 0;
  const huntRisk: keyof typeof RANK = chainsN > 0 && (hunt.eventsAnalyzed ?? 0) >= 5 ? "high" : (hunt.eventsAnalyzed ?? 0) >= 3 ? "medium" : "low";
  const oracleRisk = (oracle.alert?.severity ?? "low") as keyof typeof RANK;
  const sentRisk: keyof typeof RANK = (sf?.score ?? 0) >= 70 ? "high" : (sf?.score ?? 0) >= 40 ? "medium" : "low";
  const risks = [oracleRisk, huntRisk, sentRisk];
  const risk = risks.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
  const reasons: string[] = [];
  if (new Set(risks).size > 1) reasons.push(`oracle=${oracleRisk} hunter=${huntRisk} sentinel=${sentRisk}`);
  const conflict = { detected: reasons.length > 0, reasons };

  const candidate = (cand.candidates ?? []).find((c: { ip: string }) => c.ip === sourceIp) ?? null;
  let action: ActionRequest | null = null;
  if (candidate && RANK[risk] >= RANK.high) {
    action = await trace.step("Vanguard", "propose ip.block", async () => (await proposeAction(tenantId, {
      action_id: "ip.block", input: { ip: sourceIp, minutes: 60, reason: `SOC investigation of ${alertId}` },
      actor: { kind: "agent", agent: "Vanguard" }, origin: opts.origin ?? "agent", mode: opts.mode ?? "simulation",
      idempotency_key: opts.key ?? `inv:${alertId}:${sourceIp}`,
    })).action, (a) => `${a.status} (policy ${a.policy_decision}, ${a.execution_mode})`);
  }
  return {
    alertId, trace, sentinel: { patterns: sf?.patterns ?? [], score: sf?.score ?? 0 },
    hunter: { chains: chainsN, stages: (hunt.chains ?? []).flatMap((c: { stages?: string[] }) => c.stages ?? []), events: hunt.eventsAnalyzed ?? 0 },
    guardian: { findings: vul.findings?.length ?? 0, exposure: JSON.stringify(exp.assets?.[0]?.exposure ?? "unknown") },
    oracle: { severity: oracleRisk, summary: String(oracle.summary ?? "") },
    conflict, risk, candidate: candidate ? { ip: candidate.ip, score: candidate.score, reasons: candidate.reasons ?? [] } : null, action,
  };
}

/** Verifies an action's outcome the way an operator would; records the verification in the trace. */
export async function verify(trace: Trace, tenantId: string, actionId: string, ip: string) {
  return trace.step("Legion", "verify result", async () => {
    const a = (await query("SELECT status, result, approval_id, policy_decision FROM action_requests WHERE tenant_id = $1 AND id = $2", [tenantId, actionId])).rows[0];
    const blocks = (await query("SELECT count(*)::int AS n FROM ip_blocks WHERE tenant_id = $1 AND ip = $2", [tenantId, ip])).rows[0].n as number;
    const events = (await query("SELECT to_status FROM action_events WHERE tenant_id = $1 AND action_id = $2 ORDER BY seq", [tenantId, actionId])).rows.map((r) => r.to_status as string);
    const chain = await verifyAuditChain(tenantId);
    return { status: a.status as string, result: a.result as Record<string, any> | null, approval: a.approval_id as string | null, events, blocks, chain };
  }, (v) => `status ${v.status}; real blocks ${v.blocks}; transitions ${v.events.join(">")}; audit chain ${v.chain.ok ? "valid" : "BROKEN"} (${v.chain.events})`);
}

export async function auditEventsOf(tenantId: string) {
  return (await query("SELECT seq, category, event FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq", [tenantId])).rows as Array<{ seq: string; category: string; event: string }>;
}
