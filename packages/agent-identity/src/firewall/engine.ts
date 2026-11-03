import { randomUUID } from "node:crypto";
import dns from "node:dns";
import { constants as fsc, promises as fs } from "node:fs";
import https from "node:https";
import type { LookupFunction } from "node:net";
import path from "node:path";
import type { Request } from "express";
import type { Pool } from "pg";
import { effectivePermissions, isPermission, type Permission } from "../permissions.js";
import { identityBlockReason } from "../principal.js";
import type { IdentityStore } from "../store.js";
import { isMachine, type HostAdapter, type MachinePrincipal } from "../types.js";
import type { DelegationStore } from "./delegations.js";
import { isNonPublicIp } from "./destinations.js";
import { DecisionLog } from "./log.js";
import type { PolicyStore, VersionedPolicy } from "./policy.js";
import { evaluateRules, scoreOf, type RuleInputs } from "./rules.js";
import { hashToolDefinition } from "./scan.js";
import { definitionTexts, scanToolDefinition } from "./tool-poisoning.js";
import type { Classification } from "../prompt-guard/types.js";
import type { PromptInjectionGuard } from "../prompt-guard/guard.js";
import type { BehaviorMonitor } from "../behavior/monitor.js";
import { findToolRequests, matchRecentRequests, type HiddenDelegationMatch } from "../a2a/hidden.js";
import type { InteractionLog, InteractionRow } from "../a2a/log.js";
import { analyzeToolCall } from "../tools/analyzers.js";
import type { ApprovalStore } from "./approvals.js";
import {
  DECISIONS,
  decisionRank,
  permits,
  refusingHits,
  type ActionRequest,
  type Advisor,
  type Authority,
  type FirewallContext,
  type FirewallDecision,
  type RelayedMessage,
  type RuleHit,
  type Sensitivity,
} from "./types.js";

/** Thrown for every decision that does not permit the action (CONFIRM, BLOCK, QUARANTINE, KILL). */
export class FirewallBlockedError extends Error {
  constructor(readonly decision: FirewallDecision) {
    super(`${decision.decision === "CONFIRM" ? "Needs a person's approval" : "Blocked by the agent firewall"}: ${refusingHits(decision).map((h) => h.id).join(", ") || "blocked"}`);
    this.name = "FirewallBlockedError";
  }
}

/**
 * Applies QUARANTINE / KILL: the kill switch, wired in by createAgentIdentity.
 * Awaited before the decision is returned, so the agent is stopped before it
 * hears the answer.
 */
export type ContainmentResponder = (ctx: FirewallContext, req: ActionRequest, d: FirewallDecision) => Promise<void>;

export interface FirewallOptions {
  pool: Pool;
  store: IdentityStore;
  host: HostAdapter;
  policies: PolicyStore;
  decisions: DecisionLog;
  delegations: DelegationStore;
  /** Optional second opinions (e.g. an LLM classifier). They can only make a decision stricter. */
  advisors?: Advisor[];
  advisorTimeoutMs?: number;
  /** Called after every WARN or BLOCK is logged — e.g. to raise a Legion alert. Errors are ignored. */
  onDecision?: (ctx: FirewallContext, req: ActionRequest, d: FirewallDecision) => void | Promise<void>;
  /** DNS resolver used by guardedRequest; every address it returns is checked. */
  dnsLookup?: (host: string) => Promise<{ address: string; family: number }[]>;
  /** Supplies prompt-injection history per agent, and classifies agent-to-agent payloads. */
  contentGuard?: PromptInjectionGuard;
  /** Runtime behaviour classification per agent. Set after construction (setBehaviorMonitor). */
  behavior?: BehaviorMonitor;
  /** The agent-to-agent interaction chain. Without it, interactions are not recorded. */
  interactions?: InteractionLog;
  /** People's approvals for CONFIRM decisions. Without it, CONFIRM is answered as BLOCK. */
  approvals?: ApprovalStore;
  log: (msg: string, err?: unknown) => void;
}

/** What a sent request is, as the sender and every later reader see it. */
export interface SentRequest {
  messageId: string;
  interactionId: string;
  parentMessageId: string | null;
  hop: number;
  sourceAgent: string;
  destinationAgent: string;
  tenantId: string;
  requestedAction: { permission: Permission; resource: { type: string; id: string } | null };
  authority: Authority;
  chain: string[];
  expiresAt: string;
}

const RELAYED_COLUMNS = `id, from_identity, to_identity, requested_permission, chain, interaction_id, parent_message_id, hop, authority,
  resource_type, resource_id, expires_at`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function relayedFromRow(r: any, permission: Permission): RelayedMessage {
  return {
    id: r.id,
    fromAgentId: r.from_identity,
    permission,
    chain: r.chain ?? [],
    interactionId: r.interaction_id ?? r.id,
    hop: r.hop ?? 1,
    // Rows written before authority was recorded ran on the sender's own grants.
    authority: r.authority ?? { kind: "agent", agentId: r.from_identity, ownerUserId: "" },
    resource: r.resource_type ? { type: r.resource_type, id: r.resource_id ?? "" } : null,
    expiresAt: new Date(r.expires_at).toISOString(),
  };
}

const HIDDEN_DELEGATION_SURFACES = new Set(["tool_call", "mcp_tool", "tool", "egress"]);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const resourceLabel = (r: { type: string; id?: string } | null | undefined) => (r ? `${r.type}:${r.id ?? ""}` : null);

export interface EgressResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  decisions: FirewallDecision[];
}

/** Sliding one-minute window of actions per identity (per instance). */
class Velocity {
  private readonly hits = new Map<string, number[]>();
  record(id: string): number {
    const now = Date.now();
    const list = (this.hits.get(id) ?? []).filter((t) => now - t < 60_000);
    list.push(now);
    this.hits.set(id, list);
    if (this.hits.size > 50_000) this.hits.clear();
    return list.length - 1; // actions before this one
  }
}

export class AgentFirewall {
  private readonly velocity = new Velocity();
  private readonly advisors: Advisor[];
  private readonly lookup: (host: string) => Promise<{ address: string; family: number }[]>;
  private responder: ContainmentResponder | null = null;

  constructor(private readonly o: FirewallOptions) {
    this.advisors = o.advisors ?? [];
    this.lookup = o.dnsLookup ?? ((h) => dns.promises.lookup(h, { all: true, verbatim: true }));
  }

  /**
   * THE chokepoint. Decides ALLOW / WARN / CONFIRM / BLOCK / QUARANTINE /
   * KILL deterministically, records the decision, applies containment, and
   * only then returns it. If the decision cannot be recorded, the answer is
   * BLOCK. Nothing an agent does can reach a sensitive action without
   * passing here first: every guard, executor and ticket starts with it.
   */
  async evaluate(ctx: FirewallContext, req: ActionRequest, extraHits: RuleHit[] = []): Promise<FirewallDecision> {
    const p = ctx.principal;
    const decisionId = randomUUID();

    let versioned: VersionedPolicy;
    try {
      versioned = await this.o.policies.get(p.tenantId);
    } catch (err) {
      this.o.log("firewall policy unavailable; blocking", err);
      return this.failClosed(decisionId, req, "firewall.policy_unavailable", "The firewall policy could not be loaded.");
    }
    const { policy, version } = versioned;

    let inputs: RuleInputs;
    try {
      inputs = {
        principal: p,
        req,
        policy,
        delegation: await this.resolveDelegation(ctx, req),
        recipient: req.surface === "agent_message" ? await this.resolveRecipient(p, req.toAgentId) : undefined,
        viaMessage: ctx.viaMessage ? await this.resolveViaMessage(p, ctx) : undefined,
        a2a: req.surface === "agent_message" ? await this.resolveA2a(ctx, req, policy) : undefined,
        hiddenDelegation: await this.hiddenDelegation(ctx, req, policy.agentMessages.influenceWindowSeconds),
        chain: ctx.chain ?? [],
        actionsLastMinute: this.velocity.record(p.id),
        contentRisk: await this.contentRisk(p, policy.promptInjection.suspiciousWindowSeconds, policy.promptInjection.untrustedHoldSeconds),
        payloadClassification: req.surface === "agent_message" ? this.classifyPayload(req.payload) : undefined,
        behavior: await this.behaviorState(p),
        live: await this.liveIdentity(p),
      };
    } catch (err) {
      this.o.log("firewall could not look up facts; blocking", err);
      return this.failClosed(decisionId, req, "firewall.lookup_failed", "Facts needed for the decision could not be read.");
    }

    const out = evaluateRules(inputs);
    const hits = [...out.hits, ...extraHits];
    const score = scoreOf(out.factors);
    const responses = policy.responses;
    // Refusals that say something about the agent itself also contain it.
    const kill = new Set(responses.killOn);
    const quarantine = new Set(responses.quarantineOn);
    for (let i = 0; i < hits.length; i++) {
      const h = hits[i]!;
      if (h.effect !== "BLOCK") continue;
      if (kill.has(h.id)) hits[i] = { ...h, effect: "KILL" };
      else if (quarantine.has(h.id)) hits[i] = { ...h, effect: "QUARANTINE" };
    }
    const confirmAt = responses.confirm.riskAt;
    if (score >= policy.thresholds.blockAt) {
      hits.push({ id: "risk.score_block", effect: "BLOCK", hard: false, reason: `Risk score ${score} ≥ ${policy.thresholds.blockAt}.` });
    } else if (score >= confirmAt) {
      hits.push({ id: "risk.score_confirm", effect: "CONFIRM", hard: false, reason: `Risk score ${score} ≥ ${confirmAt}: a person must approve this action.` });
    } else if (score >= policy.thresholds.warnAt) {
      hits.push({ id: "risk.score_warn", effect: "WARN", hard: false, reason: `Risk score ${score} ≥ ${policy.thresholds.warnAt}.` });
    }
    // Permissions the organisation wants a person to approve per use. Hard:
    // monitor mode does not waive it. A message to another agent is not the
    // action itself — the recipient meets this rule when it acts.
    if (req.surface !== "agent_message" && out.permission && responses.confirm.permissions.includes(out.permission)) {
      hits.push({ id: "confirm.permission", effect: "CONFIRM", hard: true, reason: `Using ${out.permission} needs a person's approval for each action.` });
    }

    const d: FirewallDecision = {
      decisionId,
      decision: "ALLOW",
      wouldBlock: false,
      mode: policy.mode,
      riskScore: score,
      riskFactors: out.factors,
      hits,
      policyVersion: version,
      destination: out.destination,
      sensitivity: out.sensitivity,
      delegation: inputs.delegation.state === "valid" ? { userId: inputs.delegation.userId, grantId: inputs.delegation.grantId } : null,
      advisor: [],
    };
    this.compose(d);

    // Advisors run last and can only escalate. A crashed, slow or "allow"-
    // saying advisor never changes a deterministic decision.
    if (decisionRank(d.decision) < decisionRank("BLOCK")) {
      for (const a of this.advisors) {
        let verdict: "WARN" | "BLOCK" | null = null;
        let error: string | undefined;
        try {
          verdict = await Promise.race([
            a.review(ctx, req, d),
            new Promise<null>((_, rej) => setTimeout(() => rej(new Error("timeout")), this.o.advisorTimeoutMs ?? 2_000).unref()),
          ]);
          if (verdict !== "WARN" && verdict !== "BLOCK") verdict = null;
        } catch (err) {
          error = err instanceof Error ? err.message : String(err);
        }
        d.advisor.push({ name: a.name, verdict, ...(error ? { error } : {}) });
        if (verdict) {
          d.hits.push({ id: `advisor.${a.name}`, effect: verdict, hard: false, reason: `Advisor ${a.name} flagged this action.` });
          this.compose(d);
        }
      }
    }

    // CONFIRM: a person's approval of this exact action, or a request for one.
    if (d.decision === "CONFIRM") {
      try {
        await this.resolveConfirmation(ctx, req, d, policy);
      } catch (err) {
        this.o.log("approval lookup failed; blocking", err);
        return this.failClosed(decisionId, req, "approval.unavailable", "The approval could not be checked.", d);
      }
    }

    try {
      await this.o.decisions.record(DecisionLog.build(ctx, req, d, out.permission));
    } catch (err) {
      this.o.log("firewall decision could not be recorded; blocking", err);
      if (d.approval?.status === "pending") await this.o.approvals?.cancel(p.tenantId, d.approval.id).catch(() => {});
      return this.failClosed(decisionId, req, "firewall.log_unavailable", "The decision could not be recorded.", d);
    }

    // Acting on another agent's request (or refusing hidden delegation) is
    // part of the interaction chain. If it cannot be recorded, it does not happen.
    if (this.o.interactions && req.surface !== "agent_message" && (ctx.viaMessage || inputs.hiddenDelegation?.length)) {
      try {
        await this.recordAction(ctx, req, d, inputs.hiddenDelegation ?? []);
      } catch (err) {
        this.o.log("agent interaction could not be recorded; blocking", err);
        if (permits(d)) return this.failClosed(decisionId, req, "a2a.log_unavailable", "The agent interaction could not be recorded.", d);
      }
    }

    // A poisoned tool description has already been read by the model that
    // asked to call the tool: record it against the agent as malicious
    // external content, so it is held from unsafe actions until reviewed.
    await this.recordPoisonedDefinition(ctx, req, d);

    // QUARANTINE / KILL: the agent is stopped before it hears the answer.
    if (d.decision === "QUARANTINE" || d.decision === "KILL") {
      const action = d.decision === "KILL" ? "kill" as const : "quarantine" as const;
      if (!this.responder) {
        d.response = { action, applied: false, error: "no kill switch is configured" };
        this.o.log(`firewall decided ${d.decision} for ${p.id} but no kill switch is configured`);
      } else {
        try {
          await this.responder(ctx, req, d);
          d.response = { action, applied: true };
        } catch (err) {
          d.response = { action, applied: false, error: err instanceof Error ? err.message : String(err) };
          this.o.log(`containment (${action}) failed for ${p.id}`, err);
        }
      }
    }

    if (d.decision !== "ALLOW" && this.o.onDecision) {
      Promise.resolve(this.o.onDecision(ctx, req, d)).catch((err) => this.o.log("onDecision hook failed", err));
    }
    return d;
  }

  private async recordAction(ctx: FirewallContext, req: ActionRequest, d: FirewallDecision, hidden: HiddenDelegationMatch[]) {
    const p = ctx.principal;
    const ruleIds = d.hits.map((h) => h.id);
    const via = ctx.viaMessage;
    if (via) {
      await this.o.interactions!.record({
        tenantId: p.tenantId, kind: permits(d) ? "acted" : "act_blocked", interactionId: via.interactionId,
        messageId: via.id, parentMessageId: null, hop: via.hop, sourceAgent: via.fromAgentId, destinationAgent: p.id, actorId: p.id,
        action: req.action, requestedPermission: via.permission, resource: resourceLabel(req.resource),
        authority: via.authority, agentChain: ctx.chain ?? [], decision: d.decision, decisionId: d.decisionId, ruleIds,
      });
    }
    if (ruleIds.includes("a2a.hidden_tool_delegation")) {
      for (const h of hidden.filter((x) => x.permission !== req.permission)) {
        await this.o.interactions!.record({
          tenantId: p.tenantId, kind: "hidden_delegation_blocked", interactionId: h.interactionId, messageId: h.messageId,
          parentMessageId: null, hop: h.hop, sourceAgent: h.fromAgentId, destinationAgent: p.id, actorId: p.id,
          action: req.action, requestedPermission: h.permission, resource: resourceLabel(req.resource) ?? `matched:${h.matched}`,
          authority: h.authority, agentChain: [h.fromAgentId], decision: d.decision, decisionId: d.decisionId, ruleIds,
        });
      }
    }
  }

  /**
   * The strictest effect wins. Monitor mode observes: soft refusals are
   * logged as WARN (wouldBlock), and containment (QUARANTINE / KILL) is not
   * taken — hard rules still refuse, as BLOCK. Hard CONFIRM still asks.
   */
  private compose(d: FirewallDecision): void {
    const rank = decisionRank;
    let hard = 0;
    let soft = 0;
    for (const h of d.hits) {
      if (h.hard) hard = Math.max(hard, rank(h.effect));
      else soft = Math.max(soft, rank(h.effect));
    }
    d.wouldBlock = false;
    if (d.mode === "monitor") {
      hard = Math.min(hard, rank("BLOCK"));
      if (soft > rank("WARN")) {
        soft = rank("WARN");
        d.wouldBlock = true;
      }
    }
    d.decision = DECISIONS[Math.max(hard, soft)] ?? "BLOCK";
  }

  /**
   * A CONFIRM decision either uses the person's approval the agent cites
   * (x-legion-approval-id) — which turns the CONFIRM rules into visible
   * warnings and nothing else — or opens a request for one. An approval that
   * is for another action, another agent, already used or expired is not a
   * softer "no": it is refused outright.
   */
  private async resolveConfirmation(ctx: FirewallContext, req: ActionRequest, d: FirewallDecision, policy: VersionedPolicy["policy"]): Promise<void> {
    const satisfy = (note: string) => {
      d.hits = d.hits.map((h) => (h.effect === "CONFIRM" ? { ...h, effect: "WARN" as const, reason: `${h.reason} ${note}` } : h));
      this.compose(d);
    };
    // Inside an execution a consumed approval already covers (set by Legion's
    // own executors, never from a request): the nested checks of the same action.
    if (ctx.confirmed) {
      satisfy(`Covered by approval ${ctx.confirmed.approvalId}.`);
      return;
    }
    if (!this.o.approvals) {
      d.hits.push({ id: "approval.unavailable", effect: "BLOCK", hard: true, reason: "This action needs a person's approval and approvals are not configured." });
      this.compose(d);
      return;
    }
    if (ctx.approvalId !== undefined) {
      const r = await this.o.approvals.consume(ctx, req, ctx.approvalId, d.decisionId);
      if (r.ok) {
        d.approval = { id: r.row.id, status: "consumed", expiresAt: r.row.expiresAt, approvedBy: r.row.decidedBy ?? undefined };
        satisfy(`Approved by ${r.row.decidedBy} (approval ${r.row.id}).`);
        return;
      }
      if (r.reason === "pending") {
        d.approval = { id: r.row.id, status: "pending", expiresAt: r.row.expiresAt };
        return;
      }
      d.hits.push(r.reason === "denied"
        ? { id: "approval.denied", effect: "BLOCK", hard: true, reason: "A person refused this action." }
        : { id: "approval.invalid", effect: "BLOCK", hard: true, reason: "The cited approval is not an unused, unexpired approval of this exact action by this agent." });
      this.compose(d);
      return;
    }
    const created = await this.o.approvals.request(ctx, req, {
      decisionId: d.decisionId, riskScore: d.riskScore, ruleIds: refusingHits(d).map((h) => h.id),
    }, { ttlSeconds: policy.responses.confirm.ttlSeconds, maxPending: policy.responses.confirm.maxPendingPerAgent });
    if ("tooMany" in created) {
      d.hits.push({ id: "approval.too_many_pending", effect: "BLOCK", hard: true, reason: "This agent already has too many actions waiting for approval." });
      this.compose(d);
      return;
    }
    d.approval = { id: created.row.id, status: "pending", expiresAt: created.row.expiresAt };
    d.hits.push({
      id: "approval.required", effect: "CONFIRM", hard: true,
      reason: `A person must approve this action (approval ${created.row.id}); then retry it unchanged with x-legion-approval-id.`,
    });
  }

  private async recordPoisonedDefinition(ctx: FirewallContext, req: ActionRequest, d: FirewallDecision): Promise<void> {
    if (!this.o.contentGuard || !d.hits.some((h) => h.id === "mcp.poisoned_definition" || h.id === "mcp.suspicious_definition")) return;
    const def = req.surface === "mcp_tool" ? req.definition
      : req.surface === "tool_call" ? (req.call as { definition?: { name: string; description?: string; inputSchema?: unknown } } | null)?.definition
      : undefined;
    if (!def || typeof def.name !== "string") return;
    const report = scanToolDefinition(def);
    const content = definitionTexts(def).join("\n").slice(0, 100_000);
    const classification: Classification = {
      verdict: report.verdict, riskScore: report.score, sanitized: content, removedChars: 0,
      findings: report.findings.map((f) => ({ category: "action_directive" as const, id: f.id, points: f.points, detail: "tool description", excerpt: f.excerpt })),
    };
    await this.o.contentGuard.recordIfFlagged(
      { tenantId: ctx.principal.tenantId, principal: ctx.principal, requestId: ctx.requestId },
      "other", content, { sourceId: `tool-definition:${def.name}`.slice(0, 200) }, classification,
    ).catch((err) => this.o.log("poisoned tool definition could not be recorded against the agent", err));
  }

  /** Wires QUARANTINE / KILL to the kill switch (set after construction; they depend on each other). */
  setResponder(r: ContainmentResponder): void {
    this.responder = r;
  }

  private failClosed(decisionId: string, req: ActionRequest, id: string, reason: string, base?: FirewallDecision): FirewallDecision {
    return {
      ...(base ?? {
        mode: "enforce" as const,
        riskScore: 100,
        riskFactors: [],
        policyVersion: -1,
        destination: null,
        sensitivity: (req.sensitivity ?? "internal") as Sensitivity,
        delegation: null,
        advisor: [],
      }),
      decisionId,
      decision: "BLOCK",
      wouldBlock: false,
      hits: [...(base?.hits ?? []), { id, effect: "BLOCK", hard: true, reason }],
    };
  }

  /**
   * An optional enrichment: if the lookup fails, the decision is still made
   * on every other rule and carries a visible WARN, rather than taking every
   * agent offline because of this one signal.
   */
  private async contentRisk(p: MachinePrincipal, windowSeconds: number, holdSeconds: number): Promise<RuleInputs["contentRisk"]> {
    if (!this.o.contentGuard) return undefined;
    try {
      return await this.o.contentGuard.summary(p.tenantId, p.id, windowSeconds, holdSeconds);
    } catch (err) {
      this.o.log("prompt-injection history unavailable", err);
      return "unavailable";
    }
  }

  /**
   * Not an enrichment: a status that cannot be read is a failed lookup, and
   * the decision fails closed. This is what makes a suspension take effect
   * for callers that hold a principal resolved before it.
   */
  private async liveIdentity(p: MachinePrincipal): Promise<RuleInputs["live"]> {
    if (p.type !== "ai_agent" && p.type !== "service_account") return undefined;
    if (!/^[0-9a-f-]{36}$/i.test(p.id)) return null;
    const r = (await this.o.pool.query(
      `SELECT status, risk_level, (expires_at IS NOT NULL AND expires_at <= now()) AS expired
         FROM machine_identities WHERE id = $1 AND tenant_id = $2`,
      [p.id, p.tenantId],
    )).rows[0];
    return r ? { status: r.status, riskLevel: r.risk_level, expired: r.expired } : null;
  }

  setBehaviorMonitor(m: BehaviorMonitor): void {
    this.o.behavior = m;
  }

  /** Like content risk: an enrichment. If it cannot be assessed, decide on everything else and WARN. */
  private async behaviorState(p: MachinePrincipal): Promise<RuleInputs["behavior"]> {
    if (!this.o.behavior) return undefined;
    try {
      return await this.o.behavior.stateFor(p);
    } catch (err) {
      this.o.log("behaviour assessment unavailable", err);
      return "unavailable";
    }
  }

  private classifyPayload(payload: unknown): RuleInputs["payloadClassification"] {
    if (!this.o.contentGuard || payload === undefined || payload === null) return undefined;
    const c = this.o.contentGuard.classify({ source: "agent_message", content: typeof payload === "string" ? payload : JSON.stringify(payload) });
    return { verdict: c.verdict, riskScore: c.riskScore, findingIds: c.findings.map((f) => f.id) };
  }

  private async resolveDelegation(ctx: FirewallContext, req: ActionRequest): Promise<RuleInputs["delegation"]> {
    const p = ctx.principal;
    // On a relayed request, the authority is the request's: a person's grant
    // travels with it (checked again now — revoked or expired means void);
    // the agent cannot swap in its own.
    const inherited = ctx.viaMessage?.authority;
    if (inherited?.kind === "delegation") {
      const user = await this.o.host.getUser(p.tenantId, inherited.userId);
      if (!user || user.status !== "active" || user.tenantId !== p.tenantId) {
        return { state: "invalid", userId: inherited.userId, reason: "the person whose authority this request carries is no longer an active user" };
      }
      const g = await this.o.delegations.activeById(p.tenantId, inherited.grantId);
      if (!g) return { state: "invalid", userId: inherited.userId, reason: "the delegation this request carries was revoked or has expired" };
      if (!g.redelegable) return { state: "invalid", userId: inherited.userId, reason: "the delegation this request carries cannot be passed on" };
      return { state: "valid", userId: inherited.userId, grantId: g.id, userRole: user.role, permissions: g.permissions, redelegable: true, inherited: true };
    }
    const userId = ctx.onBehalfOf;
    if (!userId) return { state: "none" };
    const user = await this.o.host.getUser(p.tenantId, userId);
    if (!user || user.status !== "active" || user.tenantId !== p.tenantId) {
      return { state: "invalid", userId, reason: "not an active user of this organisation" };
    }
    const grants = await this.o.delegations.active(p.tenantId, p.id, userId);
    if (!grants.length) return { state: "invalid", userId, reason: "no active delegation from this person to this agent" };
    const wanted = req.surface === "agent_message" ? req.requestedPermission : req.permission;
    const covers = grants.filter((g) => wanted && g.permissions.includes(wanted));
    const grant = (req.surface === "agent_message" ? covers.find((g) => g.redelegable) : undefined) ?? covers[0] ?? grants[0]!;
    return { state: "valid", userId, grantId: grant.id, userRole: user.role, permissions: grant.permissions, redelegable: grant.redelegable, inherited: false };
  }

  private async resolveRecipient(sender: MachinePrincipal, toAgentId: string): Promise<RuleInputs["recipient"]> {
    if (!/^[0-9a-f-]{36}$/i.test(toAgentId)) return { state: "missing" };
    const r = await this.o.store.get(sender.tenantId, "ai_agent", toAgentId);
    if (!r) {
      // An id from another organisation is answered exactly like an id that
      // does not exist. Anything else — a different rule id in the 403, or a
      // "cross-tenant" entry in the SENDER's own logs, which its administrators
      // read — would let one organisation probe which agent ids exist in others.
      // The platform operator still hears about it, without either tenant seeing.
      const elsewhere = await this.o.pool.query("SELECT 1 FROM machine_identities WHERE id = $1 AND tenant_id <> $2", [toAgentId, sender.tenantId]);
      if (elsewhere.rowCount) {
        console.warn(`agent-identity: agent ${sender.id} (tenant ${sender.tenantId}) addressed an agent id belonging to another tenant; answered as unknown.`);
      }
      return { state: "missing" };
    }
    const block = await identityBlockReason(r, this.o.host);
    if (block.reason !== null) return { state: "blocked", reason: block.reason };
    return { state: "ok", id: r.id, effectivePermissions: effectivePermissions(r.permissions, block.ownerRole) };
  }

  private async resolveViaMessage(p: MachinePrincipal, ctx: FirewallContext): Promise<RuleInputs["viaMessage"]> {
    const m = ctx.viaMessage!;
    const sender = await this.o.store.get(p.tenantId, "ai_agent", m.fromAgentId);
    const senderActive = !!sender && (await identityBlockReason(sender, this.o.host)).reason === null;
    // Every agent earlier in the chain must still be able to act: stopping
    // one voids everything downstream of it.
    const upstream = m.chain.filter((id) => id !== m.fromAgentId);
    let chainInactive: string[] = [];
    if (upstream.length) {
      const ok = upstream.filter((id) => UUID_RE.test(id));
      const res = ok.length
        ? await this.o.pool.query(
            `SELECT id::text FROM machine_identities WHERE tenant_id = $1 AND id = ANY($2::uuid[])
               AND status = 'active' AND (expires_at IS NULL OR expires_at > now())`,
            [p.tenantId, ok],
          )
        : { rows: [] };
      const active = new Set(res.rows.map((r: { id: string }) => r.id));
      chainInactive = upstream.filter((id) => !active.has(id));
    }
    const authorityMismatch = ctx.onBehalfOf !== undefined &&
      (m.authority.kind !== "delegation" || m.authority.userId !== ctx.onBehalfOf);
    return { id: m.id, fromAgentId: m.fromAgentId, permission: m.permission, senderActive, chainInactive, resource: m.resource, authorityMismatch };
  }

  private async resolveA2a(ctx: FirewallContext, req: ActionRequest, policy: VersionedPolicy["policy"]): Promise<RuleInputs["a2a"]> {
    if (req.surface !== "agent_message") return undefined;
    const via = ctx.viaMessage;
    let interactionMessages = 0;
    let fanOut = 0;
    if (via) {
      const r = await this.o.pool.query(
        `SELECT count(*) FILTER (WHERE interaction_id = $2)::int AS total, count(*) FILTER (WHERE parent_message_id = $3)::int AS fan
           FROM agent_messages WHERE tenant_id = $1 AND (interaction_id = $2 OR parent_message_id = $3)`,
        [ctx.principal.tenantId, via.interactionId, via.id],
      );
      interactionMessages = r.rows[0].total;
      fanOut = r.rows[0].fan;
    }
    const payloadTools = req.payload === undefined || req.payload === null
      ? []
      : findToolRequests(req.payload, req.requestedPermission, (call) => analyzeToolCall(call, { principal: ctx.principal, policy }).permission);
    return { interactionMessages, fanOut, payloadTools };
  }

  /** Requests this agent read recently whose content names what this call targets. */
  private async hiddenDelegation(ctx: FirewallContext, req: ActionRequest, windowSeconds: number): Promise<HiddenDelegationMatch[] | undefined> {
    if (ctx.viaMessage || !windowSeconds || !HIDDEN_DELEGATION_SURFACES.has(req.surface)) return undefined;
    const res = await this.o.pool.query(
      `SELECT ${RELAYED_COLUMNS}, payload FROM agent_messages
        WHERE tenant_id = $1 AND to_identity = $2 AND read_at > now() - make_interval(secs => $3)
        ORDER BY read_at DESC LIMIT 20`,
      [ctx.principal.tenantId, ctx.principal.id, windowSeconds],
    );
    const recent = res.rows.flatMap((r) => {
      const permission = asPermission(r.requested_permission);
      if (!permission) return [];
      const m = relayedFromRow(r, permission);
      const text = typeof r.payload === "string" ? r.payload : JSON.stringify(r.payload ?? "");
      return [{ id: m.id, fromAgentId: m.fromAgentId, permission, text, interactionId: m.interactionId, hop: m.hop, authority: m.authority }];
    });
    return matchRecentRequests(req, recent);
  }

  /** Evaluate, then run `fn` only if the firewall did not block. */
  async execute<T>(ctx: FirewallContext, req: ActionRequest, fn: (d: FirewallDecision) => Promise<T>): Promise<T> {
    const d = await this.evaluate(ctx, req);
    if (!permits(d)) throw new FirewallBlockedError(d);
    return fn(d);
  }

  // ---- Executors: the safe way to reach each surface ------------------------

  /**
   * Reads a file inside the policy's roots. Symlinks are resolved and the
   * real path is evaluated again, so a link cannot lead outside the roots.
   */
  async readFile(ctx: FirewallContext, filePath: string, opts: { action?: string; permission?: Permission | null; maxBytes?: number } = {}): Promise<Buffer> {
    const base = { surface: "file" as const, action: opts.action ?? "files:read", permission: opts.permission ?? null, mode: "read" as const };
    await this.mustAllow(ctx, { ...base, path: filePath });
    const real = await fs.realpath(filePath);
    if (real !== path.resolve(filePath)) await this.mustAllow(ctx, { ...base, path: real });
    const handle = await fs.open(real, fsc.O_RDONLY | fsc.O_NOFOLLOW);
    try {
      const { size } = await handle.stat();
      const max = opts.maxBytes ?? 5 * 1024 * 1024;
      if (size > max) throw new Error(`File is ${size} bytes; the limit is ${max}.`);
      return await handle.readFile();
    } finally {
      await handle.close();
    }
  }

  /** Writes a file inside a read-write root. Never follows a symlink at the target. */
  async writeFile(ctx: FirewallContext, filePath: string, data: string | Buffer, opts: { action?: string; permission?: Permission | null } = {}): Promise<void> {
    const base = { surface: "file" as const, action: opts.action ?? "files:write", permission: opts.permission ?? null, mode: "write" as const };
    await this.mustAllow(ctx, { ...base, path: filePath });
    const target = path.join(await fs.realpath(path.dirname(path.resolve(filePath))), path.basename(filePath));
    if (target !== path.resolve(filePath)) await this.mustAllow(ctx, { ...base, path: target });
    let handle;
    try {
      handle = await fs.open(target, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_TRUNC | fsc.O_NOFOLLOW, 0o640);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ELOOP") {
        const d = await this.evaluate(ctx, { ...base, path: target }, [
          { id: "file.symlink_target", effect: "BLOCK", hard: true, reason: "The target is a symbolic link." },
        ]);
        throw new FirewallBlockedError(d);
      }
      throw err;
    }
    try {
      await handle.writeFile(data);
    } finally {
      await handle.close();
    }
  }

  /**
   * HTTPS request to an external destination. The URL, method and body are
   * evaluated first; then every address DNS returns is checked at connect
   * time (so a name that resolves to an internal address — DNS rebinding —
   * is refused); redirects are followed by hand, each hop evaluated again.
   */
  async request(
    ctx: FirewallContext,
    spec: {
      url: string;
      method?: string;
      headers?: Record<string, string>;
      body?: string;
      action?: string;
      permission?: Permission | null;
      sensitivity?: Sensitivity;
      maxRedirects?: number;
      maxResponseBytes?: number;
      timeoutMs?: number;
      /** Aborts the request in flight (the kill switch uses this). */
      signal?: AbortSignal;
    },
  ): Promise<EgressResponse> {
    const decisions: FirewallDecision[] = [];
    let url = spec.url;
    let method = (spec.method ?? "GET").toUpperCase();
    let body = spec.body;
    for (let hop = 0; ; hop++) {
      const req = {
        surface: "egress" as const,
        action: spec.action ?? "egress:request",
        permission: spec.permission ?? null,
        sensitivity: spec.sensitivity,
        url,
        method,
        payload: { headers: spec.headers ?? {}, body },
      };
      spec.signal?.throwIfAborted();
      const d = await this.evaluate(ctx, req);
      decisions.push(d);
      if (!permits(d)) throw new FirewallBlockedError(d);

      let res: { status: number; headers: EgressResponse["headers"]; body: Buffer };
      try {
        res = await this.send(url, method, spec.headers ?? {}, body, spec.maxResponseBytes ?? 5 * 1024 * 1024, spec.timeoutMs ?? 10_000, spec.signal);
      } catch (err) {
        if ((err as { code?: string }).code === "EFIREWALL") {
          const blocked = await this.evaluate(ctx, req, [
            { id: "egress.resolved_internal", effect: "BLOCK", hard: true, reason: (err as Error).message },
          ]);
          decisions.push(blocked);
          throw new FirewallBlockedError(blocked);
        }
        throw err;
      }

      const location = res.headers.location;
      if (res.status >= 300 && res.status < 400 && typeof location === "string" && hop < (spec.maxRedirects ?? 3)) {
        url = new URL(location, url).href;
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
          method = "GET";
          body = undefined;
        }
        continue;
      }
      return { ...res, decisions };
    }
  }

  private send(url: string, method: string, headers: Record<string, string>, body: string | undefined, maxBytes: number, timeoutMs: number, signal?: AbortSignal) {
    const lookup: LookupFunction = (hostname, options, callback) => {
      this.lookup(hostname).then(
        (addrs) => {
          const bad = addrs.filter((a) => isNonPublicIp({ address: a.address, family: a.family === 6 ? "ipv6" : "ipv4" }));
          if (!addrs.length || bad.length) {
            const err = Object.assign(
              new Error(`${hostname} resolves to an internal or reserved address (${bad.map((b) => b.address).join(", ") || "none"})`),
              { code: "EFIREWALL" },
            );
            return (callback as (e: Error) => void)(err);
          }
          if ((options as { all?: boolean }).all) (callback as (e: null, a: typeof addrs) => void)(null, addrs);
          else (callback as (e: null, a: string, f: number) => void)(null, addrs[0]!.address, addrs[0]!.family);
        },
        (err) => (callback as (e: Error) => void)(err),
      );
    };

    return new Promise<{ status: number; headers: EgressResponse["headers"]; body: Buffer }>((resolve, reject) => {
      const r = https.request(url, { method, headers, lookup, timeout: timeoutMs, agent: false, signal }, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > maxBytes) {
            r.destroy(new Error(`Response exceeds ${maxBytes} bytes.`));
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on("error", reject);
      });
      r.on("timeout", () => r.destroy(new Error("Request timed out.")));
      r.on("error", reject);
      if (body !== undefined) r.write(body);
      r.end();
    });
  }

  /** Evaluate an MCP tool call. The definition hash is computed here, not trusted from the caller. */
  async callMcpTool<T>(
    ctx: FirewallContext,
    call: { server: string; definition: { name: string; description?: string; inputSchema?: unknown }; args: Record<string, unknown>; sensitivity?: Sensitivity },
    fn: (d: FirewallDecision) => Promise<T>,
  ): Promise<T> {
    return this.execute(ctx, {
      surface: "mcp_tool",
      action: `mcp:${call.server}/${call.definition.name}`,
      permission: null,
      server: call.server,
      tool: call.definition.name,
      definitionSha256: hashToolDefinition(call.definition),
      definition: call.definition,
      args: call.args,
      sensitivity: call.sensitivity,
    }, fn);
  }

  /**
   * Builds the firewall context for an HTTP request from a machine principal.
   * `x-legion-on-behalf-of` names a person (verified against a delegation
   * grant during evaluation). `x-legion-message-id` names a relayed message;
   * it must exist, be addressed to this agent and be unexpired, and the chain
   * comes from that stored message — never from a header.
   */
  async contextFromRequest(req: Request): Promise<{ ctx: FirewallContext; extraHits: RuleHit[] }> {
    const p = req.principal;
    if (!isMachine(p)) throw new Error("contextFromRequest needs a machine principal");
    const ctx: FirewallContext = { principal: p, requestId: req.requestId, ip: req.ip };
    const extraHits: RuleHit[] = [];

    const onBehalfOf = req.get("x-legion-on-behalf-of");
    if (onBehalfOf !== undefined) {
      if (/^[^\s]{1,200}$/.test(onBehalfOf)) ctx.onBehalfOf = onBehalfOf;
      else extraHits.push({ id: "delegation.malformed", effect: "BLOCK", hard: true, reason: "Malformed x-legion-on-behalf-of." });
    }

    // A person's approval of this action (CONFIRM). Only its id travels in
    // the header; what it approves is checked against the stored request.
    const approvalId = req.get("x-legion-approval-id");
    if (approvalId !== undefined) {
      if (UUID_RE.test(approvalId)) ctx.approvalId = approvalId;
      else extraHits.push({ id: "approval.malformed", effect: "BLOCK", hard: true, reason: "Malformed x-legion-approval-id." });
    }

    const messageId = req.get("x-legion-message-id");
    if (messageId !== undefined) {
      const m = /^[0-9a-f-]{36}$/i.test(messageId)
        ? (await this.o.pool.query(
            `SELECT ${RELAYED_COLUMNS} FROM agent_messages
              WHERE id = $1 AND tenant_id = $2 AND to_identity = $3 AND expires_at > now() AND withdrawn_at IS NULL`,
            [messageId, p.tenantId, p.id],
          )).rows[0]
        : undefined;
      const permission = asPermission(m?.requested_permission);
      if (!m || !permission) {
        extraHits.push({ id: "a2a.message_invalid", effect: "BLOCK", hard: true, reason: "No such unexpired message addressed to this agent." });
      } else {
        ctx.viaMessage = relayedFromRow(m, permission);
        ctx.chain = [...m.chain, m.from_identity];
      }
    }
    return { ctx, extraHits };
  }

  /** Agent-to-agent: evaluate, then store the message for the recipient. */
  async sendMessage(
    ctx: FirewallContext,
    msg: { toAgentId: string; requestedPermission: Permission; payload: unknown; resource?: { type: string; id: string }; tenantId?: string },
    extraHits: RuleHit[] = [],
  ): Promise<{ decision: FirewallDecision; messageId: string | null; request: SentRequest | null }> {
    const p = ctx.principal;
    let d = await this.evaluate(ctx, {
      surface: "agent_message",
      action: "agents:message",
      permission: null,
      toAgentId: msg.toAgentId,
      requestedPermission: msg.requestedPermission,
      requestResource: msg.resource,
      claimedTenantId: msg.tenantId,
      payload: msg.payload,
    }, extraHits);
    // An agent emitting injection-like payloads may itself be compromised:
    // record it against the sender, whether or not the message went out.
    // Only when flagged: this is what the agent WROTE, not something it read,
    // so a clean outgoing message must not put the sender on the
    // untrusted-content hold.
    if (this.o.contentGuard && msg.payload !== undefined && msg.payload !== null) {
      const content = typeof msg.payload === "string" ? msg.payload : JSON.stringify(msg.payload);
      const c = this.o.contentGuard.classify({ source: "agent_message", content });
      await this.o.contentGuard.recordIfFlagged(
        { tenantId: p.tenantId, principal: p, requestId: ctx.requestId },
        "agent_message", content, { sourceId: `to:${msg.toAgentId}` }, c,
      );
    }

    // Whose authority the request carries: the relayed request's (unchanged
    // down the chain), a person's re-delegable grant, or the sender's own.
    const via = ctx.viaMessage;
    const authority: Authority = via
      ? via.authority
      : d.delegation
        ? { kind: "delegation", userId: d.delegation.userId, grantId: d.delegation.grantId, agentId: p.id }
        : { kind: "agent", agentId: p.id, ownerUserId: p.ownerUserId };
    const step = {
      tenantId: p.tenantId, parentMessageId: via?.id ?? null, hop: (ctx.chain?.length ?? 0) + 1,
      sourceAgent: p.id, destinationAgent: msg.toAgentId.slice(0, 64), actorId: p.id, action: "agents:message",
      requestedPermission: msg.requestedPermission, resource: resourceLabel(msg.resource), authority,
      agentChain: ctx.chain ?? [], decisionId: d.decisionId, ruleIds: d.hits.map((h) => h.id),
    };

    if (!permits(d)) {
      await this.o.interactions?.record({ ...step, kind: "request_blocked", interactionId: via?.interactionId ?? null, messageId: null, decision: d.decision })
        .catch((err) => this.o.log("agent interaction write failed for a refused request", err));
      return { decision: d, messageId: null, request: null };
    }

    // Stored and recorded together: a request that is not in the
    // interaction chain is not delivered.
    const messageId = randomUUID();
    const interactionId = via?.interactionId ?? messageId;
    let expiresAt: string;
    const c = await this.o.pool.connect();
    try {
      await c.query("BEGIN");
      const res = await c.query(
        `INSERT INTO agent_messages (id, tenant_id, from_identity, to_identity, requested_permission, payload, chain, decision_id, expires_at,
                                     interaction_id, parent_message_id, hop, authority, resource_type, resource_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8, LEAST(now() + interval '1 hour', COALESCE($9::timestamptz, 'infinity')), $10,$11,$12,$13,$14,$15)
         RETURNING expires_at`,
        [messageId, p.tenantId, p.id, msg.toAgentId, msg.requestedPermission, JSON.stringify(msg.payload ?? null), ctx.chain ?? [],
          d.decisionId, via?.expiresAt ?? null, interactionId, via?.id ?? null, step.hop, JSON.stringify(authority),
          msg.resource?.type ?? null, msg.resource?.id ?? null],
      );
      expiresAt = new Date(res.rows[0].expires_at).toISOString();
      await this.o.interactions?.record({ ...step, kind: "request_sent", interactionId, messageId, decision: d.decision }, c);
      await c.query("COMMIT");
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      this.o.log("agent request could not be stored and recorded; not delivered", err);
      d = this.failClosed(d.decisionId, { surface: "agent_message", action: "agents:message", permission: null, toAgentId: msg.toAgentId, requestedPermission: msg.requestedPermission }, "a2a.log_unavailable", "The request could not be recorded.", d);
      return { decision: d, messageId: null, request: null };
    } finally {
      c.release();
    }
    const request: SentRequest = {
      messageId, interactionId, parentMessageId: via?.id ?? null, hop: step.hop, sourceAgent: p.id, destinationAgent: msg.toAgentId,
      tenantId: p.tenantId, requestedAction: { permission: msg.requestedPermission, resource: msg.resource ?? null },
      authority, chain: ctx.chain ?? [], expiresAt,
    };
    // A flagged payload that was still delivered (suspicious, or monitor
    // mode) is external content reaching the recipient: record it against
    // the recipient once, at delivery — not on every inbox read.
    if (this.o.contentGuard && msg.payload !== undefined && msg.payload !== null) {
      const content = typeof msg.payload === "string" ? msg.payload : JSON.stringify(msg.payload);
      const c = this.o.contentGuard.classify({ source: "agent_message", content });
      if (c.verdict !== "clean") {
        const r = await this.o.store.get(ctx.principal.tenantId, "ai_agent", msg.toAgentId);
        if (r) {
          const recipient: MachinePrincipal = {
            type: "ai_agent", id: r.id, tenantId: r.tenantId, displayName: r.name, ownerUserId: r.ownerUserId,
            permissions: [], riskLevel: r.riskLevel, credentialId: "", tokenId: "",
          };
          await this.o.contentGuard.recordIfFlagged(
            { tenantId: r.tenantId, principal: recipient, requestId: ctx.requestId }, "agent_message", content, { sourceId: messageId }, c,
          );
        }
      }
    }
    return { decision: d, messageId, request };
  }

  async inbox(p: MachinePrincipal) {
    // First read of each request is part of the interaction chain: from now
    // on, uncited tool use matching it is hidden delegation.
    const c = await this.o.pool.connect();
    try {
      await c.query("BEGIN");
      const fresh = await c.query(
        `UPDATE agent_messages SET read_at = now()
          WHERE tenant_id = $1 AND to_identity = $2 AND read_at IS NULL AND expires_at > now() AND withdrawn_at IS NULL
          RETURNING ${RELAYED_COLUMNS}`,
        [p.tenantId, p.id],
      );
      for (const r of fresh.rows) {
        const m = relayedFromRow(r, r.requested_permission);
        await this.o.interactions?.record({
          tenantId: p.tenantId, kind: "request_read", interactionId: m.interactionId, messageId: m.id, parentMessageId: r.parent_message_id,
          hop: m.hop, sourceAgent: m.fromAgentId, destinationAgent: p.id, actorId: p.id, action: "agents:read_request",
          requestedPermission: m.permission, resource: resourceLabel(m.resource), authority: m.authority,
          agentChain: m.chain, decision: "ALLOW", decisionId: null, ruleIds: [],
        }, c);
      }
      await c.query("COMMIT");
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
    const res = await this.o.pool.query(
      `SELECT ${RELAYED_COLUMNS}, payload, decision_id, created_at FROM agent_messages
        WHERE tenant_id = $1 AND to_identity = $2 AND expires_at > now() AND withdrawn_at IS NULL
        ORDER BY created_at DESC LIMIT 100`,
      [p.tenantId, p.id],
    );
    const out = [];
    for (const r of res.rows) {
      const content = typeof r.payload === "string" ? r.payload : JSON.stringify(r.payload);
      // Another agent's words are external content to this one: marked
      // untrusted, with their classification (recorded once, at delivery).
      const c = this.o.contentGuard?.classify({ source: "agent_message", content });
      const m = relayedFromRow(r, r.requested_permission);
      out.push({
        id: r.id,
        fromAgentId: r.from_identity,
        requestedPermission: r.requested_permission,
        // The five facts every request carries.
        source: m.fromAgentId,
        destination: p.id,
        tenantId: p.tenantId,
        requestedAction: { permission: m.permission, resource: m.resource },
        authority: m.authority,
        interactionId: m.interactionId,
        hop: m.hop,
        payload: r.payload,
        trust: "untrusted" as const,
        contentRisk: c ? { verdict: c.verdict, riskScore: c.riskScore, findings: c.findings.map((f) => f.id) } : null,
        chain: r.chain,
        decisionId: r.decision_id,
        createdAt: new Date(r.created_at).toISOString(),
        expiresAt: new Date(r.expires_at).toISOString(),
      });
    }
    return out;
  }

  private async mustAllow(ctx: FirewallContext, req: ActionRequest): Promise<FirewallDecision> {
    const d = await this.evaluate(ctx, req);
    if (!permits(d)) throw new FirewallBlockedError(d);
    return d;
  }
}

export function asPermission(v: unknown): Permission | null {
  return typeof v === "string" && isPermission(v) ? v : null;
}
