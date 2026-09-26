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
import type { PromptInjectionGuard } from "../prompt-guard/guard.js";
import type { BehaviorMonitor } from "../behavior/monitor.js";
import type {
  ActionRequest,
  Advisor,
  Decision,
  FirewallContext,
  FirewallDecision,
  RuleHit,
  Sensitivity,
} from "./types.js";

export class FirewallBlockedError extends Error {
  constructor(readonly decision: FirewallDecision) {
    super(`Blocked by the agent firewall: ${decision.hits.filter((h) => h.effect === "BLOCK").map((h) => h.id).join(", ") || "blocked"}`);
    this.name = "FirewallBlockedError";
  }
}

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
  log: (msg: string, err?: unknown) => void;
}

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

  constructor(private readonly o: FirewallOptions) {
    this.advisors = o.advisors ?? [];
    this.lookup = o.dnsLookup ?? ((h) => dns.promises.lookup(h, { all: true, verbatim: true }));
  }

  /**
   * THE chokepoint. Decides ALLOW / WARN / BLOCK deterministically, records
   * the decision, and only then returns it. If the decision cannot be
   * recorded, the answer is BLOCK.
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
        viaMessage: ctx.viaMessage ? await this.resolveViaMessage(p, ctx.viaMessage) : undefined,
        chain: ctx.chain ?? [],
        actionsLastMinute: this.velocity.record(p.id),
        contentRisk: await this.contentRisk(p, policy.promptInjection.suspiciousWindowSeconds),
        payloadClassification: req.surface === "agent_message" ? this.classifyPayload(req.payload) : undefined,
        behavior: await this.behaviorState(p),
      };
    } catch (err) {
      this.o.log("firewall could not look up facts; blocking", err);
      return this.failClosed(decisionId, req, "firewall.lookup_failed", "Facts needed for the decision could not be read.");
    }

    const out = evaluateRules(inputs);
    const hits = [...out.hits, ...extraHits];
    const score = scoreOf(out.factors);
    if (score >= policy.thresholds.blockAt) {
      hits.push({ id: "risk.score_block", effect: "BLOCK", hard: false, reason: `Risk score ${score} ≥ ${policy.thresholds.blockAt}.` });
    } else if (score >= policy.thresholds.warnAt) {
      hits.push({ id: "risk.score_warn", effect: "WARN", hard: false, reason: `Risk score ${score} ≥ ${policy.thresholds.warnAt}.` });
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
    if (d.decision !== "BLOCK") {
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

    try {
      await this.o.decisions.record(DecisionLog.build(ctx, req, d, out.permission));
    } catch (err) {
      this.o.log("firewall decision could not be recorded; blocking", err);
      return this.failClosed(decisionId, req, "firewall.log_unavailable", "The decision could not be recorded.", d);
    }

    if (d.decision !== "ALLOW" && this.o.onDecision) {
      Promise.resolve(this.o.onDecision(ctx, req, d)).catch((err) => this.o.log("onDecision hook failed", err));
    }
    return d;
  }

  private compose(d: FirewallDecision): void {
    const hard = d.hits.some((h) => h.hard && h.effect === "BLOCK");
    const soft = d.hits.some((h) => !h.hard && h.effect === "BLOCK");
    const warn = d.hits.some((h) => h.effect === "WARN");
    let decision: Decision = "ALLOW";
    d.wouldBlock = false;
    if (hard) decision = "BLOCK";
    else if (soft) {
      decision = d.mode === "monitor" ? "WARN" : "BLOCK";
      d.wouldBlock = d.mode === "monitor";
    } else if (warn) decision = "WARN";
    d.decision = decision;
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
  private async contentRisk(p: MachinePrincipal, windowSeconds: number): Promise<RuleInputs["contentRisk"]> {
    if (!this.o.contentGuard) return undefined;
    try {
      return await this.o.contentGuard.summary(p.tenantId, p.id, windowSeconds);
    } catch (err) {
      this.o.log("prompt-injection history unavailable", err);
      return "unavailable";
    }
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
    const userId = ctx.onBehalfOf;
    if (!userId) return { state: "none" };
    const p = ctx.principal;
    const user = await this.o.host.getUser(p.tenantId, userId);
    if (!user || user.status !== "active" || user.tenantId !== p.tenantId) {
      return { state: "invalid", userId, reason: "not an active user of this organisation" };
    }
    const grants = await this.o.delegations.active(p.tenantId, p.id, userId);
    if (!grants.length) return { state: "invalid", userId, reason: "no active delegation from this person to this agent" };
    const wanted = req.permission;
    const grant = grants.find((g) => wanted && g.permissions.includes(wanted)) ?? grants[0]!;
    return { state: "valid", userId, grantId: grant.id, userRole: user.role, permissions: grant.permissions };
  }

  private async resolveRecipient(sender: MachinePrincipal, toAgentId: string): Promise<RuleInputs["recipient"]> {
    if (!/^[0-9a-f-]{36}$/i.test(toAgentId)) return { state: "missing" };
    const r = await this.o.store.get(sender.tenantId, "ai_agent", toAgentId);
    if (!r) return { state: "missing" };
    const block = await identityBlockReason(r, this.o.host);
    if (block.reason !== null) return { state: "blocked", reason: block.reason };
    return { state: "ok", id: r.id, effectivePermissions: effectivePermissions(r.permissions, block.ownerRole) };
  }

  private async resolveViaMessage(p: MachinePrincipal, m: NonNullable<FirewallContext["viaMessage"]>): Promise<RuleInputs["viaMessage"]> {
    const sender = await this.o.store.get(p.tenantId, "ai_agent", m.fromAgentId);
    const senderActive = !!sender && (await identityBlockReason(sender, this.o.host)).reason === null;
    return { id: m.id, fromAgentId: m.fromAgentId, permission: m.permission, senderActive };
  }

  /** Evaluate, then run `fn` only if the firewall did not block. */
  async execute<T>(ctx: FirewallContext, req: ActionRequest, fn: (d: FirewallDecision) => Promise<T>): Promise<T> {
    const d = await this.evaluate(ctx, req);
    if (d.decision === "BLOCK") throw new FirewallBlockedError(d);
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
      const d = await this.evaluate(ctx, req);
      decisions.push(d);
      if (d.decision === "BLOCK") throw new FirewallBlockedError(d);

      let res: { status: number; headers: EgressResponse["headers"]; body: Buffer };
      try {
        res = await this.send(url, method, spec.headers ?? {}, body, spec.maxResponseBytes ?? 5 * 1024 * 1024, spec.timeoutMs ?? 10_000);
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

  private send(url: string, method: string, headers: Record<string, string>, body: string | undefined, maxBytes: number, timeoutMs: number) {
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
      const r = https.request(url, { method, headers, lookup, timeout: timeoutMs, agent: false }, (res) => {
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

    const messageId = req.get("x-legion-message-id");
    if (messageId !== undefined) {
      const m = /^[0-9a-f-]{36}$/i.test(messageId)
        ? (await this.o.pool.query(
            `SELECT id, from_identity, requested_permission, chain FROM agent_messages
              WHERE id = $1 AND tenant_id = $2 AND to_identity = $3 AND expires_at > now()`,
            [messageId, p.tenantId, p.id],
          )).rows[0]
        : undefined;
      const permission = asPermission(m?.requested_permission);
      if (!m || !permission) {
        extraHits.push({ id: "a2a.message_invalid", effect: "BLOCK", hard: true, reason: "No such unexpired message addressed to this agent." });
      } else {
        ctx.viaMessage = { id: m.id, fromAgentId: m.from_identity, permission, chain: m.chain };
        ctx.chain = [...m.chain, m.from_identity];
      }
    }
    return { ctx, extraHits };
  }

  /** Agent-to-agent: evaluate, then store the message for the recipient. */
  async sendMessage(
    ctx: FirewallContext,
    msg: { toAgentId: string; requestedPermission: Permission; payload: unknown },
    extraHits: RuleHit[] = [],
  ): Promise<{ decision: FirewallDecision; messageId: string | null }> {
    const d = await this.evaluate(ctx, {
      surface: "agent_message",
      action: "agents:message",
      permission: null,
      toAgentId: msg.toAgentId,
      requestedPermission: msg.requestedPermission,
      payload: msg.payload,
    }, extraHits);
    // An agent emitting injection-like payloads may itself be compromised:
    // record it against the sender, whether or not the message went out.
    if (this.o.contentGuard && msg.payload !== undefined && msg.payload !== null) {
      const content = typeof msg.payload === "string" ? msg.payload : JSON.stringify(msg.payload);
      await this.o.contentGuard.ingest(
        { tenantId: ctx.principal.tenantId, principal: ctx.principal, requestId: ctx.requestId },
        "agent_message", content, { sourceId: `to:${msg.toAgentId}` },
      );
    }
    if (d.decision === "BLOCK") return { decision: d, messageId: null };
    const res = await this.o.pool.query(
      `INSERT INTO agent_messages (tenant_id, from_identity, to_identity, requested_permission, payload, chain, decision_id, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7, now() + interval '1 hour') RETURNING id`,
      [ctx.principal.tenantId, ctx.principal.id, msg.toAgentId, msg.requestedPermission, JSON.stringify(msg.payload ?? null), ctx.chain ?? [], d.decisionId],
    );
    const messageId: string = res.rows[0].id;
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
    return { decision: d, messageId };
  }

  async inbox(p: MachinePrincipal) {
    const res = await this.o.pool.query(
      `SELECT id, from_identity, requested_permission, payload, chain, decision_id, created_at, expires_at
         FROM agent_messages WHERE tenant_id = $1 AND to_identity = $2 AND expires_at > now()
        ORDER BY created_at DESC LIMIT 100`,
      [p.tenantId, p.id],
    );
    const out = [];
    for (const r of res.rows) {
      const content = typeof r.payload === "string" ? r.payload : JSON.stringify(r.payload);
      // Another agent's words are external content to this one: marked
      // untrusted, with their classification (recorded once, at delivery).
      const c = this.o.contentGuard?.classify({ source: "agent_message", content });
      out.push({
        id: r.id,
        fromAgentId: r.from_identity,
        requestedPermission: r.requested_permission,
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
    if (d.decision === "BLOCK") throw new FirewallBlockedError(d);
    return d;
  }
}

export function asPermission(v: unknown): Permission | null {
  return typeof v === "string" && isPermission(v) ? v : null;
}
