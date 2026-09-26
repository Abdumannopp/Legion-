import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Pool } from "pg";
import { canonical } from "../chain.js";
import { FirewallBlockedError, type AgentFirewall } from "../firewall/engine.js";
import type { PolicyStore } from "../firewall/policy.js";
import { checkFilePath } from "../firewall/paths.js";
import { digest } from "../firewall/scan.js";
import type { FirewallContext, FirewallDecision } from "../firewall/types.js";
import type { PromptInjectionGuard } from "../prompt-guard/guard.js";
import type { ContentSource, Verdict } from "../prompt-guard/types.js";
import { newAccessToken, parseAccessToken } from "../secrets.js";
import type { MachinePrincipal } from "../types.js";
import { analyzeToolCall, invalidCallAnalysis } from "./analyzers.js";
import { ToolAuditLog } from "./audit.js";
import { toolCallSchema, type ToolAnalysis, type ToolCall, type ToolKind } from "./types.js";

export class ToolBlockedError extends FirewallBlockedError {
  constructor(decision: FirewallDecision, readonly analysis: ToolAnalysis) {
    super(decision);
    this.name = "ToolBlockedError";
  }
}

export interface ToolAuthorization {
  decision: FirewallDecision;
  analysis: ToolAnalysis;
  /** The validated call (null if the input was not a valid call). */
  call: ToolCall | null;
  /** Written to the tool audit log (blocked, warned, or high-risk). */
  audited: boolean;
  /** Single-use proof for a tool server, when allowed. */
  ticket: { value: string; expiresAt: string } | null;
}

export interface ToolResult {
  /** Text the tool produced that a model will read. Classified as untrusted content. */
  output?: string;
  data?: unknown;
}

/** Tool output is external content: a page, an API body, an email, an issue. */
const OUTPUT_SOURCE: Record<ToolKind, ContentSource> = {
  browser: "webpage", http: "api_response", database: "api_response", files: "document", shell: "other",
  email: "email", github: "github_issue", slack: "user_generated", mcp: "api_response", cloud: "api_response",
};

/** The digest a ticket is bound to: the exact, validated call. */
export function callDigest(call: ToolCall): string {
  return digest(JSON.parse(canonical(call)));
}

/**
 * Every AI tool call passes here before it runs. The call is validated,
 * analysed deterministically for its tool family, decided by the agent
 * firewall (identity, tenant, delegation, permission, sensitivity, risk,
 * destination, prompt-injection quarantine), and — if blocked or risky —
 * written to the tool audit log before anything happens.
 */
export class ToolGateway {
  readonly audit: ToolAuditLog;

  constructor(
    private readonly o: {
      pool: Pool;
      firewall: AgentFirewall;
      policies: PolicyStore;
      contentGuard: PromptInjectionGuard;
      log: (msg: string, err?: unknown) => void;
    },
  ) {
    this.audit = new ToolAuditLog(o.pool);
  }

  async authorize(ctx: FirewallContext, input: unknown, extraHits: FirewallDecision["hits"] = []): Promise<ToolAuthorization> {
    const { policy } = await this.o.policies.get(ctx.principal.tenantId);
    const parsed = toolCallSchema.safeParse(input);
    const call = parsed.success ? parsed.data : null;
    const analysis = call
      ? analyzeToolCall(call, { principal: ctx.principal, policy })
      : invalidCallAnalysis(input, parsed.error?.issues.map((i) => `${i.path.join(".") || "call"}: ${i.message}`).slice(0, 3).join("; ") ?? "invalid");

    const decision = await this.o.firewall.evaluate(ctx, {
      surface: "tool_call",
      action: `tool:${analysis.toolKind}.${analysis.operation}`.slice(0, 200),
      permission: analysis.permission,
      resource: { type: `tool:${analysis.toolKind}`, id: analysis.target.slice(0, 200), tenantId: ctx.principal.tenantId },
      sensitivity: analysis.sensitivity,
      toolKind: analysis.toolKind,
      operation: analysis.operation,
      target: analysis.target,
      destination: analysis.destination,
      changesState: analysis.changesState,
      externalEffect: analysis.externalEffect,
      analysisHits: analysis.hits,
      analysisFactors: analysis.factors,
      call: input,
    }, extraHits);

    const audited =
      decision.decision !== "ALLOW" || analysis.highRisk || decision.riskScore >= policy.toolSecurity.auditRiskThreshold;
    if (audited) {
      try {
        await this.audit.record(ToolAuditLog.build("decision", ctx, input, analysis, decision));
      } catch (err) {
        // A risky call we cannot record is a call we do not allow.
        this.o.log("tool audit unavailable; blocking", err);
        const blocked: FirewallDecision = {
          ...decision,
          decision: "BLOCK",
          hits: [...decision.hits, { id: "tool.audit_unavailable", effect: "BLOCK", hard: true, reason: "The tool call could not be audited." }],
        };
        return { decision: blocked, analysis, call, audited: false, ticket: null };
      }
    }

    let ticket: ToolAuthorization["ticket"] = null;
    if (decision.decision !== "BLOCK" && call) {
      const { token, hash } = newAccessToken();
      const value = token.replace(/^lgt_/, "ltk_");
      const res = await this.o.pool.query(
        `INSERT INTO tool_call_tickets (ticket_hash, tenant_id, identity_id, decision_id, call_digest, tool_kind, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6, now() + make_interval(secs => $7)) RETURNING expires_at`,
        [hash, ctx.principal.tenantId, ctx.principal.id, decision.decisionId, callDigest(call), call.kind, policy.toolSecurity.ticketTtlSeconds],
      );
      ticket = { value, expiresAt: new Date(res.rows[0].expires_at).toISOString() };
    }
    return { decision, analysis, call, audited, ticket };
  }

  /**
   * For tool servers (service accounts): is this exact call approved? The
   * ticket is consumed — a second use, a changed argument, another tenant or
   * an expired ticket is refused. Every verification is audited.
   */
  async verifyTicket(verifier: MachinePrincipal, ticket: string, input: unknown): Promise<{ ok: true; decisionId: string; agentId: string } | { ok: false; reason: string }> {
    const hash = parseAccessToken(ticket.replace(/^ltk_/, "lgt_"));
    const parsed = toolCallSchema.safeParse(input);
    const reject = async (reason: string, row?: { identity_id: string; decision_id: string }) => {
      // Rejections are recorded in the tool audit against the verifier.
      const ctx: FirewallContext = { principal: verifier };
      const analysis = parsed.success ? analyzeToolCall(parsed.data, { principal: verifier, policy: (await this.o.policies.get(verifier.tenantId)).policy }) : invalidCallAnalysis(input, "invalid call");
      const pseudo: FirewallDecision = {
        decisionId: row?.decision_id ?? "00000000-0000-0000-0000-000000000000", decision: "BLOCK", wouldBlock: false, mode: "enforce",
        riskScore: 100, riskFactors: [], hits: [{ id: `ticket.${reason}`, effect: "BLOCK", hard: true, reason: `Ticket rejected: ${reason}` }],
        policyVersion: -1, destination: analysis.destination, sensitivity: analysis.sensitivity, delegation: null, advisor: [],
      };
      await this.audit.record(ToolAuditLog.build("ticket_rejected", ctx, input, analysis, pseudo, { outcomeDetail: row ? `agent ${row.identity_id}` : undefined }))
        .catch((err) => this.o.log("tool audit write failed for a rejected ticket", err));
      return { ok: false as const, reason };
    };
    if (!hash) return reject("malformed");
    if (!parsed.success) return reject("invalid_call");
    // One atomic statement: only an unused, unexpired ticket for this tenant
    // AND this exact call is consumed. A mismatch does not burn the ticket.
    const digestOfCall = callDigest(parsed.data);
    const res = await this.o.pool.query(
      `UPDATE tool_call_tickets SET consumed_at = now(), consumed_by = $2
        WHERE ticket_hash = $1 AND consumed_at IS NULL AND expires_at > now() AND tenant_id = $3 AND call_digest = $4
        RETURNING identity_id, decision_id`,
      [hash, verifier.id, verifier.tenantId, digestOfCall],
    );
    const row = res.rows[0];
    if (!row) {
      const known = (await this.o.pool.query(
        "SELECT tenant_id, identity_id, decision_id, call_digest, consumed_at, expires_at > now() AS live FROM tool_call_tickets WHERE ticket_hash = $1",
        [hash],
      )).rows[0];
      if (!known) return reject("unknown");
      if (known.tenant_id !== verifier.tenantId) return reject("unknown"); // do not reveal other tenants' tickets
      if (known.consumed_at) return reject("already_used", known);
      if (!known.live) return reject("expired", known);
      return reject("call_mismatch", known);
    }
    const analysis = analyzeToolCall(parsed.data, { principal: verifier, policy: (await this.o.policies.get(verifier.tenantId)).policy });
    await this.audit.record(ToolAuditLog.build("ticket_verified", { principal: verifier }, input, { ...analysis, highRisk: false }, {
      decisionId: row.decision_id, decision: "ALLOW", wouldBlock: false, mode: "enforce", riskScore: 0, riskFactors: [], hits: [],
      policyVersion: -1, destination: analysis.destination, sensitivity: analysis.sensitivity, delegation: null, advisor: [],
    }, { outcomeDetail: `agent ${row.identity_id}` }));
    return { ok: true, decisionId: row.decision_id, agentId: row.identity_id };
  }

  /**
   * Authorize, then run `executor` only if allowed. The output is treated
   * as external content (classified, recorded against the agent if
   * flagged). For audited calls the outcome is recorded too.
   */
  async execute<T extends ToolResult>(ctx: FirewallContext, input: unknown, executor: (call: ToolCall, auth: ToolAuthorization) => Promise<T>): Promise<T & { decisionId: string; outputVerdict: Verdict | null }> {
    const auth = await this.authorize(ctx, input);
    if (auth.decision.decision === "BLOCK" || !auth.call) throw new ToolBlockedError(auth.decision, auth.analysis);
    const call = auth.call;
    let result: T;
    try {
      result = await executor(call, auth);
    } catch (err) {
      if (auth.audited) {
        await this.audit.record(ToolAuditLog.build("outcome", ctx, input, auth.analysis, auth.decision, {
          outcome: "error", outcomeDetail: err instanceof Error ? err.message : String(err),
        })).catch((e) => this.o.log("tool audit write failed for an outcome", e));
      }
      throw err;
    }
    let outputVerdict: Verdict | null = null;
    if (typeof result.output === "string" && result.output.length) {
      const ingested = await this.o.contentGuard.ingest(
        { tenantId: ctx.principal.tenantId, principal: ctx.principal, requestId: ctx.requestId },
        OUTPUT_SOURCE[call.kind], result.output, { sourceId: `${call.kind}:${auth.decision.decisionId}` },
      );
      outputVerdict = ingested.classification.verdict;
    }
    if (auth.audited || (outputVerdict && outputVerdict !== "clean")) {
      await this.audit.record(ToolAuditLog.build("outcome", ctx, input, auth.analysis, auth.decision, {
        outcome: "success", outputVerdict: outputVerdict ?? undefined,
      }));
    }
    return { ...result, decisionId: auth.decision.decisionId, outputVerdict };
  }

  /** Housekeeping: drop tickets that expired more than a day ago. */
  async purgeExpiredTickets(): Promise<number> {
    const res = await this.o.pool.query("DELETE FROM tool_call_tickets WHERE expires_at < now() - interval '1 day'");
    return res.rowCount ?? 0;
  }

  // ---- Built-in executors ---------------------------------------------------

  /**
   * Runs an allowlisted command without a shell (execFile): arguments are
   * never interpreted, the environment is reduced to a fixed PATH, and time,
   * output and working directory are bounded.
   */
  async runShell(ctx: FirewallContext, input: unknown, opts: { timeoutMs?: number; maxOutputBytes?: number } = {}) {
    return this.execute(ctx, input, async (call) => {
      if (call.kind !== "shell") throw new Error("not a shell call");
      const { policy } = await this.o.policies.get(ctx.principal.tenantId);
      const cwd = call.cwd ?? policy.files.roots.find((r) => r.access === "readwrite")!.path;
      const real = await fs.realpath(cwd);
      // The analyser checked the path as written; a symlink could still lead out.
      const atReal = checkFilePath(policy, real, "write");
      if (atReal.problems.length) throw new Error(`Refusing to run in ${real}: ${atReal.problems.map((p) => p.id).join(", ")}`);
      const { stdout, stderr, code } = await new Promise<{ stdout: string; stderr: string; code: number }>((resolve) => {
        execFile(call.command, call.args, {
          cwd: real,
          shell: false,
          env: { PATH: "/usr/local/bin:/usr/bin:/bin", LANG: "C.UTF-8" },
          timeout: opts.timeoutMs ?? 10_000,
          maxBuffer: opts.maxOutputBytes ?? 1_048_576,
          windowsHide: true,
        }, (err, stdout, stderr) => {
          const code = err ? (typeof (err as { code?: unknown }).code === "number" ? (err as { code: number }).code : 1) : 0;
          resolve({ stdout: String(stdout), stderr: String(stderr), code });
        });
      });
      return { output: stdout, data: { exitCode: code, stderr: stderr.slice(0, 10_000) } };
    });
  }

  /** Files through the firewall's own executors (symlink-safe, re-checked at the real path). */
  async files(ctx: FirewallContext, input: unknown) {
    return this.execute(ctx, input, async (call) => {
      if (call.kind !== "files") throw new Error("not a files call");
      const fw = this.o.firewall;
      switch (call.operation) {
        case "read": return { output: (await fw.readFile(ctx, call.path, { permission: "tool.files:read" })).toString("utf8") };
        case "write": await fw.writeFile(ctx, call.path, call.content ?? "", { permission: "tool.files:write" }); return { data: { written: true } };
        case "list": {
          const real = await fs.realpath(call.path);
          if (real !== path.resolve(call.path)) throw new Error("Refusing to list through a symbolic link.");
          const entries = await fs.readdir(real, { withFileTypes: true });
          return { output: entries.map((e) => `${e.isDirectory() ? "d" : "-"} ${e.name}`).join("\n") };
        }
        case "delete": {
          const real = await fs.realpath(call.path);
          if (real !== path.resolve(call.path)) throw new Error("Refusing to delete through a symbolic link.");
          await fs.unlink(real);
          return { data: { deleted: true } };
        }
        case "move": throw new Error("move is authorized but has no built-in executor; supply one.");
      }
    });
  }

  /** HTTP through the firewall's egress executor (DNS answers re-checked at connect time). */
  async http(ctx: FirewallContext, input: unknown) {
    return this.execute(ctx, input, async (call) => {
      if (call.kind !== "http") throw new Error("not an http call");
      const res = await this.o.firewall.request(ctx, {
        url: call.url, method: call.method, headers: call.headers, body: call.body,
        action: `tool:http.${call.method.toLowerCase()}`, permission: call.method.toUpperCase() === "GET" || call.method.toUpperCase() === "HEAD" ? "tool.http:read" : "tool.http:write",
      });
      return { output: res.body.toString("utf8"), data: { status: res.status } };
    });
  }
}
