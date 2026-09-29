import { randomUUID } from "node:crypto";
import type { AuditLog } from "../audit.js";
import type { AgentFirewall } from "../firewall/engine.js";
import { byteSize, digest, findSecrets, maskSecrets } from "../firewall/scan.js";
import type { FirewallContext, RuleHit } from "../firewall/types.js";
import { redactSecrets } from "../killswitch/service.js";
import { SYSTEM_PROMPTS, type SystemPromptId } from "../prompt-guard/assembly.js";
import type { IngestContext, PromptInjectionGuard } from "../prompt-guard/guard.js";
import { worstVerdict, type Classification, type ContentSource, type Verdict } from "../prompt-guard/types.js";
import type { SkillAssignments } from "./assignments.js";
import { SKILL_NAME, type SkillRegistry } from "./registry.js";
import {
  assetSchema,
  capabilityPermission,
  intelResultSchema,
  securityEventSchema,
  SkillError,
  vulnerabilitySchema,
  type Asset,
  type IntelResult,
  type Narrative,
  type SecurityEvent,
  type SkillCapability,
  type SkillContext,
  type SkillDataSource,
  type SkillDefinition,
  type SkillModel,
  type UntrustedSummary,
  type Vulnerability,
} from "./types.js";

export interface SkillRuntimeOptions {
  registry: SkillRegistry;
  assignments: SkillAssignments;
  firewall: AgentFirewall;
  audit: AuditLog;
  contentGuard: PromptInjectionGuard;
  data?: SkillDataSource;
  model?: SkillModel;
  log: (msg: string, err?: unknown) => void;
  /** Whole invocation (default 30 s). */
  timeoutMs?: number;
  /** One model call (default 15 s). */
  modelTimeoutMs?: number;
}

export interface InvocationMeta {
  requestId?: string;
  ip?: string;
  userAgent?: string;
  /** Extra firewall hits from the request (e.g. a spoofed header), as for any guarded route. */
  extraHits?: RuleHit[];
}

export interface SkillInvocationResult<O = unknown> {
  skill: string;
  version: string;
  invocationId: string;
  /** Firewall decisions this invocation was authorized by. */
  decisionIds: string[];
  /** External content this invocation read. */
  untrusted: UntrustedSummary;
  output: O;
}

const MAX_INPUT_BYTES = 65_536;
const MAX_RECORDS = 500;
const MAX_RECORDED_CHARS = 100_000;

/**
 * Records that do not belong to the caller's tenant. Every record a data
 * source returns is checked; one foreign record fails the whole read.
 */
export function recordsOutsideTenant(records: readonly { tenantId?: string }[], tenantId: string): number {
  return records.filter((r) => r.tenantId !== tenantId).length;
}

/** Removes secrets from every string in a result before it is validated and returned. */
function scrub(value: unknown, depth = 0): unknown {
  if (depth > 12) return value;
  if (typeof value === "string") return redactSecrets(maskSecrets(value));
  if (Array.isArray(value)) return value.map((v) => scrub(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrub(v, depth + 1)]));
  }
  return value;
}

function firstIssue(err: { issues: { path: PropertyKey[]; message: string }[] }): string {
  const i = err.issues[0];
  return `${i?.path.map(String).join(".") || "input"}: ${i?.message ?? "invalid"}`;
}

/**
 * Runs skills. Every invocation, in this order, and failing closed at each
 * step:
 *   1. the skill exists and is assigned to this agent;
 *   2. the input is well formed (strict schema, size, no credentials);
 *   3. the agent holds every permission the skill's capabilities map to;
 *   4. the agent firewall allows each of those permissions for this skill
 *      (identity, suspension, risk hold, tenant, behaviour, prompt-injection
 *      quarantine — the same checks as every other agent action);
 *   5. the attempt is audited — no trace, no run;
 * then the handler runs with capability-gated, tenant-forced data accessors,
 * external text is classified and recorded against the agent, the result is
 * scrubbed of secrets and validated, and the outcome is audited.
 */
export class SkillRuntime {
  constructor(private readonly o: SkillRuntimeOptions) {}

  get registry(): SkillRegistry {
    return this.o.registry;
  }

  async invoke(ctx: FirewallContext, name: string, rawInput: unknown, meta: InvocationMeta = {}): Promise<SkillInvocationResult> {
    const p = ctx.principal;
    const invocationId = randomUUID();
    const label = typeof name === "string" && SKILL_NAME.test(name) ? name : "(invalid)";
    const base = {
      principal: p, action: "skill.invoke", resourceType: "skill", resourceId: label,
      requestId: meta.requestId, ip: meta.ip, userAgent: meta.userAgent,
    };
    const deny = async (err: SkillError): Promise<never> => {
      await this.o.audit
        .record({ ...base, outcome: "denied", reason: `${err.code}: ${err.message}`.slice(0, 500), details: { invocationId, ...err.details } })
        .catch((e) => this.o.log("audit write failed for a denied skill invocation", e));
      throw err;
    };

    // 1. Exists and is assigned.
    const def = this.o.registry.get(label);
    if (!def) return deny(new SkillError("unknown_skill", "No such skill."));
    let assigned: boolean;
    try {
      assigned = await this.o.assignments.isAssigned(p.tenantId, p.id, def.name);
    } catch (err) {
      this.o.log("skill assignment lookup failed; refusing", err);
      return deny(new SkillError("failed", "Skill assignment could not be checked."));
    }
    if (!assigned) return deny(new SkillError("not_assigned", `Skill ${def.name} is not assigned to this agent.`));

    // 2. Input.
    if (rawInput === undefined || byteSize(rawInput) > MAX_INPUT_BYTES) {
      return deny(new SkillError("invalid_input", `Input is missing or larger than ${MAX_INPUT_BYTES} bytes.`));
    }
    const secrets = findSecrets(rawInput);
    if (secrets.length) return deny(new SkillError("invalid_input", `Input contains credentials (${secrets.join(", ")}); they are never passed to a skill.`));
    const parsed = def.input.safeParse(rawInput);
    if (!parsed.success) return deny(new SkillError("invalid_input", firstIssue(parsed.error)));
    const inputDigest = digest(parsed.data);

    // 3. Permissions the agent already holds. Assignment granted none.
    const missing = def.capabilities.filter((c) => !p.permissions.includes(capabilityPermission(c)));
    if (missing.length) {
      return deny(new SkillError("capability_missing",
        `This agent does not hold ${missing.map(capabilityPermission).join(", ")} (needed for ${missing.join(", ")}). Assigning a skill grants no permission.`,
        { missing }));
    }

    // 4. The firewall, once per capability.
    const decisionIds: string[] = [];
    for (const c of def.capabilities) {
      const d = await this.o.firewall.evaluate(ctx, {
        surface: "api",
        action: `skill:${def.name}`,
        permission: capabilityPermission(c),
        resource: { type: "skill", id: def.name, tenantId: p.tenantId },
        sensitivity: "internal",
      }, meta.extraHits ?? []);
      decisionIds.push(d.decisionId);
      if (d.decision === "BLOCK") {
        const rules = d.hits.filter((h) => h.effect === "BLOCK").map((h) => h.id);
        return deny(new SkillError("firewall_blocked", d.hits.find((h) => h.effect === "BLOCK")?.reason ?? "Blocked by the agent firewall.", { decisionIds, rules }));
      }
    }

    // 5. No trace, no run.
    try {
      await this.o.audit.record({ ...base, outcome: "attempt", details: { invocationId, skill: def.name, version: def.version, decisionIds, inputDigest } });
    } catch (err) {
      this.o.log(`audit unavailable; refusing skill ${def.name}`, err);
      throw new SkillError("audit_unavailable", "The skill was not run because it could not be recorded.");
    }

    const controller = new AbortController();
    const run = new Run(def, ctx, this.o, controller.signal, meta.requestId);
    let output: unknown;
    try {
      const timeout = new Promise<never>((_, reject) => {
        const t = setTimeout(() => {
          controller.abort();
          reject(new SkillError("timeout", "The skill took too long."));
        }, this.o.timeoutMs ?? 30_000);
        t.unref();
        controller.signal.addEventListener("abort", () => clearTimeout(t), { once: true });
      });
      timeout.catch(() => {});
      const raw = await Promise.race([def.handler(run.context(), parsed.data), timeout]);
      controller.abort();
      const checked = def.output.safeParse(scrub(raw));
      if (!checked.success) {
        this.o.log(`skill ${def.name} produced invalid output: ${firstIssue(checked.error)}`);
        throw new SkillError("invalid_output", "The skill produced output that does not match its schema; nothing was returned.");
      }
      output = checked.data;
    } catch (err) {
      controller.abort();
      const e = err instanceof SkillError ? err : new SkillError("failed", "The skill failed.");
      if (!(err instanceof SkillError)) this.o.log(`skill ${def.name} failed`, err);
      await this.o.audit
        .record({ ...base, outcome: "failure", reason: `${e.code}: ${redactSecrets(maskSecrets(e.message))}`.slice(0, 500), details: { invocationId, decisionIds, untrusted: run.untrusted() } })
        .catch((x) => this.o.log("audit write failed for a failed skill invocation", x));
      throw e;
    }

    const untrusted = run.untrusted();
    try {
      await this.o.audit.record({
        ...base, outcome: "success",
        details: { invocationId, skill: def.name, version: def.version, decisionIds, inputDigest, outputDigest: digest(output), untrusted, reads: run.reads },
      });
    } catch (err) {
      this.o.log(`audit unavailable; withholding result of skill ${def.name}`, err);
      throw new SkillError("audit_unavailable", "The result was withheld because it could not be recorded.");
    }
    return { skill: def.name, version: def.version, invocationId, decisionIds, untrusted, output };
  }
}

/** One invocation's state: what it read and how that content was classified. */
class Run {
  private readonly verdicts = new Map<string, Verdict>();
  readonly reads: Record<string, number> = {};
  private readonly ingest: IngestContext;

  constructor(
    private readonly def: SkillDefinition<any, any>,
    private readonly ctx: FirewallContext,
    private readonly o: SkillRuntimeOptions,
    private readonly signal: AbortSignal,
    requestId?: string,
  ) {
    this.ingest = { tenantId: ctx.principal.tenantId, principal: ctx.principal, requestId };
  }

  untrusted(): UntrustedSummary {
    const all = [...this.verdicts.entries()];
    return { verdict: worstVerdict(all.map(([, v]) => v)), flaggedIds: all.filter(([, v]) => v !== "clean").map(([id]) => id).slice(0, 1_000) };
  }

  private gate(c: SkillCapability): void {
    if (!this.def.capabilities.includes(c)) {
      throw new SkillError("undeclared_capability", `Skill ${this.def.name} did not declare ${c}.`);
    }
  }

  /** Calls the host, validates every record and refuses anything from another tenant. */
  private async load<T extends object>(
    what: keyof SkillDataSource,
    call: (() => Promise<unknown[]>) | undefined,
    schema: { safeParse(v: unknown): { success: true; data: T } | { success: false } },
    limit: number,
    tenantScoped = true,
  ): Promise<T[]> {
    if (this.signal.aborted) throw new SkillError("timeout", "The skill took too long.");
    if (!call) throw new SkillError("data_unavailable", `This Legion installation does not provide ${what}.`, { reason: "not_configured" });
    let raw: unknown;
    try {
      raw = await call();
    } catch (err) {
      this.o.log(`skill data source ${what} failed`, err);
      throw new SkillError("data_unavailable", `${what} could not be read.`, { reason: "source_failed" });
    }
    if (!Array.isArray(raw)) throw new SkillError("data_invalid", `${what} returned something that is not a list.`);
    const out: T[] = [];
    for (const r of raw.slice(0, limit)) {
      const v = schema.safeParse(r);
      if (!v.success) throw new SkillError("data_invalid", `${what} returned a record that failed validation.`);
      out.push(v.data);
    }
    if (tenantScoped && recordsOutsideTenant(out as { tenantId?: string }[], this.ctx.principal.tenantId) > 0) {
      this.o.log(`SECURITY: ${what} returned records of another tenant to skill ${this.def.name}; refusing`);
      throw new SkillError("foreign_tenant", `${what} returned data belonging to another organisation; nothing was used.`);
    }
    this.reads[what] = (this.reads[what] ?? 0) + out.length;
    return out;
  }

  /**
   * External text becomes known to the agent here: each record is classified,
   * and the batch is recorded against the agent (which is what the
   * untrusted-content hold is built on). If it cannot be recorded, it is
   * not used.
   */
  private async observe(source: ContentSource, items: { id: string; text: string; hint?: "identifier" }[]): Promise<void> {
    if (!items.length) return;
    for (const it of items) {
      const c = this.o.contentGuard.classify({ source, content: it.text, fieldHint: it.hint });
      const prev = this.verdicts.get(it.id);
      this.verdicts.set(it.id, prev ? worstVerdict([prev, c.verdict]) : c.verdict);
    }
    const joined = items.map((i) => `[${i.id}]\n${i.text}`).join("\n\n").slice(0, MAX_RECORDED_CHARS);
    const batch: Classification = this.o.contentGuard.classify({ source, content: joined });
    const worst = worstVerdict([batch.verdict, ...items.map((i) => this.verdicts.get(i.id)!)]);
    try {
      await this.o.contentGuard.record(this.ingest, source, joined, { sourceId: `skill:${this.def.name}` }, { ...batch, verdict: worst });
    } catch {
      throw new SkillError("data_unavailable", "External content could not be recorded; it was not used.");
    }
  }

  context(): SkillContext {
    const p = this.ctx.principal;
    const tenantId = p.tenantId;
    const d = this.o.data;
    const clamp = (n: number) => Math.max(1, Math.min(MAX_RECORDS, Math.floor(Number(n) || 1)));
    const self = this;
    return Object.freeze({
      principal: Object.freeze({ ...p, permissions: [...p.permissions] }),
      tenantId,
      now: new Date(),
      signal: this.signal,
      modelAvailable: Boolean(this.o.model) && this.def.usesModel === true,
      data: Object.freeze({
        async securityEvents(q) {
          self.gate("read:security_events");
          const limit = clamp(q.limit);
          const rows = await self.load<SecurityEvent>("listSecurityEvents", d?.listSecurityEvents && (() => d.listSecurityEvents!(tenantId, { ...q, limit })), securityEventSchema, limit);
          await self.observe("security_alert", rows.map((e) => ({ id: e.id, text: [e.title, e.summary, e.process, e.filePath, e.user].filter(Boolean).join("\n") })));
          return rows;
        },
        async assets(q) {
          self.gate("read:assets");
          const limit = clamp(q.limit);
          const rows = await self.load<Asset>("listAssets", d?.listAssets && (() => d.listAssets!(tenantId, { names: q.names, limit })), assetSchema, limit);
          await self.observe("api_response", rows.map((a) => ({ id: `asset:${a.name}`, text: a.name, hint: "identifier" as const })));
          return rows;
        },
        async lookupIndicators(indicators) {
          self.gate("read:threat_intel");
          const list = indicators.slice(0, 100);
          const asked = new Set(list.map((i) => `${i.type}:${i.value}`));
          const rows = await self.load<IntelResult>("lookupIndicators", d?.lookupIndicators && (() => d.lookupIndicators!(tenantId, list)), intelResultSchema, MAX_RECORDS, false);
          // A provider may only answer what was asked.
          const answered = rows.filter((r) => asked.has(`${r.type}:${r.indicator}`));
          await self.observe("api_response", answered.filter((r) => r.notes).map((r) => ({ id: `intel:${r.type}:${r.indicator}`, text: r.notes! })));
          return answered;
        },
        async vulnerabilities(q) {
          self.gate("read:vulnerabilities");
          const limit = clamp(q.limit);
          const rows = await self.load<Vulnerability>("listVulnerabilities", d?.listVulnerabilities && (() => d.listVulnerabilities!(tenantId, { cve: q.cve, asset: q.asset, component: q.component, limit })), vulnerabilitySchema, limit);
          await self.observe("api_response", rows.map((v) => ({ id: `vuln:${v.id}`, text: [v.component, v.evidence].filter(Boolean).join("\n") })));
          return rows;
        },
      } satisfies SkillContext["data"]),
      verdictOf: (id: string) => this.verdicts.get(id) ?? "clean",
      untrusted: () => this.untrusted(),
      narrate: (req: Parameters<SkillContext["narrate"]>[0]) => this.narrate(req),
    });
  }

  private async narrate(req: Parameters<SkillContext["narrate"]>[0]): Promise<Narrative> {
    if (this.def.usesModel !== true) throw new SkillError("undeclared_capability", `Skill ${this.def.name} does not use a model.`);
    if (!this.o.model) throw new SkillError("model_unavailable", "No language model is configured.");
    const promptId = req.prompt as SystemPromptId;
    if (!String(promptId).startsWith("skill.") || !Object.prototype.hasOwnProperty.call(SYSTEM_PROMPTS, promptId)) {
      throw new SkillError("undeclared_capability", "Skills may only use skill system prompts.");
    }
    const assembly = this.o.contentGuard.createAssembly(this.ingest, promptId);
    assembly.setUserIntent(maskSecrets(req.intent));
    for (const [k, v] of Object.entries(req.trusted ?? {})) assembly.addTrustedData(k, v);
    for (const u of req.untrusted.slice(0, 50)) assembly.addUntrustedContent(u.source, maskSecrets(u.text), { sourceId: u.id });
    try {
      await assembly.settle();
    } catch {
      throw new SkillError("data_unavailable", "External content could not be recorded; the model was not called.");
    }
    // Nothing that looks like a credential reaches the model.
    const messages = assembly.toMessages().map((m) => ({ ...m, content: maskSecrets(m.content) }));
    const controller = new AbortController();
    const onAbort = () => controller.abort();
    this.signal.addEventListener("abort", onAbort, { once: true });
    const t = setTimeout(() => controller.abort(), this.o.modelTimeoutMs ?? 15_000);
    t.unref();
    let text: string;
    try {
      text = String(await this.o.model(messages, { signal: controller.signal, tenantId: this.ingest.tenantId })).slice(0, 20_000);
    } catch (err) {
      this.o.log(`model call failed for skill ${this.def.name}`, err);
      throw new SkillError("model_unavailable", "The language model did not answer.");
    } finally {
      clearTimeout(t);
      this.signal.removeEventListener("abort", onAbort);
    }
    // The model read untrusted text: its answer is untrusted too. It is
    // classified and recorded, never parsed for instructions or actions,
    // and withheld if it reads like an injection.
    let verdict: Verdict;
    try {
      verdict = (await this.o.contentGuard.ingest(this.ingest, "model_output", text, { sourceId: `skill:${this.def.name}` })).classification.verdict;
    } catch {
      throw new SkillError("data_unavailable", "The model's answer could not be recorded; it was not used.");
    }
    this.verdicts.set(`model:${this.def.name}`, verdict);
    const shown = verdict === "malicious" ? "[withheld: the model's answer contained instruction-like content]" : text;
    return { trust: "model_output", text: redactSecrets(maskSecrets(shown)), verdict };
  }
}
