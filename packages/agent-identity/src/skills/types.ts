import { z } from "zod";
import { PERMISSION_TIERS, type Permission } from "../permissions.js";
import type { PromptMessage, SystemPromptId } from "../prompt-guard/assembly.js";
import type { Verdict } from "../prompt-guard/types.js";
import type { MachinePrincipal } from "../types.js";

/*
 * Security skills: named, versioned, read-only analyses an AI agent may run
 * on its own tenant's data. A skill never acts on the world — it reads
 * through capability-gated accessors and returns a validated result. Any
 * action it recommends is returned as a proposal, never executed.
 */

// ---- Capabilities ------------------------------------------------------------

/**
 * What a skill may read, and the existing Legion permission each one needs.
 * A capability is only a name for a permission the agent must already hold:
 * assigning a skill grants nothing.
 */
export const SKILL_CAPABILITIES = {
  "read:security_events": { permission: "alerts:read", description: "Read the tenant's security events (alerts)." },
  "read:assets": { permission: "assets:read", description: "Read the tenant's asset inventory." },
  "read:threat_intel": { permission: "intel:read", description: "Look up indicators with the configured threat-intelligence provider." },
  "read:vulnerabilities": { permission: "vulnerabilities:read", description: "Read vulnerability findings for the tenant's assets." },
  "run:security_self_test": { permission: "security:self_test", description: "Run synthetic attacks against Legion's own in-process defences." },
} as const satisfies Record<string, { permission: Permission; description: string }>;

export type SkillCapability = keyof typeof SKILL_CAPABILITIES;
export const ALL_SKILL_CAPABILITIES = Object.keys(SKILL_CAPABILITIES) as SkillCapability[];

export function capabilityPermission(c: SkillCapability): Permission {
  return SKILL_CAPABILITIES[c].permission;
}

/** Highest permission tier a skill capability may map to. Tier 2 (state changes) is never available to a skill. */
export const MAX_SKILL_PERMISSION_TIER = 1;

export function capabilityTier(c: SkillCapability): number {
  return PERMISSION_TIERS[capabilityPermission(c)];
}

// ---- Data the host supplies -------------------------------------------------------

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

const isoTime = z.iso.datetime({ offset: true });
const shortText = (max: number) => z.string().max(max);

/** One security event (a Legion alert). Host data is validated; unknown fields are dropped. */
export const securityEventSchema = z.object({
  id: z.string().min(1).max(200),
  tenantId: z.string().min(1).max(100),
  title: shortText(2_000),
  summary: shortText(20_000).default(""),
  severity: z.enum(SEVERITIES),
  status: shortText(50).nullish(),
  createdAt: isoTime,
  source: shortText(100).default("unknown"),
  sourceIp: shortText(100).nullish(),
  destinationIp: shortText(100).nullish(),
  asset: shortText(300).nullish(),
  user: shortText(300).nullish(),
  process: shortText(1_000).nullish(),
  filePath: shortText(2_000).nullish(),
  mitreTechniques: z.array(z.string().regex(/^T\d{4}(?:\.\d{3})?$/)).max(20).default([]),
  ruleId: shortText(50).nullish(),
  ruleGroups: z.array(shortText(100)).max(30).default([]),
});
export type SecurityEvent = z.infer<typeof securityEventSchema>;

export const assetSchema = z.object({
  name: z.string().min(1).max(300),
  tenantId: z.string().min(1).max(100),
  ip: shortText(100).nullish(),
  os: shortText(200).nullish(),
  risk: z.enum(SEVERITIES).nullish(),
  online: z.boolean().nullish(),
  /** Whether the asset is reachable from the internet, if the host knows. */
  exposure: z.enum(["internet", "internal", "unknown"]).default("unknown"),
  lastSeen: isoTime.nullish(),
});
export type Asset = z.infer<typeof assetSchema>;

export const INDICATOR_TYPES = ["ip", "domain", "url", "hash", "cve", "email"] as const;
export type IndicatorType = (typeof INDICATOR_TYPES)[number];

/** A provider's answer about one indicator. Its free text is untrusted. */
export const intelResultSchema = z.object({
  indicator: z.string().min(1).max(2_048),
  type: z.enum(INDICATOR_TYPES),
  verdict: z.enum(["malicious", "suspicious", "benign", "unknown"]),
  source: z.string().min(1).max(100),
  confidence: z.number().min(0).max(100).nullish(),
  lastSeen: isoTime.nullish(),
  notes: shortText(2_000).nullish(),
});
export type IntelResult = z.infer<typeof intelResultSchema>;

export const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

export const vulnerabilitySchema = z.object({
  id: z.string().min(1).max(200),
  tenantId: z.string().min(1).max(100),
  asset: z.string().min(1).max(300),
  component: z.string().min(1).max(300),
  installedVersion: shortText(100).nullish(),
  fixedVersion: shortText(100).nullish(),
  cve: z.string().regex(CVE_RE).nullish(),
  severity: z.enum([...SEVERITIES, "unknown"]).nullish(),
  cvss: z.number().min(0).max(10).nullish(),
  detectedAt: isoTime,
  source: z.string().min(1).max(100),
  evidence: shortText(2_000).nullish(),
});
export type Vulnerability = z.infer<typeof vulnerabilitySchema>;

export interface SecurityEventQuery {
  ids?: string[];
  since?: string;
  until?: string;
  asset?: string;
  sourceIp?: string;
  minSeverity?: Severity;
  limit: number;
}

/**
 * The host's data, read on behalf of a skill. Every method receives the
 * tenant id from the authenticated agent — never from skill input — and
 * every record it returns is validated and checked against that tenant.
 * A provider that reaches outside Legion (threat intelligence) should do so
 * through the firewall's egress executor (`identity.firewall.request`).
 */
export interface SkillDataSource {
  listSecurityEvents?(tenantId: string, q: SecurityEventQuery): Promise<unknown[]>;
  listAssets?(tenantId: string, q: { names?: string[]; limit: number }): Promise<unknown[]>;
  lookupIndicators?(tenantId: string, indicators: { type: IndicatorType; value: string }[]): Promise<unknown[]>;
  listVulnerabilities?(tenantId: string, q: { cve?: string; asset?: string; component?: string; limit: number }): Promise<unknown[]>;
}

/** A language model the host provides. It only ever receives assembled prompts (see prompt-guard/assembly.ts). */
/**
 * `tenantId` is the organisation whose data is in the prompt, so the host can
 * apply that organisation's own AI policy (on/off, data mode) before anything
 * leaves. `signal` aborts the call when the skill's deadline passes.
 */
export type SkillModel = (messages: PromptMessage[], opts: { signal: AbortSignal; tenantId: string }) => Promise<string>;

// ---- What a skill sees ----------------------------------------------------------------

export interface UntrustedSummary {
  /** Worst verdict over the external content this invocation read. */
  verdict: Verdict;
  /** Records whose text was flagged by the prompt-injection classifier. */
  flaggedIds: string[];
}

export interface Narrative {
  /** Model output: untrusted, never parsed for instructions or actions. */
  trust: "model_output";
  text: string;
  verdict: Verdict;
}

export interface SkillContext {
  /** The agent running the skill (read-only). */
  readonly principal: Readonly<MachinePrincipal>;
  readonly tenantId: string;
  readonly now: Date;
  readonly signal: AbortSignal;
  /** Capability-gated reads. Calling one the skill did not declare fails closed. */
  readonly data: {
    securityEvents(q: SecurityEventQuery): Promise<SecurityEvent[]>;
    assets(q: { names?: string[]; limit: number }): Promise<Asset[]>;
    lookupIndicators(indicators: { type: IndicatorType; value: string }[]): Promise<IntelResult[]>;
    vulnerabilities(q: { cve?: string; asset?: string; component?: string; limit: number }): Promise<Vulnerability[]>;
  };
  /** Prompt-injection verdict for a record's text, as classified when it was read. */
  verdictOf(id: string): Verdict;
  /** Summary of everything external this invocation has read so far. */
  untrusted(): UntrustedSummary;
  /** Whether a language model is available to this skill. */
  readonly modelAvailable: boolean;
  /** Optional model narrative over untrusted data. Throws if unavailable or not declared. */
  narrate(req: {
    prompt: SystemPromptId;
    intent: string;
    trusted?: Record<string, unknown>;
    untrusted: { source: "security_alert" | "user_generated" | "api_response"; id: string; text: string }[];
  }): Promise<Narrative>;
}

export interface SkillDefinition<I = unknown, O = unknown> {
  /** Unique, lowercase snake_case. */
  name: string;
  title: string;
  description: string;
  /** Semantic version. */
  version: string;
  /** Strict: unknown fields are refused. */
  input: z.ZodType<I>;
  output: z.ZodType<O>;
  capabilities: readonly SkillCapability[];
  /** Audit actions this skill's invocations produce. */
  auditEvents: readonly string[];
  /** Whether the skill may ask the host's model for a narrative. */
  usesModel?: boolean;
  /** Short example input, for documentation and discovery (validated against `input` at registration). */
  example: Record<string, unknown>;
  /** What the skill cannot do or know. Returned in discovery. */
  limitations: readonly string[];
  handler(ctx: SkillContext, input: I): Promise<O>;
}

// ---- Errors -----------------------------------------------------------------------

export type SkillErrorCode =
  | "unknown_skill"
  | "not_found"
  | "not_assigned"
  | "invalid_input"
  | "capability_missing"
  | "firewall_blocked"
  | "audit_unavailable"
  | "data_unavailable"
  | "data_invalid"
  | "foreign_tenant"
  | "undeclared_capability"
  | "model_unavailable"
  | "invalid_output"
  | "timeout"
  | "failed";

const STATUS: Record<SkillErrorCode, number> = {
  unknown_skill: 404,
  not_found: 404,
  not_assigned: 403,
  invalid_input: 400,
  capability_missing: 403,
  firewall_blocked: 403,
  audit_unavailable: 503,
  data_unavailable: 503,
  data_invalid: 502,
  foreign_tenant: 502,
  undeclared_capability: 500,
  model_unavailable: 503,
  invalid_output: 500,
  timeout: 504,
  failed: 500,
};

export class SkillError extends Error {
  readonly status: number;
  constructor(readonly code: SkillErrorCode, message: string, readonly details: Record<string, unknown> = {}) {
    super(message);
    this.name = "SkillError";
    this.status = STATUS[code];
  }
}

// ---- Shared output pieces ---------------------------------------------------------------

export const riskLevel = z.enum(["low", "medium", "high", "critical"]);
export type RiskLevelOut = z.infer<typeof riskLevel>;
export const verdictSchema = z.enum(["clean", "suspicious", "malicious"]);
export const untrustedSummarySchema = z.strictObject({ verdict: verdictSchema, flaggedIds: z.array(z.string()).max(1_000) });
export const narrativeSchema = z.strictObject({ trust: z.literal("model_output"), text: z.string().max(20_000), verdict: verdictSchema });

/**
 * An action a skill recommends. Skills never execute it: a person, or an
 * agent through the normal guarded routes and tool gateway, does — and that
 * path checks its own permission again.
 */
export const proposedActionSchema = z.strictObject({
  action: z.string().max(100),
  description: z.string().max(1_000),
  /** The Legion permission this action would need, or null when Legion has no such action for machines. */
  permission: z.string().max(100).nullable(),
  /** Only a person may do this (suspension, containment, deletion, anything outside Legion's grantable permissions). */
  humanOnly: z.boolean(),
  destructive: z.boolean(),
  /** From reviewProposedAction(): allow | confirm | block, given the external content this plan was built from. */
  review: z.enum(["allow", "confirm", "block"]),
  reviewReasons: z.array(z.string().max(300)).max(10),
  /** Always false: skills do not act. */
  executed: z.literal(false),
});
export type ProposedActionOut = z.infer<typeof proposedActionSchema>;
