/**
 * A workspace's policy document: strict, small, no free-form expressions.
 * Anything unknown (a field, an action, an agent) is a validation error — a
 * typo must never silently widen what an agent may do.
 */
import { z } from "zod";
import { ACTION_IDS } from "./catalog.js";
import { AGENTS, AUTONOMY, ORIGINS, RISK_CLASSES } from "./types.js";

export const MAX_POLICY_BYTES = 65_536;
export const MAX_RULES = 100;

const actionRef = z.string().refine((a) => a === "*" || ACTION_IDS.includes(a), "Unknown action");

export const ruleSchema = z.strictObject({
  id: z.string().regex(/^[a-z0-9_-]{1,40}$/, "Rule id: lowercase letters, digits, - and _, at most 40"),
  effect: z.enum(["ALLOW", "REQUIRE_APPROVAL", "RECORD_ONLY", "DENY"]),
  actions: z.array(actionRef).min(1).max(50),
  agents: z.array(z.enum(AGENTS)).min(1).max(5).optional(),
  origins: z.array(z.enum(ORIGINS)).min(1).max(4).optional(),
  classes: z.array(z.enum(RISK_CLASSES)).min(1).max(5).optional(),
  reason: z.string().max(200).refine((s) => !/[\u0000-\u001f\u007f]/.test(s), "No control characters").optional(),
});
export type PolicyRule = z.infer<typeof ruleSchema>;

export const policyDocumentSchema = z.strictObject({
  schema: z.literal(1),
  default_autonomy: z.enum(AUTONOMY),
  agents: z.partialRecord(z.enum(AGENTS), z.strictObject({ autonomy: z.enum(AUTONOMY) })).optional(),
  actions: z.record(actionRef, z.strictObject({ autonomy: z.enum(AUTONOMY) })).optional(),
  rules: z.array(ruleSchema).max(MAX_RULES).default([]),
}).superRefine((doc, ctx) => {
  const seen = new Set<string>();
  for (const r of doc.rules) {
    if (seen.has(r.id)) ctx.addIssue({ code: "custom", message: `Duplicate rule id: ${r.id}` });
    seen.add(r.id);
  }
  if (doc.actions && "*" in doc.actions) ctx.addIssue({ code: "custom", message: "Per-action autonomy needs a specific action" });
});
export type PolicyDocument = z.infer<typeof policyDocumentSchema>;

export type ParseResult = { ok: true; document: PolicyDocument } | { ok: false; error: string };

export function parsePolicyDocument(raw: unknown): ParseResult {
  let size: number;
  try { size = Buffer.byteLength(JSON.stringify(raw ?? null), "utf8"); } catch { return { ok: false, error: "Not JSON" }; }
  if (size > MAX_POLICY_BYTES) return { ok: false, error: `A policy is at most ${MAX_POLICY_BYTES} bytes` };
  const r = policyDocumentSchema.safeParse(raw);
  if (!r.success) {
    const issue = r.error.issues[0]!;
    return { ok: false, error: `${issue.path.join(".") || "policy"}: ${issue.message}` };
  }
  return { ok: true, document: r.data };
}

/**
 * D0 — what a workspace gets before anyone writes a policy: agents only
 * observe. Every effectful action is recorded, nothing is done on its own.
 */
export const DEFAULT_POLICY: PolicyDocument = Object.freeze({ schema: 1, default_autonomy: "OBSERVE", rules: [] }) as PolicyDocument;
