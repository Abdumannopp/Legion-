/**
 * The universal event envelope (v1): one strict shape for anything a source
 * tells Legion, whatever the vendor. Adapters already produce a Finding;
 * `fromFinding` lifts it into the envelope that the SOC core (orchestrator,
 * memory, audit) consumes, so nothing downstream learns a vendor's format.
 *
 * Everything inside is DATA. Text fields are bounded and stripped of control
 * characters; entities are typed and validated (an "ip" is an IP address);
 * nothing in an envelope is ever read as an instruction or a permission.
 */
import { isIP } from "node:net";
import { z } from "zod";
import { digestOf } from "../policy/canonical.js";
import type { Finding } from "./types.js";

export const ENVELOPE_VERSION = 1;
export const MAX_ENVELOPE_BYTES = 16_384;

const clean = (max: number) => z.string().transform((s) => s.replace(/[\u0000-\u0008\u000b-\u001f\u007f​-‏‪-‮⁠-⁤\u{E0000}-\u{E007F}]/gu, "").slice(0, max));

export const entitySchema = z.discriminatedUnion("type", [
  z.strictObject({ type: z.literal("ip"), value: z.string().max(45).refine((v) => isIP(v) !== 0, "Not an IP address"), role: z.enum(["source", "destination", "unknown"]) }),
  z.strictObject({ type: z.literal("host"), value: clean(200), role: z.enum(["target", "unknown"]) }),
  z.strictObject({ type: z.literal("account"), value: clean(200), role: z.enum(["actor", "target", "unknown"]) }),
  z.strictObject({ type: z.literal("technique"), value: z.string().regex(/^T\d{4}(\.\d{3})?$/), role: z.literal("observed") }),
]);
export type Entity = z.infer<typeof entitySchema>;

export const envelopeSchema = z.strictObject({
  version: z.literal(ENVELOPE_VERSION),
  /** Stable id: digest of (tenant, source, external id) — a re-sent event has the same id. */
  id: z.string().regex(/^[0-9a-f]{64}$/),
  tenant_id: z.string().uuid(),
  source: z.string().regex(/^[a-z][a-z0-9_]{1,40}$/),
  category: z.enum(["finding", "authentication", "network", "file", "process", "cloud", "other"]),
  observed_at: z.string().datetime({ offset: true }).nullable(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  confidence: z.number().int().min(0).max(100),
  title: clean(300),
  summary: clean(4000),
  entities: z.array(entitySchema).max(50),
  /** Marks every envelope: its text came from outside and is untrusted. */
  trust: z.literal("untrusted_data"),
});
export type EventEnvelope = z.infer<typeof envelopeSchema>;

export type EnvelopeResult = { ok: true; envelope: EventEnvelope } | { ok: false; error: string };

export function validateEnvelope(raw: unknown): EnvelopeResult {
  let size: number;
  try { size = Buffer.byteLength(JSON.stringify(raw ?? null)); } catch { return { ok: false, error: "Not JSON" }; }
  if (size > MAX_ENVELOPE_BYTES) return { ok: false, error: "Envelope too large" };
  const r = envelopeSchema.safeParse(raw);
  return r.success ? { ok: true, envelope: r.data } : { ok: false, error: `${r.error.issues[0]!.path.join(".")}: ${r.error.issues[0]!.message}` };
}

/** A normalised Finding as an envelope. Invalid entities are dropped, never guessed. */
export function fromFinding(tenantId: string, source: string, f: Finding): EnvelopeResult {
  const entities: unknown[] = [];
  if (f.sourceIp && isIP(f.sourceIp)) entities.push({ type: "ip", value: f.sourceIp, role: "source" });
  if (f.target) entities.push({ type: "host", value: f.target, role: "target" });
  for (const t of f.mitre.slice(0, 20)) if (/^T\d{4}(\.\d{3})?$/.test(t)) entities.push({ type: "technique", value: t, role: "observed" });
  const occurred = f.occurredAt && !Number.isNaN(Date.parse(f.occurredAt)) ? new Date(f.occurredAt).toISOString() : null;
  return validateEnvelope({
    version: ENVELOPE_VERSION,
    id: digestOf({ tenant_id: tenantId, source, external_id: f.externalId }),
    tenant_id: tenantId, source, category: "finding", observed_at: occurred,
    severity: f.severity, confidence: Math.max(0, Math.min(100, Math.round(f.confidence))),
    title: f.title, summary: f.summary, entities, trust: "untrusted_data",
  });
}
