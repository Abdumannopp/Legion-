import { z } from "zod";
import {
  ALL_SKILL_CAPABILITIES,
  capabilityPermission,
  capabilityTier,
  MAX_SKILL_PERMISSION_TIER,
  SKILL_CAPABILITIES,
  type SkillDefinition,
} from "./types.js";

export const SKILL_NAME = /^[a-z][a-z0-9_]{2,62}$/;
const SEMVER = /^\d+\.\d+\.\d+$/;

/** A skill as discovery shows it: everything but the handler. */
export interface SkillDescriptor {
  name: string;
  title: string;
  description: string;
  version: string;
  capabilities: { name: string; permission: string; description: string }[];
  /** The Legion permissions an agent must already hold to run it. */
  requiredPermissions: string[];
  usesModel: boolean;
  auditEvents: string[];
  inputSchema: unknown;
  outputSchema: unknown;
  example: unknown;
  limitations: string[];
}

/**
 * The fixed set of skills this Legion build offers. Skills are registered in
 * code, not at runtime by callers, and a definition is refused if it could
 * do more than read: a capability that maps to a state-changing permission
 * (tier 2+) is rejected here, whatever the skill says it does.
 */
export class SkillRegistry {
  private readonly skills = new Map<string, SkillDefinition<any, any>>();

  register<I, O>(def: SkillDefinition<I, O>): this {
    const problems = validateDefinition(def);
    if (problems.length) throw new Error(`Skill ${String(def?.name)} refused: ${problems.join("; ")}`);
    if (this.skills.has(def.name)) throw new Error(`Skill ${def.name} is already registered.`);
    this.skills.set(def.name, Object.freeze({ ...def, capabilities: Object.freeze([...def.capabilities]) }) as SkillDefinition<any, any>);
    return this;
  }

  get(name: string): SkillDefinition<any, any> | undefined {
    return SKILL_NAME.test(name) ? this.skills.get(name) : undefined;
  }

  names(): string[] {
    return [...this.skills.keys()].sort();
  }

  describe(name: string): SkillDescriptor | undefined {
    const d = this.get(name);
    return d ? describe(d) : undefined;
  }

  list(): SkillDescriptor[] {
    return this.names().map((n) => describe(this.skills.get(n)!));
  }
}

export function validateDefinition(def: SkillDefinition<any, any>): string[] {
  const p: string[] = [];
  if (!def || typeof def !== "object") return ["not a definition"];
  if (typeof def.name !== "string" || !SKILL_NAME.test(def.name)) p.push("name must be lowercase snake_case, 3–63 characters");
  if (typeof def.version !== "string" || !SEMVER.test(def.version)) p.push("version must be semantic (x.y.z)");
  if (!def.title || !def.description) p.push("title and description are required");
  if (!(def.input instanceof z.ZodType) || !(def.output instanceof z.ZodType)) p.push("input and output must be zod schemas");
  if (typeof def.handler !== "function") p.push("handler is required");
  if (!Array.isArray(def.capabilities) || def.capabilities.length === 0) p.push("at least one capability is required");
  else {
    for (const c of def.capabilities) {
      if (!ALL_SKILL_CAPABILITIES.includes(c)) p.push(`unknown capability ${String(c)}`);
      else if (capabilityTier(c) > MAX_SKILL_PERMISSION_TIER) p.push(`capability ${c} needs a state-changing permission; skills are read-only`);
    }
    if (new Set(def.capabilities).size !== def.capabilities.length) p.push("duplicate capability");
  }
  if (!Array.isArray(def.auditEvents) || !def.auditEvents.length) p.push("audit events must be declared");
  // The input schema must refuse unknown fields: an agent cannot smuggle
  // options the skill does not declare (e.g. "execute": true).
  if (def.input instanceof z.ZodType && def.example !== undefined) {
    const probe = def.input.safeParse({ ...(def.example as object), __undeclared__: true });
    if (probe.success) p.push("input schema must be strict (unknown fields refused)");
    if (!def.input.safeParse(def.example).success) p.push("example does not match the input schema");
  } else p.push("an example input is required");
  return p;
}

function jsonSchema(s: z.ZodType): unknown {
  try {
    return z.toJSONSchema(s, { unrepresentable: "any", io: "input" });
  } catch {
    return null;
  }
}

function describe(d: SkillDefinition<any, any>): SkillDescriptor {
  return {
    name: d.name,
    title: d.title,
    description: d.description,
    version: d.version,
    capabilities: d.capabilities.map((c) => ({ name: c, permission: capabilityPermission(c), description: SKILL_CAPABILITIES[c].description })),
    requiredPermissions: [...new Set(d.capabilities.map(capabilityPermission))],
    usesModel: d.usesModel === true,
    auditEvents: [...d.auditEvents],
    inputSchema: jsonSchema(d.input),
    outputSchema: jsonSchema(d.output),
    example: d.example,
    limitations: [...d.limitations],
  };
}
