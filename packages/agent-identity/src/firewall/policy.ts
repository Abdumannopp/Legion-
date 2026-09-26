import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { z } from "zod";
import { ALL_PERMISSIONS, type Permission } from "../permissions.js";
import { isBlockedHostName, parseIpLiteral, isNonPublicIp } from "./destinations.js";

/**
 * Tables no machine identity may touch through the firewall, whatever a
 * tenant's policy says: identities, secrets, sessions and the logs that
 * record what agents did. Checked at evaluation AND refused at policy save.
 */
export const PROTECTED_TABLES = new Set([
  "users", "tenants", "refresh_tokens", "mfa_used_counters", "sessions",
  "machine_identities", "machine_credentials", "machine_tokens", "agent_delegations",
  "principal_audit_log", "firewall_decisions", "firewall_policies", "audit_log",
]);

const permission = z.enum(ALL_PERMISSIONS as unknown as [Permission, ...Permission[]]);
const sensitivity = z.enum(["public", "internal", "confidential", "restricted"]);
const sideEffects = z.enum(["none", "internal", "external"]);
const identifier = z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/, "letters, digits, _ . : - only");
const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/);

const hostPattern = z
  .string()
  .toLowerCase()
  .regex(/^(\*\.)?[a-z0-9.-]{1,253}$/, "a hostname or *.domain")
  .refine((h) => h.replace(/^\*\./, "").includes("."), "must be a full domain, not a bare name or *")
  .refine((h) => !isBlockedHostName(h.replace(/^\*\./, "")), "internal names cannot be allowlisted")
  .refine((h) => {
    const ip = parseIpLiteral(h);
    return !ip || !isNonPublicIp(ip);
  }, "private, loopback and link-local addresses cannot be allowlisted");

const toolSpec = z.strictObject({
  permission: permission.nullable(),
  sensitivity: sensitivity.default("internal"),
  sideEffects: sideEffects.default("none"),
  /** If set, any other argument name is refused. */
  allowedArgs: z.array(identifier).max(50).optional(),
  maxArgBytes: z.number().int().min(1).max(1_048_576).default(16_384),
});

export const policySchema = z.strictObject({
  /** monitor: soft blocks are logged as WARN (wouldBlock). Hard blocks always block. */
  mode: z.enum(["enforce", "monitor"]).default("enforce"),
  thresholds: z
    .strictObject({ warnAt: z.number().int().min(1).max(100), blockAt: z.number().int().min(1).max(101) })
    .refine((t) => t.warnAt < t.blockAt, "warnAt must be below blockAt")
    .default({ warnAt: 40, blockAt: 70 }),
  velocity: z
    .strictObject({ warnPerMinute: z.number().int().min(1), blockPerMinute: z.number().int().min(1) })
    .refine((v) => v.warnPerMinute < v.blockPerMinute, "warnPerMinute must be below blockPerMinute")
    .default({ warnPerMinute: 120, blockPerMinute: 600 }),
  /** Sensitivity per resource type, overriding what a route declares only upwards. */
  resources: z.record(identifier, sensitivity).default({}),
  egress: z
    .strictObject({
      allowedHosts: z.array(hostPattern).max(200).default([]),
      allowedPorts: z.array(z.number().int().min(1).max(65535)).max(20).default([443]),
    })
    .default({ allowedHosts: [], allowedPorts: [443] }),
  files: z
    .strictObject({
      roots: z
        .array(z.strictObject({
          path: z.string().refine((p) => path.isAbsolute(p) && path.resolve(p) !== path.parse(p).root, "absolute, and not the filesystem root"),
          access: z.enum(["read", "readwrite"]),
        }))
        .max(20)
        .default([]),
    })
    .default({ roots: [] }),
  database: z
    .strictObject({
      tables: z
        .record(identifier, z.array(z.enum(["select", "insert", "update", "delete"])).max(4))
        .refine((t) => Object.keys(t).every((name) => !PROTECTED_TABLES.has(name.toLowerCase())), "protected tables cannot be opened to machines")
        .default({}),
      maxRows: z.number().int().min(1).max(100_000).default(1000),
    })
    .default({ tables: {}, maxRows: 1000 }),
  tools: z.record(identifier, toolSpec).default({}),
  mcp: z
    .strictObject({
      servers: z
        .record(identifier, z.strictObject({
          tools: z.record(identifier, toolSpec.extend({ sha256: sha256Hex })),
        }))
        .default({}),
    })
    .default({ servers: {} }),
  agentMessages: z
    .strictObject({
      maxDepth: z.number().int().min(1).max(4).default(2),
      allow: z
        .array(z.strictObject({
          from: z.uuid(),
          to: z.uuid(),
          permissions: z.array(permission).max(20).optional(),
        }))
        .max(500)
        .default([]),
    })
    .default({ maxDepth: 2, allow: [] }),
});

export type FirewallPolicy = z.infer<typeof policySchema>;
export const DEFAULT_POLICY: FirewallPolicy = policySchema.parse({});

export interface VersionedPolicy {
  version: number;
  policy: FirewallPolicy;
}

/** Latest policy per tenant, versioned and append-only; cached briefly per instance. */
export class PolicyStore {
  private cache = new Map<string, { at: number; value: VersionedPolicy }>();
  constructor(private readonly pool: Pool, private readonly ttlMs = 5_000) {}

  async get(tenantId: string): Promise<VersionedPolicy> {
    const hit = this.cache.get(tenantId);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.value;
    const res = await this.pool.query(
      "SELECT version, policy FROM firewall_policies WHERE tenant_id = $1 ORDER BY version DESC LIMIT 1",
      [tenantId],
    );
    // Stored policies were validated on save; parse again so a hand-edited row cannot smuggle in bad values.
    const value: VersionedPolicy = res.rows[0]
      ? { version: res.rows[0].version, policy: policySchema.parse(res.rows[0].policy) }
      : { version: 0, policy: DEFAULT_POLICY };
    this.cache.set(tenantId, { at: Date.now(), value });
    return value;
  }

  async put(client: PoolClient, tenantId: string, policy: FirewallPolicy, createdBy: string): Promise<VersionedPolicy> {
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`firewall_policies:${tenantId}`]);
    const res = await client.query(
      `INSERT INTO firewall_policies (tenant_id, version, policy, created_by)
       SELECT $1, COALESCE(MAX(version), 0) + 1, $2, $3 FROM firewall_policies WHERE tenant_id = $1
       RETURNING version`,
      [tenantId, JSON.stringify(policy), createdBy],
    );
    this.cache.delete(tenantId);
    return { version: res.rows[0].version, policy };
  }

  invalidate(tenantId: string): void {
    this.cache.delete(tenantId);
  }
}
