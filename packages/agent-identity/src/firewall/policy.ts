import path from "node:path";
import type { Pool, PoolClient } from "pg";
import { z } from "zod";
import { ALL_PERMISSIONS, type Permission } from "../permissions.js";
import { isBlockedHostName, parseIpLiteral, isNonPublicIp } from "./destinations.js";
import { DENIED_COMMANDS } from "../tools/shell.js";

/**
 * Tables no machine identity may touch through the firewall, whatever a
 * tenant's policy says: identities, secrets, sessions and the logs that
 * record what agents did. Checked at evaluation AND refused at policy save.
 */
export const PROTECTED_TABLES = new Set([
  "users", "tenants", "refresh_tokens", "mfa_used_counters", "sessions",
  "machine_identities", "machine_credentials", "machine_tokens", "agent_delegations",
  "principal_audit_log", "firewall_decisions", "firewall_policies", "audit_log",
  // Everything else this module keeps: evidence, tickets, messages, state.
  "agent_messages", "content_ingestion_log", "content_risk_acknowledgements", "tool_call_audit", "tool_call_tickets",
  "agent_behavior_profiles", "agent_behavior_state", "agent_behavior_events", "security_events", "security_notifications",
  "agent_interactions", "agent_trust_graph_snapshots", "agent_skill_assignments", "agent_action_approvals",
]);

/** Tool permissions that act on the world: approval per action, by default. */
export const DEFAULT_CONFIRM_PERMISSIONS: readonly Permission[] = [
  "tool.browser:write", "tool.http:write", "tool.database:write", "tool.files:write", "tool.shell:execute",
  "tool.email:write", "tool.github:write", "tool.slack:write", "tool.mcp:write", "tool.cloud:write",
];

/**
 * Refusals that say more about the agent than about the action: it is
 * reaching into another organisation, laundering permissions through another
 * agent, spreading a prompt-injection payload, or trying to carry
 * credentials out. The action is refused either way; these also take the
 * agent offline until a person looks.
 */
export const DEFAULT_QUARANTINE_RULES: readonly string[] = [
  "tenant.mismatch", "a2a.cross_tenant", "sql.foreign_tenant", "a2a.laundering", "a2a.injection_payload", "a2a.hidden_tool_request",
  "egress.secret_in_payload", "a2a.secret_in_payload",
];

/** Trying to send Legion's own credentials out: treated as a confirmed compromise. */
export const DEFAULT_KILL_RULES: readonly string[] = ["http.legion_secret"];

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
      /** Agents a request may pass through (A→B is 1 hop, A→B→C is 2). */
      maxDepth: z.number().int().min(1).max(4).default(2),
      /** Requests one interaction (a root request and everything forwarded from it) may produce. */
      maxMessagesPerInteraction: z.number().int().min(1).max(100).default(10),
      /** Agents one received request may be forwarded to. */
      maxFanOut: z.number().int().min(1).max(20).default(3),
      /**
       * After an agent reads a request, how long its tool calls that match the
       * request's content but do not cite it are treated as hidden delegation.
       * 0 disables the correlation.
       */
      influenceWindowSeconds: z.number().int().min(0).max(86_400).default(900),
      /** Tool instructions hidden in a request's text: block, or allow with a warning. */
      hiddenToolText: z.enum(["block", "warn"]).default("block"),
      allow: z
        .array(z.strictObject({
          from: z.uuid(),
          to: z.uuid(),
          permissions: z.array(permission).max(20).optional(),
        }))
        .max(500)
        .default([]),
    })
    .default({ maxDepth: 2, maxMessagesPerInteraction: 10, maxFanOut: 3, influenceWindowSeconds: 900, hiddenToolText: "block", allow: [] }),
  /** Tool gateway (src/tools). Everything closed until opened here. */
  toolSecurity: z
    .strictObject({
      /** Allowed calls at or above this risk score are written to the tool audit log. */
      auditRiskThreshold: z.number().int().min(1).max(100).default(40),
      /** Lifetime of the single-use ticket a tool server verifies. */
      ticketTtlSeconds: z.number().int().min(10).max(600).default(60),
      browser: z.strictObject({ allowDownloads: z.boolean().default(false) }).default({ allowDownloads: false }),
      shell: z
        .strictObject({
          commands: z
            .record(
              z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/i, "a bare command name, no path"),
              z.strictObject({
                /** If set, the first argument must be one of these (e.g. git: status, log, diff). */
                subcommands: z.array(z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/i)).max(50).optional(),
                maxArgs: z.number().int().min(0).max(100).default(30),
              }),
            )
            .refine((c) => Object.keys(c).every((name) => !DENIED_COMMANDS.has(name.toLowerCase())),
              "interpreters, privilege, network and destructive commands cannot be allowed")
            .default({}),
        })
        .default({ commands: {} }),
      email: z
        .strictObject({
          allowedRecipientDomains: z.array(z.string().toLowerCase().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/)).max(100).default([]),
          allowedSenders: z.array(z.email().toLowerCase()).max(20).default([]),
          maxRecipients: z.number().int().min(1).max(100).default(10),
          allowAttachments: z.boolean().default(false),
        })
        .default({ allowedRecipientDomains: [], allowedSenders: [], maxRecipients: 10, allowAttachments: false }),
      github: z
        .strictObject({
          repos: z.record(z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "owner/repo"), z.enum(["read", "write"])).default({}),
        })
        .default({ repos: {} }),
      slack: z
        .strictObject({
          channels: z.record(z.string().regex(/^[A-Z0-9]{6,20}$/, "a Slack channel id"), z.enum(["read", "write"])).default({}),
          allowMassMentions: z.boolean().default(false),
          allowDirectMessages: z.boolean().default(false),
          allowUploads: z.boolean().default(false),
        })
        .default({ channels: {}, allowMassMentions: false, allowDirectMessages: false, allowUploads: false }),
      cloud: z
        .strictObject({
          accounts: z
            .array(z.strictObject({
              provider: z.enum(["aws", "gcp", "azure"]),
              account: z.string().regex(/^[A-Za-z0-9_.:-]{1,100}$/),
              regions: z.array(z.string().regex(/^[a-z0-9-]{2,40}$/)).max(40).default([]),
              access: z.enum(["read", "write"]),
            }))
            .max(50)
            .default([]),
          /** Delete/terminate/destroy actions. Identity, logging and public-exposure changes stay blocked regardless. */
          allowDestructive: z.boolean().default(false),
        })
        .default({ accounts: [], allowDestructive: false }),
    })
    .default({
      auditRiskThreshold: 40,
      ticketTtlSeconds: 60,
      browser: { allowDownloads: false },
      shell: { commands: {} },
      email: { allowedRecipientDomains: [], allowedSenders: [], maxRecipients: 10, allowAttachments: false },
      github: { repos: {} },
      slack: { channels: {}, allowMassMentions: false, allowDirectMessages: false, allowUploads: false },
      cloud: { accounts: [], allowDestructive: false },
    }),
  /** Runtime behaviour monitoring (src/behavior). */
  behavior: z
    .strictObject({
      /** The recent activity compared with the baseline. */
      windowMinutes: z.number().int().min(5).max(1440).default(60),
      /** How much history forms the baseline. */
      baselineDays: z.number().int().min(1).max(90).default(14),
      /** Before this much history, nothing counts as "new" or "unusual" — only intent indicators. */
      minBaselineEvents: z.number().int().min(10).max(100_000).default(100),
      minBaselineDays: z.number().min(0).max(30).default(2),
      /** Suspend the identity when it reaches CRITICAL (containment of unsafe actions happens regardless). */
      autoSuspendOnCritical: z.boolean().default(false),
    })
    .default({ windowMinutes: 60, baselineDays: 14, minBaselineEvents: 100, minBaselineDays: 2, autoSuspendOnCritical: false }),
  /**
   * What the firewall does beyond BLOCK. Everything here only makes a
   * decision stricter; nothing can relax a hard rule.
   */
  responses: z
    .strictObject({
      confirm: z
        .strictObject({
          /**
           * Permissions an agent may hold but never use without a person
           * approving the specific action first. By default every tool
           * permission that acts on the world: AI does not send, push, run,
           * write or delete on its own.
           */
          permissions: z.array(permission).max(ALL_PERMISSIONS.length).default([...DEFAULT_CONFIRM_PERMISSIONS]),
          /**
           * Otherwise-allowed actions at or above this risk score also need
           * approval. 101 = off (the default: the band between warnAt and
           * blockAt stays a visible WARN, as before; lower it to ask instead).
           */
          riskAt: z.number().int().min(1).max(101).default(101),
          /** How long a request for approval stays open, and an approval stays usable. */
          ttlSeconds: z.number().int().min(60).max(86_400).default(900),
          /** Open requests per agent; beyond this the agent is refused instead of queueing more. */
          maxPendingPerAgent: z.number().int().min(1).max(500).default(20),
        })
        .default({ permissions: [...DEFAULT_CONFIRM_PERMISSIONS], riskAt: 101, ttlSeconds: 900, maxPendingPerAgent: 20 }),
      /** Rules whose refusal also suspends the agent until a person reviews it. */
      quarantineOn: z.array(identifier).max(200).default([...DEFAULT_QUARANTINE_RULES]),
      /** Rules whose refusal kills the agent: suspended, credentials and delegations revoked. */
      killOn: z.array(identifier).max(200).default([...DEFAULT_KILL_RULES]),
    })
    .default({
      confirm: { permissions: [...DEFAULT_CONFIRM_PERMISSIONS], riskAt: 101, ttlSeconds: 900, maxPendingPerAgent: 20 },
      quarantineOn: [...DEFAULT_QUARANTINE_RULES],
      killOn: [...DEFAULT_KILL_RULES],
    }),
  promptInjection: z
    .strictObject({
      /** How long suspicious (not malicious) content keeps raising an agent's risk. Malicious content counts until reviewed. */
      suspiciousWindowSeconds: z.number().int().min(60).max(7 * 86_400).default(3_600),
      /**
       * After an agent reads ANY external content, how long it may only read
       * — not change state, act outside Legion, touch confidential data or
       * message other agents — unless a person reviews what it read. Applies
       * whatever the classifier said: a word list cannot be what stands
       * between attacker-written text and an agent's permissions.
       * 0 turns the hold off (the agent then acts on content the classifier
       * calls clean, which is how a realistic poisoned alert got through).
       */
      untrustedHoldSeconds: z.number().int().min(0).max(7 * 86_400).default(900),
    })
    .default({ suspiciousWindowSeconds: 3_600, untrustedHoldSeconds: 900 }),
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
