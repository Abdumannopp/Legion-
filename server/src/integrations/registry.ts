/**
 * Which integrations exist. Available adapters are registered here; planned
 * ones are listed with the contract they will implement, so the catalogue,
 * the API and the documentation describe the same thing.
 *
 * Adding an integration = one file implementing PushAdapter or PullAdapter
 * (types.ts), one register() call, and its manifest — no change to routes,
 * storage, the worker, notifications or tenant isolation.
 */
import type { Adapter, IntegrationManifest, PullAdapter, PushAdapter } from "./types.js";
import { wazuhAdapter } from "./wazuh.js";

const adapters = new Map<string, Adapter>();

export function register(adapter: Adapter): void {
  if (!/^[a-z][a-z0-9_]{1,40}$/.test(adapter.manifest.kind)) throw new Error(`invalid integration kind: ${adapter.manifest.kind}`);
  adapters.set(adapter.manifest.kind, adapter);
}
/** Test hook: remove an adapter registered by a test. */
export function unregister(kind: string): void {
  if (kind !== "wazuh") adapters.delete(kind);
}

export function pushAdapter(kind: string): PushAdapter | null {
  const a = adapters.get(kind);
  return a && a.manifest.inbound === "push" ? (a as PushAdapter) : null;
}
export function pullAdapter(kind: string): PullAdapter | null {
  const a = adapters.get(kind);
  return a && a.manifest.inbound === "pull" ? (a as PullAdapter) : null;
}

register(wazuhAdapter);

/**
 * The roadmap, as contracts. Each is the adapter type it will be, the data it
 * will bring in or the action it will take, and how it authenticates — so the
 * shape of the work is fixed before any of it is written.
 */
const PLANNED: IntegrationManifest[] = [
  {
    kind: "aws", displayName: "AWS", vendor: "Amazon Web Services", status: "planned", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["securityhub.*.amazonaws.com", "sts.amazonaws.com"],
    summary: "Security Hub findings (GuardDuty, Inspector, Macie, Config) in ASFF, polled by UpdatedAt cursor per region.",
    auth: "Cross-account IAM role assumed with an external id (no long-lived keys stored).",
  },
  {
    kind: "azure", displayName: "Microsoft Azure", vendor: "Microsoft", status: "planned", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["management.azure.com", "login.microsoftonline.com"],
    summary: "Microsoft Defender for Cloud alerts per subscription, polled by timeGeneratedUtc.",
    auth: "Entra ID app registration (client credentials), read-only Security Reader role.",
  },
  {
    kind: "gcp", displayName: "Google Cloud", vendor: "Google", status: "planned", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["securitycenter.googleapis.com", "oauth2.googleapis.com"],
    summary: "Security Command Center findings per organisation, polled by eventTime.",
    auth: "Service account with Security Center Findings Viewer (workload identity federation preferred).",
  },
  {
    kind: "github", displayName: "GitHub", vendor: "GitHub", status: "planned", plane: "data", inbound: "push", outbound: [],
    egressHosts: ["api.github.com"],
    summary: "Secret scanning, code scanning and Dependabot alerts from an organisation webhook.",
    auth: "GitHub App; webhook deliveries verified with X-Hub-Signature-256 (HMAC-SHA256 of the raw body).",
  },
  {
    kind: "m365", displayName: "Microsoft 365", vendor: "Microsoft", status: "planned", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["graph.microsoft.com", "login.microsoftonline.com"],
    summary: "Microsoft Graph security alerts_v2 (Defender XDR, Entra ID Protection, Purview), polled by lastUpdateDateTime.",
    auth: "Entra ID app registration with SecurityAlert.Read.All (application permission).",
  },
  {
    kind: "slack", displayName: "Slack", vendor: "Salesforce", status: "planned", plane: "tool", inbound: null, outbound: ["notify"],
    egressHosts: ["slack.com"],
    summary: "Alert notifications to a channel, delivered through the notification outbox like email (retries, dead letters).",
    auth: "Slack app bot token (chat:write), sealed per connection.",
  },
  {
    kind: "mcp", displayName: "MCP servers", vendor: "Model Context Protocol", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: [],
    summary: "Tools AI agents may call, each pinned by definition hash, scanned for tool poisoning and authorized per call by the agent firewall.",
    auth: "Configured in the firewall policy (mcp.servers); tool servers verify single-use tickets.",
  },
  {
    kind: "a2a", displayName: "Agent-to-agent", vendor: "Legion", status: "available", plane: "tool", inbound: null, outbound: ["respond"],
    egressHosts: [],
    summary: "Requests between a workspace's agents, relayed and bounded by the agent firewall with the authority carried down the chain.",
    auth: "Agent identities and short-lived tokens; allowlisted agent pairs in the firewall policy.",
  },
];

export function catalogue(): IntegrationManifest[] {
  const live = [...adapters.values()].map((a) => a.manifest);
  const planned = PLANNED.filter((p) => !adapters.has(p.kind));
  return [...live, ...planned].sort((a, b) => (a.status === b.status ? a.displayName.localeCompare(b.displayName) : a.status === "available" ? -1 : 1));
}
