/**
 * Which integrations exist. Available adapters are registered here; planned
 * ones are listed with the contract they will implement, so the catalogue,
 * the API and the documentation describe the same thing.
 *
 * Adding an integration = one file implementing PushAdapter or PullAdapter
 * (types.ts), one register() call, and its manifest — no change to routes,
 * storage, the worker, notifications or tenant isolation.
 */
import type { Adapter, IntegrationManifest, OutboundAdapter, PullAdapter, PushAdapter } from "./types.js";
import { azureAdapter } from "./azure.js";
import { gcpAdapter } from "./gcp.js";
import { oktaAdapter } from "./okta.js";
import { pagerdutyAdapter } from "./pagerduty.js";
import { teamsAdapter } from "./teams.js";
import { githubAdapter } from "./github.js";
import { guarddutyAdapter } from "./guardduty.js";
import { jiraAdapter } from "./jira.js";
import { m365Adapter } from "./m365.js";
import { slackAdapter } from "./slack.js";
import { cefAdapter } from "./cef.js";
import { genericWebhookAdapter } from "./generic.js";
import { wazuhAdapter } from "./wazuh.js";
import { crowdstrikeAdapter } from "./crowdstrike.js";
import { sentineloneAdapter } from "./sentinelone.js";
import { msentinelAdapter } from "./msentinel.js";
import { securityhubAdapter } from "./securityhub.js";
import { elasticAdapter } from "./elastic.js";
import { splunkAdapter } from "./splunk.js";
import { cloudflareAdapter } from "./cloudflare.js";
import { gworkspaceAdapter } from "./gworkspace.js";
import { servicenowAdapter } from "./servicenow.js";
import { opsgenieAdapter } from "./opsgenie.js";

const adapters = new Map<string, Adapter>();
const BUILT_IN = new Set(["wazuh", "generic_webhook", "cef", "slack", "jira", "m365", "guardduty", "azure", "gcp", "okta", "pagerduty", "teams", "github",
  "crowdstrike", "sentinelone", "msentinel", "securityhub", "elastic", "splunk", "cloudflare", "gworkspace", "servicenow", "opsgenie"]);

export function register(adapter: Adapter): void {
  if (!/^[a-z][a-z0-9_]{1,40}$/.test(adapter.manifest.kind)) throw new Error(`invalid integration kind: ${adapter.manifest.kind}`);
  adapters.set(adapter.manifest.kind, adapter);
}
/** Test hook: remove an adapter registered by a test. */
export function unregister(kind: string): void {
  if (!BUILT_IN.has(kind)) adapters.delete(kind);
}

export function pushAdapter(kind: string): PushAdapter | null {
  const a = adapters.get(kind);
  return a && a.manifest.inbound === "push" ? (a as PushAdapter) : null;
}
export function pullAdapter(kind: string): PullAdapter | null {
  const a = adapters.get(kind);
  return a && a.manifest.inbound === "pull" ? (a as PullAdapter) : null;
}

export function outboundAdapter(kind: string): OutboundAdapter | null {
  const a = adapters.get(kind);
  return a && a.manifest.inbound === null && "deliver" in a ? (a as OutboundAdapter) : null;
}
/** A push adapter that is configured as a connection with its own secret (GitHub: the webhook secret). */
export function connectedPushAdapter(kind: string): (PushAdapter & { configSchema: import("zod").ZodType<Record<string, unknown>>; secretFields: string[] }) | null {
  const a = adapters.get(kind) as (PushAdapter & { configSchema?: unknown; secretFields?: unknown }) | undefined;
  return a && a.manifest.inbound === "push" && a.configSchema && Array.isArray(a.secretFields) ? (a as never) : null;
}
/** Kinds the poll worker may claim: only real pull adapters. */
export function pullKinds(): string[] { return [...adapters.values()].filter((a) => a.manifest.inbound === "pull").map((a) => a.manifest.kind); }
/** Kinds that receive alerts (notify/ticket). */
export function outboundKinds(): string[] { return [...adapters.values()].filter((a) => "deliver" in a).map((a) => a.manifest.kind); }

register(wazuhAdapter);
register(genericWebhookAdapter);
register(cefAdapter);
register(slackAdapter);
register(jiraAdapter);
register(m365Adapter);
register(guarddutyAdapter);
register(githubAdapter);
register(teamsAdapter);
register(pagerdutyAdapter);
register(oktaAdapter);
register(gcpAdapter);
register(azureAdapter);
register(crowdstrikeAdapter);
register(sentineloneAdapter);
register(msentinelAdapter);
register(securityhubAdapter);
register(elasticAdapter);
register(splunkAdapter);
register(cloudflareAdapter);
register(gworkspaceAdapter);
register(servicenowAdapter);
register(opsgenieAdapter);

/**
 * The roadmap, as contracts. Each is the adapter type it will be, the data it
 * will bring in or the action it will take, and how it authenticates — so the
 * shape of the work is fixed before any of it is written.
 */
const PLANNED: IntegrationManifest[] = [
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
