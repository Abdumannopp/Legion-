/**
 * The tool plane's contract for ACTIONS: which connector could carry out which
 * catalog action, in which systems. This is the foundation the action engine
 * will use when live execution is introduced — and in v0 it deliberately
 * cannot execute anything:
 *
 *  - an ActionConnector has `preview` (read-only: what would be sent where)
 *    and no execute method; the type system and a test both enforce that;
 *  - every capability names a catalog action (unknown ids are refused at
 *    registration) and is marked `simulation_only`;
 *  - egress is declared per connector (same rule as the data plane:
 *    adapterFetch refuses undeclared hosts).
 *
 * Adding live execution later = a new capability mode, a live executor behind
 * the action engine's approval consumption, a migration that allows
 * execution_mode 'live', and a policy decision — not a change here alone.
 */
import { queryAll } from "../db/pool.js";
import { catalogEntry } from "../policy/catalog.js";

export interface ActionCapability {
  action_id: string;
  /** v0: every capability is simulation-only. */
  mode: "simulation_only";
}

export interface ActionConnectorManifest {
  /** Matches integration_connections.kind for a workspace that has connected it. */
  kind: string;
  displayName: string;
  status: "available" | "planned";
  capabilities: ActionCapability[];
  egressHosts: string[];
  auth: string;
}

export interface ActionPreview {
  connector: string;
  action_id: string;
  /** Human-readable: the request that would be sent, without secrets. */
  would_send: string;
  egress_host: string | null;
}

/** v0 connectors can describe an action; there is intentionally nothing that performs it. */
export interface ActionConnector {
  manifest: ActionConnectorManifest;
  preview(input: Record<string, unknown>, actionId: string): ActionPreview;
}

const connectors = new Map<string, ActionConnector>();

export function registerActionConnector(c: ActionConnector): void {
  if (!/^[a-z][a-z0-9_]{1,40}$/.test(c.manifest.kind)) throw new Error(`invalid connector kind: ${c.manifest.kind}`);
  for (const cap of c.manifest.capabilities) {
    if (!catalogEntry(cap.action_id)) throw new Error(`connector ${c.manifest.kind}: unknown action ${cap.action_id}`);
    if (cap.mode !== "simulation_only") throw new Error(`connector ${c.manifest.kind}: only simulation_only capabilities exist in v0`);
  }
  if ("execute" in c || "run" in c || "perform" in c) throw new Error(`connector ${c.manifest.kind}: v0 connectors cannot execute`);
  connectors.set(c.manifest.kind, Object.freeze(c));
}

const describe = (kind: string, host: string) => (input: Record<string, unknown>, actionId: string): ActionPreview => ({
  connector: kind, action_id: actionId, egress_host: host,
  would_send: actionId === "account.disable" ? `disable account ${String(input.account)}`
    : actionId === "host.isolate" ? `isolate host ${String(input.host)}`
    : actionId === "ip.block" ? `add ${String(input.ip)} to the blocklist for ${String(input.minutes)} minutes`
    : actionId,
});

registerActionConnector({
  manifest: { kind: "wazuh", displayName: "Wazuh active response", status: "available", capabilities: [{ action_id: "ip.block", mode: "simulation_only" }, { action_id: "ip.unblock", mode: "simulation_only" }],
    egressHosts: [], auth: "Wazuh pulls Legion's blocklist with a signed credential (WAZUH.md); Legion makes no outbound call" },
  preview: (input, actionId) => ({ ...describe("wazuh", "")(input, actionId), egress_host: null }),
});
registerActionConnector({
  manifest: { kind: "entra", displayName: "Microsoft Entra ID", status: "planned", capabilities: [{ action_id: "account.disable", mode: "simulation_only" }],
    egressHosts: ["graph.microsoft.com"], auth: "App registration, User.EnableDisableAccount.All (application), approved per action" },
  preview: describe("entra", "graph.microsoft.com"),
});
registerActionConnector({
  manifest: { kind: "okta", displayName: "Okta", status: "planned", capabilities: [{ action_id: "account.disable", mode: "simulation_only" }],
    egressHosts: ["*.okta.com"], auth: "OAuth service app with okta.users.manage, approved per action" },
  preview: describe("okta", "*.okta.com"),
});
registerActionConnector({
  manifest: { kind: "google", displayName: "Google Workspace", status: "planned", capabilities: [{ action_id: "account.disable", mode: "simulation_only" }],
    egressHosts: ["admin.googleapis.com"], auth: "Service account with domain-wide delegation, admin.directory.user scope" },
  preview: describe("google", "admin.googleapis.com"),
});
registerActionConnector({
  manifest: { kind: "defender_endpoint", displayName: "Microsoft Defender for Endpoint", status: "planned", capabilities: [{ action_id: "host.isolate", mode: "simulation_only" }],
    egressHosts: ["api.securitycenter.microsoft.com"], auth: "App registration, Machine.Isolate (application)" },
  preview: describe("defender_endpoint", "api.securitycenter.microsoft.com"),
});

export function actionConnectors(): ActionConnectorManifest[] {
  return [...connectors.values()].map((c) => c.manifest);
}

export function connectorsFor(actionId: string): ActionConnector[] {
  return [...connectors.values()].filter((c) => c.manifest.capabilities.some((cap) => cap.action_id === actionId));
}

/** Which connectors for this action the workspace has actually connected (active). */
export async function connectedFor(tenantId: string, actionId: string): Promise<string[]> {
  const kinds = connectorsFor(actionId).map((c) => c.manifest.kind);
  if (!kinds.length) return [];
  const rows = await queryAll<{ kind: string }>(
    "SELECT DISTINCT kind FROM integration_connections WHERE tenant_id = $1 AND status = 'active' AND kind = ANY($2::text[]) ORDER BY kind",
    [tenantId, kinds],
  );
  return rows.map((r) => r.kind);
}

/** Read-only previews from every connector able to perform the action. */
export function previews(actionId: string, input: Record<string, unknown>): ActionPreview[] {
  return connectorsFor(actionId).map((c) => c.preview(input, actionId));
}
