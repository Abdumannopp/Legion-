/**
 * Which plain-language explanation fits a firewall rule. Rule ids are
 * technical ("sql.foreign_tenant", "a2a.laundering"); people get one of a
 * small set of explanations (t.agents.rules) — what happened and what to do —
 * chosen by the rule's family. The exact rule id stays visible under
 * "technical details" for whoever needs it.
 */
export type RuleGroup =
  | "otherWorkspace" | "secret" | "injection" | "toolDefinition" | "destination" | "database" | "command"
  | "files" | "notPermitted" | "needsApproval" | "unusual" | "notActive" | "agentToAgent" | "unknownTool" | "policy";

// Checked in order: the most specific (and most serious) explanation wins.
const EXACT: Record<string, RuleGroup> = {
  "a2a.cross_tenant": "otherWorkspace",
  "sql.foreign_tenant": "otherWorkspace",
  "sql.tenant_move": "otherWorkspace",
  "sql.tenant_scope": "otherWorkspace",
  "sql.tenant_scope_or": "otherWorkspace",
  "db.tenant_filter": "otherWorkspace",
  "egress.secret_in_payload": "secret",
  "egress.credentials_in_url": "secret",
  "a2a.secret_in_payload": "secret",
  "http.legion_secret": "secret",
  "shell.secret_in_args": "secret",
  "files.secret_written": "secret",
  "a2a.injection_payload": "injection",
  "a2a.hidden_tool_request": "injection",
  "a2a.hidden_tool_text": "injection",
  "a2a.hidden_tool_delegation": "injection",
  "a2a.laundering": "injection",
  "confirm.permission": "needsApproval",
  "risk.score_confirm": "needsApproval",
  "permission.not_granted": "notPermitted",
  "tool.unknown": "unknownTool",
};

const PREFIX: [string, RuleGroup][] = [
  ["tenant.", "otherWorkspace"],
  ["content.", "injection"],
  ["poison.", "toolDefinition"],
  ["mcp.", "toolDefinition"],
  ["egress.", "destination"],
  ["http.", "destination"],
  ["browser.", "destination"],
  ["sql.", "database"],
  ["db.", "database"],
  ["shell.", "command"],
  ["cmd.", "command"],
  ["file.", "files"],
  ["files.", "files"],
  ["delegation.", "notPermitted"],
  ["approval.", "needsApproval"],
  ["risk.", "unusual"],
  ["behavior.", "unusual"],
  ["velocity.", "unusual"],
  ["identity.", "notActive"],
  ["a2a.", "agentToAgent"],
  ["tool.", "unknownTool"],
];

export function ruleGroup(ruleId: string): RuleGroup {
  if (EXACT[ruleId]) return EXACT[ruleId];
  return PREFIX.find(([p]) => ruleId.startsWith(p))?.[1] ?? "policy";
}

/** The explanation for a set of rule hits: the first one that refused, else the first. */
export function primaryRule(hits: { id: string; effect: string }[]): string | null {
  return (hits.find((h) => h.effect !== "WARN" && h.effect !== "ALLOW") ?? hits[0])?.id ?? null;
}

/**
 * Agent presets for the "add an agent" form. Read-only first: an agent starts
 * with the least it needs, and anything that changes data asks first.
 */
export const AGENT_PRESETS = {
  readOnly: ["alerts:read", "assets:read", "stats:read", "vulnerabilities:read"],
  triage: ["alerts:read", "assets:read", "stats:read", "vulnerabilities:read", "alerts:comment", "alerts:update_status"],
} as const;
