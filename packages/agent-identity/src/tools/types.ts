import { z } from "zod";
import type { Permission } from "../permissions.js";
import type { RiskFactor, RuleHit, Sensitivity } from "../firewall/types.js";

/*
 * Every tool call an AI agent wants to make, in one of ten strict shapes.
 * Unknown fields, unknown operations and unknown tool kinds are refused —
 * a call Legion cannot understand is a call Legion cannot approve.
 */

export const TOOL_KINDS = ["browser", "http", "database", "files", "shell", "email", "github", "slack", "mcp", "cloud"] as const;
export type ToolKind = (typeof TOOL_KINDS)[number];

const text = (max: number) => z.string().max(max);
const url = z.string().min(1).max(4096);
const json = z.unknown();

export const browserCall = z.strictObject({
  kind: z.literal("browser"),
  operation: z.enum(["navigate", "read_page", "screenshot", "click", "fill_form", "submit_form", "download", "upload", "execute_script"]),
  url,
  selector: text(500).optional(),
  fields: z.record(text(200), text(2000)).optional(),
  filename: text(255).optional(),
  uploadPath: text(4096).optional(),
  script: text(20_000).optional(),
});

export const httpCall = z.strictObject({
  kind: z.literal("http"),
  operation: z.literal("request"),
  method: z.string().max(10),
  url,
  headers: z.record(text(100), text(8000)).optional(),
  body: text(1_048_576).optional(),
});

export const databaseCall = z.strictObject({
  kind: z.literal("database"),
  operation: z.literal("query"),
  sql: text(20_000),
  params: z.array(z.union([z.string().max(10_000), z.number(), z.boolean(), z.null()])).max(100).default([]),
});

export const filesCall = z.strictObject({
  kind: z.literal("files"),
  operation: z.enum(["read", "list", "write", "delete", "move"]),
  path: text(4096),
  destinationPath: text(4096).optional(),
  content: text(5_242_880).optional(),
  recursive: z.boolean().optional(),
});

export const shellCall = z.strictObject({
  kind: z.literal("shell"),
  operation: z.literal("execute"),
  /** A bare command name. No path, no shell string — argument list only. */
  command: text(100),
  args: z.array(text(4096)).max(100).default([]),
  cwd: text(4096).optional(),
});

const address = z.string().max(320);
export const emailCall = z.strictObject({
  kind: z.literal("email"),
  operation: z.enum(["read", "search", "send", "reply", "forward", "delete", "move"]),
  from: address.optional(),
  to: z.array(address).max(500).default([]),
  cc: z.array(address).max(500).default([]),
  bcc: z.array(address).max(500).default([]),
  subject: text(1000).optional(),
  body: text(1_048_576).optional(),
  attachments: z.array(z.strictObject({ filename: text(255), size: z.number().int().min(0) })).max(50).default([]),
  messageIds: z.array(text(500)).max(1000).default([]),
  query: text(2000).optional(),
});

export const githubCall = z.strictObject({
  kind: z.literal("github"),
  operation: z.enum([
    "read_repo", "read_file", "list_issues", "read_issue", "read_pr", "search_code",
    "create_issue", "comment", "update_issue", "label", "create_branch", "push_commit", "create_pr",
    "merge_pr", "delete_branch", "delete_repo", "change_visibility", "update_settings", "add_collaborator",
    "remove_collaborator", "create_deploy_key", "manage_secrets", "manage_webhooks", "update_branch_protection",
    "create_release", "workflow_dispatch",
  ]),
  repo: text(200),
  branch: text(255).optional(),
  force: z.boolean().optional(),
  files: z.array(z.strictObject({ path: text(1000), content: text(1_048_576).optional() })).max(200).default([]),
  title: text(1000).optional(),
  body: text(262_144).optional(),
});

export const slackCall = z.strictObject({
  kind: z.literal("slack"),
  operation: z.enum(["read_channel", "post_message", "reply_thread", "react", "upload_file", "dm_user", "invite_user", "create_channel", "archive_channel", "set_topic"]),
  channel: text(100),
  text: text(40_000).optional(),
  filename: text(255).optional(),
  userId: text(100).optional(),
});

export const mcpCall = z.strictObject({
  kind: z.literal("mcp"),
  operation: z.literal("call_tool"),
  server: text(100),
  /** The tool definition the MCP server advertises right now — hashed and compared with the approved one. */
  definition: z.strictObject({ name: text(100), description: text(20_000).optional(), inputSchema: json.optional() }),
  args: z.record(z.string(), json).default({}),
});

export const cloudCall = z.strictObject({
  kind: z.literal("cloud"),
  operation: z.literal("invoke"),
  provider: z.enum(["aws", "gcp", "azure"]),
  account: text(100),
  region: text(40).optional(),
  /** Provider action, e.g. "ec2:TerminateInstances", "compute.instances.delete", "Microsoft.Compute/virtualMachines/delete". */
  action: text(300),
  resource: text(2048).optional(),
  params: z.record(z.string(), json).default({}),
});

export const toolCallSchema = z.discriminatedUnion("kind", [
  browserCall, httpCall, databaseCall, filesCall, shellCall, emailCall, githubCall, slackCall, mcpCall, cloudCall,
]);
export type ToolCall = z.infer<typeof toolCallSchema>;
export type ToolCallInput = z.input<typeof toolCallSchema>;

/** The deterministic reading of one tool call. */
export interface ToolAnalysis {
  toolKind: ToolKind | "unknown";
  operation: string;
  /** What is acted on: URL, table list, path, repo, channel, recipients, cloud resource. */
  target: string;
  /** Where the effect lands, normalised for the logs and the firewall. */
  destination: string;
  permission: Permission | null;
  sensitivity: Sensitivity;
  changesState: boolean;
  externalEffect: boolean;
  /** Always audited, even when allowed (sending, pushing, running, cloud writes…). */
  highRisk: boolean;
  hits: RuleHit[];
  factors: RiskFactor[];
}
