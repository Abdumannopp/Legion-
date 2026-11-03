import type { Permission } from "../permissions.js";
import { TOOL_KINDS, toolCallSchema, type ToolCall } from "../tools/types.js";
import type { ActionRequest, Authority } from "../firewall/types.js";

/*
 * Hidden tool delegation: one agent getting another to use a tool without
 * that tool ever appearing in what the firewall checked. Two ways in:
 *
 *   1. In the request itself: a tool call (structured, or spelled out in
 *      text) inside the payload of a request that asks for something else.
 *      Checked when the request is sent (findToolRequests).
 *   2. After the request: the recipient reads it, then makes a tool call
 *      that matches the request's content without citing the request, so
 *      the request's (narrower) authority never applies. Checked on every
 *      uncited tool call (matchRecentRequests).
 *
 * Both are deterministic. Neither needs to understand the text: (1) looks
 * for the shapes of tool calls and command lines, (2) for the tool call's
 * specific target — a host, a channel, a table, a command — in text the
 * agent was just given.
 */

export interface PayloadToolFinding {
  /** structured: a tool-call object; text: tool instructions in prose. */
  form: "structured" | "text";
  /** Tool family: shell, database, http, … or "tool" when unspecific. */
  tool: string;
  /** For a valid structured call: the permission it needs. null: unverifiable. */
  permission: Permission | null;
  detail: string;
}

const MAX_NODES = 500;
const MAX_TEXT = 32_768;

/** Keys that mark an object as a tool invocation in the formats agents and LLM APIs use. */
const INVOCATION_KEYS = ["tool", "tool_name", "toolName", "tool_calls", "toolCalls", "function_call", "functionCall", "tool_use"];

function isToolShaped(o: Record<string, unknown>): string | null {
  if (typeof o.kind === "string" && (TOOL_KINDS as readonly string[]).includes(o.kind)) return o.kind;
  if (o.method === "tools/call") return "mcp";
  if (o.type === "tool_use" || o.type === "function") return "tool";
  if (INVOCATION_KEYS.some((k) => k in o)) return "tool";
  if (typeof o.name === "string" && ("arguments" in o || "args" in o || "input" in o || "parameters" in o)) return "tool";
  if ("command" in o && (typeof o.command === "string" || Array.isArray(o.command)) && ("args" in o || "argv" in o || "cwd" in o || "shell" in o)) return "shell";
  if (typeof o.sql === "string" || typeof o.query === "string" && /^\s*(select|insert|update|delete|drop|alter|truncate|grant)\b/i.test(o.query)) return "database";
  return null;
}

const TEXT_PATTERNS: { tool: string; re: RegExp; detail: string }[] = [
  {
    tool: "shell",
    re: /(?:^|[\s`;|&$(>])(?:sudo\s|rm\s+-[a-z]*[rf]|curl\s|wget\s|bash\s|sh\s+-c|zsh\s|powershell|pwsh\s|cmd(?:\.exe)?\s+\/c|nc\s+-|ncat\s|netcat\s|scp\s|ssh\s|chmod\s|chown\s|python3?\s+-c|perl\s+-e|base64\s+-d|crontab\s|systemctl\s|kubectl\s|docker\s+(?:run|exec))/i,
    detail: "a command line",
  },
  {
    tool: "database",
    re: /\b(?:select\s+[\w*,.\s]+\s+from\s+\w|insert\s+into\s+\w|update\s+\w+\s+set\s|delete\s+from\s+\w|drop\s+(?:table|database|schema)\s|truncate\s+table\s|alter\s+table\s|grant\s+\w+\s+on\s)/i,
    detail: "an SQL statement",
  },
  {
    tool: "tool",
    re: /\b(?:run|execute|exec|call|invoke|trigger)\s+(?:the\s+|a\s+|this\s+|that\s+)?(?:shell|terminal|command|bash|script|tool|function|mcp|plugin|webhook|lambda|workflow)\b/i,
    detail: "an instruction to use a tool",
  },
  {
    tool: "egress",
    re: /\b(?:send|post|upload|email|forward|exfiltrate|transfer|copy)\b[^.\n]{0,60}?\b(?:to|into)\s+(?:https?:\/\/|s3:\/\/|gs:\/\/|[\w.+-]+@[\w-]+\.\w|#[\w-]{2,})/i,
    detail: "an instruction to send data out",
  },
];

/** Tool families a requested permission legitimately covers. */
function familyCovers(requested: Permission, tool: string): boolean {
  if (!requested.startsWith("tool.")) return false;
  const kind = requested.slice(5, requested.indexOf(":"));
  if (tool === "tool") return true;
  if (tool === "egress") return ["http", "email", "slack", "cloud", "github", "mcp"].includes(kind) && requested.endsWith(":write");
  return kind === tool;
}

/**
 * Tool invocations in a request's payload. A structured call is resolved to
 * the permission it needs via `permissionOf` (the tool gateway's analyser);
 * the caller compares that with what the request asks for.
 */
export function findToolRequests(payload: unknown, requested: Permission, permissionOf: (call: ToolCall) => Permission | null): PayloadToolFinding[] {
  const out: PayloadToolFinding[] = [];
  const texts: string[] = [];
  let nodes = 0;
  let textSize = 0;
  const walk = (v: unknown, depth: number) => {
    if (++nodes > MAX_NODES || depth > 8 || out.length >= 10) return;
    if (typeof v === "string") {
      if (textSize < MAX_TEXT) { texts.push(v.slice(0, MAX_TEXT - textSize)); textSize += v.length; }
      // A tool call serialised as a JSON string is still a tool call.
      const t = v.trim();
      if (t.length < 16_384 && (t.startsWith("{") || t.startsWith("["))) {
        try { walk(JSON.parse(t), depth + 1); } catch { /* not JSON */ }
      }
      return;
    }
    if (Array.isArray(v)) { for (const x of v) walk(x, depth + 1); return; }
    if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      const call = toolCallSchema.safeParse(o);
      if (call.success) {
        const permission = permissionOf(call.data);
        if (permission !== requested) {
          out.push({ form: "structured", tool: call.data.kind, permission, detail: `a ${call.data.kind} call that needs ${permission ?? "an unknown permission"}` });
        }
        return; // judged as a whole: its fields are not also prose
      }
      const tool = isToolShaped(o);
      if (tool) {
        if (!familyCovers(requested, tool)) out.push({ form: "structured", tool, permission: null, detail: `a ${tool} invocation Legion cannot verify` });
        return;
      }
      for (const [k, x] of Object.entries(o)) {
        if (textSize < MAX_TEXT) { texts.push(k); textSize += k.length; }
        walk(x, depth + 1);
      }
    }
  };
  walk(payload, 0);

  const text = texts.join("\n");
  for (const p of TEXT_PATTERNS) {
    if (!familyCovers(requested, p.tool) && p.re.test(text)) {
      out.push({ form: "text", tool: p.tool, permission: null, detail: `text containing ${p.detail}` });
    }
  }
  return out;
}

// ---- Correlation ------------------------------------------------------------------

/** Words too common to tie a tool call to a request. */
const STOP = new Set([
  "http", "https", "www", "true", "false", "null", "none", "undefined", "json", "text", "html", "data", "file", "files",
  "from", "into", "where", "limit", "order", "select", "insert", "update", "delete", "values", "table", "group",
  "read", "write", "list", "post", "patch", "head", "status", "message", "messages", "query", "search", "result", "results",
  "alert", "alerts", "agent", "agents", "user", "users", "channel", "channels", "email", "mail", "issue", "issues",
  "execute", "call", "call_tool", "tool", "tools", "shell", "http", "database", "files", "browser", "github", "slack", "cloud", "mcp",
  "echo", "true", "main", "master", "default", "index", "test", "tests", "local", "localhost", "tmp", "home", "srv", "usr", "bin",
  "com", "net", "org", "api", "app", "the", "and", "for", "with", "this", "that", "please",
]);

/** The specific things a tool call touches: hosts, channels, tables, paths, commands, argument values. */
export function targetTokens(req: ActionRequest): string[] {
  const strings: string[] = [];
  const take = (v: unknown, depth = 0) => {
    if (depth > 5 || strings.length > 200) return;
    if (typeof v === "string") strings.push(v);
    else if (Array.isArray(v)) v.forEach((x) => take(x, depth + 1));
    else if (v && typeof v === "object") Object.values(v).forEach((x) => take(x, depth + 1));
  };
  const r = req as unknown as Record<string, unknown>;
  switch (req.surface) {
    case "tool_call": take(r.target); take(r.destination); take((r.call as Record<string, unknown> | undefined) ?? null); break;
    case "mcp_tool": take(r.server); take(r.tool); take(r.args); break;
    case "tool": take(r.tool); take(r.args); break;
    case "egress": take(r.url); break;
    default: return [];
  }
  const tokens = new Set<string>();
  for (const s of strings) {
    for (const raw of s.toLowerCase().split(/[\s,;|&"'`()<>[\]{}=?#]+/)) {
      const parts = [raw];
      // A URL or path contributes its host and its segments too.
      const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:]+)/.exec(raw);
      if (m) parts.push(m[1]!);
      parts.push(...raw.split(/[/:@]+/));
      for (const p of parts) {
        const tok = p.replace(/^[.\-_]+|[.\-_]+$/g, "");
        if (tok.length < 4 || tok.length > 200 || STOP.has(tok) || /^\d+$/.test(tok)) continue;
        if ((TOOL_KINDS as readonly string[]).includes(tok)) continue;
        tokens.add(tok);
      }
    }
  }
  return [...tokens].slice(0, 100);
}

export interface RecentRequest {
  id: string;
  fromAgentId: string;
  permission: Permission;
  text: string;
  interactionId: string;
  hop: number;
  authority: Authority;
}

export interface HiddenDelegationMatch {
  messageId: string;
  fromAgentId: string;
  permission: Permission;
  /** The token of the call's target found in the request. */
  matched: string;
  interactionId: string;
  hop: number;
  authority: Authority;
}

/** Requests the agent recently read whose text names this call's specific target. */
export function matchRecentRequests(req: ActionRequest, recent: RecentRequest[]): HiddenDelegationMatch[] {
  if (!recent.length) return [];
  const tokens = targetTokens(req);
  if (!tokens.length) return [];
  const out: HiddenDelegationMatch[] = [];
  for (const m of recent) {
    const text = m.text.toLowerCase();
    const hit = tokens.find((tok) => {
      let i = text.indexOf(tok);
      while (i !== -1) {
        const before = i === 0 ? "" : text[i - 1]!;
        const after = text[i + tok.length] ?? "";
        if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return true;
        i = text.indexOf(tok, i + 1);
      }
      return false;
    });
    if (hit) {
      out.push({ messageId: m.id, fromAgentId: m.fromAgentId, permission: m.permission, matched: hit, interactionId: m.interactionId, hop: m.hop, authority: m.authority });
    }
  }
  return out;
}
