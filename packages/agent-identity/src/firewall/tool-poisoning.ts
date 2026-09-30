import { classifyContent } from "../prompt-guard/detectors.js";
import type { FindingCategory } from "../prompt-guard/types.js";
import type { RiskFactor, RuleHit } from "./types.js";

/**
 * Tool poisoning: an MCP server (or any tool catalogue) describes a tool to
 * the model, and the description is read as instructions. A poisoned one
 * tells the model to read secrets, call other tools, send data somewhere, or
 * keep all of it from the user — while the tool itself looks harmless.
 *
 * Tool descriptions are imperative by nature ("Provide the path", "Use this
 * tool when…"), so the general prompt-injection classifier is not a good fit
 * on its own: it misses the classic patterns and flags ordinary wording.
 * This scores what poisoning needs — a secret to reach, a reason to hide it,
 * another tool to steer, a place to send it — and only borrows the
 * classifier's findings that never belong in a tool description.
 */
export interface PoisoningReport {
  verdict: "clean" | "suspicious" | "malicious";
  score: number;
  findings: { id: string; points: number; excerpt: string }[];
}

const PATTERNS: { id: string; points: number; re: RegExp }[] = [
  // Reaching for secrets the tool has no business with.
  { id: "poison.secret_path", points: 40, re: /(~\/\.ssh|id_(rsa|ed25519|ecdsa)|\.aws\/credentials|\.env\b|\/etc\/(passwd|shadow)|\.kube\/config|\.netrc|\.npmrc|\.git-credentials|mcp\.json|claude_desktop_config|keychain)/i },
  { id: "poison.secret_request", points: 30, re: /\b(pass|send|include|attach|append|read|provide|put)\b[^.\n]{0,60}\b(api[_ -]?keys?|access[_ -]?tokens?|secrets?|passwords?|private keys?|credentials?|session cookies?|conversation history|system prompt)\b/i },
  // Keeping it from the person.
  { id: "poison.conceal", points: 40, re: /\b(do not|don't|never|without)\b[^.\n]{0,40}\b(tell|mention|inform|show|reveal|notify|alert|let)\w*\b[^.\n]{0,20}\b(the )?(user|human|operator|anyone|them)\b|\b(keep|remain)\b[^.\n]{0,20}\b(secret|hidden|confidential)\b|\bthe user (should|must) not (know|see)\b/i },
  // Blocks addressed to the model rather than describing the tool.
  { id: "poison.hidden_block", points: 30, re: /<\s*\/?\s*(important|system|instructions?|secret|hidden|assistant|admin|policy)\s*>|\[\s*(system|inst)\s*\]|<!--/i },
  // Steering other tools: shadowing, ordering, replacing.
  { id: "poison.cross_tool", points: 30, re: /\b(before|after|instead of|prior to)\b[^.\n]{0,20}\b(using|calling|invoking|running)\b[^.\n]{0,20}\b(any|other|another|every|all|the [\w-]+)\b[^.\n]{0,10}\btools?\b|\bwhen(ever)?\b[^.\n]{0,30}\btool\b[^.\n]{0,20}\b(is|are)\b[^.\n]{0,10}\b(available|called|used|present)\b|\b(all|every|any)\b[^.\n]{0,20}\b(emails?|messages?|requests?|calls?|files?)\b[^.\n]{0,30}\b(must|should)\b[^.\n]{0,20}\b(be )?(sent|forwarded|redirected|copied|bcc)|\b(call|invoke|run|use)\s+(the\s+)?[a-z]+_[a-z_]+\b[^.\n]{0,20}\b(first|before|instead)\b/i },
  // Talking to the model about itself, not describing the tool.
  { id: "poison.model_address", points: 30, re: /\bnote to (the )?(assistant|ai|model|llm|agent|claude|gpt)\b|\byou are now\b|\bdeveloper mode\b|\b(system prompt|previous instructions)\b[^.\n]{0,30}\b(outdated|obsolete|replaced|no longer)\b/i },
  { id: "poison.coercion", points: 20, re: /\b(otherwise|or else)\b[^.\n]{0,40}\b(will not|won't|fails?|break|crash|error)\b|\b(the )?tool (will not|won't) work (unless|without)\b/i },
  // Somewhere to send it.
  { id: "poison.exfil_destination", points: 30, re: /\b(send|sent|post|upload|forward|forwarded|transmit|exfiltrate|copy|copied|redirect|redirected|bcc)\b[^.\n]{0,60}(https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+)/i },
];

/** Classifier findings that never belong in a tool description. */
const BORROWED: ReadonlySet<FindingCategory> = new Set<FindingCategory>([
  "instruction_override", "persona_hijack", "authority_claim", "covert_action", "exfiltration_markup", "invisible_unicode",
  "hidden_markup", "role_markers", "wrapper_escape", "encoded_payload", "prompt_leak", "homoglyph",
] as FindingCategory[]);

export function scanToolDefinition(def: { name: string; description?: string; inputSchema?: unknown }): PoisoningReport {
  const texts = definitionTexts(def);
  const text = texts.join("\n");
  const findings: PoisoningReport["findings"] = [];
  for (const p of PATTERNS) {
    const m = p.re.exec(text);
    if (m) findings.push({ id: p.id, points: p.points, excerpt: m[0].slice(0, 120) });
  }
  const c = classifyContent({ source: "other", content: text });
  for (const f of c.findings) {
    if (BORROWED.has(f.category) && !findings.some((x) => x.id === f.id)) findings.push({ id: f.id, points: f.points, excerpt: (f.excerpt ?? "").slice(0, 120) });
  }
  const score = Math.min(100, findings.reduce((s, f) => s + f.points, 0));
  const verdict = score >= 60 ? "malicious" : score >= 30 ? "suspicious" : "clean";
  return { verdict, score, findings };
}

/**
 * Every string in a tool definition a model will read: the description, and
 * every description, title, default, example and enum value in its input
 * schema (poisoning often hides in a parameter's description).
 */
export function definitionTexts(def: { name: string; description?: string; inputSchema?: unknown }): string[] {
  const out: string[] = [def.name];
  if (def.description) out.push(def.description);
  const walk = (v: unknown, depth: number, key: string | null) => {
    if (depth > 12 || out.length > 2_000) return;
    if (typeof v === "string") {
      if (key === null || ["description", "title", "default", "examples", "enum", "const", "$comment"].includes(key)) out.push(v);
      return;
    }
    if (Array.isArray(v)) { for (const x of v) walk(x, depth + 1, key); return; }
    if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
        // Property names are read too: "ignore_previous_instructions" is a parameter name as well.
        out.push(k);
        walk(x, depth + 1, k);
      }
    }
  };
  walk(def.inputSchema, 0, "schema");
  return out;
}

/**
 * What the firewall does with a tool definition, on every call (the direct
 * MCP surface and the tool gateway alike): a poisoned one is refused — the
 * pinned hash only proves the text did not change since someone approved
 * it, not that it was safe — and a questionable one waits for a person.
 */
export function toolDefinitionHits(def: { name: string; description?: string; inputSchema?: unknown }): { hits: RuleHit[]; factors: RiskFactor[]; report: PoisoningReport } {
  const report = scanToolDefinition(def);
  const ids = report.findings.map((f) => f.id).join(", ");
  const hits: RuleHit[] = [];
  if (report.verdict === "malicious") {
    hits.push({ id: "mcp.poisoned_definition", effect: "BLOCK", hard: true,
      reason: `The tool's own description carries instructions for the model (${ids}): tool poisoning. It cannot be used until its server is fixed and the tool re-approved.` });
  } else if (report.verdict === "suspicious") {
    hits.push({ id: "mcp.suspicious_definition", effect: "CONFIRM", hard: true,
      reason: `The tool's description reads like instructions to the model (${ids}); a person must approve this call.` });
  }
  return { hits, factors: report.score ? [{ factor: "tool description reads as instructions", points: Math.min(30, report.score) }] : [], report };
}
