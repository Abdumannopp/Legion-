import { findSecrets } from "../firewall/scan.js";
import { analysisViews, inspectInvisible, mixedScriptWords, sanitizeForModel } from "./normalize.js";
import {
  RICH_SOURCES,
  verdictOf,
  type Classification,
  type ContentSource,
  type FieldHint,
  type Finding,
  type FindingCategory,
} from "./types.js";

/*
 * Detection is layered so that no single keyword decides anything:
 *
 *   1. Normalisation (normalize.ts) removes the evasion tricks first.
 *   2. Structural signals that don't depend on wording: invisible and
 *      smuggled characters, lookalike letters, chat-template tokens,
 *      attempts to close Legion's wrapper, content whose shape doesn't fit
 *      its field, hidden HTML, encoded blobs that decode to directives.
 *   3. A statistical signal: how much the text addresses its reader.
 *   4. Directive patterns: overriding instructions, claiming authority,
 *      addressing an AI, hiding actions from people, SOC-specific commands
 *      ("mark this alert as a false positive").
 *
 * The score sums the strongest finding per category, so several weak,
 * independent signals add up while repeating one phrase doesn't.
 *
 * Detection only raises risk. The protection that doesn't depend on
 * detection is the separation in assembly.ts and the firewall's action
 * gating: undetected injected text is still only data, and still can't
 * trigger a sensitive action on its own.
 */

interface Pattern {
  category: FindingCategory;
  id: string;
  points: number;
  re: RegExp;
  detail: string;
}

const W = "(?:\\W+\\w+){0,4}?\\W+"; // up to four filler words

/** Run against normalised (and de-obfuscated) text; all lower-case. */
const DIRECTIVES: Pattern[] = [
  {
    category: "instruction_override", id: "override.previous_instructions", points: 45,
    re: new RegExp(`\\b(?:ignore|disregard|forget|override|bypass|skip|drop)${W}(?:previous|prior|above|earlier|preceding|all|any|your|the|system|original)${W}?(?:instructions?|prompts?|rules?|directives?|guidelines?|context|constraints?|guardrails?|polic(?:y|ies)|programming)\\b`),
    detail: "Tells the reader to ignore its instructions.",
  },
  {
    category: "instruction_override", id: "override.new_instructions", points: 35,
    re: /\b(?:new|updated|revised|real|actual|true|additional|secret)\s+(?:instructions?|system\s+prompt|directives?|rules|task|objective)\s*[:\-–]/,
    detail: "Announces replacement instructions.",
  },
  {
    category: "persona_hijack", id: "persona.reassign", points: 30,
    re: /\b(?:you are now|from now on,? you|you will now (?:act|behave|respond)|act as (?:an? )?(?:admin|root|system|developer|unrestricted|jailbroken)|pretend (?:to be|you are)|role-?play as|your new (?:role|task|goal|objective|purpose) is|you are no longer)\b/,
    detail: "Tries to give the reader a new role.",
  },
  {
    category: "authority_claim", id: "authority.fake_system", points: 30,
    re: /\b(?:this is (?:a|an|the) (?:system|admin(?:istrator)?|developer|security team|official|priority) (?:message|notice|instruction|override|update)|(?:message|instruction|order|note) from (?:the )?(?:system|developer|admin(?:istrator)?|security team|openai|anthropic|legion))\b/,
    detail: "Claims to come from the system, a developer or an administrator.",
  },
  {
    category: "ai_addressing", id: "ai.direct_address", points: 30,
    re: /\b(?:if you are an? (?:ai|llm|language model|assistant|agent|bot)|(?:ai|llm|language model|assistant|copilot|agent|chatbot|gpt|claude|gemini)s?\b[^.\n]{0,40}\b(?:reading|processing|analy[sz]ing|summari[sz]ing|reviewing|parsing) (?:this|these|the following)|(?:note|message|instructions?|attention)\s+(?:to|for)\s+(?:any|all|the)?\s*(?:automated|automatic|ai|machine)\s+(?:reviewers?|readers?|systems?|analysts?|triage|pipelines?|handlers?|processors?|agents?|assistants?))\b/,
    detail: "Speaks directly to an AI processing the content.",
  },
  {
    category: "covert_action", id: "covert.hide_from_humans", points: 35,
    re: /\b(?:do not|don't|never|without|skip|avoid|no need to|refrain from)\b[^.\n]{0,30}\b(?:tell|inform|notify|notifying|alert|mention|report|reveal|show|log|flag|escalate)(?:ing)?\b[^.\n]{0,30}\b(?:the )?(?:user|operator|analyst|admin(?:istrator)?|human|anyone|team|soc|security team)s?\b/,
    detail: "Asks for something to be hidden from people.",
  },
  {
    category: "covert_action", id: "covert.stealth", points: 25,
    re: /\b(?:secretly|silently|covertly|without (?:them|anyone|the user) (?:knowing|noticing))\b/,
    detail: "Asks for stealth.",
  },
  {
    category: "prompt_leak", id: "leak.system_prompt", points: 30,
    re: /\b(?:repeat|print|output|reveal|show|display|dump|leak|write out|tell me)\b[^.\n]{0,40}\b(?:system prompt|initial prompt|hidden prompt|your (?:instructions|prompt|rules|guidelines|configuration|system message)|(?:the )?(?:text|words|instructions) above)\b/,
    detail: "Asks for the model's instructions.",
  },
  {
    category: "action_directive", id: "soc.suppress_alert", points: 30,
    re: /\b(?:mark|set|change|update|classify|treat|close|resolve|dismiss)\b[^.\n]{0,40}\b(?:alert|incident|ticket|event|finding|this|it|status|severity|state)\b[^.\n]{0,40}\b(?:as |to )?(?:resolved|closed|false[ _-]?positive|benign|harmless|low (?:severity|priority)|informational|dismissed|safe|ignored?)\b/,
    detail: "Tries to get a security finding closed or downgraded.",
  },
  {
    category: "action_directive", id: "soc.disable_defences", points: 35,
    re: /\b(?:disable|turn off|stop|kill|uninstall|remove|pause|whitelist|allowlist|exclude)\b[^.\n]{0,30}\b(?:monitoring|logging|logs|alerts?|alerting|wazuh|agent|antivirus|edr|firewall|audit(?:ing)?|detections?|rules?)\b/,
    detail: "Tries to switch off defences.",
  },
  {
    category: "action_directive", id: "action.exfiltrate", points: 30,
    re: /\b(?:send|forward|email|upload|post|exfiltrate|transmit|copy|leak|share)\b(?:[^.\n]{0,50}\b(?:to|at|into)\b\s*(?:https?:\/\/|[\w.+-]+@[\w-]+\.[\w.]+)|[^.\n]{0,40}\b(?:credentials?|passwords?|secrets?|tokens?|api keys?|private keys?|keys|session cookies?|hashes)\b[^.\n]{0,20}\b(?:to|into)\b\s+(?:the\s+|our\s+|this\s+)?(?:#[\w-]+|[\w-]+\s+(?:channel|mailbox|inbox|share|bucket|chat|group|webhook|folder)))/,
    detail: "Asks for data to be sent to an address.",
  },
  {
    category: "action_directive", id: "action.execute", points: 25,
    re: /\b(?:run|execute|eval|invoke|call|use)\b[^.\n]{0,20}\b(?:the )?(?:command|shell|script|tool|function|curl|wget|powershell|bash|cmd)\b/,
    detail: "Asks for a command or tool to be run.",
  },
  {
    category: "action_directive", id: "action.grant_access", points: 30,
    re: /\b(?:grant|give|add|create|elevate|promote)\b[^.\n]{0,30}\b(?:admin|administrator|root|full|elevated)\b[^.\n]{0,20}\b(?:access|rights|privileges?|role|permissions?|account)\b/,
    detail: "Asks for privileges to be granted.",
  },
];

/**
 * "Ignore previous instructions" in the languages Legion's customers write in.
 * Run on text that has NOT had lookalike letters folded to Latin, or Cyrillic
 * words would be mangled before they are matched.
 */
const MULTILINGUAL: Pattern[] = [
  { category: "instruction_override", id: "override.previous_instructions_i18n", points: 45, detail: "Tells the reader to ignore its instructions (non-English).",
    re: new RegExp([
      "\\bignor(?:a|ar|e)\\s+(?:todas?\\s+)?(?:las\\s+|los\\s+)?(?:instrucciones|indicaciones|reglas)\\s+(?:anteriores|previas)", // es
      "\\bignorier(?:e|en)?\\s+(?:alle\\s+)?(?:vorherigen|bisherigen|obigen)\\s+(?:anweisungen|instruktionen|regeln)", // de
      "\\bignore[rz]?\\s+(?:toutes\\s+)?(?:les\\s+)?(?:instructions|consignes|règles|regles)\\s+(?:précédentes|precedentes|antérieures|anterieures)", // fr
      "игнорируй(?:те)?\\s+(?:все\\s+)?(?:предыдущие|прежние|прошлые)\\s+(?:инструкции|указания|правила)", // ru
      "(?:oldingi|avvalgi)\\s+(?:barcha\\s+)?(?:ko['‘ʻ’`]?rsatmalar|buyruqlar|qoidalar)(?:ni)?\\s+(?:e['‘ʻ’`]?tiborsiz\\s+qoldir|unut)", // uz
    ].join("|")) },
];

/** Structural markers: chat-template tokens and role labels. Case matters less; run on normalised. */
const MARKERS: Pattern[] = [
  { category: "role_markers", id: "markers.chat_template", points: 60, re: /<\|(?:im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text)\|>/, detail: "Contains model chat-template tokens." },
  { category: "role_markers", id: "markers.inst_tags", points: 50, re: /\[\/?(?:inst|sys)\]|<<\/?sys>>/, detail: "Contains instruction-format tags." },
  { category: "role_markers", id: "markers.role_label", points: 25, re: /^[ \t]*(?:system|assistant|developer)[ \t]*:/m, detail: "Contains a line pretending to be a system or assistant turn." },
  { category: "role_markers", id: "markers.fake_section", points: 25, re: /^[ \t]*#{2,}[ \t]*(?:system|instructions?|new task|admin)\b/m, detail: "Contains a fake instructions heading." },
  { category: "role_markers", id: "markers.xml_role", points: 30, re: /<\/?\s*(?:system|instructions?|assistant|prompt|admin)\s*>/, detail: "Contains role tags." },
  { category: "wrapper_escape", id: "wrapper.close_tag", points: 45, re: /<\/\s*(?:external_content|untrusted|data|document|context)\s*>|end[ _-]?(?:of[ _-]?)?(?:external|untrusted)[ _-]?(?:content|data)/, detail: "Tries to close the untrusted-content wrapper." },
];

const IMPERATIVE_STARTS = new Set([
  "ignore", "disregard", "forget", "execute", "run", "delete", "remove", "send", "forward", "email", "upload", "download",
  "disable", "enable", "bypass", "override", "act", "pretend", "respond", "reply", "print", "output", "reveal", "grant",
  "mark", "close", "resolve", "change", "update", "set", "stop", "call", "invoke", "open", "visit", "click", "approve",
  "restart", "reboot", "shutdown", "kill", "drop", "wipe", "export", "share", "post", "write", "copy", "create", "add",
  "give", "allow", "unblock", "whitelist", "allowlist", "exclude", "install", "uninstall", "transfer", "pay",
]);

function excerptOf(text: string, re: RegExp): string | undefined {
  const m = re.exec(text);
  if (!m) return undefined;
  const e = m[0].slice(0, 80);
  return findSecrets(e).length ? "[REDACTED]" : e;
}

function runPatterns(patterns: Pattern[], views: { normalized: string; deobfuscated: string }, out: Finding[]): void {
  let evasion = false;
  for (const p of patterns) {
    if (p.re.test(views.normalized)) {
      out.push({ category: p.category, id: p.id, points: p.points, detail: p.detail, excerpt: excerptOf(views.normalized, p.re) });
    } else if (p.re.test(views.deobfuscated)) {
      out.push({ category: p.category, id: p.id, points: p.points, detail: `${p.detail} (after undoing letter-spacing/leetspeak)`, excerpt: excerptOf(views.deobfuscated, p.re) });
      evasion = true;
    }
  }
  if (evasion) {
    out.push({ category: "obfuscation", id: "obfuscation.spaced_or_leet", points: 15, detail: "A directive was disguised with letter-spacing or leetspeak." });
  }
}

/** Long base64 / hex / percent-encoded runs that decode to readable directives. */
function encodedPayloads(raw: string, out: Finding[]): void {
  const candidates: string[] = [];
  for (const m of raw.match(/[A-Za-z0-9+/_-]{24,}={0,2}/g) ?? []) {
    try {
      candidates.push(Buffer.from(m.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    } catch { /* not base64 */ }
    if (candidates.length > 20) break;
  }
  for (const m of raw.match(/(?:\\x[0-9a-f]{2}){12,}/gi) ?? []) {
    candidates.push(Buffer.from(m.replace(/\\x/gi, ""), "hex").toString("utf8"));
  }
  for (const m of raw.match(/(?:[0-9a-f]{2}){16,}/gi) ?? []) {
    candidates.push(Buffer.from(m, "hex").toString("utf8"));
  }
  for (const m of raw.match(/(?:%[0-9a-f]{2}){8,}/gi) ?? []) {
    try { candidates.push(decodeURIComponent(m)); } catch { /* malformed */ }
  }
  for (const decoded of candidates) {
    const printable = decoded.replace(/[^\x20-\x7e\n\t]/g, "").length;
    if (decoded.length < 12 || printable / decoded.length < 0.9) continue; // hashes, keys, binary: not text
    const inner: Finding[] = [];
    const inv = inspectInvisible(decoded);
    runPatterns([...DIRECTIVES, ...MARKERS], analysisViews(decoded, inv), inner);
    if (inner.length) {
      // Hiding a directive in an encoding is evasion on top of the directive.
      out.push({
        category: "encoded_payload", id: "encoded.directive", points: Math.min(60, 20 + Math.max(...inner.map((f) => f.points))),
        detail: `Encoded text decodes to instructions (${inner.map((f) => f.id).join(", ")}).`,
        excerpt: decoded.slice(0, 80),
      });
      return;
    }
  }
}

function invisibleFindings(raw: string, out: Finding[]): ReturnType<typeof inspectInvisible> {
  const inv = inspectInvisible(raw);
  if (inv.tagChars) {
    out.push({
      category: "invisible_unicode", id: "unicode.tag_smuggling", points: 60,
      detail: `${inv.tagChars} invisible Unicode tag characters (hidden ASCII) — no legitimate use in text.`,
      excerpt: inv.hiddenTagText.slice(0, 80) || undefined,
    });
  }
  if (inv.bidiControls) out.push({ category: "invisible_unicode", id: "unicode.bidi", points: 25, detail: `${inv.bidiControls} bidirectional override characters (text shown to people differs from what is read).` });
  if (inv.variationSelectors > 2) out.push({ category: "invisible_unicode", id: "unicode.variation_smuggling", points: 30, detail: `${inv.variationSelectors} non-emoji variation selectors (a data-smuggling channel).` });
  if (inv.zeroWidth >= 3) out.push({ category: "invisible_unicode", id: "unicode.zero_width", points: 15, detail: `${inv.zeroWidth} zero-width characters.` });
  else if (inv.zeroWidth > 0) out.push({ category: "invisible_unicode", id: "unicode.zero_width_few", points: 5, detail: `${inv.zeroWidth} zero-width character(s).` });
  return inv;
}

/**
 * HTML comment bodies, found in linear time. (A lazy `<!--([\s\S]*?)-->`
 * rescans to the end of the text from every unclosed "<!--": quadratic, and a
 * page of repeated "<!--" froze the process.)
 */
function htmlComments(raw: string): string[] {
  const out: string[] = [];
  let i = raw.indexOf("<!--");
  while (i !== -1) {
    const end = raw.indexOf("-->", i + 4);
    if (end === -1) break; // no closer anywhere after this: none after later openers either
    out.push(raw.slice(i + 4, end).trim());
    i = raw.indexOf("<!--", end + 3);
  }
  return out;
}

/** Hidden text in HTML: invisible to the person reading the page or email, visible to a model. */
function hiddenMarkup(raw: string, out: Finding[]): void {
  const comments = htmlComments(raw).filter((c) => c.split(/\s+/).length >= 5);
  if (comments.length) out.push({ category: "hidden_markup", id: "html.comment_text", points: 20, detail: "Prose hidden in HTML comments.", excerpt: comments[0]!.slice(0, 80) });
  const hiddenStyle = /<[^<>]{0,300}?style\s*=\s*["'][^"'<>]{0,300}?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\s*[;"']|color\s*:\s*(?:#fff(?:fff)?|white|transparent)\b|left\s*:\s*-\d{3,}px)[^"'<>]{0,300}["'][^<>]{0,300}>\s*[^<\s][^<]{10,}/i;
  if (hiddenStyle.test(raw)) out.push({ category: "hidden_markup", id: "html.hidden_style", points: 30, detail: "Text styled to be invisible to people.", excerpt: excerptOf(raw, hiddenStyle) });
  if (/<(?:span|div|p)\b[^<>]{0,300}?\bhidden\b[^<>]{0,300}>\s*[^<\s][^<]{10,}/i.test(raw)) out.push({ category: "hidden_markup", id: "html.hidden_attr", points: 25, detail: "Text in an element marked hidden." });
}

/** Markup that makes a renderer fetch a URL — the classic way to leak data out of a model's context. */
function exfiltrationMarkup(raw: string, source: ContentSource, out: Finding[]): void {
  const rich = RICH_SOURCES.has(source);
  const longParam = /[?&][\w.-]{0,30}=[A-Za-z0-9+/_%=-]{24,}/;
  const images = [...raw.matchAll(/!\[[^\][]{0,500}\]\(\s*<?(https?:\/\/[^)\s>]+)/gi), ...raw.matchAll(/<img\b[^<>]{0,500}?src\s*=\s*["']?(https?:\/\/[^"'\s>]+)/gi)].map((m) => m[1]!);
  const withData = images.find((u) => longParam.test(u) || /\{[^}]*\}/.test(u));
  if (withData) out.push({ category: "exfiltration_markup", id: "exfil.image_with_data", points: 40, detail: "An auto-loading image URL with a data-carrying parameter.", excerpt: withData.slice(0, 80) });
  else if (images.length) out.push({ category: "exfiltration_markup", id: "exfil.image", points: rich ? 5 : 25, detail: "An auto-loading image URL." });
  const links = [...raw.matchAll(/\]\(\s*<?(https?:\/\/[^)\s>]+)/g)].map((m) => m[1]!);
  if (!withData && links.some((u) => longParam.test(u))) out.push({ category: "exfiltration_markup", id: "exfil.link_with_data", points: rich ? 10 : 25, detail: "A link with a long data-carrying parameter." });
  if (/\{\{[^{}]{0,200}?(?:secret|token|password|key|prompt|context|history)[^{}]{0,200}\}\}/i.test(raw)) out.push({ category: "exfiltration_markup", id: "exfil.template_placeholder", points: 30, detail: "Template placeholders asking for secrets or context." });
}

/** How much the text talks TO its reader. Data describes things; injected text instructs. */
function readerAddressing(normalized: string, hint: FieldHint, out: Finding[]): void {
  const sentences = normalized.split(/(?<=[.!?;])\s+|\n+/).map((s) => s.trim()).filter((s) => s.split(/\s+/).length >= 3);
  if (!sentences.length) return;
  const directive = sentences.filter((s) => {
    const first = s.replace(/^(?:please|now|then|also|and|first|next|finally)[, ]+/, "").split(/[\s,:]+/)[0] ?? "";
    return IMPERATIVE_STARTS.has(first) || /\byou (?:must|should|need to|have to|will|are (?:required|instructed|ordered) to)\b/.test(s);
  }).length;
  const ratio = directive / sentences.length;
  if (hint !== "free_text" && directive > 0) {
    out.push({ category: "reader_addressing", id: "reader.directive_in_field", points: 30, detail: "A data field contains an instruction." });
  } else if (sentences.length >= 3 && ratio >= 0.6) {
    out.push({ category: "reader_addressing", id: "reader.mostly_directives", points: 20, detail: `${Math.round(ratio * 100)}% of sentences instruct the reader.` });
  } else if (sentences.length >= 3 && ratio >= 0.4) {
    out.push({ category: "reader_addressing", id: "reader.many_directives", points: 10, detail: `${Math.round(ratio * 100)}% of sentences instruct the reader.` });
  }
}

/** Content that doesn't have the shape of the field it claims to be. */
function shapeMismatch(raw: string, hint: FieldHint, out: Finding[]): void {
  if (hint === "identifier" && !/^[\p{L}\p{N}_.:@/\\\-\[\]%+=,()]{1,255}$/u.test(raw.trim())) {
    out.push({ category: "shape_mismatch", id: "shape.identifier", points: 40, detail: "An identifier field (hostname, IP, id, user) contains spaces, prose or control characters." });
  } else if (hint === "short_text" && (raw.length > 500 || (raw.match(/\n/g) ?? []).length > 3)) {
    out.push({ category: "shape_mismatch", id: "shape.short_text", points: 20, detail: "A short field (title, subject) is unusually long or multi-line." });
  }
}

export interface ClassifyInput {
  source: ContentSource;
  content: string;
  fieldHint?: FieldHint;
  /** The wrapper boundary this content will be placed inside; finding it in the content is an escape attempt. */
  boundary?: string;
}

/** Deterministic classification. Same input, same result; no I/O, no model. */
export function classifyContent(input: ClassifyInput): Classification {
  const raw = input.content ?? "";
  const hint = input.fieldHint ?? "free_text";
  const findings: Finding[] = [];

  const inv = invisibleFindings(raw, findings);
  const views = analysisViews(raw, inv);
  const mixed = mixedScriptWords(raw.normalize("NFKC"));
  if (mixed.length) findings.push({ category: "homoglyph", id: "homoglyph.mixed_script", points: 25, detail: `Words mixing Latin with lookalike Cyrillic/Greek letters: ${mixed.slice(0, 3).join(", ")}`, excerpt: mixed[0] });

  runPatterns([...DIRECTIVES, ...MARKERS], views, findings);
  const plain = sanitizeForModel(raw).normalize("NFKC").toLowerCase();
  runPatterns(MULTILINGUAL, { normalized: plain, deobfuscated: views.normalized }, findings);
  if (input.boundary && raw.includes(input.boundary)) {
    findings.push({ category: "wrapper_escape", id: "wrapper.boundary_forgery", points: 60, detail: "Contains the wrapper's secret boundary marker." });
  }
  encodedPayloads(raw, findings);
  hiddenMarkup(raw, findings);
  exfiltrationMarkup(raw, input.source, findings);
  readerAddressing(views.normalized, hint, findings);
  shapeMismatch(raw, hint, findings);

  const strongest = new Map<FindingCategory, number>();
  for (const f of findings) strongest.set(f.category, Math.max(strongest.get(f.category) ?? 0, f.points));
  const riskScore = Math.min(100, [...strongest.values()].reduce((a, b) => a + b, 0));

  const sanitized = sanitizeForModel(raw);
  return { verdict: verdictOf(riskScore), riskScore, findings, sanitized, removedChars: raw.length - sanitized.length };
}
