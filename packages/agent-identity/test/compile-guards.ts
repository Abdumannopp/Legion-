/*
 * Compile-time guarantees, checked by `npm run check` (tsc). Not executed.
 * Each @ts-expect-error line must be a type error; if a refactor ever lets
 * one of these compile, the typecheck fails.
 */
import { PromptAssembly } from "../src/prompt-guard/assembly.js";

declare const externalText: string;

// A system prompt can only be chosen by registry key, never supplied as text.
// @ts-expect-error — arbitrary runtime strings are not system prompts
new PromptAssembly(externalText);

// @ts-expect-error — no such registered prompt
new PromptAssembly("oracle.explain_alert.with_extra_instructions");

// There is no way to set or append system text on an assembly.
const a = new PromptAssembly("copilot.chat");
// @ts-expect-error — no such method
a.setSystem(externalText);
// @ts-expect-error — no such method
a.addSystemInstruction(externalText);
// @ts-expect-error — the chosen prompt is read-only
a.systemPromptId = "copilot.chat";

// Untrusted content must name a known source.
// @ts-expect-error — unknown source
a.addUntrustedContent("somewhere", externalText);

export {};
