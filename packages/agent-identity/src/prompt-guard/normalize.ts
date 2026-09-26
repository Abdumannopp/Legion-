/*
 * Normalisation: undo the tricks that make injected text invisible to people
 * or to pattern checks, BEFORE anything is analysed. A keyword filter sees
 * "i​gnore previous instructions" or "іgnore" (Cyrillic і) as harmless;
 * after this step the detectors see "ignore previous instructions".
 *
 * Also produces the sanitised text that is handed to a model: characters with
 * no legitimate use in data — Unicode tag characters (ASCII smuggling), bidi
 * overrides, zero-width joiners inside words — are removed, so a hidden
 * instruction cannot reach the model even if nothing else caught it.
 */

export interface InvisibleReport {
  /** Unicode tag characters (U+E0000–U+E007F): invisible ASCII, the "ASCII smuggling" channel. */
  tagChars: number;
  /** Text hidden in tag characters, decoded. */
  hiddenTagText: string;
  /** Bidirectional overrides/isolates: reorder what a human sees. */
  bidiControls: number;
  /** Zero-width and other invisible formatting characters. */
  zeroWidth: number;
  /** Variation selectors outside emoji use (data-smuggling channel). */
  variationSelectors: number;
}

const TAG_RE = /[\u{E0000}-\u{E007F}]/gu;
const BIDI_RE = /[‪-‮⁦-⁩]/g;
// ZWSP, ZWNJ, LRM, RLM, word joiner & friends, BOM (not at start), soft hyphen,
// Mongolian vowel separator, combining grapheme joiner, Hangul fillers.
const ZERO_WIDTH_RE = /[​‌‎‏⁠-⁤­᠎͏ᅟᅠㅤﾠ]|(?<!^)﻿/g;
// ZWJ is legitimate inside emoji sequences; count it only between letters.
const ZWJ_IN_WORD_RE = /(?<=\p{L})‍(?=\p{L})/gu;
const VARIATION_SUPPLEMENT_RE = /[\u{E0100}-\u{E01EF}]/gu;
const VARIATION_NON_EMOJI_RE = /[︀-︍]/g;

export function inspectInvisible(text: string): InvisibleReport {
  const tags = text.match(TAG_RE) ?? [];
  const hiddenTagText = tags
    .map((c) => c.codePointAt(0)! - 0xe0000)
    .filter((cp) => cp >= 0x20 && cp < 0x7f)
    .map((cp) => String.fromCharCode(cp))
    .join("");
  return {
    tagChars: tags.length,
    hiddenTagText,
    bidiControls: (text.match(BIDI_RE) ?? []).length,
    zeroWidth: (text.match(ZERO_WIDTH_RE) ?? []).length + (text.match(ZWJ_IN_WORD_RE) ?? []).length,
    variationSelectors: (text.match(VARIATION_SUPPLEMENT_RE) ?? []).length + (text.match(VARIATION_NON_EMOJI_RE) ?? []).length,
  };
}

/** What a model is given: the same text minus the invisible channels. */
export function sanitizeForModel(text: string): string {
  return text
    .replace(TAG_RE, "")
    .replace(BIDI_RE, "")
    .replace(ZERO_WIDTH_RE, "")
    .replace(ZWJ_IN_WORD_RE, "")
    .replace(VARIATION_SUPPLEMENT_RE, "")
    .replace(VARIATION_NON_EMOJI_RE, "")
    // Other C0/C1 control characters except tab and newline.
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "");
}

/** Cyrillic and Greek letters that render like Latin ones. */
const CONFUSABLES: Record<string, string> = {
  а: "a", в: "b", е: "e", ё: "e", к: "k", м: "m", н: "h", о: "o", р: "p", с: "c", т: "t", у: "y", х: "x",
  і: "i", ї: "i", ј: "j", ѕ: "s", ԁ: "d", ԛ: "q", ԝ: "w", һ: "h", ӏ: "l", ɡ: "g",
  А: "A", В: "B", Е: "E", К: "K", М: "M", Н: "H", О: "O", Р: "P", С: "C", Т: "T", Х: "X", У: "Y",
  І: "I", Ј: "J", Ѕ: "S", Ԁ: "D", Ԛ: "Q", Ԝ: "W", Һ: "H", Ӏ: "I",
  α: "a", β: "b", ε: "e", ι: "i", κ: "k", ν: "v", ο: "o", ρ: "p", τ: "t", υ: "u", χ: "x", γ: "y",
  Α: "A", Β: "B", Ε: "E", Ζ: "Z", Η: "H", Ι: "I", Κ: "K", Μ: "M", Ν: "N", Ο: "O", Ρ: "P", Τ: "T", Υ: "Y", Χ: "X",
};
const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join("")}]`, "g");

/** Words mixing Latin with Cyrillic or Greek letters — a lookalike-substitution attack. */
export function mixedScriptWords(text: string): string[] {
  const out: string[] = [];
  for (const word of text.match(/\p{L}{2,}/gu) ?? []) {
    const latin = /\p{Script=Latin}/u.test(word);
    const other = /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(word);
    if (latin && other) out.push(word);
    if (out.length >= 20) break;
  }
  return out;
}

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i" };

export interface AnalysisViews {
  /** NFKC, invisibles removed, hidden tag text appended, lookalikes mapped to Latin, lower-cased. */
  normalized: string;
  /** Additionally: "i g n o r e" / "i.g.n.o.r.e" letter-spacing collapsed and leetspeak undone. */
  deobfuscated: string;
}

/**
 * The texts the detectors read. They never see the raw input, so
 * formatting tricks do not decide whether something is caught.
 */
export function analysisViews(raw: string, invisible: InvisibleReport): AnalysisViews {
  let t = raw.normalize("NFKC"); // fullwidth ｉｇｎｏｒｅ, 𝐢𝐠𝐧𝐨𝐫𝐞 → ignore
  t = sanitizeForModel(t);
  if (invisible.hiddenTagText) t += `\n${invisible.hiddenTagText}`;
  t = t.replace(CONFUSABLE_RE, (c) => CONFUSABLES[c] ?? c).toLowerCase();
  const normalized = t.replace(/[ \t]+/g, " ");

  // "i g n o r e   p r e v i o u s": single separators join letters, wider
  // gaps stay word breaks. Done before whitespace is collapsed.
  const despaced = t
    .replace(/\b(?:\p{L}[ .\-_*]){3,}\p{L}\b/gu, (run) => run.replace(/[ .\-_*]/g, ""))
    .replace(/[ \t]+/g, " ");
  const deobfuscated = despaced.replace(/\b[\p{L}0-9@$!]{3,}\b/gu, (w) =>
    /\p{L}/u.test(w) && /[0-9@$!]/.test(w) && !/^\d+$/.test(w) ? w.replace(/[0134570@$!]/g, (c) => LEET[c] ?? c) : w,
  );
  return { normalized, deobfuscated };
}
