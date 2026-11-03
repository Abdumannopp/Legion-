#!/usr/bin/env node
/**
 * Fails when interface text is written straight into a component instead of
 * going through the translations — i.e. text that would show in English to a
 * Russian or Uzbek user.
 *
 * TypeScript already guarantees every translation has all three languages
 * (see lib/i18n/core.ts). This covers the other half: text that never entered
 * the translations at all. It parses every .tsx/.ts file under app/ and
 * components/ and reports:
 *   - text between JSX tags ("<p>Hello</p>");
 *   - placeholder / title / aria-label / alt / label attributes with words;
 *   - string literals that read like a sentence ("Could not save.") anywhere
 *     else — error messages set in state, confirm() prompts, and so on.
 *
 * Deliberate exceptions (brand names, technical identifiers) take a comment
 * containing `i18n-ignore` on the same line or the line above.
 *
 * Usage: node scripts/check-i18n.mjs   (exit 1 when anything is found)
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ts = require("typescript");

const root = join(fileURLToPath(import.meta.url), "..", "..");
const DIRS = ["app", "components", "lib"];
// The translations themselves, and test code (never shown to a user).
const SKIP = /[\\/]lib[\\/]i18n[\\/]|\.(?:test|harness)\.tsx?$/;
const TEXT_ATTRS = new Set(["placeholder", "title", "aria-label", "alt", "label"]);
// Object properties that hold display text even when it is a single word
// ({ label: "Critical" }).
const TEXT_PROPS = /^(label|title|heading|subtitle|description|desc|text|message|placeholder|hint|cta|name|caption|tooltip|empty|help)$/i;
// Two or more letters in a row (any script).
const WORDY = /\p{L}{2,}/u;
// "Capitalised word, space, another word" — how UI sentences look, and how
// class names, URLs, identifiers and CSS values do not.
const SENTENCE = /^[\p{Lu}][\p{Ll}'’]+[,:]?\s+[\p{L}'’]/u;

function files(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (/\.(tsx|ts)$/.test(name) && !name.endsWith(".d.ts") && !SKIP.test(path)) out.push(path);
  }
  return out;
}

function ignored(source, node) {
  const lines = source.text.split("\n");
  const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line;
  return [lines[line], lines[line - 1]].some((l) => l && l.includes("i18n-ignore"));
}

/** Contexts where a string is code, not text a person reads. */
function isCodeContext(node) {
  const p = node.parent;
  if (!p) return false;
  if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isExternalModuleReference(p)) return true;
  if (ts.isPropertyAssignment(p) && p.name === node) return true;
  if (ts.isLiteralTypeNode(p)) return true;
  if (ts.isElementAccessExpression(p)) return true;
  if (ts.isCaseClause(p)) return true;
  if (ts.isBinaryExpression(p) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(p.operatorToken.kind)) return true;
  if (ts.isJsxAttribute(p)) {
    const name = p.name.getText();
    return !TEXT_ATTRS.has(name);
  }
  // console.log("…"), new Error("…") for developers, process.env reads
  for (let n = p; n; n = n.parent) {
    if (ts.isCallExpression(n) && /^console\./.test(n.expression.getText())) return true;
    if (ts.isJsxAttribute(n) && n.name.getText() === "className") return true;
    if (ts.isCallExpression(n) && /^(useRouter|router\.(push|replace)|new URL|fetch)/.test(n.expression.getText())) return true;
  }
  return false;
}

const problems = [];
for (const dir of DIRS) {
  for (const file of files(join(root, dir))) {
    const text = readFileSync(file, "utf8");
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const report = (node, what) => {
      if (ignored(source, node)) return;
      const { line } = source.getLineAndCharacterOfPosition(node.getStart(source));
      problems.push(`${relative(root, file)}:${line + 1}  ${what}`);
    };
    const visit = (node) => {
      if (ts.isJsxText(node)) {
        const value = node.getText().trim();
        if (WORDY.test(value)) report(node, `text in JSX: "${value.replace(/\s+/g, " ").slice(0, 60)}"`);
      } else if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        const value = node.text.trim();
        const p = node.parent;
        const inTextAttr = p && ts.isJsxAttribute(p) && TEXT_ATTRS.has(p.name.getText());
        const inTextProp = p && ts.isPropertyAssignment(p) && p.initializer === node && TEXT_PROPS.test(p.name.getText().replace(/["']/g, ""));
        if (inTextAttr || inTextProp ? WORDY.test(value) : SENTENCE.test(value) && !isCodeContext(node)) {
          report(node, `string: "${value.slice(0, 60)}"`);
        }
      } else if (ts.isTemplateExpression(node)) {
        const value = node.head.text.trim();
        if (SENTENCE.test(value) && !isCodeContext(node)) report(node, `template: "${value.slice(0, 60)}…"`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
}

if (problems.length) {
  console.error(`Untranslated interface text (${problems.length}). Move it into lib/i18n/ns/<screen>.ts in all three languages:\n`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log("i18n: no hard-coded interface text found in app/, components/ or lib/.");
