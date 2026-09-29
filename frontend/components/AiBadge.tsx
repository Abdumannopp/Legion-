"use client";

import { Bot, ShieldCheck } from "lucide-react";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/**
 * Says who wrote a piece of analysis. Text written by an AI model is labelled a
 * SUGGESTION, with the reason in plain words: it was generated from alert text
 * an attacker may control, and Legion does not act on it. Text from Legion's
 * built-in rules is labelled as such, so the two are never confused.
 */
export default function AiBadge({ aiGenerated }: { aiGenerated: boolean }) {
  const { t } = useLanguage();
  const label = aiGenerated ? t.ai.badge.ai : t.ai.badge.local;
  const hint = aiGenerated ? t.ai.badge.aiHint : t.ai.badge.localHint;
  return (
    <span
      title={hint}
      aria-label={`${label}. ${hint}`}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
        aiGenerated ? "border-amber-500/40 bg-amber-500/10 text-amber-300" : "border-line bg-panel text-ink-faint"
      }`}
    >
      {aiGenerated ? <Bot size={11} /> : <ShieldCheck size={11} />}
      {label}
    </span>
  );
}
