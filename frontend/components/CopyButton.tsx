"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/** Copies a value (a key, a config block) and says so. */
export default function CopyButton({ value, label, copiedLabel }: { value: string; label?: string; copiedLabel?: string }) {
  const { t } = useLanguage();
  const [done, setDone] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 2000);
    } catch {
      // Clipboard blocked (insecure origin, permissions): the value stays selectable on screen.
    }
  }
  return (
    <button type="button" onClick={copy} className="inline-flex items-center gap-1 text-[11px] font-medium text-brand-bright hover:underline shrink-0">
      {done ? <Check size={12} /> : <Copy size={12} />}
      {done ? copiedLabel ?? t.connect.copied : label ?? t.connect.copy}
    </button>
  );
}
