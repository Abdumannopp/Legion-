"use client";

import { Globe } from "lucide-react";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { LOCALES, Locale } from "@/lib/i18n/translations";

export default function LanguageSwitcher({
  compact = false,
  short = false,
}: {
  compact?: boolean;
  /** Show "RU" instead of "Русский" — for phone-width headers. */
  short?: boolean;
}) {
  const { locale, setLocale, t } = useLanguage();

  return (
    <div
      className={`flex items-center gap-1.5 rounded-lg border border-line bg-surface ${
        compact ? "px-2 py-1.5" : "px-2.5 py-2"
      }`}
    >
      <Globe size={14} className="text-ink-faint shrink-0" />
      <select
        value={locale}
        onChange={(e) => setLocale(e.target.value as Locale)}
        aria-label={t.footer.language}
        className="bg-transparent text-ink-muted text-xs font-medium outline-none cursor-pointer w-full appearance-none pr-1"
      >
        {LOCALES.map(({ code, label, short: abbr }) => (
          <option key={code} value={code} className="bg-surface text-ink">
            {short ? abbr : label}
          </option>
        ))}
      </select>
    </div>
  );
}
