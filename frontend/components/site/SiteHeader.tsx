"use client";

import Link from "next/link";
import LegionLogo from "@/components/brand/LegionLogo";
import LegionMark from "@/components/brand/LegionMark";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { TRIAL_DAYS } from "@/lib/site";

export default function SiteHeader() {
  const { t } = useLanguage();
  const h = t.site.header;
  return (
    <header className="border-b border-line/70 bg-canvas/70 backdrop-blur sticky top-0 z-20">
      <div className="max-w-6xl mx-auto px-5 h-16 flex items-center justify-between gap-4">
        <Link href="/" aria-label={h.homeAria} className="shrink-0">
          {/* Phones: the mark alone, so the menu and language switcher fit. */}
          <span className="sm:hidden"><LegionMark size={30} /></span>
          <span className="hidden sm:block"><LegionLogo layout="horizontal" size={30} tagline={false} /></span>
        </Link>
        {/* Russian and Uzbek labels run longer and the language switcher needs
            room, so the secondary links appear from wider breakpoints. */}
        <nav className="flex items-center gap-1 sm:gap-2 text-sm min-w-0">
          <Link href="/#features" className="hidden md:inline px-3 py-2 text-ink-muted hover:text-ink whitespace-nowrap">{h.features}</Link>
          <Link href="/pricing" className="hidden sm:inline px-3 py-2 text-ink-muted hover:text-ink whitespace-nowrap">{h.pricing}</Link>
          <Link href="/login" className="px-2 sm:px-3 py-2 text-ink-muted hover:text-ink whitespace-nowrap">{t.common.signIn}</Link>
          <Link
            href="/signup"
            className="ml-1 px-3.5 py-2 rounded-lg bg-brand hover:bg-brand-hover text-white font-medium shadow-glow transition-colors whitespace-nowrap"
          >
            <span className="hidden md:inline">{h.startTrial(TRIAL_DAYS)}</span>
            <span className="md:hidden">{h.tryFree}</span>
          </Link>
          <div className="ml-1 shrink-0 sm:hidden">
            <LanguageSwitcher compact short />
          </div>
          <div className="ml-1 shrink-0 hidden sm:block">
            <LanguageSwitcher compact />
          </div>
        </nav>
      </div>
    </header>
  );
}
