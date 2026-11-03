"use client";

import Link from "next/link";
import { ReactNode } from "react";
import LegionLogo from "@/components/brand/LegionLogo";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { IS_SAAS } from "@/lib/site";

/** Language picker pinned to the top-right corner of a public account page,
 *  so a visitor can switch language before signing in. The page's root
 *  element must be `relative`. */
export function AuthLanguageSwitcher() {
  return (
    <div className="absolute top-4 right-4 z-10">
      <LanguageSwitcher compact />
    </div>
  );
}

/** Frame shared by the small public account pages (sign-up, email
 *  confirmation, password reset): the logo, one card, legal links. */
export default function AuthShell({ title, children, footer }: { title: string; children: ReactNode; footer?: ReactNode }) {
  const { t } = useLanguage();
  return (
    <main className="relative min-h-screen legion-backdrop flex flex-col items-center justify-center gap-8 p-6">
      <AuthLanguageSwitcher />
      {/* i18n-ignore: brand name */}
      <Link href="/" aria-label="Legion">
        <LegionLogo layout="stacked" size={84} tagline={false} />
      </Link>
      <div className="w-full max-w-sm rounded-2xl border border-line bg-surface p-6">
        <h1 className="legion-title text-ink mb-5">{title}</h1>
        {children}
      </div>
      {footer}
      <nav className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-[11px] text-ink-faint">
        <Link href="/terms" className="hover:text-ink-muted">{t.auth.links.terms}</Link>
        <Link href="/privacy" className="hover:text-ink-muted">{t.auth.links.privacy}</Link>
        {IS_SAAS && <Link href="/refunds" className="hover:text-ink-muted">{t.auth.links.refunds}</Link>}
        <Link href="/support" className="hover:text-ink-muted">{t.auth.links.support}</Link>
      </nav>
    </main>
  );
}

export const authInput =
  "w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover";
export const authButton =
  "w-full flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover shadow-glow disabled:opacity-60 text-white font-medium text-sm py-2.5 rounded-lg transition-colors";
