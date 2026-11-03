"use client";

import Link from "next/link";
import LegionLogo from "@/components/brand/LegionLogo";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { SELLER } from "@/lib/site";
import { SUPPORT_EMAIL } from "@/content/legal/privacy";

export default function SiteFooter() {
  const { t } = useLanguage();
  const f = t.site.footer;
  return (
    <footer className="border-t border-line/70 mt-24">
      <div className="max-w-6xl mx-auto px-5 py-10 grid gap-8 sm:grid-cols-[1fr_auto]">
        <div>
          <LegionLogo layout="horizontal" size={28} />
          <p className="text-xs text-ink-faint mt-4 max-w-md leading-relaxed">
            {f.merchantNotice(SELLER)}
          </p>
        </div>
        <nav className="grid grid-cols-2 gap-x-10 gap-y-2 text-sm content-start">
          <Link href="/pricing" className="text-ink-muted hover:text-ink">{f.pricing}</Link>
          <Link href="/terms" className="text-ink-muted hover:text-ink">{f.terms}</Link>
          <Link href="/signup" className="text-ink-muted hover:text-ink">{f.freeTrial}</Link>
          <Link href="/privacy" className="text-ink-muted hover:text-ink">{f.privacy}</Link>
          <a href={`mailto:${SUPPORT_EMAIL}`} className="text-ink-muted hover:text-ink">{f.contact}</a>
          <Link href="/refunds" className="text-ink-muted hover:text-ink">{f.refunds}</Link>
        </nav>
      </div>
      <p className="text-center text-[11px] text-ink-disabled pb-8">© {new Date().getFullYear()} {SELLER}</p>
    </footer>
  );
}
