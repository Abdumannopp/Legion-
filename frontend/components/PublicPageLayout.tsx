"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { ReactNode } from "react";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import LegionLogo from "@/components/brand/LegionLogo";
import SiteHeader from "@/components/site/SiteHeader";
import SiteFooter from "@/components/site/SiteFooter";
import { IS_SAAS } from "@/lib/site";

export default function PublicPageLayout({
  children,
}: {
  children: ReactNode;
}) {
  const { t } = useLanguage();

  // Hosted service: legal and support pages are part of the public website.
  if (IS_SAAS) {
    return (
      <div className="min-h-screen legion-backdrop">
        <SiteHeader />
        <main className="max-w-3xl mx-auto px-6 py-12">{children}</main>
        <SiteFooter />
      </div>
    );
  }

  return (
    <div className="min-h-screen legion-backdrop">
      <header className="border-b border-line">
        <div className="max-w-3xl mx-auto px-6 py-4 flex items-center justify-between">
          {/* i18n-ignore: brand name */}
          <Link href="/" aria-label="Legion">
            <LegionLogo layout="horizontal" size={32} tagline={false} />
          </Link>
          <LanguageSwitcher compact />
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-12">
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-ink-faint hover:text-ink-muted transition-colors mb-8"
        >
          <ArrowLeft size={13} />
          {t.legal.backToDashboard}
        </Link>
        {children}
      </main>
    </div>
  );
}
