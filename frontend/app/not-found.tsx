"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import PublicPageLayout from "@/components/PublicPageLayout";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export default function NotFound() {
  const { t } = useLanguage();
  const n = t.notFound;
  return (
    <PublicPageLayout>
      <div className="py-12 sm:py-20 text-center">
        <p className="legion-eyebrow text-brand-bright">{n.code}</p>
        <h1 className="legion-title text-ink text-xl mt-3">{n.title}</h1>
        <p className="text-sm text-ink-muted leading-relaxed mt-4 max-w-md mx-auto">{n.text}</p>
        <Link
          href="/"
          className="mt-8 inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-brand hover:bg-brand-hover text-white text-sm font-medium shadow-glow transition-colors"
        >
          <ArrowLeft size={15} />
          {n.home}
        </Link>
      </div>
    </PublicPageLayout>
  );
}
