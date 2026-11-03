"use client";

import { useEffect } from "react";
import { notFound } from "next/navigation";
import PublicPageLayout from "@/components/PublicPageLayout";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { resolveLegalDoc, SUPPORT_EMAIL } from "@/content/legal/privacy";
import { saasRefunds, withDataLocation } from "@/content/legal/saas";
import { IS_SAAS, SELLER } from "@/lib/site";

export default function RefundsPage() {
  const { locale, t } = useLanguage();
  const doc = resolveLegalDoc(withDataLocation(saasRefunds[locale]), SELLER);

  // A client page cannot export `metadata`, so the tab title is set here —
  // in the reader's language.
  useEffect(() => {
    document.title = `${doc.title} | Legion Cyber Intelligence`; // i18n-ignore: brand suffix
  }, [doc.title]);

  // Nothing is sold on a self-hosted installation.
  if (!IS_SAAS) notFound();
  return (
    <PublicPageLayout>
      <h1 className="legion-title text-ink text-xl mb-1.5">{doc.title}</h1>
      <p className="text-xs text-ink-faint mb-8">{t.legal.effectiveDate}: {doc.effectiveDate}</p>
      <p className="text-sm text-ink-muted leading-relaxed mb-10">{doc.intro}</p>
      <div className="flex flex-col gap-8">
        {doc.sections.map((section) => (
          <section key={section.heading}>
            <h2 className="text-sm font-semibold text-ink mb-2.5">{section.heading}</h2>
            {section.body.map((p, i) => (
              <p key={i} className="text-sm text-ink-muted leading-relaxed mb-2">{p}</p>
            ))}
          </section>
        ))}
        <p className="text-sm text-ink-muted pt-4 border-t border-line">
          {t.legal.contactLabel}: <a href={`mailto:${SUPPORT_EMAIL}`} className="text-brand-bright hover:underline">{SUPPORT_EMAIL}</a>
        </p>
      </div>
    </PublicPageLayout>
  );
}
