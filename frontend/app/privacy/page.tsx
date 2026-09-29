"use client";

import { useLanguage } from "@/lib/i18n/LanguageContext";
import { privacyContent, resolveLegalDoc, SUPPORT_EMAIL } from "@/content/legal/privacy";
import PublicPageLayout from "@/components/PublicPageLayout";
import { saasPrivacy, withDataLocation } from "@/content/legal/saas";
import { IS_SAAS, SELLER } from "@/lib/site";

export default function PrivacyPage() {
  const { locale, t } = useLanguage();
  const doc = IS_SAAS
    ? resolveLegalDoc(withDataLocation(saasPrivacy[locale]), SELLER)
    : resolveLegalDoc(privacyContent[locale]);

  return (
    <PublicPageLayout>
      <h1 className="legion-title text-ink text-xl mb-1.5">
        {doc.title}
      </h1>
      <p className="text-xs text-ink-faint mb-8">
        {t.legal.effectiveDate}: {doc.effectiveDate}
      </p>

      <p className="text-sm text-ink-muted leading-relaxed mb-10">
        {doc.intro}
      </p>

      <div className="flex flex-col gap-8">
        {doc.sections.map((section) => (
          <section key={section.heading}>
            <h2 className="text-sm font-semibold text-ink mb-2.5">
              {section.heading}
            </h2>
            <div className="flex flex-col gap-2">
              {section.body.map((paragraph, i) => (
                <p
                  key={i}
                  className="text-sm text-ink-muted leading-relaxed"
                >
                  {paragraph}
                </p>
              ))}
            </div>
          </section>
        ))}

        <section className="pt-4 border-t border-line">
          <h2 className="text-sm font-semibold text-ink mb-2.5">
            {t.legal.contactHeading}
          </h2>
          <p className="text-sm text-ink-muted leading-relaxed mb-2">
            {t.legal.contactBody}
          </p>
          <a
            href={`mailto:${SUPPORT_EMAIL}`}
            className="text-sm text-brand-bright hover:underline"
          >
            {SUPPORT_EMAIL}
          </a>
        </section>
      </div>
    </PublicPageLayout>
  );
}
