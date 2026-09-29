"use client";

import { Mail, Clock, ArrowUpRight } from "lucide-react";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { SUPPORT_EMAIL } from "@/content/legal/privacy";
import PublicPageLayout from "@/components/PublicPageLayout";
import { palette } from "@/lib/theme";

export default function SupportPage() {
  const { t } = useLanguage();

  return (
    <PublicPageLayout>
      <h1 className="legion-title text-ink text-xl mb-1.5">
        {t.support.title}
      </h1>
      <p className="text-sm text-ink-faint mb-8">{t.support.subtitle}</p>

      <p className="text-sm text-ink-muted leading-relaxed mb-8 max-w-xl">
        {t.support.intro}
      </p>

      <div className="flex flex-col gap-3 max-w-md">
        <a
          href={`mailto:${SUPPORT_EMAIL}`}
          className="group flex items-center justify-between gap-3 rounded-xl border border-line bg-surface px-4 py-3.5 hover:border-brand-hover/50 transition-colors"
        >
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-canvas border border-line flex items-center justify-center shrink-0">
              <Mail size={16} color={palette.brandBright} strokeWidth={2} />
            </div>
            <div>
              <p className="text-xs text-ink-faint">{t.support.emailLabel}</p>
              <p className="text-sm text-ink font-medium">
                {SUPPORT_EMAIL}
              </p>
            </div>
          </div>
          <ArrowUpRight
            size={15}
            className="text-ink-disabled group-hover:text-brand-bright transition-colors"
          />
        </a>

        <div className="flex items-center gap-3 rounded-xl border border-line bg-surface px-4 py-3.5">
          <div className="w-9 h-9 rounded-lg bg-canvas border border-line flex items-center justify-center shrink-0">
            <Clock size={16} color={palette.brandBright} strokeWidth={2} />
          </div>
          <div>
            <p className="text-xs text-ink-faint">{t.support.responseTime}</p>
            <p className="text-sm text-ink font-medium">
              {t.support.responseTimeValue}
            </p>
          </div>
        </div>
      </div>

      <p className="text-xs text-ink-faint mt-10">
        {t.support.moreHelp}{" "}
        <a
          href={`mailto:${SUPPORT_EMAIL}`}
          className="text-brand-bright hover:underline"
        >
          {t.support.moreHelpLink}
        </a>
      </p>
    </PublicPageLayout>
  );
}
