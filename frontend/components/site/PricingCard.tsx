"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Check } from "lucide-react";
import { getPriceLabel, PADDLE_PRICE_ID, PriceLabel } from "@/lib/paddle";
import { PRICE_FALLBACK, TRIAL_DAYS } from "@/lib/site";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import type { PriceInterval } from "@/lib/i18n/ns/site";

/** Paddle describes the period as "month" or "3 months"; split it for translation. */
function parsePeriod(per: string): { count: number; unit: PriceInterval } | null {
  const m = /^(?:(\d+) )?(day|week|month|year)s?$/.exec(per);
  return m ? { count: m[1] ? Number(m[1]) : 1, unit: m[2] as PriceInterval } : null;
}

/** The one plan. The price comes from Paddle, localized to the visitor's
 *  currency, so the page can never disagree with the checkout. */
export default function PricingCard() {
  const { t } = useLanguage();
  const c = t.site.pricingCard;
  const [price, setPrice] = useState<PriceLabel | null>(null);
  useEffect(() => { getPriceLabel(PADDLE_PRICE_ID).then(setPrice); }, []);

  const periodLabel = (per: string) => {
    const p = parsePeriod(per);
    return p ? c.per(p.count, p.unit) : c.perOther(per);
  };

  return (
    <div className="relative rounded-2xl border border-brand-hover/40 bg-surface p-7 shadow-glow max-w-md w-full mx-auto">
      {/* i18n-ignore: product name */}
      <p className="legion-eyebrow text-brand-bright">Legion</p>
      <div className="mt-4 flex items-baseline gap-2">
        <span className="text-4xl font-semibold text-ink tabular-nums">
          {price?.amount || PRICE_FALLBACK || "—"}
        </span>
        <span className="text-ink-muted text-sm">
          {price ? (price.per ? periodLabel(price.per) : "") : PRICE_FALLBACK ? c.per(1, "month") : c.priceAtCheckout}
        </span>
      </div>
      <p className="text-ink-muted text-sm mt-2">
        {c.trialTerms(TRIAL_DAYS)}
      </p>
      <ul className="mt-6 space-y-2.5">
        {t.site.planFeatures.map((f) => (
          <li key={f} className="flex gap-2.5 text-sm text-ink-soft">
            <Check size={16} className="text-brand-bright shrink-0 mt-0.5" />
            {f}
          </li>
        ))}
      </ul>
      <Link
        href="/signup"
        className="mt-7 block text-center rounded-lg bg-brand hover:bg-brand-hover text-white font-medium py-3 shadow-glow transition-colors"
      >
        {c.startTrial}
      </Link>
      <p className="text-[11px] text-ink-faint mt-3 text-center">
        {c.taxNote}
      </p>
    </div>
  );
}

/** The body of the public /pricing page: heading, plan card and FAQ. It lives
 *  here, in a client component, so it follows the language switcher, while
 *  app/pricing/page.tsx stays a server component for its metadata. */
export function PricingPageContent() {
  const { t } = useLanguage();
  const p = t.pricing;
  const faq = [
    { q: p.faq.afterTrial.q, a: p.faq.afterTrial.a(TRIAL_DAYS) },
    { q: p.faq.cancel.q, a: p.faq.cancel.a },
    { q: p.faq.refunds.q, a: p.faq.refunds.a },
    { q: p.faq.payment.q, a: p.faq.payment.a },
  ];
  return (
    <>
      <p className="legion-eyebrow text-brand-bright text-center">{p.eyebrow}</p>
      <h1 className="legion-title text-center text-2xl mt-3">{p.title}</h1>
      <p className="text-center text-ink-muted mt-3 mb-12">{p.subtitle(TRIAL_DAYS)}</p>
      <PricingCard />
      <div className="max-w-2xl mx-auto mt-20 space-y-6">
        {faq.map(({ q, a }) => (
          <div key={q}>
            <h2 className="font-semibold text-ink">{q}</h2>
            <p className="text-sm text-ink-muted mt-1.5 leading-relaxed">{a}</p>
          </div>
        ))}
        <p className="text-sm text-ink-muted">
          {p.contactPrompt} <Link href="/support" className="text-brand-bright">{p.contactLink}</Link>.
        </p>
      </div>
    </>
  );
}
