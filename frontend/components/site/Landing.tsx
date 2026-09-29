"use client";

import Link from "next/link";
import {
  Activity, Bot, Boxes, KeyRound, Radar, ShieldCheck, Sparkles, Workflow,
} from "lucide-react";
import LegionLogo from "@/components/brand/LegionLogo";
import SiteHeader from "./SiteHeader";
import SiteFooter from "./SiteFooter";
import PricingCard from "./PricingCard";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { TRIAL_DAYS } from "@/lib/site";

/** Order and icons of the feature cards; the text is in t.site.landing. */
const FEATURES = [
  { key: "realtime", Icon: Radar },
  { key: "explained", Icon: Sparkles },
  { key: "triage", Icon: Workflow },
  { key: "assets", Icon: Boxes },
  { key: "agents", Icon: Bot },
  { key: "secure", Icon: KeyRound },
] as const;

export default function Landing() {
  const { t } = useLanguage();
  const l = t.site.landing;
  const steps = [
    { n: "1", title: l.steps.create.title, text: l.steps.create.text(TRIAL_DAYS) },
    { n: "2", title: l.steps.connect.title, text: l.steps.connect.text },
    { n: "3", title: l.steps.act.title, text: l.steps.act.text },
  ];
  return (
    <div className="min-h-screen legion-backdrop text-ink">
      <SiteHeader />

      <section className="max-w-6xl mx-auto px-5 pt-16 pb-20 text-center">
        <div className="flex justify-center">
          <LegionLogo layout="stacked" size={120} />
        </div>
        <h1 className="mt-10 text-3xl sm:text-5xl font-semibold tracking-tight leading-tight">
          {l.heroTitle}
          <br />
          <span className="bg-gradient-to-r from-brand-bright via-brand-hover to-brand bg-clip-text text-transparent">
            {l.heroTitleAccent}
          </span>
        </h1>
        <p className="mt-5 text-ink-muted text-base sm:text-lg max-w-2xl mx-auto leading-relaxed">
          {l.heroText}
        </p>
        <div className="mt-8 flex flex-col sm:flex-row gap-3 justify-center">
          <Link href="/signup" className="px-6 py-3 rounded-lg bg-brand hover:bg-brand-hover text-white font-medium shadow-glow transition-colors">
            {l.ctaTrial(TRIAL_DAYS)}
          </Link>
          <Link href="/pricing" className="px-6 py-3 rounded-lg border border-line-strong text-ink-soft hover:text-ink hover:border-brand-hover transition-colors">
            {l.ctaPricing}
          </Link>
        </div>
        <p className="mt-4 text-xs text-ink-faint">{l.noCard}</p>
      </section>

      <section id="features" className="max-w-6xl mx-auto px-5 scroll-mt-20">
        <p className="legion-eyebrow text-brand-bright text-center">{l.featuresEyebrow}</p>
        <h2 className="legion-title text-center text-xl mt-3">{l.featuresTitle}</h2>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map(({ key, Icon }) => (
            <div key={key} className="rounded-2xl border border-line bg-surface/70 p-6">
              <div className="w-10 h-10 rounded-xl bg-brand/15 flex items-center justify-center">
                <Icon size={20} className="text-brand-bright" />
              </div>
              <h3 className="mt-4 font-semibold text-ink">{l.features[key].title}</h3>
              <p className="mt-2 text-sm text-ink-muted leading-relaxed">{l.features[key].text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-6xl mx-auto px-5 mt-24">
        <p className="legion-eyebrow text-brand-bright text-center">{l.stepsEyebrow}</p>
        <div className="mt-8 grid gap-4 sm:grid-cols-3">
          {steps.map((s) => (
            <div key={s.n} className="rounded-2xl border border-line p-6">
              <span className="font-display text-brand-bright text-lg">{s.n}</span>
              <h3 className="mt-3 font-semibold">{s.title}</h3>
              <p className="mt-2 text-sm text-ink-muted leading-relaxed">{s.text}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="pricing" className="max-w-6xl mx-auto px-5 mt-24 scroll-mt-20">
        <p className="legion-eyebrow text-brand-bright text-center">{l.pricingEyebrow}</p>
        <h2 className="legion-title text-center text-xl mt-3 mb-10">{l.pricingTitle}</h2>
        <PricingCard />
      </section>

      <section className="max-w-3xl mx-auto px-5 mt-24 grid gap-4 sm:grid-cols-3 text-center">
        {[
          { Icon: ShieldCheck, text: l.trust.access },
          { Icon: Activity, text: l.trust.audited },
          { Icon: KeyRound, text: l.trust.neverSold },
        ].map(({ Icon, text }) => (
          <div key={text} className="flex flex-col items-center gap-2">
            <Icon size={18} className="text-brand-bright" />
            <p className="text-xs text-ink-muted">{text}</p>
          </div>
        ))}
      </section>

      <SiteFooter />
    </div>
  );
}
