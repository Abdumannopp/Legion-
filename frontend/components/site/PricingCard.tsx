"use client";

import Link from "next/link";
import { useState } from "react";
import { Check } from "lucide-react";
import { ADDONS, PLANS, PLAN_IDS, SELF_HOSTED, SETUP_SERVICES, type PlanId } from "@/lib/plans";
import { TRIAL_DAYS } from "@/lib/site";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export type BillingPeriod = "month" | "year";

/** The monthly / annual switch. Annual is ten months' price: two months free. */
export function PeriodToggle({ value, onChange }: { value: BillingPeriod; onChange: (v: BillingPeriod) => void }) {
  const { t } = useLanguage();
  const p = t.pricing;
  const base = "px-4 py-1.5 text-sm rounded-md transition-colors";
  return (
    <div className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface p-1" role="group">
      <button type="button" aria-pressed={value === "month"} onClick={() => onChange("month")}
        className={`${base} ${value === "month" ? "bg-brand text-white" : "text-ink-muted hover:text-ink"}`}>{p.monthly}</button>
      <button type="button" aria-pressed={value === "year"} onClick={() => onChange("year")}
        className={`${base} ${value === "year" ? "bg-brand text-white" : "text-ink-muted hover:text-ink"}`}>
        {p.annual} <span className="text-[11px] opacity-80">· {p.annualBadge}</span>
      </button>
    </div>
  );
}

const usd = (n: number) => `$${n.toLocaleString("en-US")}`;

/** What a plan costs in the chosen period, as text parts. */
export function planPrice(id: PlanId, period: BillingPeriod): { amount: string | null; from: boolean; sub: "month" | "year" | null } {
  const plan = PLANS[id];
  if (period === "year") return plan.annualUsd === null ? { amount: null, from: false, sub: null } : { amount: usd(plan.annualUsd), from: plan.from, sub: "year" };
  return { amount: plan.monthlyUsd === null ? null : usd(plan.monthlyUsd), from: plan.from, sub: "month" };
}

/**
 * The four plans. Used on the landing page and the pricing page (compact =
 * no feature rows beyond the three headline limits).
 */
export default function PlansGrid({ showToggle = true }: { showToggle?: boolean }) {
  const { t } = useLanguage();
  const p = t.pricing;
  const [period, setPeriod] = useState<BillingPeriod>("month");
  return (
    <div>
      {showToggle && <div className="flex justify-center mb-8"><PeriodToggle value={period} onChange={setPeriod} /></div>}
      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
        {PLAN_IDS.map((id) => {
          const plan = PLANS[id];
          const e = plan.entitlements;
          const price = planPrice(id, period);
          const featured = id === "professional";
          const enterprise = id === "enterprise";
          const monthlyEquivalent = period === "year" && plan.annualUsd ? Math.round(plan.annualUsd / 12) : null;
          const savePercent = plan.monthlyUsd && plan.annualUsd ? Math.round((1 - plan.annualUsd / (plan.monthlyUsd * 12)) * 1000) / 10 : null;
          return (
            <div key={id} data-testid={`plan-${id}`}
              className={`relative flex flex-col rounded-2xl border bg-surface p-6 ${featured ? "border-brand-hover/60 shadow-glow" : "border-line"}`}>
              {featured && (
                <span className="absolute -top-3 left-6 rounded-full bg-brand px-3 py-0.5 text-[11px] font-medium text-white">{p.recommended}</span>
              )}
              <h3 className="font-semibold text-ink">{plan.name}</h3>
              <p className="text-ink-muted text-sm mt-1">{p.audience[id]}</p>
              <div className="mt-5 min-h-[4.5rem]">
                {price.amount ? (
                  <>
                    <div className="flex items-baseline gap-1.5">
                      {price.from && <span className="text-ink-muted text-sm">{p.from}</span>}
                      <span className="text-3xl font-semibold text-ink tabular-nums">{price.amount}{enterprise && "+"}</span>
                      <span className="text-ink-muted text-sm">{price.sub === "year" ? p.perYear : p.perMonth}</span>
                    </div>
                    {monthlyEquivalent !== null && (
                      <p className="text-ink-faint text-xs mt-1">
                        {p.billedYearly(monthlyEquivalent)}{savePercent !== null && ` · ${p.savePercent(savePercent)}`}
                      </p>
                    )}
                  </>
                ) : (
                  <p className="text-2xl font-semibold text-ink">{p.byAgreement}</p>
                )}
              </div>
              <ul className="mt-5 space-y-2 text-sm text-ink-soft flex-1">
                {[p.headline.endpoints(e.endpoints), p.headline.admins(e.admins), p.headline.history(e.retentionDays)].map((line) => (
                  <li key={line} className="flex gap-2"><Check size={15} className="text-brand-bright shrink-0 mt-0.5" />{line}</li>
                ))}
              </ul>
              <Link href={enterprise ? "/support" : "/signup"}
                className={`mt-6 block text-center rounded-lg font-medium py-2.5 transition-colors ${
                  featured ? "bg-brand hover:bg-brand-hover text-white shadow-glow" : "border border-line-strong text-ink-soft hover:text-ink hover:border-brand-hover"}`}>
                {enterprise ? p.contactSales : p.startTrial}
              </Link>
            </div>
          );
        })}
      </div>
      <p className="text-[11px] text-ink-faint mt-4 text-center">{p.taxNote}</p>
    </div>
  );
}

function Table({ head, rows }: { head: string[]; rows: (string | JSX.Element)[][] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-line">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-surface text-ink text-left">{head.map((h, i) => <th key={i} className="px-4 py-3 font-medium whitespace-nowrap">{h}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-t border-line text-ink-soft">
              {r.map((c, j) => <td key={j} className={`px-4 py-3 ${j === 0 ? "font-medium text-ink" : ""}`}>{c}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ComparisonTable() {
  const { t } = useLanguage();
  const c = t.pricing.compare;
  const ent = (id: PlanId) => PLANS[id].entitlements;
  const bool = (v: boolean) => (v ? c.yes : c.no);
  const rows: (string | JSX.Element)[][] = [
    [c.rows.endpoints, ...PLAN_IDS.map((id) => c.endpoints(ent(id).endpoints))],
    [c.rows.admins, ...PLAN_IDS.map((id) => c.admins(ent(id).admins))],
    [c.rows.retention, ...PLAN_IDS.map((id) => c.retention(ent(id).retentionDays))],
    [c.rows.aiAnalysis, ...PLAN_IDS.map((id) => c.aiAnalysis[ent(id).aiAnalysis])],
    [c.rows.aiAgents, ...PLAN_IDS.map((id) => bool(ent(id).aiAgents))],
    [c.rows.agentSecurity, ...PLAN_IDS.map((id) => (ent(id).agentSecurity ? c.yes : c.addon))],
    [c.rows.paymentCheck, ...PLAN_IDS.map((id) => c.paymentCheck[ent(id).paymentCheck])],
    [c.rows.ipBlocking, ...PLAN_IDS.map((id) => c.ipBlocking[ent(id).ipBlocking])],
    [c.rows.api, ...PLAN_IDS.map((id) => c.api[ent(id).api])],
    [c.rows.support, ...PLAN_IDS.map((id) => c.support[ent(id).support])],
  ];
  return <Table head={[c.feature, ...PLAN_IDS.map((id) => PLANS[id].name)]} rows={rows} />;
}

export function AddonsTable() {
  const { t } = useLanguage();
  const a = t.pricing.addons;
  return (
    <Table head={[a.title, "", ""]} rows={Object.values(ADDONS).map((x) => [
      a.names[x.id], <span key="h" className="text-ink-muted">{a.help[x.id]}</span>, <span key="p" className="whitespace-nowrap font-medium text-ink">+{usd(x.monthlyUsd)} {a.perMonth}</span>,
    ])} />
  );
}

export function SelfHostedTable() {
  const { t } = useLanguage();
  const s = t.pricing.selfHosted;
  const c = t.pricing.compare;
  return (
    <Table head={[s.plan, s.endpoints, s.licence]} rows={SELF_HOSTED.map((l) => [
      PLANS[l.plan].name, c.endpoints(l.endpoints), `${usd(l.annualUsd)}${l.from ? "+" : ""} ${t.pricing.perYear}`,
    ])} />
  );
}

export function SetupTable() {
  const { t } = useLanguage();
  const s = t.pricing.setup;
  const key = (id: string) => id as "basic" | "professional" | "enterprise";
  return (
    <Table head={[s.title, "", ""]} rows={SETUP_SERVICES.map((x) => [
      s.names[key(x.id)], <span key="h" className="text-ink-muted">{s.help[key(x.id)]}</span>, <span key="p" className="whitespace-nowrap font-medium text-ink">{s.range(x.fromUsd, x.toUsd)}</span>,
    ])} />
  );
}

/** The body of the public /pricing page. It lives in a client component so it
 *  follows the language switcher, while app/pricing/page.tsx stays a server
 *  component for its metadata. */
export function PricingPageContent() {
  const { t } = useLanguage();
  const p = t.pricing;
  const faq = [
    { q: p.faq.afterTrial.q, a: p.faq.afterTrial.a(TRIAL_DAYS) },
    { q: p.faq.limits.q, a: p.faq.limits.a },
    { q: p.faq.cancel.q, a: p.faq.cancel.a },
    { q: p.faq.refunds.q, a: p.faq.refunds.a },
    { q: p.faq.payment.q, a: p.faq.payment.a },
  ];
  return (
    <>
      <p className="legion-eyebrow text-brand-bright text-center">{p.eyebrow}</p>
      <h1 className="legion-title text-center text-2xl mt-3">{p.title}</h1>
      <p className="text-center text-ink-muted mt-3 mb-10">{p.subtitle(TRIAL_DAYS)}</p>
      <PlansGrid />

      <section className="mt-20" id="compare">
        <h2 className="font-semibold text-ink text-lg mb-4">{p.compare.title}</h2>
        <ComparisonTable />
      </section>
      <section className="mt-14">
        <h2 className="font-semibold text-ink text-lg">{p.addons.title}</h2>
        <p className="text-ink-muted text-sm mt-1 mb-4">{p.addons.intro}</p>
        <AddonsTable />
      </section>
      <section className="mt-14" id="self-hosted">
        <h2 className="font-semibold text-ink text-lg">{p.selfHosted.title}</h2>
        <p className="text-ink-muted text-sm mt-1 mb-4">{p.selfHosted.intro}</p>
        <SelfHostedTable />
        <p className="text-ink-faint text-xs mt-2">{p.selfHosted.note}</p>
      </section>
      <section className="mt-14">
        <h2 className="font-semibold text-ink text-lg">{p.setup.title}</h2>
        <p className="text-ink-muted text-sm mt-1 mb-4">{p.setup.intro}</p>
        <SetupTable />
      </section>

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
