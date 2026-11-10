"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { CreditCard, Loader2, CheckCircle2, ExternalLink } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import {
  getSubscription,
  openBillingPortal,
  getCheckoutContext,
  getEntitlements,
  getPlans,
  getMe,
  isLoggedIn,
  ApiError,
  Subscription,
  CurrentUser,
  PlanCatalog,
  PlanEntitlements,
} from "@/lib/api";
import { openCheckout, isPaddleConfigured, CHECKOUT_COMPLETED } from "@/lib/paddle";
import { ADDONS, PLANS, type AddonId, type PlanId } from "@/lib/plans";
import { PeriodToggle, planPrice, type BillingPeriod } from "@/components/site/PricingCard";
import Link from "next/link";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { formatDate } from "@/lib/i18n/format";
import ErrorNotice from "@/components/ErrorNotice";

// Paddle prices are chosen by the server (PADDLE_PLAN_PRICES / PADDLE_ADDON_PRICES): the
// browser sends a plan, a period and add-ons, never a price.
const BUYABLE: PlanId[] = ["starter", "professional", "business"];

const STATUS_COLOR: Record<Subscription["status"], string> = {
  trialing: palette.warning,
  active: palette.success,
  past_due: palette.critical,
  paused: palette.inkMuted,
  canceled: palette.inkMuted,
};

export default function BillingPage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [entitlements, setEntitlements] = useState<PlanEntitlements | null>(null);
  const [catalog, setCatalog] = useState<PlanCatalog | null>(null);
  const [period, setPeriod] = useState<BillingPeriod>("month");
  const [addons, setAddons] = useState<AddonId[]>([]);
  const [loading, setLoading] = useState(true);
  const [checkoutBusy, setCheckoutBusy] = useState(false);
  const [portalBusy, setPortalBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [meData, subData, ent, plans] = await Promise.all([getMe(), getSubscription(), getEntitlements().catch(() => null), getPlans().catch(() => null)]);
      setMe(meData);
      setSubscription(subData);
      setEntitlements(ent);
      setCatalog(plans);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    load();
  }, [router, load]);

  // After a successful checkout, poll until Paddle's webhook has activated
  // the subscription (usually a few seconds), so the page shows the new plan.
  const [activating, setActivating] = useState(false);
  // Read at the moment the timeout hits, so the message is in the current language.
  const notConfirmedRef = useRef(t.billing.notConfirmed);
  useEffect(() => { notConfirmedRef.current = t.billing.notConfirmed; }, [t]);
  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | undefined;
    const onCompleted = () => {
      setActivating(true);
      let tries = 0;
      timer = setInterval(async () => {
        tries += 1;
        const sub = await getSubscription().catch(() => null);
        if (sub && (sub.status === "active" || sub.status === "trialing")) {
          setSubscription(sub);
          setActivating(false);
          clearInterval(timer);
        } else if (tries >= 20) {
          setActivating(false);
          setError(new Error(notConfirmedRef.current));
          clearInterval(timer);
        }
      }, 2000);
    };
    window.addEventListener(CHECKOUT_COMPLETED, onCompleted);
    return () => { window.removeEventListener(CHECKOUT_COMPLETED, onCompleted); if (timer) clearInterval(timer); };
  }, []);

  async function handleChoose(plan: PlanId) {
    if (!me) return;
    setCheckoutBusy(true);
    setError(null);
    try {
      // The server turns the plan, period and add-ons into Paddle prices and binds the checkout to this workspace.
      const ctx = await getCheckoutContext({ plan, interval: period, addons: period === "month" ? addons : [] });
      await openCheckout(ctx.items ?? ctx.price_id ?? "", ctx.checkout_token, me.email, locale);
    } catch (err) {
      setError(err instanceof ApiError ? err : new Error(t.billing.checkoutError));
    } finally {
      setCheckoutBusy(false);
    }
  }

  async function handleManage() {
    setPortalBusy(true);
    setError(null);
    try {
      const { url } = await openBillingPortal();
      window.location.href = url;
    } catch (err) {
      setError(err instanceof ApiError ? err : new Error(t.billing.portalError));
    } finally {
      setPortalBusy(false);
    }
  }

  const isActive = subscription?.status === "active" || subscription?.status === "trialing";
  // No subscription yet: the plan is the workspace's free trial.
  const trialEnd = subscription?.trial_ends_at ?? me?.trial_ends_at ?? null;
  const trialDays = trialEnd ? Math.ceil((new Date(trialEnd).getTime() - Date.now()) / 86_400_000) : 0;

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <div className="border-b border-line px-6 py-4 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-brand/15 flex items-center justify-center">
            <CreditCard size={16} color={palette.brandBright} />
          </div>
          <div>
            <h1 className="text-ink font-semibold text-sm leading-none">
              {t.billing.title}
            </h1>
            <p className="text-ink-faint text-[11px] mt-1">
              {t.billing.subtitle}
            </p>
          </div>
        </div>

        <div className="flex-1 p-6 max-w-2xl">
          {loading ? (
            <div className="flex items-center gap-2 text-ink-faint text-sm">
              <Loader2 size={16} className="animate-spin" />
              {t.common.loading}
            </div>
          ) : (
            <div className="flex flex-col gap-5">
              {error != null && <ErrorNotice error={error} onRetry={load} isAdmin={me?.role === "admin"} />}

              {activating && (
                <div className="text-sm text-brand-bright bg-brand/10 border border-brand-hover/30 rounded-lg px-4 py-3 flex items-center gap-2">
                  <Loader2 size={14} className="animate-spin" /> {t.billing.activating}
                </div>
              )}

              {!isPaddleConfigured() && (
                <div className="text-sm text-warning bg-warning/10 border border-warning/30 rounded-lg px-4 py-3">
                  {t.billing.paddleNotConfigured}
                </div>
              )}

              <div className="rounded-xl border border-line bg-surface p-5">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-ink font-medium text-sm">
                    {t.billing.currentPlan}
                  </h2>
                  {subscription && (
                    <span
                      className="text-[11px] font-medium uppercase tracking-wide rounded px-2 py-0.5"
                      style={{
                        color: STATUS_COLOR[subscription.status],
                        backgroundColor: `${STATUS_COLOR[subscription.status]}1A`,
                      }}
                    >
                      {t.common.subscription[subscription.status]}
                    </span>
                  )}
                </div>

                {subscription ? (
                  <div className="flex flex-col gap-2 text-sm text-ink-muted">
                    {subscription.current_period_end && (
                      <p>
                        {subscription.cancel_at_period_end
                          ? t.billing.accessEnds(formatDate(subscription.current_period_end, locale))
                          : t.billing.renews(formatDate(subscription.current_period_end, locale))}
                      </p>
                    )}
                    <button
                      onClick={handleManage}
                      disabled={portalBusy}
                      className="mt-2 inline-flex items-center gap-1.5 self-start text-sm text-brand-bright hover:text-ink transition-colors disabled:opacity-50"
                    >
                      {portalBusy ? (
                        <Loader2 size={14} className="animate-spin" />
                      ) : (
                        <ExternalLink size={14} />
                      )}
                      {t.billing.manage}
                    </button>
                  </div>
                ) : (
                  <p className="text-sm text-ink-muted" data-testid="plan-status">
                    {trialEnd
                      ? trialDays > 0
                        ? t.billing.trialActive(formatDate(trialEnd, locale), trialDays)
                        : t.billing.trialEnded(formatDate(trialEnd, locale))
                      : t.billing.notSubscribed}
                  </p>
                )}
                {me && me.role !== "admin" && (
                  <p className="text-ink-faint text-xs mt-3">{t.billing.adminOnlyNote}</p>
                )}
                {entitlements && entitlements.source !== "self-hosted" && (
                  <div className="mt-4 pt-4 border-t border-line" data-testid="plan-usage">
                    <p className="text-ink text-sm font-medium" data-testid="plan-name">
                      {t.billing.planName(PLANS[entitlements.plan].name, entitlements.source === "trial")}
                      {entitlements.addons.length > 0 && (
                        <span className="text-ink-muted font-normal"> + {entitlements.addons.map((a) => t.pricing.addons.names[a]).join(", ")}</span>
                      )}
                    </p>
                    {t.billing.planSource[entitlements.source] && (
                      <p className="text-ink-muted text-xs mt-1">{t.billing.planSource[entitlements.source]}</p>
                    )}
                    <p className="text-ink-faint text-[11px] uppercase tracking-wide mt-4">{t.billing.usage.title}</p>
                    <dl className="mt-2 grid grid-cols-[1fr_auto] gap-x-6 gap-y-1.5 text-sm">
                      <dt className="text-ink-muted">{t.billing.usage.endpoints}</dt>
                      <dd className={entitlements.usage.endpoints.over ? "text-warning font-medium" : "text-ink"}>
                        {t.billing.usage.of(entitlements.usage.endpoints.used, entitlements.usage.endpoints.limit)}
                      </dd>
                      <dt className="text-ink-muted">{t.billing.usage.admins}</dt>
                      <dd className={entitlements.usage.admins.over ? "text-warning font-medium" : "text-ink"}>
                        {t.billing.usage.of(entitlements.usage.admins.used, entitlements.usage.admins.limit)}
                      </dd>
                    </dl>
                    {entitlements.usage.endpoints.over && <p className="text-warning text-xs mt-3">{t.billing.usage.overEndpoints}</p>}
                    {entitlements.usage.admins.over && <p className="text-warning text-xs mt-2">{t.billing.usage.overAdmins}</p>}
                  </div>
                )}
                {isActive && <p className="text-ink-faint text-xs mt-4">{t.billing.changePlan}</p>}
              </div>

              {!isActive && me?.role === "admin" && (
                <div className="rounded-xl border border-brand-hover/40 bg-brand/5 p-5">
                  <h2 className="text-ink font-medium text-sm mb-3">{t.billing.subscribeTitle}</h2>
                  <div className="mb-4"><PeriodToggle value={period} onChange={setPeriod} /></div>
                  <div className="grid gap-3 sm:grid-cols-3">
                    {BUYABLE.map((id) => {
                      const price = planPrice(id, period);
                      const buyable = catalog?.plans.find((p) => p.id === id)?.buy[period] ?? false;
                      return (
                        <div key={id} data-testid={`choose-${id}`} className={`rounded-lg border p-4 flex flex-col ${id === "professional" ? "border-brand-hover/60" : "border-line"} bg-surface`}>
                          <p className="text-ink font-medium text-sm">{PLANS[id].name}</p>
                          <p className="text-ink text-lg font-semibold mt-1">
                            {price.amount}<span className="text-ink-muted text-xs font-normal"> {price.sub === "year" ? t.pricing.perYear : t.pricing.perMonth}</span>
                          </p>
                          <ul className="flex flex-col gap-1 my-3 text-xs text-ink-soft flex-1">
                            <li className="flex gap-1.5"><CheckCircle2 size={12} color={palette.brandBright} className="mt-0.5 shrink-0" />{t.pricing.headline.endpoints(PLANS[id].entitlements.endpoints)}</li>
                            <li className="flex gap-1.5"><CheckCircle2 size={12} color={palette.brandBright} className="mt-0.5 shrink-0" />{t.pricing.headline.admins(PLANS[id].entitlements.admins)}</li>
                            <li className="flex gap-1.5"><CheckCircle2 size={12} color={palette.brandBright} className="mt-0.5 shrink-0" />{t.pricing.headline.history(PLANS[id].entitlements.retentionDays)}</li>
                          </ul>
                          <button
                            onClick={() => handleChoose(id)}
                            disabled={checkoutBusy || !buyable || !isPaddleConfigured()}
                            title={buyable ? undefined : t.billing.notAvailable}
                            className="inline-flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover text-white text-sm font-medium rounded-lg px-3 py-2 transition-colors disabled:opacity-50"
                          >
                            {checkoutBusy && <Loader2 size={14} className="animate-spin" />}
                            {t.billing.choosePlan(PLANS[id].name)}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                  {period === "month" && (
                    <div className="mt-4">
                      <p className="text-ink-faint text-[11px] uppercase tracking-wide mb-2">{t.billing.addonsTitle}</p>
                      <div className="flex flex-col gap-1.5">
                        {Object.values(ADDONS).filter((a) => catalog?.addons.find((x) => x.id === a.id)?.buy).map((a) => (
                          <label key={a.id} className="flex items-center gap-2 text-sm text-ink-soft">
                            <input type="checkbox" checked={addons.includes(a.id)}
                              onChange={(e) => setAddons((cur) => (e.target.checked ? [...cur, a.id] : cur.filter((x) => x !== a.id)))} />
                            {t.pricing.addons.names[a.id]} <span className="text-ink-muted">+${a.monthlyUsd} {t.pricing.addons.perMonth}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                  <p className="text-ink-faint text-xs mt-4">
                    {t.pricing.taxNote} <Link href="/pricing#compare" className="text-brand-bright">{t.pricing.seeComparison}</Link> · <Link href="/support" className="text-brand-bright">{t.billing.contactUs}</Link>
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
