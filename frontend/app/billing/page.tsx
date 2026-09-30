"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { CreditCard, Loader2, CheckCircle2, ExternalLink } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import {
  getSubscription,
  openBillingPortal,
  getCheckoutContext,
  getMe,
  isLoggedIn,
  ApiError,
  Subscription,
  CurrentUser,
} from "@/lib/api";
import { openCheckout, isPaddleConfigured, CHECKOUT_COMPLETED, getPriceLabel, PriceLabel } from "@/lib/paddle";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { formatDate } from "@/lib/i18n/format";
import type { BillingInterval } from "@/lib/i18n/ns/billing";

// A single paid plan for now — swap in real Paddle price IDs from
// Paddle > Catalog > Prices once you've created them, or add more
// entries here for multiple tiers.
const PRICE_ID = process.env.NEXT_PUBLIC_PADDLE_PRICE_ID || "";

const STATUS_COLOR: Record<Subscription["status"], string> = {
  trialing: palette.warning,
  active: palette.success,
  past_due: palette.critical,
  paused: palette.inkMuted,
  canceled: palette.inkMuted,
};

/** Paddle describes the period as "month" or "3 months"; split it for translation. */
function parseInterval(per: string): { count: number; unit: BillingInterval } | null {
  const m = /^(?:(\d+) )?(day|week|month|year)s?$/.exec(per);
  return m ? { count: m[1] ? Number(m[1]) : 1, unit: m[2] as BillingInterval } : null;
}

export default function BillingPage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [subscription, setSubscription] = useState<Subscription | null>(null);
  const [loading, setLoading] = useState(true);
  const [checkoutBusy, setCheckoutBusy] = useState(false);
  const [portalBusy, setPortalBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [meData, subData] = await Promise.all([getMe(), getSubscription()]);
      setMe(meData);
      setSubscription(subData);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err instanceof ApiError ? err.message : t.billing.loadError);
    } finally {
      setLoading(false);
    }
  }, [router, t]);

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
  const [price, setPrice] = useState<PriceLabel | null>(null);
  useEffect(() => { getPriceLabel(PRICE_ID).then(setPrice); }, []);
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
          setError(notConfirmedRef.current);
          clearInterval(timer);
        }
      }, 2000);
    };
    window.addEventListener(CHECKOUT_COMPLETED, onCompleted);
    return () => { window.removeEventListener(CHECKOUT_COMPLETED, onCompleted); if (timer) clearInterval(timer); };
  }, []);

  async function handleUpgrade() {
    if (!me || !PRICE_ID) return;
    setCheckoutBusy(true);
    setError(null);
    try {
      // The server picks the price for this workspace's billing currency when it has one.
      const { checkout_token, price_id } = await getCheckoutContext();
      await openCheckout(price_id || PRICE_ID, checkout_token, me.email, locale);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.billing.checkoutError);
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
      setError(
        err instanceof ApiError ? err.message : t.billing.portalError
      );
    } finally {
      setPortalBusy(false);
    }
  }

  const perLabel = (per: string) => {
    const parsed = parseInterval(per);
    return parsed ? t.billing.interval(parsed.count, parsed.unit) : per;
  };

  const isActive = subscription?.status === "active" || subscription?.status === "trialing";

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
              {error && (
                <div className="text-sm text-critical bg-critical/10 border border-critical/30 rounded-lg px-4 py-3">
                  {error}
                </div>
              )}

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
                  <p className="text-sm text-ink-muted">
                    {t.billing.notSubscribed}
                  </p>
                )}
              </div>

              {!isActive && (
                <div className="rounded-xl border border-brand-hover/40 bg-brand/5 p-5">
                  <h2 className="text-ink font-medium text-sm mb-1">
                    {t.billing.subscribeTitle}
                  </h2>
                  {price && (
                    <p className="text-ink text-lg font-semibold mb-3">
                      {price.amount}
                      {price.per && <span className="text-ink-muted text-sm font-normal"> / {perLabel(price.per)}</span>}
                    </p>
                  )}
                  <ul className="flex flex-col gap-1.5 mb-4">
                    {t.site.planFeatures.map((feature: string) => (
                      <li
                        key={feature}
                        className="flex items-center gap-2 text-sm text-ink-soft"
                      >
                        <CheckCircle2 size={14} color={palette.brandBright} />
                        {feature}
                      </li>
                    ))}
                  </ul>
                  <button
                    onClick={handleUpgrade}
                    disabled={checkoutBusy || !PRICE_ID}
                    className="inline-flex items-center gap-2 bg-brand hover:bg-brand-hover text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors disabled:opacity-50"
                  >
                    {checkoutBusy && <Loader2 size={14} className="animate-spin" />}
                    {t.billing.subscribeNow}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
