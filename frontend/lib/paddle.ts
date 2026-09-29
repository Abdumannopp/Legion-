"use client";

// Thin wrapper around @paddle/paddle-js so billing/page.tsx doesn't have to
// deal with initialization/caching itself. Paddle.js renders its checkout
// as an overlay it injects into the page — nothing to build ourselves.
import { initializePaddle, Paddle } from "@paddle/paddle-js";
import type { Locale } from "@/lib/i18n/core";
import { translations } from "@/lib/i18n/translations";

export const CHECKOUT_COMPLETED = "legion:checkout-completed";

let paddleInstance: Paddle | undefined;
let initPromise: Promise<Paddle | undefined> | null = null;

const CLIENT_TOKEN = process.env.NEXT_PUBLIC_PADDLE_CLIENT_TOKEN || "";
const ENVIRONMENT =
  (process.env.NEXT_PUBLIC_PADDLE_ENVIRONMENT as "sandbox" | "production") || "sandbox";

async function getPaddle(): Promise<Paddle | undefined> {
  if (paddleInstance) return paddleInstance;
  if (!CLIENT_TOKEN) return undefined;

  if (!initPromise) {
    initPromise = initializePaddle({
      environment: ENVIRONMENT,
      token: CLIENT_TOKEN,
      // Paddle confirms the payment to our server by webhook a few seconds
      // after the overlay says "thank you". Let the page know so it can wait
      // for that instead of showing the old plan.
      eventCallback: (event) => {
        if (event.name === "checkout.completed" && typeof window !== "undefined") {
          window.dispatchEvent(new Event(CHECKOUT_COMPLETED));
        }
      },
    }).then((instance) => {
      paddleInstance = instance;
      return instance;
    });
  }
  return initPromise;
}

/** Opens the Paddle.js checkout overlay for a given price.
 *
 * `checkoutToken` is minted by the authenticated backend and binds the
 * checkout to the current tenant without trusting a browser-supplied ID. */
export async function openCheckout(priceId: string, checkoutToken: string, email: string | undefined, locale: Locale) {
  const paddle = await getPaddle();
  if (!paddle) {
    throw new Error(translations[locale].billing.paddleNotConfigured);
  }

  paddle.Checkout.open({
    // Paddle's checkout has Russian but no Uzbek; Uzbek falls back to English.
    settings: { locale: locale === "ru" ? "ru" : "en" },
    items: [{ priceId, quantity: 1 }],
    customData: { checkout_token: checkoutToken },
    customer: email ? { email } : undefined,
  });
}

export function isPaddleConfigured(): boolean {
  return Boolean(CLIENT_TOKEN);
}

export interface PriceLabel {
  /** Localized, tax-inclusive where Paddle shows tax, e.g. "$49.00". */
  amount: string;
  /** "month", "year", "3 months"… or null for one-off prices. */
  per: string | null;
}

/** The plan's price as Paddle would charge this visitor (currency and tax
 *  follow their location). Null when Paddle is not configured or unreachable. */
export async function getPriceLabel(priceId: string): Promise<PriceLabel | null> {
  if (!priceId) return null;
  const paddle = await getPaddle();
  if (!paddle) return null;
  try {
    const preview = await paddle.PricePreview({ items: [{ priceId, quantity: 1 }] });
    const line = preview.data.details.lineItems[0];
    if (!line) return null;
    const cycle = line.price.billingCycle;
    const per = cycle ? (cycle.frequency === 1 ? cycle.interval : `${cycle.frequency} ${cycle.interval}s`) : null;
    return { amount: line.formattedTotals.total, per };
  } catch {
    return null;
  }
}

export const PADDLE_PRICE_ID = process.env.NEXT_PUBLIC_PADDLE_PRICE_ID || "";
