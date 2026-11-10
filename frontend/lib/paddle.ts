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

/** Opens the Paddle.js checkout overlay for the items the server chose.
 *
 * `checkoutToken` is minted by the authenticated backend and binds the
 * checkout to the current tenant without trusting a browser-supplied ID.
 * `items` come from POST /billing/checkout-context (a plan and its add-ons);
 * a bare price id is the older single-plan call. */
export async function openCheckout(
  items: string | Array<{ priceId: string; quantity: number }>,
  checkoutToken: string, email: string | undefined, locale: Locale,
) {
  const paddle = await getPaddle();
  if (!paddle) {
    throw new Error(translations[locale].billing.paddleNotConfigured);
  }

  paddle.Checkout.open({
    settings: { locale: "en" },
    items: typeof items === "string" ? [{ priceId: items, quantity: 1 }] : items,
    customData: { checkout_token: checkoutToken },
    customer: email ? { email } : undefined,
  });
}

export function isPaddleConfigured(): boolean {
  return Boolean(CLIENT_TOKEN);
}
