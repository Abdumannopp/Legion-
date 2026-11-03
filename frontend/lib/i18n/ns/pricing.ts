import { defineMessages, plural } from "../core";

/** The public /pricing page (the plan card itself is in site.pricingCard). */


export const pricing = defineMessages({
  en: {
    metaTitle: "Pricing | Legion Cyber Intelligence",
    eyebrow: "Pricing",
    title: "One plan, everything included",
    subtitle: (days: number) => `Start free for ${days} days. Pay only if you keep it.`,
    faq: {
      afterTrial: {
        q: "What happens after the trial?",
        a: (days: number) =>
          `For ${days} days everything is free and no card is needed. To keep using Legion, subscribe from Billing inside the app. If you don't, the workspace is locked — your data is kept, and subscribing later unlocks it.`,
      },
      cancel: {
        q: "Can I cancel?",
        a: "Yes, at any time, from Billing → Manage subscription. You keep access until the end of the period you paid for.",
      },
      refunds: {
        q: "Refunds?",
        a: "If Legion isn't right for you, ask for a refund of your first payment within 14 days. See the Refund Policy.",
      },
      payment: {
        q: "Who handles payment and invoices?",
        a: "Paddle.com, our reseller and Merchant of Record. Paddle charges your card, calculates sales tax/VAT for your country and sends the invoice.",
      },
    },
    contactPrompt: "Questions before you buy?",
    contactLink: "Contact us",
  },
});
