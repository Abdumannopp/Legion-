import { defineMessages, plural } from "../core";

/** Billing periods Paddle reports for a recurring price. */
export type BillingInterval = "day" | "week" | "month" | "year";

const RU_INTERVAL: Record<BillingInterval, { one: string; few: string; many: string }> = {
  day: { one: "день", few: "дня", many: "дней" },
  week: { one: "неделя", few: "недели", many: "недель" },
  month: { one: "месяц", few: "месяца", many: "месяцев" },
  year: { one: "год", few: "года", many: "лет" },
};

const UZ_INTERVAL: Record<BillingInterval, string> = {
  day: "kun",
  week: "hafta",
  month: "oy",
  year: "yil",
};

export const billing = defineMessages({
  en: {
    title: "Billing",
    subtitle: "Manage your Legion subscription",
    loadError: "Couldn't load billing info.",
    notConfirmed:
      "Payment received by Paddle, but not confirmed here yet. Refresh in a minute; if it persists, contact support.",
    checkoutError: "Couldn't open checkout.",
    portalError: "Couldn't open the billing portal.",
    activating: "Payment received — activating your subscription…",
    paddleNotConfigured:
      "Paddle isn't configured yet — set NEXT_PUBLIC_PADDLE_CLIENT_TOKEN in frontend/.env.local.",
    currentPlan: "Current plan",
    trialActive: (date: string, days: number) => `Free trial — ${days === 1 ? "1 day" : `${days} days`} left (ends on ${date}). Everything works until then.`,
    trialEnded: (date: string) => `The free trial ended on ${date}. Your data is safe; choose a plan to keep using Legion.`,
    adminOnlyNote: "Only workspace admins can change the plan or payment details.",
    accessEnds: (date: string) => `Access ends on ${date}`,
    renews: (date: string) => `Renews on ${date}`,
    manage: "Manage subscription",
    notSubscribed: "You're not subscribed yet — upgrade to unlock the full Legion platform.",
    subscribeTitle: "Choose a plan",
    subscribeNow: "Subscribe now",
    choosePlan: (name: string) => `Choose ${name}`,
    notAvailable: "Not available online yet — contact us",
    contactUs: "Contact us",
    planName: (name: string, trial: boolean) => (trial ? `${name} (free trial)` : name),
    planSource: {
      trial: "Your free trial includes everything in the Professional plan.",
      legacy: "You are on the Professional plan.",
      override: "Your plan was set by agreement with us.",
      subscription: "",
      "self-hosted": "",
    } as Record<string, string>,
    usage: {
      title: "Your limits",
      endpoints: "Endpoints (seen in the last 30 days)",
      admins: "Administrators (including invited)",
      unlimited: "no fixed limit",
      of: (used: number, limit: number | null) => (limit === null ? `${used}` : `${used} of ${limit}`),
      overEndpoints: "You are over your endpoint limit. Legion keeps recording every event, but please move to a bigger plan or add endpoints.",
      overAdmins: "You have more administrators than your plan includes. Remove one or upgrade to add more.",
    },
    addonsTitle: "Add-ons (monthly plans only)",
    changePlan: "To change plan or add an add-on to a running subscription, contact support — we switch you without losing any data.",
    /** Billing period after the price: "$49 / month", "$120 / 3 months". */
    interval: (count: number, unit: BillingInterval) => (count === 1 ? unit : `${count} ${unit}s`),
  },
});
