import { defineMessages, plural } from "../core";

export const accessBanner = defineMessages({
  en: {
    blocked:
      "This workspace doesn't have an active subscription. Your data is safe and alerts are still being collected, but the console is locked.",
    readonly:
      "A subscription payment is past due. Legion is read-only until it's settled — alerts keep arriving in the background.",
    trialEnds: (n: number) =>
      plural("en", n, { one: `Your trial ends in ${n} day.`, other: `Your trial ends in ${n} days.` }),
    manageBilling: "Manage billing",
    choosePlan: "Choose a plan",
    askAdmin: "Ask a workspace admin to update billing.",
  },
});
