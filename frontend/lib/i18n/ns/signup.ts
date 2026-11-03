import { defineMessages, plural } from "../core";

export const signup = defineMessages({
  en: {
    closed: {
      title: "Sign-up is closed",
      body: "This Legion installation belongs to one organisation. Ask your administrator for an invitation.",
    },
    checkEmail: {
      title: "Check your email",
      /** Wraps the email address: before + {email} + after. */
      sentBefore: "We sent a confirmation link to ",
      sentAfter: ". Open it to activate your workspace, then sign in. The link is valid for 24 hours.",
      resend: "Didn't get it? Send it again",
      resent: "A new link is on its way.",
    },
    title: "Start your free trial",
    trialNote: (days: number) =>
      `${plural("en", days, { one: `${days} day`, other: `${days} days` })} free, no card needed. You choose a plan only if you decide to keep Legion.`,
    companyLabel: "Company or team name",
    emailLabel: "Work email",
    /** "I agree to the {Terms} and {Privacy Policy}." — the two links sit between these parts. */
    agree: {
      before: "I agree to the ",
      terms: "Terms",
      and: " and ",
      privacy: "Privacy Policy",
      after: ".",
    },
    createAccount: "Create account",
    haveAccount: "Already have an account?",
    createFailed: "Could not create the account.",
  },
});
