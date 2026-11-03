import { defineMessages, plural } from "../core";

/** Shared by the public account screens: AuthShell frame, password hints, links back to sign-in. */
export const auth = defineMessages({
  en: {
    links: {
      terms: "Terms",
      privacy: "Privacy",
      refunds: "Refunds",
      support: "Support",
    },
    backToSignIn: "Back to sign in",
    goToSignIn: "Go to sign in",
    /** Label for a new-password field that shows the minimum length. */
    passwordWithMin: (n: number) => `Password (at least ${n} characters)`,
    /** Hint shown under a new-password field. */
    passwordHint: (n: number) => `At least ${n} characters.`,
  },
});
