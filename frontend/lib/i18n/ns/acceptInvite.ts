import { defineMessages, plural } from "../core";

export const acceptInvite = defineMessages({
  en: {
    missingToken: "This invitation link is missing its token.",
    loadFailed: "We couldn't load this invitation.",
    passwordTooShort: (n: number) => `Choose a password of at least ${n} characters.`,
    passwordMismatch: "Those passwords don't match.",
    setupFailed: "We couldn't set up your account.",
    readyTitle: "Your account is ready",
    redirecting: "Taking you to the sign-in page…",
    invalidTitle: "This invitation isn't valid",
    invalidReason: "It may have expired or already been used.",
    askAdmin: "Ask an admin on your team to send a new one.",
    join: (name: string) => `Join ${name}`,
    /** "Set a password for {email} to finish setting up your {role} account." */
    intro: {
      before: "Set a password for ",
      middle: " to finish setting up your ",
      after: " account.",
    },
    confirmPassword: "Confirm password",
    submit: "Create my account",
    existingIntro: (email: string) => `${email} already has a Legion account. Accept to add this workspace to it.`,
    acceptExisting: "Accept invitation",
    signInFirst: "Sign in with that account, then open this link again.",
    wrongAccount: (current: string, invited: string) => `You are signed in as ${current}. Sign in as ${invited} to accept.`,
    accepted: "Invitation accepted — opening the workspace…",
  },
});
