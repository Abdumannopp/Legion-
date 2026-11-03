import { defineMessages } from "../core";

export const forgotPassword = defineMessages({
  en: {
    title: "Forgot password",
    intro: "Enter your email and we will send you a link to choose a new password.",
    sendLink: "Send reset link",
    /** Wraps the email address: before + {email} + after. */
    sentBefore: "If ",
    sentAfter: " has an account, a reset link is on its way. It is valid for one hour.",
  },
});
