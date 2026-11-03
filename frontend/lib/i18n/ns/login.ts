import { defineMessages } from "../core";

export const login = defineMessages({
  en: {
    eyebrow: "Sign in to your console",
    headline: {
      line1: "Stop Chasing Alerts.",
      line2: "Start Stopping Threats.",
    },
    intro: "Turn thousands of security alerts into clear, actionable decisions with Legion AI.",
    forgotPassword: "Forgot password?",
    startTrial: "Start a free trial",
    resendConfirmation: "Send the confirmation link again",
    confirmationResent: "A new confirmation link is on its way.",
    mfa: {
      title: "Two-factor authentication",
      codeHelp: "Enter the 6-digit code from your authenticator app.",
      recoveryHelp:
        "Enter one of the recovery codes you saved when you set up two-factor authentication. Each code works once.",
      codeLabel: "Authentication code",
      recoveryLabel: "Recovery code",
      verify: "Verify",
      useApp: "Use authenticator app",
      useRecovery: "Use a recovery code",
    },
  },
});
