import { defineMessages, plural } from "../core";

export const mfa = defineMessages({
  en: {
    heading: "Two-factor authentication",
    onBadge: "ON",
    intro:
      "Require a code from your phone in addition to your password. Strongly recommended for accounts with access to security data.",
    setUp: "Set up",
    enrolHint:
      "Add this key to your authenticator app (1Password, Authy, Google Authenticator), then enter the code it shows.",
    setupKey: "Setup key",
    verifyAndEnable: "Verify and enable",
    codesRemaining: (n: number) =>
      plural("en", n, { one: `${n} recovery code remaining.`, other: `${n} recovery codes remaining.` }),
    generateSoon: "Generate a new set soon.",
    passwordForCodes: "Password (to generate new recovery codes)",
    newCodes: "New recovery codes",
    turnOff: "Turn off",
    disableHint:
      "Turning this off requires your password and a current code, so a borrowed session cannot remove it on its own.",
    codePlaceholder: "Authenticator or recovery code",
    turnOffTwoFactor: "Turn off two-factor",
    disabledNotice: "Two-factor authentication is off.",
    errors: {
      loadStatus: "Could not load MFA status",
      startSetup: "Could not start setup",
      enable: "Could not enable MFA",
      disable: "Could not disable MFA",
      regenerate: "Could not regenerate codes",
    },
    recovery: {
      heading: "Save your recovery codes",
      body:
        "Each code can be used once to sign in if you lose your authenticator device. This is the only time they can be displayed — store them somewhere safe.",
      copyAll: "Copy all",
      confirmSaved: "I have saved these codes somewhere safe",
      done: "Done",
    },
  },
});
