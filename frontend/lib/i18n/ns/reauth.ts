import { defineMessages } from "../core";

/** The "confirm it is you" dialog before a dangerous action (components/ReauthDialog.tsx). */
export const reauth = defineMessages({
  en: {
    title: "Confirm it is you",
    intro: "This action is protected: enter your password to continue. You will not be asked again for the next 10 minutes.",
    password: "Password",
    code: "Code from your authenticator app",
    confirm: "Confirm",
    cancel: "Cancel",
    wrongPassword: "That password is not correct.",
    needCode: "Enter the current code from your authenticator app.",
    failed: "Could not confirm. Try again.",
  },
});
