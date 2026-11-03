import { defineMessages } from "../core";

export const confirmNotification = defineMessages({
  en: {
    title: "Receive Legion security alerts?",
    body: "An administrator of a Legion workspace asked for security alert emails to be sent to your address. Confirm only if you expect them.",
    confirm: "Yes, send alerts to this address",
    ignoreHint: "Not expecting this? Close this page — nothing will be sent to you.",
    confirmedTitle: "Address confirmed",
    invalidTitle: "Link not valid",
    missingToken: "This link is missing its token. Open the link from the email again.",
    failed: "We couldn't confirm this address.",
  },
});
