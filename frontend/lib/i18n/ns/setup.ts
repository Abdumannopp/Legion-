import { defineMessages } from "../core";

export const setup = defineMessages({
  en: {
    eyebrow: "First-run setup",
    heading: "Create the first administrator",
    /** Wraps the token file name: before + {.legion-setup-token} + after. */
    tokenHelpBefore:
      "The setup token was printed in the Legion server's console when it started. It is also in the file ",
    tokenHelpAfter: " next to the server. It works once.",
    tokenLabel: "Setup token",
    organisationLabel: "Organisation name",
    emailLabel: "Your email",
    submit: "Create administrator",
  },
});
