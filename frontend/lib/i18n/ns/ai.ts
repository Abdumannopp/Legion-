import { defineMessages } from "../core";

/**
 * AI provenance labels and the AI settings card (components/AiBadge.tsx,
 * components/AiSettingsSection.tsx), plus the realtime "N new alerts" notice.
 */
export const ai = defineMessages({
  en: {
    badge: {
      ai: "AI suggestion",
      aiHint: "Written by an AI model from alert text an attacker may control. Review it before acting — Legion takes no action on its own.",
      local: "Legion analysis",
      localHint: "Written by Legion's built-in rules, not by an AI model.",
    },
    settings: {
      heading: "AI analysis",
      intro: "Oracle explanations and Copilot answers can use an external AI provider. AI only advises: it cannot change alerts or run any action.",
      providerNone: "No AI provider is configured on this server, so all answers come from Legion's built-in analysis and no data leaves the server.",
      provider: (name: string) => `Provider: ${name}. With AI on, alert text is sent to this third party.`,
      enabled: "Use AI for this organisation",
      stateOn: "On",
      stateOff: "Off",
      stateDefault: (on: boolean) => `Server default (${on ? "on" : "off"})`,
      strict: "Strict data mode",
      strictHint: "Replace IP addresses, e-mail addresses and hostnames with placeholders before anything is sent. Answers still show the real values. Recommended.",
      strictDefault: "This is the starting setting for your workspace. You have not changed it.",
      standardWarning: "Strict mode is off: real IP addresses, e-mail addresses and host names from your alerts are sent to the AI provider. Turn it on unless you need the provider to see them.",
      circuitOpen: "The AI provider has been failing, so Legion is answering from its built-in analysis for now.",
      saved: "Saved.",
      loadError: "Couldn't load the AI settings.",
      adminOnly: "Only administrators can change these settings.",
    },
    newAlertsNotice: (n: number) => `${n} new alerts`,
  },
});
