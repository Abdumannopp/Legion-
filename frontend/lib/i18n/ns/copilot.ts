import { defineMessages } from "../core";

export const copilot = defineMessages({
  en: {
    title: "AI Copilot",
    subtitle: "Grounded in your live alert data",
    greeting:
      "Hi, I'm Legion's AI Copilot. Ask me anything about your current alerts — I'll only answer from real data in your system, not guesses.",
    /** Example questions shown before the first message; sent as-is when clicked. */
    suggestions: [
      "What are my critical alerts right now?",
      "What should I do about the highest severity alert?",
      "Summarize what's happened in the last hour.",
    ],
    /** Titles for the example questions above, in the same order. */
    suggestionTitles: ["Analyze critical alerts", "Next step for the worst alert", "The last hour"],
    hello: "What are we investigating?",
    helloBody: "Ask about alerts, suspicious activity, hosts or what changed recently.",
    newConversation: "New conversation",
    assistantName: "Legion Copilot",
    assistantRole: "AI security assistant",
    contextTitle: "Investigation context",
    contextSubtitle: "Open alerts in this workspace",
    relatedAlerts: "Open alerts",
    noRelated: "No open alerts right now.",
    askAbout: (title: string) => `Explain this alert and what I should check first: "${title}"`,
    approvalTitle: "A person decides",
    approvalBody: "Copilot only explains and suggests. It cannot block, isolate or change anything; actions go through Defense, with approval.",
    disclaimer: "AI-generated analysis can be wrong. Verify findings before acting.",
    you: "You",
    inputPlaceholder: "Ask about your alerts…",
    error: "Copilot couldn't respond right now.",
  },
});
