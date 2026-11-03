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
    inputPlaceholder: "Ask about your alerts…",
    error: "Copilot couldn't respond right now.",
  },
});
