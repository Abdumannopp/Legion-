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
  ru: {
    title: "AI Copilot",
    subtitle: "На основе ваших актуальных оповещений",
    greeting:
      "Здравствуйте, я AI Copilot от Legion. Спрашивайте о ваших текущих оповещениях — я отвечаю только на основе реальных данных вашей системы, без догадок.",
    suggestions: [
      "Какие у меня сейчас критические оповещения?",
      "Что делать с оповещением наивысшей критичности?",
      "Кратко: что произошло за последний час?",
    ],
    inputPlaceholder: "Спросите о ваших оповещениях…",
    error: "Copilot сейчас не может ответить.",
  },
  uz: {
    title: "AI Copilot",
    subtitle: "Jonli ogohlantirishlaringiz ma'lumotlariga asoslanadi",
    greeting:
      "Salom, men Legion'ning AI Copilot yordamchisiman. Joriy ogohlantirishlaringiz haqida istalgan savolni bering — taxmin qilmayman, faqat tizimingizdagi haqiqiy ma'lumotlarga tayanib javob beraman.",
    suggestions: [
      "Hozir qanday kritik ogohlantirishlarim bor?",
      "Eng jiddiy ogohlantirish bo'yicha nima qilishim kerak?",
      "So'nggi bir soatda nima bo'lganini qisqacha aytib bering.",
    ],
    inputPlaceholder: "Ogohlantirishlaringiz haqida so'rang…",
    error: "Copilot hozir javob bera olmadi.",
  },
});
