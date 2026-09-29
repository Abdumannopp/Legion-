import { defineMessages, plural } from "../core";

/** Shared by the public account screens: AuthShell frame, password hints, links back to sign-in. */
export const auth = defineMessages({
  en: {
    links: {
      terms: "Terms",
      privacy: "Privacy",
      refunds: "Refunds",
      support: "Support",
    },
    backToSignIn: "Back to sign in",
    goToSignIn: "Go to sign in",
    /** Label for a new-password field that shows the minimum length. */
    passwordWithMin: (n: number) => `Password (at least ${n} characters)`,
    /** Hint shown under a new-password field. */
    passwordHint: (n: number) => `At least ${n} characters.`,
  },
  ru: {
    links: {
      terms: "Условия",
      privacy: "Конфиденциальность",
      refunds: "Возвраты",
      support: "Поддержка",
    },
    backToSignIn: "Вернуться ко входу",
    goToSignIn: "Перейти ко входу",
    passwordWithMin: (n: number) =>
      `Пароль (минимум ${n} ${plural("ru", n, { one: "символ", few: "символа", many: "символов", other: "символа" })})`,
    passwordHint: (n: number) =>
      `Минимум ${n} ${plural("ru", n, { one: "символ", few: "символа", many: "символов", other: "символа" })}.`,
  },
  uz: {
    links: {
      terms: "Shartlar",
      privacy: "Maxfiylik",
      refunds: "Pulni qaytarish",
      support: "Yordam",
    },
    backToSignIn: "Kirish sahifasiga qaytish",
    goToSignIn: "Kirish sahifasiga o'tish",
    passwordWithMin: (n: number) => `Parol (kamida ${n} ta belgi)`,
    passwordHint: (n: number) => `Kamida ${n} ta belgi.`,
  },
});
