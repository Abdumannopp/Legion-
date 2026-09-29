import { defineMessages } from "../core";

export const verifyEmail = defineMessages({
  en: {
    confirming: "Confirming…",
    confirmedTitle: "Email confirmed",
    confirmedBody: "Your workspace is active. Sign in to start your trial.",
    invalidTitle: "Link not valid",
    missingToken: "This link is missing its token. Open the link from the email again.",
    failed: "We couldn't confirm your email.",
    signInForNewLink: "Sign in to request a new link",
  },
  ru: {
    confirming: "Подтверждаем…",
    confirmedTitle: "Почта подтверждена",
    confirmedBody: "Ваше рабочее пространство активно. Войдите, чтобы начать пробный период.",
    invalidTitle: "Ссылка недействительна",
    missingToken: "В ссылке нет токена. Откройте ссылку из письма ещё раз.",
    failed: "Не удалось подтвердить вашу почту.",
    signInForNewLink: "Войти и запросить новую ссылку",
  },
  uz: {
    confirming: "Tasdiqlanmoqda…",
    confirmedTitle: "Email tasdiqlandi",
    confirmedBody: "Ish maydoningiz faollashtirildi. Sinov muddatini boshlash uchun tizimga kiring.",
    invalidTitle: "Havola yaroqsiz",
    missingToken: "Havolada token yo'q. Xatdagi havolani qaytadan oching.",
    failed: "Email manzilingizni tasdiqlab bo'lmadi.",
    signInForNewLink: "Yangi havola olish uchun kiring",
  },
});
