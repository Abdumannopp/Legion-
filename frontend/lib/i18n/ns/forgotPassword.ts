import { defineMessages } from "../core";

export const forgotPassword = defineMessages({
  en: {
    title: "Forgot password",
    intro: "Enter your email and we will send you a link to choose a new password.",
    sendLink: "Send reset link",
    /** Wraps the email address: before + {email} + after. */
    sentBefore: "If ",
    sentAfter: " has an account, a reset link is on its way. It is valid for one hour.",
  },
  ru: {
    title: "Забыли пароль?",
    intro: "Введите вашу почту, и мы пришлём ссылку для создания нового пароля.",
    sendLink: "Отправить ссылку",
    sentBefore: "Если для ",
    sentAfter: " есть аккаунт, ссылка для сброса пароля уже отправлена. Она действует один час.",
  },
  uz: {
    title: "Parolni unutdingizmi?",
    intro: "Email manzilingizni kiriting — yangi parol o'rnatish uchun havola yuboramiz.",
    sendLink: "Havolani yuborish",
    sentBefore: "Agar ",
    sentAfter: " manzili bilan hisob mavjud bo'lsa, parolni tiklash havolasi yuborildi. U bir soat amal qiladi.",
  },
});
