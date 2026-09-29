import { defineMessages } from "../core";

export const resetPassword = defineMessages({
  en: {
    title: "Reset password",
    newPassword: "New password",
    update: "Update password",
    updating: "Updating…",
    missingToken: "Reset token is missing.",
    failed: "Password reset failed.",
  },
  ru: {
    title: "Сброс пароля",
    newPassword: "Новый пароль",
    update: "Сменить пароль",
    updating: "Сохраняем…",
    missingToken: "В ссылке нет токена для сброса пароля.",
    failed: "Не удалось сбросить пароль.",
  },
  uz: {
    title: "Parolni tiklash",
    newPassword: "Yangi parol",
    update: "Parolni yangilash",
    updating: "Yangilanmoqda…",
    missingToken: "Havolada parolni tiklash tokeni yo'q.",
    failed: "Parolni tiklab bo'lmadi.",
  },
});
