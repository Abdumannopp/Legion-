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
  ru: {
    eyebrow: "Первоначальная настройка",
    heading: "Создайте первого администратора",
    tokenHelpBefore:
      "Токен настройки был выведен в консоль сервера Legion при запуске. Он также сохранён в файле ",
    tokenHelpAfter: " рядом с сервером. Токен одноразовый.",
    tokenLabel: "Токен настройки",
    organisationLabel: "Название организации",
    emailLabel: "Ваша эл. почта",
    submit: "Создать администратора",
  },
  uz: {
    eyebrow: "Dastlabki sozlash",
    heading: "Birinchi administratorni yarating",
    tokenHelpBefore:
      "Sozlash tokeni Legion serveri ishga tushganda uning konsoliga chiqarilgan. U server yonidagi ",
    tokenHelpAfter: " faylida ham bor. Token faqat bir marta ishlaydi.",
    tokenLabel: "Sozlash tokeni",
    organisationLabel: "Tashkilot nomi",
    emailLabel: "Email manzilingiz",
    submit: "Administratorni yaratish",
  },
});
