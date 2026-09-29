import { defineMessages } from "../core";

export const confirmNotification = defineMessages({
  en: {
    title: "Receive Legion security alerts?",
    body: "An administrator of a Legion workspace asked for security alert emails to be sent to your address. Confirm only if you expect them.",
    confirm: "Yes, send alerts to this address",
    ignoreHint: "Not expecting this? Close this page — nothing will be sent to you.",
    confirmedTitle: "Address confirmed",
    invalidTitle: "Link not valid",
    missingToken: "This link is missing its token. Open the link from the email again.",
    failed: "We couldn't confirm this address.",
  },
  ru: {
    title: "Получать оповещения безопасности Legion?",
    body: "Администратор рабочего пространства Legion попросил отправлять оповещения безопасности на ваш адрес. Подтвердите, только если вы их ожидаете.",
    confirm: "Да, отправлять оповещения на этот адрес",
    ignoreHint: "Не ожидали этого? Просто закройте страницу — вам ничего не будет отправлено.",
    confirmedTitle: "Адрес подтверждён",
    invalidTitle: "Ссылка недействительна",
    missingToken: "В ссылке нет токена. Откройте ссылку из письма ещё раз.",
    failed: "Не удалось подтвердить адрес.",
  },
  uz: {
    title: "Legion xavfsizlik ogohlantirishlarini olasizmi?",
    body: "Legion ish maydonining administratori xavfsizlik ogohlantirishlarini sizning manzilingizga yuborishni so'radi. Faqat ularni kutayotgan bo'lsangiz tasdiqlang.",
    confirm: "Ha, ogohlantirishlarni shu manzilga yuboring",
    ignoreHint: "Buni kutmaganmisiz? Sahifani yoping — sizga hech narsa yuborilmaydi.",
    confirmedTitle: "Manzil tasdiqlandi",
    invalidTitle: "Havola yaroqsiz",
    missingToken: "Havolada token yo'q. Xatdagi havolani qaytadan oching.",
    failed: "Manzilni tasdiqlab bo'lmadi.",
  },
});
