import { defineMessages, plural } from "../core";

export const accessBanner = defineMessages({
  en: {
    blocked:
      "This workspace doesn't have an active subscription. Your data is safe and alerts are still being collected, but the console is locked.",
    readonly:
      "A subscription payment is past due. Legion is read-only until it's settled — alerts keep arriving in the background.",
    trialEnds: (n: number) =>
      plural("en", n, { one: `Your trial ends in ${n} day.`, other: `Your trial ends in ${n} days.` }),
    manageBilling: "Manage billing",
    choosePlan: "Choose a plan",
    askAdmin: "Ask a workspace admin to update billing.",
  },
  ru: {
    blocked:
      "У этого рабочего пространства нет активной подписки. Ваши данные в безопасности и оповещения продолжают собираться, но консоль заблокирована.",
    readonly:
      "Платёж по подписке просрочен. До оплаты Legion работает только в режиме чтения — оповещения продолжают поступать в фоновом режиме.",
    trialEnds: (n: number) =>
      plural("ru", n, {
        one: `Пробный период закончится через ${n} день.`,
        few: `Пробный период закончится через ${n} дня.`,
        many: `Пробный период закончится через ${n} дней.`,
        other: `Пробный период закончится через ${n} дня.`,
      }),
    manageBilling: "Управление оплатой",
    choosePlan: "Выбрать тариф",
    askAdmin: "По вопросам оплаты обратитесь к администратору.",
  },
  uz: {
    blocked:
      "Bu ish maydonida faol obuna yo'q. Ma'lumotlaringiz xavfsiz va ogohlantirishlar yig'ilishda davom etmoqda, lekin konsol bloklangan.",
    readonly:
      "Obuna to'lovi kechikdi. To'lov qilinmaguncha Legion faqat o'qish rejimida ishlaydi — ogohlantirishlar fonda kelishda davom etadi.",
    trialEnds: (n: number) => `Bepul sinov muddati ${n} kundan keyin tugaydi.`,
    manageBilling: "To'lovni boshqarish",
    choosePlan: "Tarifni tanlash",
    askAdmin: "To'lov bo'yicha administratorga murojaat qiling.",
  },
});
