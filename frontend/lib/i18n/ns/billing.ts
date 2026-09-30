import { defineMessages, plural } from "../core";

/** Billing periods Paddle reports for a recurring price. */
export type BillingInterval = "day" | "week" | "month" | "year";

const RU_INTERVAL: Record<BillingInterval, { one: string; few: string; many: string }> = {
  day: { one: "день", few: "дня", many: "дней" },
  week: { one: "неделя", few: "недели", many: "недель" },
  month: { one: "месяц", few: "месяца", many: "месяцев" },
  year: { one: "год", few: "года", many: "лет" },
};

const UZ_INTERVAL: Record<BillingInterval, string> = {
  day: "kun",
  week: "hafta",
  month: "oy",
  year: "yil",
};

export const billing = defineMessages({
  en: {
    title: "Billing",
    subtitle: "Manage your Legion subscription",
    loadError: "Couldn't load billing info.",
    notConfirmed:
      "Payment received by Paddle, but not confirmed here yet. Refresh in a minute; if it persists, contact support.",
    checkoutError: "Couldn't open checkout.",
    portalError: "Couldn't open the billing portal.",
    activating: "Payment received — activating your subscription…",
    paddleNotConfigured:
      "Paddle isn't configured yet — set NEXT_PUBLIC_PADDLE_CLIENT_TOKEN and NEXT_PUBLIC_PADDLE_PRICE_ID in frontend/.env.local.",
    currentPlan: "Current plan",
    trialActive: (date: string, days: number) => `Free trial — ${days === 1 ? "1 day" : `${days} days`} left (ends on ${date}). Everything works until then.`,
    trialEnded: (date: string) => `The free trial ended on ${date}. Your data is safe; choose a plan to keep using Legion.`,
    adminOnlyNote: "Only workspace admins can change the plan or payment details.",
    accessEnds: (date: string) => `Access ends on ${date}`,
    renews: (date: string) => `Renews on ${date}`,
    manage: "Manage subscription",
    notSubscribed: "You're not subscribed yet — upgrade to unlock the full Legion platform.",
    subscribeTitle: "Subscribe to Legion",
    subscribeNow: "Subscribe now",
    /** Billing period after the price: "$49 / month", "$120 / 3 months". */
    interval: (count: number, unit: BillingInterval) => (count === 1 ? unit : `${count} ${unit}s`),
  },
  ru: {
    title: "Оплата",
    subtitle: "Управление подпиской Legion",
    loadError: "Не удалось загрузить данные об оплате.",
    notConfirmed:
      "Paddle получил платёж, но здесь он ещё не подтверждён. Обновите страницу через минуту; если это не поможет, обратитесь в поддержку.",
    checkoutError: "Не удалось открыть страницу оплаты.",
    portalError: "Не удалось открыть портал оплаты.",
    activating: "Платёж получен — активируем подписку…",
    paddleNotConfigured:
      "Paddle ещё не настроен — укажите NEXT_PUBLIC_PADDLE_CLIENT_TOKEN и NEXT_PUBLIC_PADDLE_PRICE_ID в frontend/.env.local.",
    currentPlan: "Текущий тариф",
    trialActive: (date: string, days: number) => `Пробный период — осталось дней: ${days} (до ${date}). До этого всё работает.`,
    trialEnded: (date: string) => `Пробный период закончился ${date}. Данные в безопасности; выберите тариф, чтобы продолжить работу.`,
    adminOnlyNote: "Менять тариф и платёжные данные могут только администраторы.",
    accessEnds: (date: string) => `Доступ заканчивается ${date}`,
    renews: (date: string) => `Продление ${date}`,
    manage: "Управлять подпиской",
    notSubscribed: "У вас ещё нет подписки — оформите её, чтобы открыть все возможности Legion.",
    subscribeTitle: "Подписка на Legion",
    subscribeNow: "Оформить подписку",
    interval: (count: number, unit: BillingInterval) =>
      count === 1
        ? RU_INTERVAL[unit].one
        : `${count} ${plural("ru", count, { ...RU_INTERVAL[unit], other: RU_INTERVAL[unit].few })}`,
  },
  uz: {
    title: "To'lov",
    subtitle: "Legion obunangizni boshqaring",
    loadError: "To'lov ma'lumotlarini yuklab bo'lmadi.",
    notConfirmed:
      "Paddle to'lovni qabul qildi, lekin bu yerda hali tasdiqlanmadi. Bir daqiqadan so'ng sahifani yangilang; muammo davom etsa, qo'llab-quvvatlash xizmatiga murojaat qiling.",
    checkoutError: "To'lov oynasini ochib bo'lmadi.",
    portalError: "To'lov portalini ochib bo'lmadi.",
    activating: "To'lov qabul qilindi — obunangiz faollashtirilmoqda…",
    paddleNotConfigured:
      "Paddle hali sozlanmagan — frontend/.env.local faylida NEXT_PUBLIC_PADDLE_CLIENT_TOKEN va NEXT_PUBLIC_PADDLE_PRICE_ID qiymatlarini kiriting.",
    currentPlan: "Joriy tarif",
    trialActive: (date: string, days: number) => `Bepul sinov muddati — ${days} kun qoldi (${date} gacha). Shu vaqtgacha hammasi ishlaydi.`,
    trialEnded: (date: string) => `Bepul sinov muddati ${date} da tugadi. Ma'lumotlaringiz xavfsiz; davom etish uchun tarif tanlang.`,
    adminOnlyNote: "Tarif va to'lov ma'lumotlarini faqat administratorlar o'zgartira oladi.",
    accessEnds: (date: string) => `Kirish huquqi ${date} sanasida tugaydi`,
    renews: (date: string) => `${date} sanasida yangilanadi`,
    manage: "Obunani boshqarish",
    notSubscribed: "Siz hali obuna bo'lmagansiz — Legion platformasidan to'liq foydalanish uchun obuna bo'ling.",
    subscribeTitle: "Legion'ga obuna bo'lish",
    subscribeNow: "Obuna bo'lish",
    interval: (count: number, unit: BillingInterval) =>
      count === 1 ? UZ_INTERVAL[unit] : `${count} ${UZ_INTERVAL[unit]}`,
  },
});
