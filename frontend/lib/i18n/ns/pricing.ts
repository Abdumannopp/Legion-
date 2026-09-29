import { defineMessages, plural } from "../core";

/** The public /pricing page (the plan card itself is in site.pricingCard). */

/** "14 дней", "21 день" (accusative, after "бесплатно"). */
const ruDays = (n: number) => `${n} ${plural("ru", n, { one: "день", few: "дня", many: "дней", other: "дня" })}`;
/** "в течение 14 дней", "в течение 21 дня" (genitive). */
const ruDaysGen = (n: number) => `${n} ${plural("ru", n, { one: "дня", few: "дней", many: "дней", other: "дня" })}`;

export const pricing = defineMessages({
  en: {
    metaTitle: "Pricing | Legion Cyber Intelligence",
    eyebrow: "Pricing",
    title: "One plan, everything included",
    subtitle: (days: number) => `Start free for ${days} days. Pay only if you keep it.`,
    faq: {
      afterTrial: {
        q: "What happens after the trial?",
        a: (days: number) =>
          `For ${days} days everything is free and no card is needed. To keep using Legion, subscribe from Billing inside the app. If you don't, the workspace is locked — your data is kept, and subscribing later unlocks it.`,
      },
      cancel: {
        q: "Can I cancel?",
        a: "Yes, at any time, from Billing → Manage subscription. You keep access until the end of the period you paid for.",
      },
      refunds: {
        q: "Refunds?",
        a: "If Legion isn't right for you, ask for a refund of your first payment within 14 days. See the Refund Policy.",
      },
      payment: {
        q: "Who handles payment and invoices?",
        a: "Paddle.com, our reseller and Merchant of Record. Paddle charges your card, calculates sales tax/VAT for your country and sends the invoice.",
      },
    },
    contactPrompt: "Questions before you buy?",
    contactLink: "Contact us",
  },
  ru: {
    metaTitle: "Цены | Legion Cyber Intelligence",
    eyebrow: "Цены",
    title: "Один тариф — всё включено",
    subtitle: (days: number) => `${ruDays(days)} бесплатно. Платите, только если решите остаться.`,
    faq: {
      afterTrial: {
        q: "Что будет после пробного периода?",
        a: (days: number) =>
          `В течение ${ruDaysGen(days)} всё бесплатно, карта не нужна. Чтобы продолжить работу с Legion, оформите подписку в разделе «Оплата» внутри приложения. Если этого не сделать, рабочее пространство будет заблокировано — ваши данные сохранятся, и подписка, оформленная позже, снова откроет доступ.`,
      },
      cancel: {
        q: "Можно ли отменить подписку?",
        a: "Да, в любой момент: «Оплата» → «Управлять подпиской». Доступ сохранится до конца оплаченного периода.",
      },
      refunds: {
        q: "А возврат средств?",
        a: "Если Legion вам не подошёл, запросите возврат первого платежа в течение 14 дней. Подробнее — в Политике возврата.",
      },
      payment: {
        q: "Кто принимает оплату и выставляет инвойсы?",
        a: "Paddle.com — наш реселлер и продавец (Merchant of Record). Paddle списывает оплату с вашей карты, рассчитывает налог с продаж или НДС для вашей страны и присылает инвойс.",
      },
    },
    contactPrompt: "Есть вопросы перед покупкой?",
    contactLink: "Напишите нам",
  },
  uz: {
    metaTitle: "Narxlar | Legion Cyber Intelligence",
    eyebrow: "Narxlar",
    title: "Bitta tarif — hammasi ichida",
    subtitle: (days: number) => `${days} kun bepul foydalaning. Faqat davom ettirmoqchi bo'lsangiz to'laysiz.`,
    faq: {
      afterTrial: {
        q: "Sinov muddati tugagach nima bo'ladi?",
        a: (days: number) =>
          `${days} kun davomida hammasi bepul, karta kerak emas. Legion'dan foydalanishni davom ettirish uchun ilova ichidagi «To'lovlar» bo'limidan obuna bo'ling. Obuna bo'lmasangiz, ish maydoni bloklanadi — ma'lumotlaringiz saqlanib qoladi va keyinroq obuna bo'lsangiz, kirish yana ochiladi.`,
      },
      cancel: {
        q: "Obunani bekor qilsa bo'ladimi?",
        a: "Ha, istalgan vaqtda: «To'lovlar» → «Obunani boshqarish». To'langan davr oxirigacha kirish huquqi saqlanadi.",
      },
      refunds: {
        q: "Pul qaytariladimi?",
        a: "Agar Legion sizga to'g'ri kelmasa, birinchi to'lovingizni 14 kun ichida qaytarishni so'rashingiz mumkin. Batafsil — Pulni qaytarish siyosatida.",
      },
      payment: {
        q: "To'lov va invoyslar bilan kim shug'ullanadi?",
        a: "Paddle.com — bizning resellerimiz va rasmiy sotuvchi (Merchant of Record). Paddle kartangizdan to'lovni yechadi, mamlakatingiz uchun savdo solig'i yoki QQSni hisoblaydi va invoys yuboradi.",
      },
    },
    contactPrompt: "Xariddan oldin savollaringiz bormi?",
    contactLink: "Biz bilan bog'laning",
  },
});
