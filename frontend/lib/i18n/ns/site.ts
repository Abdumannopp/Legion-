import { defineMessages, plural } from "../core";

/**
 * The public website: product page (Landing), site header and footer, and
 * the pricing card. The English copy is what Paddle's reviewers read — keep
 * it faithful to the product; Russian and Uzbek are adapted, not literal.
 */

/** Billing periods Paddle reports for a recurring price. */
export type PriceInterval = "day" | "week" | "month" | "year";

/** "14 дней", "21 день", "3 дня" (nominative/accusative). */
const ruDays = (n: number) => `${n} ${plural("ru", n, { one: "день", few: "дня", many: "дней", other: "дня" })}`;

const RU_PER_ONE: Record<PriceInterval, string> = {
  day: "в день",
  week: "в неделю",
  month: "в месяц",
  year: "в год",
};
const RU_UNIT: Record<PriceInterval, { one: string; few: string; many: string }> = {
  day: { one: "день", few: "дня", many: "дней" },
  week: { one: "неделю", few: "недели", many: "недель" },
  month: { one: "месяц", few: "месяца", many: "месяцев" },
  year: { one: "год", few: "года", many: "лет" },
};
const UZ_PER_ONE: Record<PriceInterval, string> = {
  day: "kuniga",
  week: "haftasiga",
  month: "oyiga",
  year: "yiliga",
};
const UZ_UNIT: Record<PriceInterval, string> = {
  day: "kunda",
  week: "haftada",
  month: "oyda",
  year: "yilda",
};

export const site = defineMessages({
  en: {
    header: {
      homeAria: "Legion home",
      features: "Features",
      pricing: "Pricing",
      startTrial: (days: number) => `Start ${days}-day trial`,
      tryFree: "Try free",
    },
    footer: {
      merchantNotice: (seller: string) =>
        `Legion is provided by ${seller}. Orders are processed by our online reseller Paddle.com, which is the Merchant of Record for all orders and handles billing, invoices and payment-related customer service.`,
      pricing: "Pricing",
      terms: "Terms",
      freeTrial: "Free trial",
      privacy: "Privacy",
      contact: "Contact",
      refunds: "Refunds",
    },
    landing: {
      heroTitle: "Stop chasing alerts.",
      heroTitleAccent: "Start stopping threats.",
      heroText:
        "Legion watches your computers and your AI agents, explains every threat in plain language, and stops risky AI actions before they happen — so a small team can respond like a big one.",
      ctaTrial: (days: number) => `Start ${days}-day free trial`,
      ctaPricing: "See pricing",
      noCard: "No credit card required.",
      featuresEyebrow: "What you get",
      featuresTitle: "From alert to decision",
      features: {
        realtime: {
          title: "Connected in minutes",
          text: "Link the security sensor you already run — Wazuh today, more on the way — and alerts appear the moment they happen. No polling, no spreadsheets.",
        },
        explained: {
          title: "Explained, not just listed",
          text: "Every alert gets a plain-language explanation and a next step: what happened, why it matters, what to check first.",
        },
        triage: {
          title: "Triage to resolution",
          text: "Open, investigate, resolve. Severity, MITRE technique, source and target on every incident, with a full history of who did what.",
        },
        assets: {
          title: "Asset inventory",
          text: "The machines behind your alerts are catalogued automatically from your sensors, with risk and last-seen status.",
        },
        agents: {
          title: "AI agents with guardrails",
          text: "Give automation its own identity and only the permissions it needs. Every action passes a policy firewall and is audited.",
        },
        secure: {
          title: "Built like a security product",
          text: "Two-factor sign-in, role-based access, an append-only audit log, and each customer's data isolated in its own workspace.",
        },
      },
      stepsEyebrow: "How it works",
      steps: {
        create: {
          title: "Create a workspace",
          text: (days: number) => `Sign up with your work email. ${days} days free, no card.`,
        },
        connect: {
          title: "Connect your sensors",
          text: "Create a key, paste one block into your sensor's settings, and Legion tells you when the first event arrives.",
        },
        act: {
          title: "Act on what matters",
          text: "Critical alerts rise to the top with an explanation and a next step.",
        },
      },
      pricingEyebrow: "Pricing",
      pricingTitle: "One plan, everything included",
      trust: {
        access: "Two-factor sign-in and role-based access",
        audited: "Every administrative action audited",
        neverSold: "Your alert data is never sold",
      },
    },
    pricingCard: {
      /** After the price: "per month", "per 3 months". */
      per: (count: number, unit: PriceInterval) => (count === 1 ? `per ${unit}` : `per ${count} ${unit}s`),
      /** A period Paddle described in a way we don't recognise. */
      perOther: (period: string) => `per ${period}`,
      priceAtCheckout: "price shown at checkout",
      trialTerms: (days: number) => `${days}-day free trial · no card required · cancel any time`,
      startTrial: "Start free trial",
      taxNote: "Prices include or add tax depending on your country. Billed through Paddle.com.",
    },
    /** What the one plan includes — also listed on the in-app Billing page. */
    planFeatures: [
      "Real-time alerts from your security sensors (Wazuh today)",
      "Real-time alert feed and incident workflow",
      "AI explanations and investigation copilot",
      "Asset inventory built from your sensors",
      "Team roles, two-factor sign-in and full audit log",
      "AI agents with their own identities, behind a policy firewall",
      "Your data isolated in its own workspace",
      "Email alerts for high-severity events",
    ],
  },
  ru: {
    header: {
      homeAria: "Legion — на главную",
      features: "Возможности",
      pricing: "Цены",
      startTrial: (days: number) => `${ruDays(days)} бесплатно`,
      tryFree: "Попробовать",
    },
    footer: {
      merchantNotice: (seller: string) =>
        `Сервис Legion предоставляет ${seller}. Заказы обрабатывает наш онлайн-реселлер Paddle.com — он выступает продавцом (Merchant of Record) по всем заказам и отвечает за выставление счетов, выдачу инвойсов и поддержку клиентов по вопросам оплаты.`,
      pricing: "Цены",
      terms: "Условия",
      freeTrial: "Пробный период",
      privacy: "Конфиденциальность",
      contact: "Контакты",
      refunds: "Возвраты",
    },
    landing: {
      heroTitle: "Хватит разгребать оповещения.",
      heroTitleAccent: "Пора останавливать угрозы.",
      heroText:
        "Legion следит за вашими компьютерами и ИИ-агентами, объясняет каждую угрозу простым языком и останавливает рискованные действия ИИ до того, как они произойдут, — и небольшая команда справляется, как большая.",
      ctaTrial: (days: number) => `Попробовать ${ruDays(days)} бесплатно`,
      ctaPricing: "Посмотреть цены",
      noCard: "Банковская карта не нужна.",
      featuresEyebrow: "Что вы получаете",
      featuresTitle: "От оповещения к решению",
      features: {
        realtime: {
          title: "Подключение за минуты",
          text: "Подключите датчик безопасности, который у вас уже есть, — сейчас Wazuh, скоро и другие, — и оповещения появятся в ту же секунду. Без опросов по расписанию и без таблиц.",
        },
        explained: {
          title: "Не просто список, а объяснение",
          text: "К каждому оповещению — объяснение простым языком и следующий шаг: что произошло, чем это грозит и что проверить в первую очередь.",
        },
        triage: {
          title: "От разбора до решения",
          text: "Открыть, расследовать, закрыть. В каждом инциденте — критичность, техника MITRE, источник и цель, а также полная история того, кто и что сделал.",
        },
        assets: {
          title: "Учёт активов",
          text: "Машины, от которых приходят оповещения, автоматически попадают в каталог по данным ваших сенсоров — с уровнем риска и временем последней активности.",
        },
        agents: {
          title: "ИИ-агенты под контролем",
          text: "Дайте автоматизации собственную учётную запись и ровно те права, которые ей нужны. Каждое действие проходит проверку политиками и попадает в журнал аудита.",
        },
        secure: {
          title: "Защищён по всем правилам",
          text: "Двухфакторный вход, доступ на основе ролей, журнал аудита, записи в котором нельзя изменить, и данные каждого клиента в отдельном изолированном рабочем пространстве.",
        },
      },
      stepsEyebrow: "Как это работает",
      steps: {
        create: {
          title: "Создайте рабочее пространство",
          text: (days: number) => `Зарегистрируйтесь с рабочей почтой. ${ruDays(days)} бесплатно, без карты.`,
        },
        connect: {
          title: "Подключите датчики",
          text: "Создайте ключ, вставьте один блок в настройки датчика — Legion сообщит, когда придёт первое событие.",
        },
        act: {
          title: "Займитесь главным",
          text: "Критические оповещения поднимаются наверх — с объяснением и следующим шагом.",
        },
      },
      pricingEyebrow: "Цены",
      pricingTitle: "Один тариф — всё включено",
      trust: {
        access: "Двухфакторный вход и доступ по ролям",
        audited: "Каждое административное действие фиксируется в журнале",
        neverSold: "Мы никогда не продаём данные ваших оповещений",
      },
    },
    pricingCard: {
      per: (count: number, unit: PriceInterval) =>
        count === 1
          ? RU_PER_ONE[unit]
          : `за ${count} ${plural("ru", count, { ...RU_UNIT[unit], other: RU_UNIT[unit].few })}`,
      perOther: (period: string) => `/ ${period}`,
      priceAtCheckout: "цена будет указана при оформлении",
      trialTerms: (days: number) => `${ruDays(days)} бесплатно · без карты · отмена в любой момент`,
      startTrial: "Начать пробный период",
      taxNote: "Налог включён в цену или добавляется к ней в зависимости от вашей страны. Оплата через Paddle.com.",
    },
    planFeatures: [
      "Оповещения от ваших датчиков безопасности в реальном времени (сейчас — Wazuh)",
      "Лента оповещений в реальном времени и работа с инцидентами",
      "Объяснения от ИИ и Copilot для расследований",
      "Учёт активов по данным ваших сенсоров",
      "Роли в команде, двухфакторный вход и полный журнал аудита",
      "ИИ-агенты с собственными учётными записями под защитой политик",
      "Ваши данные изолированы в отдельном рабочем пространстве",
      "Оповещения по email о событиях высокой критичности",
    ],
  },
  uz: {
    header: {
      homeAria: "Legion — bosh sahifa",
      features: "Imkoniyatlar",
      pricing: "Narxlar",
      startTrial: (days: number) => `${days} kun bepul`,
      tryFree: "Bepul sinash",
    },
    footer: {
      merchantNotice: (seller: string) =>
        `Legion xizmatini ${seller} taqdim etadi. Buyurtmalar onlayn resellerimiz Paddle.com orqali rasmiylashtiriladi: u barcha buyurtmalar bo'yicha sotuvchi (Merchant of Record) hisoblanadi hamda hisob-kitob, invoyslar va to'lov bilan bog'liq mijozlarga xizmat ko'rsatishni o'z zimmasiga oladi.`,
      pricing: "Narxlar",
      terms: "Shartlar",
      freeTrial: "Bepul sinov",
      privacy: "Maxfiylik",
      contact: "Aloqa",
      refunds: "Pulni qaytarish",
    },
    landing: {
      heroTitle: "Ogohlantirishlar ortidan quvishni bas qiling.",
      heroTitleAccent: "Tahdidlarni to'xtatishni boshlang.",
      heroText:
        "Legion kompyuterlaringiz va AI agentlaringizni kuzatadi, har bir tahdidni oddiy tilda tushuntiradi va xavfli AI amallarini sodir bo'lishidan oldin to'xtatadi — shunda kichik jamoa ham katta jamoadek ishlay oladi.",
      ctaTrial: (days: number) => `${days} kun bepul sinab ko'ring`,
      ctaPricing: "Narxlarni ko'rish",
      noCard: "Bank kartasi talab qilinmaydi.",
      featuresEyebrow: "Nimalarga ega bo'lasiz",
      featuresTitle: "Ogohlantirishdan qarorgacha",
      features: {
        realtime: {
          title: "Bir necha daqiqada ulanish",
          text: "Sizda bor xavfsizlik sensorini ulang — hozir Wazuh, tez orada boshqalari ham — ogohlantirishlar sodir bo'lgan zahoti paydo bo'ladi. Davriy so'rovlarsiz, jadvallarsiz.",
        },
        explained: {
          title: "Ro'yxat emas — tushuntirish",
          text: "Har bir ogohlantirish oddiy tilda tushuntiriladi va keyingi qadam taklif qilinadi: nima bo'ldi, nega bu muhim va birinchi navbatda nimani tekshirish kerak.",
        },
        triage: {
          title: "Saralashdan hal qilishgacha",
          text: "Oching, tekshiring, hal qiling. Har bir hodisada jiddiylik darajasi, MITRE texnikasi, manba va nishon, shuningdek kim nima qilgani haqidagi to'liq tarix.",
        },
        assets: {
          title: "Aktivlar ro'yxati",
          text: "Ogohlantirishlar kelayotgan kompyuterlar sensorlaringiz ma'lumotlari asosida avtomatik ro'yxatga olinadi — xavf darajasi va oxirgi faollik vaqti bilan.",
        },
        agents: {
          title: "Nazorat ostidagi AI agentlar",
          text: "Avtomatlashtirishga alohida hisob va faqat kerakli ruxsatlarni bering. Har bir amal siyosatlar tekshiruvidan o'tadi va audit jurnaliga yoziladi.",
        },
        secure: {
          title: "Xavfsizlik — poydevorda",
          text: "Ikki bosqichli kirish, rollarga asoslangan ruxsatlar, o'zgartirib bo'lmaydigan audit jurnali va har bir mijoz ma'lumotlari alohida ish maydonida izolyatsiya qilingan.",
        },
      },
      stepsEyebrow: "Qanday ishlaydi",
      steps: {
        create: {
          title: "Ish maydonini yarating",
          text: (days: number) => `Ish emailingiz bilan ro'yxatdan o'ting. ${days} kun bepul, kartasiz.`,
        },
        connect: {
          title: "Sensorlaringizni ulang",
          text: "Kalit yarating, sensor sozlamalariga bitta blokni joylang — birinchi hodisa kelganda Legion xabar beradi.",
        },
        act: {
          title: "Eng muhimiga e'tibor bering",
          text: "Kritik ogohlantirishlar tushuntirish va keyingi qadam bilan ro'yxat boshiga chiqadi.",
        },
      },
      pricingEyebrow: "Narxlar",
      pricingTitle: "Bitta tarif — hammasi ichida",
      trust: {
        access: "Ikki bosqichli kirish va rollar bo'yicha ruxsatlar",
        audited: "Har bir administrativ amal audit jurnaliga yoziladi",
        neverSold: "Ogohlantirishlaringiz ma'lumotlari hech qachon sotilmaydi",
      },
    },
    pricingCard: {
      per: (count: number, unit: PriceInterval) =>
        count === 1 ? UZ_PER_ONE[unit] : `har ${count} ${UZ_UNIT[unit]}`,
      perOther: (period: string) => `/ ${period}`,
      priceAtCheckout: "narx to'lov paytida ko'rsatiladi",
      trialTerms: (days: number) => `${days} kun bepul sinov · kartasiz · istalgan vaqtda bekor qilish mumkin`,
      startTrial: "Bepul sinovni boshlash",
      taxNote: "Mamlakatingizga qarab soliq narxga kiritilgan yoki alohida qo'shiladi. To'lov Paddle.com orqali amalga oshiriladi.",
    },
    planFeatures: [
      "Xavfsizlik sensorlaringizdan real vaqtdagi ogohlantirishlar (hozircha Wazuh)",
      "Real vaqtdagi ogohlantirishlar lentasi va hodisalar bilan ishlash",
      "AI tushuntirishlari va tekshiruvlar uchun Copilot",
      "Sensorlaringiz asosida tuzilgan aktivlar ro'yxati",
      "Jamoa rollari, ikki bosqichli kirish va to'liq audit jurnali",
      "Alohida hisobga ega AI agentlar — siyosatlar nazorati ostida",
      "Ma'lumotlaringiz alohida ish maydonida izolyatsiya qilingan",
      "Yuqori jiddiylikdagi hodisalar haqida email orqali ogohlantirishlar",
    ],
  },
});
