import { defineMessages, plural } from "../core";

export const signup = defineMessages({
  en: {
    closed: {
      title: "Sign-up is closed",
      body: "This Legion installation belongs to one organisation. Ask your administrator for an invitation.",
    },
    checkEmail: {
      title: "Check your email",
      /** Wraps the email address: before + {email} + after. */
      sentBefore: "We sent a confirmation link to ",
      sentAfter: ". Open it to activate your workspace, then sign in. The link is valid for 24 hours.",
      resend: "Didn't get it? Send it again",
      resent: "A new link is on its way.",
    },
    title: "Start your free trial",
    trialNote: (days: number) =>
      `${plural("en", days, { one: `${days} day`, other: `${days} days` })} free, no card needed. You choose a plan only if you decide to keep Legion.`,
    companyLabel: "Company or team name",
    emailLabel: "Work email",
    /** "I agree to the {Terms} and {Privacy Policy}." — the two links sit between these parts. */
    agree: {
      before: "I agree to the ",
      terms: "Terms",
      and: " and ",
      privacy: "Privacy Policy",
      after: ".",
    },
    createAccount: "Create account",
    haveAccount: "Already have an account?",
    createFailed: "Could not create the account.",
  },
  ru: {
    closed: {
      title: "Регистрация закрыта",
      body: "Эта установка Legion принадлежит одной организации. Попросите администратора прислать вам приглашение.",
    },
    checkEmail: {
      title: "Проверьте почту",
      sentBefore: "Мы отправили ссылку для подтверждения на ",
      sentAfter: ". Откройте её, чтобы активировать рабочее пространство, а затем войдите. Ссылка действует 24 часа.",
      resend: "Не пришло письмо? Отправить ещё раз",
      resent: "Новая ссылка уже отправлена.",
    },
    title: "Попробуйте бесплатно",
    trialNote: (days: number) =>
      `${plural("ru", days, { one: `${days} день`, few: `${days} дня`, many: `${days} дней`, other: `${days} дня` })} бесплатно, карта не нужна. Тариф выбираете, только если решите остаться с Legion.`,
    companyLabel: "Название компании или команды",
    emailLabel: "Рабочая эл. почта",
    agree: {
      before: "Я принимаю ",
      terms: "Условия использования",
      and: " и ",
      privacy: "Политику конфиденциальности",
      after: ".",
    },
    createAccount: "Создать аккаунт",
    haveAccount: "Уже есть аккаунт?",
    createFailed: "Не удалось создать аккаунт.",
  },
  uz: {
    closed: {
      title: "Ro'yxatdan o'tish yopiq",
      body: "Bu Legion o'rnatmasi bitta tashkilotga tegishli. Administratoringizdan taklif yuborishini so'rang.",
    },
    checkEmail: {
      title: "Pochtangizni tekshiring",
      sentBefore: "Tasdiqlash havolasini ",
      sentAfter: " manziliga yubordik. Ish maydoningizni faollashtirish uchun havolani oching, so'ng tizimga kiring. Havola 24 soat amal qiladi.",
      resend: "Xat kelmadimi? Qayta yuborish",
      resent: "Yangi havola yuborildi.",
    },
    title: "Bepul sinab ko'ring",
    trialNote: (days: number) =>
      `${days} kun bepul, karta kerak emas. Tarifni faqat Legion'dan foydalanishda davom etmoqchi bo'lsangiz tanlaysiz.`,
    companyLabel: "Kompaniya yoki jamoa nomi",
    emailLabel: "Ishchi email manzili",
    agree: {
      before: "Men ",
      terms: "Foydalanish shartlari",
      and: " va ",
      privacy: "Maxfiylik siyosati",
      after: " bilan tanishib chiqdim va roziman.",
    },
    createAccount: "Hisob yaratish",
    haveAccount: "Hisobingiz bormi?",
    createFailed: "Hisob yaratib bo'lmadi.",
  },
});
