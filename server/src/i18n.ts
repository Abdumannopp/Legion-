import { isIP } from "node:net";
/**
 * Server-side language support.
 *
 * The dashboard sends the interface language in `Accept-Language` on every
 * request. Everything a person reads that the server writes — error messages,
 * confirmations, emails, AI explanations, Copilot answers — is then produced
 * in that language (English, Russian or Uzbek).
 *
 * Route code keeps writing English messages; `localizeResponses` translates
 * the `detail` and `message` fields of every JSON response on the way out,
 * using the catalogue below. tests/i18n.test.ts fails the build when a route
 * adds a message the catalogue does not have.
 */
import type { NextFunction, Request, Response } from "express";
import type { Alert } from "./types.js";

export type Locale = "en" | "ru" | "uz";
export const LOCALES: readonly Locale[] = ["en", "ru", "uz"];

export function isLocale(value: unknown): value is Locale {
  return value === "en" || value === "ru" || value === "uz";
}

/**
 * Picks the language from an Accept-Language header ("ru", "uz-Latn-UZ,en;q=0.8").
 * Highest q-value wins; anything that is not Russian or Uzbek is English.
 */
export function localeFrom(header: string | undefined | null): Locale {
  if (!header) return "en";
  const ranked = header
    .split(",")
    .map((part, index) => {
      const [tag, ...params] = part.trim().split(";");
      const q = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
      const weight = q ? Number(q.slice(2)) : 1;
      return { lang: (tag ?? "").trim().toLowerCase().split("-")[0], weight: Number.isFinite(weight) ? weight : 0, index };
    })
    .filter((x) => x.lang && x.weight > 0)
    .sort((a, b) => b.weight - a.weight || a.index - b.index);
  for (const { lang } of ranked) {
    if (isLocale(lang)) return lang;
  }
  return "en";
}

export function requestLocale(req: Request): Locale {
  return localeFrom(req.header("accept-language"));
}

type Translation = { ru: string; uz: string };

/** Every fixed English message the API returns, with its translations. */
export const CATALOG: Record<string, Translation> = {
  // --- sign-in, sessions, accounts
  "Authentication required": {
    ru: "Требуется вход в систему",
    uz: "Tizimga kirish talab qilinadi",
  },
  "This account is not active": {
    ru: "Эта учётная запись неактивна",
    uz: "Bu hisob faol emas",
  },
  "Insufficient permissions": {
    ru: "Недостаточно прав",
    uz: "Huquqlaringiz yetarli emas",
  },
  "Invalid email or password": {
    ru: "Неверный адрес эл. почты или пароль",
    uz: "Email yoki parol noto'g'ri",
  },
  "Finish setting up your account from the invitation email first": {
    ru: "Сначала завершите настройку учётной записи по ссылке из письма-приглашения",
    uz: "Avval taklif xatidagi havola orqali hisobingizni sozlab oling",
  },
  "This account has been deactivated": {
    ru: "Эта учётная запись отключена",
    uz: "Bu hisob o'chirib qo'yilgan",
  },
  "This account is no longer active": {
    ru: "Эта учётная запись больше не активна",
    uz: "Bu hisob endi faol emas",
  },
  "Confirm your email address first — we sent you a link when you signed up.": {
    ru: "Сначала подтвердите адрес эл. почты — мы отправили ссылку при регистрации.",
    uz: "Avval emailingizni tasdiqlang — ro'yxatdan o'tganingizda havola yuborganmiz.",
  },
  "This confirmation link is invalid or has expired. Request a new one from the sign-in page.": {
    ru: "Ссылка для подтверждения недействительна или устарела. Запросите новую на странице входа.",
    uz: "Tasdiqlash havolasi yaroqsiz yoki muddati o'tgan. Kirish sahifasidan yangisini so'rang.",
  },
  "Email confirmed. You can sign in now.": {
    ru: "Адрес подтверждён. Теперь можно войти.",
    uz: "Email tasdiqlandi. Endi kirishingiz mumkin.",
  },
  "If that account is waiting for confirmation, a new link has been sent.": {
    ru: "Если эта учётная запись ожидает подтверждения, мы отправили новую ссылку.",
    uz: "Agar bu hisob tasdiqlanishni kutayotgan bo'lsa, yangi havola yuborildi.",
  },
  "Email is already registered": {
    ru: "Этот адрес эл. почты уже зарегистрирован",
    uz: "Bu email allaqachon ro'yxatdan o'tgan",
  },
  "This Legion installation is already set up. Ask an administrator to invite you.": {
    ru: "Эта установка Legion уже настроена. Попросите администратора пригласить вас.",
    uz: "Bu Legion o'rnatmasi allaqachon sozlangan. Administratordan sizni taklif qilishini so'rang.",
  },
  "A valid setup token is required. It is printed in the Legion server's console on startup.": {
    ru: "Нужен действительный токен настройки. Он выводится в консоль сервера Legion при запуске.",
    uz: "Yaroqli sozlash tokeni kerak. U Legion serveri ishga tushganda konsolga chiqariladi.",
  },
  "This sign-in attempt has expired. Please log in again.": {
    ru: "Время на вход истекло. Войдите ещё раз.",
    uz: "Kirish urinishining vaqti tugadi. Qaytadan kiring.",
  },
  "A code is required": {
    ru: "Введите код",
    uz: "Kodni kiriting",
  },
  "That code is not valid": {
    ru: "Неверный код",
    uz: "Kod noto'g'ri",
  },
  "That recovery code is not valid": {
    ru: "Неверный код восстановления",
    uz: "Tiklash kodi noto'g'ri",
  },
  "Two-factor authentication is already enabled": {
    ru: "Двухфакторная аутентификация уже включена",
    uz: "Ikki bosqichli autentifikatsiya allaqachon yoqilgan",
  },
  "Start setup first": {
    ru: "Сначала начните настройку",
    uz: "Avval sozlashni boshlang",
  },
  "That code is not valid — check your authenticator app's clock": {
    ru: "Неверный код — проверьте время в приложении-аутентификаторе",
    uz: "Kod noto'g'ri — autentifikator ilovasidagi vaqtni tekshiring",
  },
  "Two-factor authentication is not enabled": {
    ru: "Двухфакторная аутентификация не включена",
    uz: "Ikki bosqichli autentifikatsiya yoqilmagan",
  },
  "Password is incorrect": {
    ru: "Неверный пароль",
    uz: "Parol noto'g'ri",
  },
  "A valid authentication or recovery code is required": {
    ru: "Нужен действительный код аутентификации или восстановления",
    uz: "Yaroqli autentifikatsiya yoki tiklash kodi kerak",
  },
  "No session to refresh": {
    ru: "Нет сеанса для продления",
    uz: "Yangilanadigan seans yo'q",
  },
  "Session reuse detected. Please log in again.": {
    ru: "Обнаружено повторное использование сеанса. Войдите ещё раз.",
    uz: "Seansdan qayta foydalanish aniqlandi. Qaytadan kiring.",
  },
  "Session expired. Please log in again.": {
    ru: "Сеанс истёк. Войдите ещё раз.",
    uz: "Seans muddati tugadi. Qaytadan kiring.",
  },
  "If that email is registered, a reset link has been generated.": {
    ru: "Если этот адрес зарегистрирован, мы отправили ссылку для сброса пароля.",
    uz: "Agar bu email ro'yxatdan o'tgan bo'lsa, parolni tiklash havolasi yuborildi.",
  },
  "Token is invalid or has expired": {
    ru: "Ссылка недействительна или устарела",
    uz: "Havola yaroqsiz yoki muddati o'tgan",
  },
  "Password updated. Please log in again.": {
    ru: "Пароль изменён. Войдите ещё раз.",
    uz: "Parol yangilandi. Qaytadan kiring.",
  },
  "Current password is incorrect": {
    ru: "Текущий пароль неверен",
    uz: "Joriy parol noto'g'ri",
  },
  "This invitation is invalid or has expired": {
    ru: "Приглашение недействительно или устарело",
    uz: "Taklif yaroqsiz yoki muddati o'tgan",
  },
  "Your account is ready. Please log in.": {
    ru: "Учётная запись готова. Войдите в систему.",
    uz: "Hisobingiz tayyor. Tizimga kiring.",
  },

  // --- alerts
  "Alert ID already exists": {
    ru: "Оповещение с таким ID уже существует",
    uz: "Bunday ID'li ogohlantirish allaqachon mavjud",
  },
  "Alert not found": {
    ru: "Оповещение не найдено",
    uz: "Ogohlantirish topilmadi",
  },

  // --- team
  "That email address is already in use": {
    ru: "Этот адрес эл. почты уже используется",
    uz: "Bu email allaqachon ishlatilmoqda",
  },
  "User not found": {
    ru: "Пользователь не найден",
    uz: "Foydalanuvchi topilmadi",
  },
  "That user has already accepted their invitation": {
    ru: "Этот пользователь уже принял приглашение",
    uz: "Bu foydalanuvchi taklifni allaqachon qabul qilgan",
  },
  "A tenant must keep at least one admin": {
    ru: "В организации должен остаться хотя бы один администратор",
    uz: "Tashkilotda kamida bitta administrator qolishi kerak",
  },
  "You cannot deactivate your own account": {
    ru: "Нельзя отключить собственную учётную запись",
    uz: "O'z hisobingizni o'chirib qo'ya olmaysiz",
  },

  // --- notifications
  "Set a notification email address first": {
    ru: "Сначала укажите адрес для уведомлений",
    uz: "Avval bildirishnomalar uchun email kiriting",
  },
  "SMTP is not configured (set SMTP_HOST)": {
    ru: "SMTP не настроен (укажите SMTP_HOST)",
    uz: "SMTP sozlanmagan (SMTP_HOST ni kiriting)",
  },

  // --- billing and access
  "Billing is not available on a self-hosted installation": {
    ru: "Оплата недоступна в собственной установке",
    uz: "O'z serveringizdagi o'rnatmada to'lov bo'limi yo'q",
  },
  "No subscription on file for this tenant yet": {
    ru: "У организации пока нет подписки",
    uz: "Tashkilotda hali obuna yo'q",
  },
  "Paddle is not configured": {
    ru: "Paddle не настроен",
    uz: "Paddle sozlanmagan",
  },
  "No Paddle customer on file for this tenant yet": {
    ru: "Для организации ещё нет покупателя в Paddle — сначала оформите подписку",
    uz: "Tashkilot uchun Paddle'da hali xaridor yo'q — avval obunani rasmiylashtiring",
  },
  "Paddle did not return a portal URL": {
    ru: "Paddle не вернул ссылку на портал",
    uz: "Paddle portal havolasini qaytarmadi",
  },
  "Your subscription payment is past due. Legion is read-only until it is settled.": {
    ru: "Оплата подписки просрочена. До оплаты Legion работает только в режиме просмотра.",
    uz: "Obuna to'lovi kechikdi. To'lov qilinguncha Legion faqat ko'rish rejimida ishlaydi.",
  },
  "This workspace does not have an active Legion subscription.": {
    ru: "У этого рабочего пространства нет активной подписки Legion.",
    uz: "Bu ish maydonida faol Legion obunasi yo'q.",
  },

  // --- ingestion, general
  "Unknown tenant": {
    ru: "Неизвестная организация",
    uz: "Noma'lum tashkilot",
  },
  "Security event webhook is disabled": {
    ru: "Вебхук событий безопасности отключён",
    uz: "Xavfsizlik hodisalari webhook'i o'chirilgan",
  },
  "Not found": {
    ru: "Не найдено",
    uz: "Topilmadi",
  },
  "Webhook credential not found": {
    ru: "Учётные данные вебхука не найдены",
    uz: "Webhook kalitlari topilmadi",
  },
  "This webhook credential is revoked or expired": {
    ru: "Эти учётные данные вебхука отозваны или просрочены",
    uz: "Bu webhook kalitlari bekor qilingan yoki muddati tugagan",
  },
  "This webhook credential is already being rotated": {
    ru: "Эти учётные данные вебхука уже заменяются",
    uz: "Bu webhook kalitlari allaqachon almashtirilmoqda",
  },
  "Two-factor sign-in is temporarily unavailable. Use a recovery code, or contact your administrator.": {
    ru: "Вход с двухфакторной аутентификацией временно недоступен. Используйте код восстановления или обратитесь к администратору.",
    uz: "Ikki bosqichli kirish vaqtincha ishlamayapti. Tiklash kodidan foydalaning yoki administratoringizga murojaat qiling.",
  },
  "Service unavailable": {
    ru: "Сервис недоступен",
    uz: "Xizmat mavjud emas",
  },
  "Internal server error": {
    ru: "Внутренняя ошибка сервера",
    uz: "Serverning ichki xatosi",
  },
  "Too many attempts. Wait a minute and try again.": {
    ru: "Слишком много попыток. Подождите минуту и попробуйте снова.",
    uz: "Urinishlar juda ko'p. Bir daqiqa kutib, qayta urinib ko'ring.",
  },

  "Too many failed sign-in attempts for this account. Try again later.": {
    ru: "Слишком много неудачных попыток входа в этот аккаунт. Повторите позже.",
    uz: "Bu hisobga kirishda juda ko'p muvaffaqiyatsiz urinish bo'ldi. Keyinroq qayta urinib ko'ring.",
  },
  "Delivery not found": {
    ru: "Доставка не найдена",
    uz: "Yetkazish topilmadi",
  },
  "No failed delivery with that id": {
    ru: "Неудавшейся доставки с таким идентификатором нет",
    uz: "Bunday identifikatorli muvaffaqiyatsiz yetkazish yo'q",
  },
  "Service temporarily unavailable. Try again shortly.": {
    ru: "Сервис временно недоступен. Повторите чуть позже.",
    uz: "Xizmat vaqtincha ishlamayapti. Birozdan so'ng qayta urinib ko'ring.",
  },
  "Could not reach the billing provider. Try again later.": {
    ru: "Не удалось связаться с платёжным провайдером. Повторите позже.",
    uz: "To'lov provayderi bilan bog'lanib bo'lmadi. Keyinroq qayta urinib ko'ring.",
  },
  "Too many incorrect attempts. Wait a few minutes and try again.": {
    ru: "Слишком много неверных попыток. Подождите несколько минут и повторите.",
    uz: "Juda ko'p noto'g'ri urinish. Bir necha daqiqa kutib, qayta urinib ko'ring.",
  },
  "Too many emails requested for this address. Try again later.": {
    ru: "Для этого адреса запрошено слишком много писем. Повторите позже.",
    uz: "Bu manzil uchun juda ko'p xat so'raldi. Keyinroq qayta urinib ko'ring.",
  },
  "Too many failed webhook authentications from this address. Try again later.": {
    ru: "Слишком много неудачных попыток аутентификации вебхука с этого адреса. Повторите позже.",
    uz: "Bu manzildan webhook autentifikatsiyasi juda ko'p marta muvaffaqiyatsiz bo'ldi. Keyinroq qayta urinib ko'ring.",
  },
  "Too many incorrect codes. Sign in again in a few minutes.": {
    ru: "Слишком много неверных кодов. Войдите снова через несколько минут.",
    uz: "Noto'g'ri kodlar juda ko'p kiritildi. Bir necha daqiqadan so'ng qayta kiring.",
  },
  "Cross-origin request refused": {
    ru: "Междоменный запрос отклонён",
    uz: "Boshqa domendan kelgan so'rov rad etildi",
  },

  "Too many confirmation emails. Try again later.": {
    ru: "Слишком много писем с подтверждением. Повторите позже.",
    uz: "Tasdiqlash xatlari juda ko'p. Keyinroq qayta urinib ko'ring.",
  },
  "This confirmation link is invalid or has expired.": {
    ru: "Ссылка для подтверждения недействительна или устарела.",
    uz: "Tasdiqlash havolasi yaroqsiz yoki muddati o'tgan.",
  },
  "Address confirmed. Security alerts will be sent here.": {
    ru: "Адрес подтверждён. Оповещения безопасности будут приходить сюда.",
    uz: "Manzil tasdiqlandi. Xavfsizlik ogohlantirishlari shu yerga yuboriladi.",
  },
  "Too many test emails. Try again later.": {
    ru: "Слишком много тестовых писем. Повторите позже.",
    uz: "Sinov xatlari juda ko'p. Keyinroq qayta urinib ko'ring.",
  },
  "The mail server could not be reached. Your administrator can see the details in the server log.": {
    ru: "Не удалось связаться с почтовым сервером. Подробности — в журнале сервера у администратора.",
    uz: "Pochta serveriga ulanib bo'lmadi. Tafsilotlar server jurnalida — administratoringizdan so'rang.",
  },
  "The test email could not be sent. Your administrator can see the details in the server log.": {
    ru: "Не удалось отправить тестовое письмо. Подробности — в журнале сервера у администратора.",
    uz: "Sinov xatini yuborib bo'lmadi. Tafsilotlar server jurnalida — administratoringizdan so'rang.",
  },
  "Too many invitations. Try again later.": {
    ru: "Слишком много приглашений. Повторите позже.",
    uz: "Takliflar juda ko'p. Keyinroq qayta urinib ko'ring.",
  },

  // --- request validation (see validationMessage)
  "Invalid request": {
    ru: "Некорректный запрос",
    uz: "So'rov noto'g'ri",
  },
  "Enter a valid email address": {
    ru: "Введите корректный адрес эл. почты",
    uz: "To'g'ri email manzilini kiriting",
  },
  "Password must be 8 to 128 characters": {
    ru: "Пароль должен содержать от 8 до 128 символов",
    uz: "Parol 8 tadan 128 tagacha belgidan iborat bo'lishi kerak",
  },
  "Organisation name must be 2 to 100 characters": {
    ru: "Название организации должно содержать от 2 до 100 символов",
    uz: "Tashkilot nomi 2 tadan 100 tagacha belgidan iborat bo'lishi kerak",
  },
  "Enter the 6-digit code": {
    ru: "Введите 6-значный код",
    uz: "6 xonali kodni kiriting",
  },
  "A value in the request is missing or invalid": {
    ru: "В запросе отсутствует или указано неверное значение",
    uz: "So'rovdagi qiymat yo'q yoki noto'g'ri",
  },
  // --- workspaces, integrations, regions (global SaaS)
  "You are no longer a member of this workspace": {
    ru: "Вы больше не участник этого рабочего пространства",
    uz: "Siz endi bu ish maydonining a'zosi emassiz",
  },
  "The billing currency cannot change while a subscription is active": {
    ru: "Валюту оплаты нельзя изменить, пока действует подписка",
    uz: "Obuna faol bo'lganda to'lov valyutasini o'zgartirib bo'lmaydi",
  },
  "Choose a period of at most a year, with from before to": {
    ru: "Выберите период не длиннее года, где начало раньше конца",
    uz: "Boshlanishi tugashidan oldin bo'lgan, bir yildan oshmaydigan davrni tanlang",
  },
  "Only administrators can create workspaces on this installation": {
    ru: "В этой установке рабочие пространства могут создавать только администраторы",
    uz: "Bu o'rnatmada ish maydonlarini faqat administratorlar yaratishi mumkin",
  },
  "Confirm your email address first": {
    ru: "Сначала подтвердите адрес электронной почты",
    uz: "Avval elektron pochta manzilingizni tasdiqlang",
  },
  "Workspace not found": {
    ru: "Рабочее пространство не найдено",
    uz: "Ish maydoni topilmadi",
  },
  "This invitation is invalid, has expired, or was sent to another account": {
    ru: "Приглашение недействительно, истекло или отправлено другой учётной записи",
    uz: "Taklifnoma yaroqsiz, muddati o'tgan yoki boshqa hisobga yuborilgan",
  },
  "This is the workspace your account belongs to; it cannot be left": {
    ru: "Это рабочее пространство, которому принадлежит ваша учётная запись; его нельзя покинуть",
    uz: "Bu hisobingiz tegishli bo'lgan ish maydoni; uni tark etib bo'lmaydi",
  },
  "A workspace must keep at least one admin": {
    ru: "В рабочем пространстве должен остаться хотя бы один администратор",
    uz: "Ish maydonida kamida bitta administrator qolishi kerak",
  },
  "You already have a Legion account. Sign in to accept this invitation.": {
    ru: "У вас уже есть учётная запись Legion. Войдите, чтобы принять приглашение.",
    uz: "Sizda allaqachon Legion hisobi bor. Taklifni qabul qilish uchun tizimga kiring.",
  },
  "That person is already a member of this workspace": {
    ru: "Этот человек уже состоит в этом рабочем пространстве",
    uz: "Bu shaxs allaqachon ushbu ish maydonining a'zosi",
  },
  "Integration not found.": {
    ru: "Интеграция не найдена.",
    uz: "Integratsiya topilmadi.",
  },
  "This workspace is hosted in another region.": {
    ru: "Это рабочее пространство размещено в другом регионе.",
    uz: "Bu ish maydoni boshqa mintaqada joylashgan.",
  },
  "That integration is not available.": {
    ru: "Эта интеграция недоступна.",
    uz: "Bu integratsiya mavjud emas.",
  },
};

/** Messages with a variable part (an address, an upstream error). */
const PATTERNS: Array<{ re: RegExp; ru: (m: RegExpMatchArray) => string; uz: (m: RegExpMatchArray) => string }> = [
  {
    re: /^You can belong to at most (\d+) workspaces$/,
    ru: (m) => `Можно состоять не более чем в ${m[1]} рабочих пространствах`,
    uz: (m) => `Ko'pi bilan ${m[1]} ta ish maydoniga a'zo bo'lish mumkin`,
  },
  {
    re: /^Too many active webhook credentials \(maximum (\d+)\)$/,
    ru: (m) => `Слишком много действующих учётных данных вебхука (максимум ${m[1]})`,
    uz: (m) => `Faol webhook kalitlari juda ko'p (eng ko'pi ${m[1]})`,
  },
  {
    re: /^SMTP connection failed: (.*)$/s,
    ru: (m) => `Не удалось подключиться к SMTP-серверу: ${m[1]}`,
    uz: (m) => `SMTP serveriga ulanib bo'lmadi: ${m[1]}`,
  },
  {
    re: /^Could not send: (.*)$/s,
    ru: (m) => `Не удалось отправить: ${m[1]}`,
    uz: (m) => `Yuborib bo'lmadi: ${m[1]}`,
  },
  {
    re: /^Could not reach Paddle: (.*)$/s,
    ru: (m) => `Нет связи с Paddle: ${m[1]}`,
    uz: (m) => `Paddle bilan bog'lanib bo'lmadi: ${m[1]}`,
  },
  {
    re: /^Paddle API returned (\d+)$/,
    ru: (m) => `Paddle API вернул ошибку ${m[1]}`,
    uz: (m) => `Paddle API ${m[1]} xatosini qaytardi`,
  },
  {
    re: /^Test email sent to (.+)$/,
    ru: (m) => `Тестовое письмо отправлено на ${m[1]}`,
    uz: (m) => `Sinov xati ${m[1]} manziliga yuborildi`,
  },
];

/** English → the requested language. Unknown text is returned unchanged. */
export function translate(text: string, locale: Locale): string {
  if (locale === "en" || !text) return text;
  const fixed = CATALOG[text];
  if (fixed) return fixed[locale];
  for (const p of PATTERNS) {
    const m = text.match(p.re);
    if (m) return p[locale](m);
  }
  return text;
}

/**
 * Translates `detail` and `message` in every JSON body this request sends.
 * Registered before all routes, so it also covers the rate limiter, the 404
 * handler and the error handler.
 */
export function localizeResponses(req: Request, res: Response, next: NextFunction): void {
  const locale = requestLocale(req);
  res.locals.locale = locale;
  if (locale !== "en") {
    const json = res.json.bind(res);
    res.json = (body: unknown) => {
      if (body && typeof body === "object" && !Array.isArray(body)) {
        const b = body as Record<string, unknown>;
        const out: Record<string, unknown> = { ...b };
        if (typeof b.detail === "string") out.detail = translate(b.detail, locale);
        if (typeof b.message === "string") out.message = translate(b.message, locale);
        return json(out);
      }
      return json(body);
    };
  }
  next();
}

/**
 * English message for the first problem in a request body. Field-specific
 * wording where a person could have caused it from a form; a generic line
 * otherwise (the dashboard validates the same rules before sending).
 */
export function validationMessage(issue: { message?: string; path?: PropertyKey[] } | undefined): string {
  if (!issue) return "Invalid request";
  if (issue.message && CATALOG[issue.message]) return issue.message;
  const field = String(issue.path?.[issue.path.length - 1] ?? "");
  if (/email/.test(field)) return "Enter a valid email address";
  if (/password/.test(field)) return "Password must be 8 to 128 characters";
  if (field === "tenant_name") return "Organisation name must be 2 to 100 characters";
  if (field === "code") return "Enter the 6-digit code";
  return "A value in the request is missing or invalid";
}

// --- Alerts: suggested next steps and the no-AI explanation ------------------

export type SuggestedAction =
  | { code: "review_timeline" | "validate_ownership" | "reset_credentials" | "escalate" }
  | { code: "block_source_ip"; ip: string };

/** The next steps for an alert, as codes the dashboard renders in any language. */
export function suggestedActions(alert: Alert): SuggestedAction[] {
  const result: SuggestedAction[] = [{ code: "review_timeline" }, { code: "validate_ownership" }];
  // Only a real IP address becomes an instruction to block something: this text is
  // shown to an analyst, and the field is written by whoever can make a log line.
  if (alert.source_ip && isIP(alert.source_ip) !== 0) result.push({ code: "block_source_ip", ip: alert.source_ip });
  if (/auth|login|credential|brute/i.test(`${alert.title} ${alert.summary}`)) result.push({ code: "reset_credentials" });
  if (alert.severity === "critical") result.push({ code: "escalate" });
  return result;
}

const ACTION_TEXT: Record<Locale, (a: SuggestedAction) => string> = {
  en: (a) => ({
    review_timeline: "Review event timeline",
    validate_ownership: "Validate affected asset ownership",
    block_source_ip: `Block or investigate source IP ${"ip" in a ? a.ip : ""}`,
    reset_credentials: "Reset affected credentials and enforce MFA",
    escalate: "Escalate to incident response immediately",
  })[a.code],
  ru: (a) => ({
    review_timeline: "Изучите хронологию событий",
    validate_ownership: "Уточните, кому принадлежит затронутый актив",
    block_source_ip: `Заблокируйте или проверьте IP-адрес источника ${"ip" in a ? a.ip : ""}`,
    reset_credentials: "Сбросьте затронутые учётные данные и включите MFA",
    escalate: "Немедленно передайте инцидент команде реагирования",
  })[a.code],
  uz: (a) => ({
    review_timeline: "Hodisalar xronologiyasini ko'rib chiqing",
    validate_ownership: "Zarar ko'rgan aktiv kimga tegishli ekanini aniqlang",
    block_source_ip: `Manba IP manzilini (${"ip" in a ? a.ip : ""}) bloklang yoki tekshiring`,
    reset_credentials: "Zarar ko'rgan hisob ma'lumotlarini yangilang va MFA'ni yoqing",
    escalate: "Darhol hodisaga javob berish jamoasiga yetkazing",
  })[a.code],
};

export function actionText(action: SuggestedAction, locale: Locale): string {
  return ACTION_TEXT[locale](action);
}

const SEVERITY: Record<Locale, Record<Alert["severity"], string>> = {
  en: { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" },
  ru: { critical: "КРИТИЧЕСКИЙ", high: "ВЫСОКИЙ", medium: "СРЕДНИЙ", low: "НИЗКИЙ" },
  uz: { critical: "KRITIK", high: "YUQORI", medium: "O'RTA", low: "PAST" },
};

export function severityLabel(severity: Alert["severity"], locale: Locale): string {
  return SEVERITY[locale][severity];
}

/** Deterministic explanation used when no AI key is configured, and as the
 *  fallback whenever the model is unreachable. */
export function localExplanation(alert: Alert, locale: Locale): string {
  const sev = severityLabel(alert.severity, locale);
  const conf = Math.round(alert.confidence);
  const critical = alert.severity === "critical";
  if (locale === "ru") {
    return `Приоритет ${sev}: ${alert.title}. Уверенность сигнала — ${conf}%${alert.source_ip ? `, источник — ${alert.source_ip}` : ""}. Сначала подтвердите активность на ${alert.target ? `узле ${alert.target}` : "затронутом активе"}, сохраните связанные журналы, затем ${critical ? "изолируйте актив и немедленно эскалируйте инцидент" : "проведите расследование, прежде чем закрывать инцидент"}.`;
  }
  if (locale === "uz") {
    return `${sev} ustuvorlik: ${alert.title}. Signalning ishonchliligi — ${conf}%${alert.source_ip ? `, manbasi — ${alert.source_ip}` : ""}. Avval ${alert.target ? `${alert.target} tugunidagi` : "zarar ko'rgan aktivdagi"} faollikni tasdiqlang, tegishli jurnallarni saqlab qo'ying, so'ng ${critical ? "aktivni izolyatsiya qiling va darhol yuqoriga xabar bering" : "hodisani yopishdan oldin uni tekshirib chiqing"}.`;
  }
  return `${sev} priority: ${alert.title}. The signal has ${conf}% confidence${alert.source_ip ? ` and originated from ${alert.source_ip}` : ""}. First validate the activity on ${alert.target || "the affected asset"}, preserve relevant logs, then ${critical ? "isolate the asset and escalate immediately" : "investigate before closing the incident"}.`;
}

/** Copilot's answer when no AI provider is configured or it is unreachable. */
export function copilotFallback(open: Alert[], urgent: Alert | undefined, locale: Locale): string {
  if (!urgent) {
    return {
      en: "There are no unresolved alerts in your tenant right now.",
      ru: "Сейчас в вашей организации нет нерешённых оповещений.",
      uz: "Hozir tashkilotingizda hal qilinmagan ogohlantirishlar yo'q.",
    }[locale];
  }
  const steps = suggestedActions(urgent);
  const next = actionText(steps[steps.length - 1] ?? { code: "review_timeline" }, locale);
  const conf = Math.round(urgent.confidence);
  const sev = severityLabel(urgent.severity, locale).toLowerCase();
  if (locale === "ru") {
    return `Нерешённых оповещений: ${open.length}. Наивысший приоритет — ${urgent.id}: «${urgent.title}» (${sev}, уверенность ${conf}%). Рекомендуемый следующий шаг: ${next}.`;
  }
  if (locale === "uz") {
    return `Hal qilinmagan ogohlantirishlar: ${open.length} ta. Eng yuqori ustuvorlik — ${urgent.id}: “${urgent.title}” (${sev}, ishonchlilik ${conf}%). Tavsiya etilgan keyingi qadam: ${next}.`;
  }
  return `You have ${open.length} unresolved alert(s). The highest priority is ${urgent.id}: “${urgent.title}” (${sev}, ${conf}% confidence). Recommended next step: ${next}.`;
}

/** Appended to the AI system prompts so the answer is in the reader's language. */
export function answerLanguageInstruction(locale: Locale): string {
  return {
    en: "Write your answer in English.",
    ru: "Write your answer in Russian. Keep alert IDs, IP addresses, hostnames, MITRE technique IDs and product names exactly as given.",
    uz: "Write your answer in Uzbek, using the Latin script (o', g', sh, ch). Keep alert IDs, IP addresses, hostnames, MITRE technique IDs and product names exactly as given.",
  }[locale];
}
