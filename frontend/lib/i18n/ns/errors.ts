import { defineMessages } from "../core";

/**
 * Every important error answers three questions: what happened, why, and
 * what to do next (lib/errors.ts picks the entry; ErrorNotice shows it).
 * The server's own message, already in the reader's language, is shown as
 * the detail of "what happened".
 */
export const errors = defineMessages({
  en: {
    whyLabel: "Why",
    nextLabel: "What you can do",
    retry: "Try again",
    network: { title: "Legion can't be reached", why: "Your connection dropped, or the Legion service is restarting.", next: "Check your internet connection, then try again in a moment." },
    session: { title: "You've been signed out", why: "Your session ended — it expired, or you signed out in another tab.", next: "Sign in again. Nothing you saved was lost.", action: "Sign in" },
    plan: { title: "This workspace's plan isn't active", why: "The free trial has ended or the subscription was cancelled. Your data is safe, and Legion keeps recording your sensors' events.", nextAdmin: "Choose a plan on the Billing page to continue.", nextMember: "Ask a workspace admin to renew the plan.", action: "Open Billing" },
    pastDue: { title: "Payment is overdue", why: "The last payment didn't go through, so the workspace is read-only for now.", nextAdmin: "Update the payment method on the Billing page.", nextMember: "Ask a workspace admin to update the payment method.", action: "Open Billing" },
    forbidden: { title: "You don't have permission to do this", why: "Your role in this workspace doesn't include this action.", next: "Ask a workspace admin to do it, or to change your role." },
    notFound: { title: "We couldn't find that", why: "It may have been removed, or it belongs to a different workspace.", next: "Check that you're in the right workspace (see the switcher in the sidebar)." },
    conflict: { title: "That can't be done right now", why: "Something changed since the page loaded, or the item is in a state that doesn't allow this.", next: "Refresh the page and try again." },
    invalid: { title: "Some information isn't right", why: "Legion checked what you entered and couldn't accept it.", next: "Correct the highlighted details and try again." },
    rateLimited: { title: "Too many attempts", why: "Legion slows down repeated attempts to protect your account and workspace.", next: "Wait a moment and try again.", nextSeconds: (s: number) => `Wait ${s} seconds and try again.` },
    region: { title: "This workspace is in another region", why: "Its data is stored in a different region, which this address doesn't serve.", next: "Open the workspace from its own region.", action: "Go there" },
    server: { title: "Something went wrong on our side", why: "Legion hit a temporary problem. Nothing you did caused it.", next: "Try again in a minute. If it keeps happening, contact support." },
    unknown: { title: "That didn't work", why: "Legion couldn't complete the request.", next: "Try again. If it keeps happening, contact support." },
  },
  ru: {
    whyLabel: "Почему",
    nextLabel: "Что можно сделать",
    retry: "Повторить",
    network: { title: "Нет связи с Legion", why: "Пропало соединение или сервис Legion перезапускается.", next: "Проверьте подключение к интернету и повторите попытку чуть позже." },
    session: { title: "Вы вышли из системы", why: "Сеанс завершился — истёк срок или вы вышли в другой вкладке.", next: "Войдите снова. Сохранённые данные не потерялись.", action: "Войти" },
    plan: { title: "Тариф рабочего пространства не активен", why: "Пробный период закончился или подписка отменена. Данные в безопасности, события датчиков продолжают записываться.", nextAdmin: "Выберите тариф на странице «Оплата».", nextMember: "Попросите администратора продлить тариф.", action: "Открыть «Оплату»" },
    pastDue: { title: "Платёж просрочен", why: "Последний платёж не прошёл, поэтому рабочее пространство пока доступно только для чтения.", nextAdmin: "Обновите способ оплаты на странице «Оплата».", nextMember: "Попросите администратора обновить способ оплаты.", action: "Открыть «Оплату»" },
    forbidden: { title: "Недостаточно прав", why: "Ваша роль в этом рабочем пространстве не включает это действие.", next: "Попросите администратора выполнить его или изменить вашу роль." },
    notFound: { title: "Не найдено", why: "Возможно, это удалено или относится к другому рабочему пространству.", next: "Проверьте, что выбрано нужное рабочее пространство (переключатель на боковой панели)." },
    conflict: { title: "Сейчас это сделать нельзя", why: "Данные изменились после загрузки страницы, или текущее состояние это не допускает.", next: "Обновите страницу и повторите попытку." },
    invalid: { title: "Некоторые данные указаны неверно", why: "Legion проверил введённые данные и не смог их принять.", next: "Исправьте отмеченные поля и повторите попытку." },
    rateLimited: { title: "Слишком много попыток", why: "Legion замедляет повторные попытки, чтобы защитить аккаунт и рабочее пространство.", next: "Подождите немного и повторите попытку.", nextSeconds: (s: number) => `Подождите ${s} с и повторите попытку.` },
    region: { title: "Рабочее пространство в другом регионе", why: "Его данные хранятся в другом регионе, который этот адрес не обслуживает.", next: "Откройте рабочее пространство в его регионе.", action: "Перейти" },
    server: { title: "Ошибка на нашей стороне", why: "У Legion временная проблема. Ваши действия ни при чём.", next: "Повторите через минуту. Если ошибка повторяется, обратитесь в поддержку." },
    unknown: { title: "Не получилось", why: "Legion не смог выполнить запрос.", next: "Повторите попытку. Если ошибка повторяется, обратитесь в поддержку." },
  },
  uz: {
    whyLabel: "Nega",
    nextLabel: "Nima qilish mumkin",
    retry: "Qayta urinish",
    network: { title: "Legion bilan aloqa yo'q", why: "Internet uzildi yoki Legion xizmati qayta ishga tushmoqda.", next: "Internet aloqasini tekshiring va birozdan keyin qayta urinib ko'ring." },
    session: { title: "Tizimdan chiqdingiz", why: "Seans tugadi — muddati o'tdi yoki boshqa oynada chiqdingiz.", next: "Qaytadan kiring. Saqlangan ma'lumotlar yo'qolmadi.", action: "Kirish" },
    plan: { title: "Ish maydoni tarifi faol emas", why: "Sinov muddati tugadi yoki obuna bekor qilindi. Ma'lumotlaringiz xavfsiz, sensor hodisalari yozib borilmoqda.", nextAdmin: "To'lovlar sahifasida tarif tanlang.", nextMember: "Administratordan tarifni yangilashni so'rang.", action: "To'lovlarni ochish" },
    pastDue: { title: "To'lov muddati o'tgan", why: "Oxirgi to'lov o'tmadi, shuning uchun ish maydoni hozircha faqat o'qish uchun.", nextAdmin: "To'lovlar sahifasida to'lov usulini yangilang.", nextMember: "Administratordan to'lov usulini yangilashni so'rang.", action: "To'lovlarni ochish" },
    forbidden: { title: "Bunga ruxsatingiz yo'q", why: "Ushbu ish maydonidagi rolingiz bu amalni o'z ichiga olmaydi.", next: "Administratordan buni bajarishni yoki rolingizni o'zgartirishni so'rang." },
    notFound: { title: "Topilmadi", why: "U o'chirilgan yoki boshqa ish maydoniga tegishli bo'lishi mumkin.", next: "To'g'ri ish maydonida ekaningizni tekshiring (yon paneldagi almashtirgich)." },
    conflict: { title: "Hozir buni bajarib bo'lmaydi", why: "Sahifa yuklangandan keyin nimadir o'zgardi yoki joriy holat bunga ruxsat bermaydi.", next: "Sahifani yangilang va qayta urinib ko'ring." },
    invalid: { title: "Ba'zi ma'lumotlar noto'g'ri", why: "Legion kiritilgan ma'lumotlarni tekshirdi va qabul qila olmadi.", next: "Belgilangan maydonlarni tuzating va qayta urinib ko'ring." },
    rateLimited: { title: "Urinishlar juda ko'p", why: "Legion hisobingiz va ish maydonini himoya qilish uchun takroriy urinishlarni sekinlashtiradi.", next: "Biroz kuting va qayta urinib ko'ring.", nextSeconds: (s: number) => `${s} soniya kuting va qayta urinib ko'ring.` },
    region: { title: "Ish maydoni boshqa mintaqada", why: "Uning ma'lumotlari ushbu manzil xizmat ko'rsatmaydigan boshqa mintaqada saqlanadi.", next: "Ish maydonini o'z mintaqasida oching.", action: "O'tish" },
    server: { title: "Bizning tomonda xatolik", why: "Legion'da vaqtinchalik muammo. Bunga siz sabab emassiz.", next: "Bir daqiqadan keyin qayta urinib ko'ring. Takrorlansa, yordam xizmatiga murojaat qiling." },
    unknown: { title: "Bajarilmadi", why: "Legion so'rovni bajara olmadi.", next: "Qayta urinib ko'ring. Takrorlansa, yordam xizmatiga murojaat qiling." },
  },
});
