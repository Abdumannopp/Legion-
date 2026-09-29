import { Locale } from "@/lib/i18n/translations";

export type LegalSection = { heading: string; body: string[] };
export type LegalDoc = {
  title: string;
  effectiveDate: string;
  intro: string;
  sections: LegalSection[];
};

/**
 * Legion is self-hosted software: the organisation running this installation
 * is the one whose privacy policy this is, and it is not the vendor. Nothing
 * in this codebase can know that organisation's name, so it is supplied at
 * deploy time and substituted into the text by `resolveLegalDoc` below.
 *
 * The fallback is deliberately conspicuous rather than a plausible-looking
 * default: an unconfigured install should look unfinished, not look like it
 * belongs to someone else.
 */
export const OPERATOR =
  process.env.NEXT_PUBLIC_OPERATOR_NAME || "[the organisation running this installation]";

export const SUPPORT_EMAIL =
  process.env.NEXT_PUBLIC_SUPPORT_EMAIL || "support-not-configured@example.invalid";

/** Fills `{operator}` / `{supportEmail}` in a legal document before rendering. */
export function resolveLegalDoc(doc: LegalDoc, operator: string = OPERATOR): LegalDoc {
  const fill = (text: string) =>
    text.replace(/\{operator\}/g, operator).replace(/\{supportEmail\}/g, SUPPORT_EMAIL);

  return {
    ...doc,
    intro: fill(doc.intro),
    sections: doc.sections.map((section) => ({
      heading: fill(section.heading),
      body: section.body.map(fill),
    })),
  };
}

export const privacyContent: Record<Locale, LegalDoc> = {
  en: {
    title: "Privacy Policy",
    effectiveDate: "August 25, 2026",
    intro:
      "This Legion installation is operated by {operator} on infrastructure {operator} controls. Legion is software that {operator} installed; the company that makes Legion does not run this system, cannot log in to it, and receives no data from it. This policy describes what this installation stores, where that data goes, and who to contact about it.",
    sections: [
      {
        heading: "1. What This Installation Stores",
        body: [
          "Account records: your name, work email address, role, and your password — stored only as a bcrypt hash, never as text that can be read back.",
          "Two-factor records, if you enable it: the shared secret your authenticator app uses, and your recovery codes, which are themselves stored hashed.",
          "Session records: for each active sign-in, the IP address and browser user-agent it started from, and its expiry time. This is what lets you see and revoke your own sessions.",
          "An audit log: who performed which administrative action, when, and from which IP address.",
          "Security data from your own systems: alerts, source IP addresses, hostnames, and the asset inventory built from them. This is the material Legion exists to analyse, and its content is determined by what your systems send in.",
        ],
      },
      {
        heading: "2. Where That Data Goes",
        body: [
          "Into the PostgreSQL database on this server, and nowhere else. Legion contains no analytics, no telemetry, no usage reporting, and no automatic update check. It makes no network connection to its vendor at any point, so there is no channel through which your data could reach them.",
          "There are exactly two ways data can leave this server, and {operator} chooses whether either is switched on. Both are off unless configured.",
          "Optional AI analysis: {operator} may supply an API key for an external AI service — Legion supports OpenRouter and Groq — in which case the text of an alert is sent to that service for analysis and the result is stored here. When no key is set, no such request is ever made, and this is the shipped default. Where it is enabled, that service becomes a processor of whatever the alert text contains, and {operator} can tell you which one is in use. Legion sends it the alert text and nothing else — not the address of this installation, and not who is signed in.",
          "Optional email notification: if {operator} configures an outgoing mail server, alert notifications are delivered through that server — one chosen by {operator}, not by the vendor.",
        ],
      },
      {
        heading: "3. Cookies",
        body: [
          "This installation sets three cookies, all of them first-party and all of them necessary to keep you signed in: legion_token (your current session), legion_refresh (renews it without asking for your password again), and legion_session (a marker the dashboard reads to know a session exists).",
          "There are no advertising cookies, no analytics cookies, and no third-party cookies. Nothing here tracks you across other websites.",
        ],
      },
      {
        heading: "4. How Long Data Is Kept",
        body: [
          "Sessions expire on their own, and expired ones are cleared out.",
          "Alerts, assets, and the audit log are kept indefinitely — this software does not delete them on a schedule. If a retention limit applies to {operator}, whether by law or by policy, {operator} is responsible for enforcing it directly in the database.",
          "Because all data sits in a database {operator} controls, {operator} can delete any of it at any time.",
        ],
      },
      {
        heading: "5. Who Can See Your Data",
        body: [
          "People {operator} has given accounts on this installation, according to the role assigned to each of them.",
          "Anyone with administrative access to the server or to its database, which is a matter of how {operator} secures that machine.",
          "The vendor cannot. Support may ask {operator} for logs or screenshots to diagnose a problem, and anything shared that way is shared because {operator} decided to share it.",
        ],
      },
      {
        heading: "6. Security",
        body: [
          "Passwords are hashed with bcrypt. Session tokens are stored hashed, and reusing an old one revokes the whole session family. Two-factor authentication is available and codes cannot be replayed.",
          "These measures protect the software. They cannot protect a server that is left unpatched, unencrypted, or reachable from the internet without HTTPS — that part belongs to {operator}, and the operations guide shipped with Legion sets out what it involves.",
        ],
      },
      {
        heading: "7. Your Rights",
        body: [
          "Requests to access, correct, export, or delete your data go to {operator}, who holds the data and is the only party able to act on such a request.",
          "The company that makes Legion cannot answer these requests, not as a matter of policy but as a matter of fact: it has no copy of the data and no access to this system.",
        ],
      },
      {
        heading: "8. Changes",
        body: [
          "{operator} may update this policy. The effective date above shows when the version you are reading was published.",
        ],
      },
    ],
  },
  ru: {
    title: "Политика конфиденциальности",
    effectiveDate: "25 августа 2026 г.",
    intro:
      "Эта установка Legion эксплуатируется организацией {operator} на инфраструктуре, которой {operator} управляет. Legion — это программное обеспечение, которое {operator} установила; компания-разработчик Legion не управляет этой системой, не может в неё войти и не получает от неё никаких данных. В настоящей политике описано, что эта установка хранит, куда эти данные попадают и к кому обращаться по их поводу.",
    sections: [
      {
        heading: "1. Что хранит эта установка",
        body: [
          "Учётные записи: ваше имя, рабочий адрес электронной почты, роль и пароль — сохранённый только в виде bcrypt-хеша, никогда в виде читаемого текста.",
          "Данные двухфакторной аутентификации, если вы её включили: общий секрет для приложения-аутентификатора и коды восстановления, которые также хранятся в хешированном виде.",
          "Данные сессий: для каждого активного входа — IP-адрес и user-agent браузера, с которых он начался, и время истечения. Именно это позволяет вам видеть и отзывать собственные сессии.",
          "Журнал аудита: кто и когда выполнил то или иное административное действие и с какого IP-адреса.",
          "Данные безопасности из ваших собственных систем: оповещения, IP-адреса источников, имена хостов и построенная на их основе инвентаризация активов. Это тот материал, ради анализа которого Legion и существует, и его содержание определяется тем, что присылают ваши системы.",
        ],
      },
      {
        heading: "2. Куда попадают эти данные",
        body: [
          "В базу данных PostgreSQL на этом сервере — и больше никуда. Legion не содержит ни аналитики, ни телеметрии, ни отчётов об использовании, ни автоматической проверки обновлений. Он ни разу не устанавливает сетевое соединение со своим разработчиком, поэтому не существует канала, по которому ваши данные могли бы к нему попасть.",
          "Есть ровно два способа, которыми данные могут покинуть этот сервер, и {operator} решает, включать ли каждый из них. Оба выключены, пока не настроены.",
          "Необязательный ИИ-анализ: {operator} может предоставить API-ключ внешнего ИИ-сервиса — Legion поддерживает OpenRouter и Groq, — и тогда текст оповещения отправляется в этот сервис для анализа, а результат сохраняется здесь. Если ключ не задан, такой запрос не отправляется никогда, и это состояние по умолчанию. Там, где это включено, такой сервис становится обработчиком всего, что содержится в тексте оповещения, и {operator} может сообщить вам, какой именно сервис используется. Legion отправляет ему только текст оповещения — ни адрес этой установки, ни сведения о том, кто вошёл в систему.",
          "Необязательные уведомления по электронной почте: если {operator} настроит сервер исходящей почты, уведомления об оповещениях доставляются через этот сервер — выбранный организацией {operator}, а не разработчиком.",
        ],
      },
      {
        heading: "3. Файлы cookie",
        body: [
          "Эта установка устанавливает три файла cookie, все первой стороны и все необходимые для поддержания входа в систему: legion_token (текущая сессия), legion_refresh (продлевает её без повторного ввода пароля) и legion_session (метка, по которой панель управления понимает, что сессия существует).",
          "Здесь нет ни рекламных, ни аналитических файлов cookie, ни файлов cookie третьих сторон. Ничто здесь не отслеживает вас на других сайтах.",
        ],
      },
      {
        heading: "4. Сколько данные хранятся",
        body: [
          "Сессии истекают сами, и истёкшие удаляются.",
          "Оповещения, активы и журнал аудита хранятся бессрочно — эта программа не удаляет их по расписанию. Если к организации {operator} применяется срок хранения — по закону или по внутренней политике, — {operator} обязана обеспечить его соблюдение непосредственно в базе данных.",
          "Поскольку все данные находятся в базе, которой управляет {operator}, {operator} может удалить любые из них в любой момент.",
        ],
      },
      {
        heading: "5. Кто может видеть ваши данные",
        body: [
          "Люди, которым {operator} выдала учётные записи в этой установке, — в объёме назначенной каждому роли.",
          "Любой, кто имеет административный доступ к серверу или к его базе данных, что зависит от того, как {operator} защищает эту машину.",
          "Разработчик — не может. Служба поддержки может попросить {operator} прислать логи или снимки экрана для диагностики проблемы, и всё переданное таким образом передаётся потому, что {operator} приняла такое решение.",
        ],
      },
      {
        heading: "6. Безопасность",
        body: [
          "Пароли хешируются алгоритмом bcrypt. Токены сессий хранятся в хешированном виде, а повторное использование старого токена отзывает всё семейство сессий. Доступна двухфакторная аутентификация, и коды невозможно использовать повторно.",
          "Эти меры защищают программу. Они не могут защитить сервер, который остаётся без обновлений, без шифрования или доступен из интернета без HTTPS, — это зона ответственности организации {operator}, и руководство по эксплуатации, поставляемое с Legion, описывает, что в неё входит.",
        ],
      },
      {
        heading: "7. Ваши права",
        body: [
          "Запросы на доступ, исправление, экспорт или удаление ваших данных направляются организации {operator}, которая хранит эти данные и является единственной стороной, способной выполнить такой запрос.",
          "Компания-разработчик Legion не может ответить на такие запросы — не в силу политики, а фактически: у неё нет копии данных и нет доступа к этой системе.",
        ],
      },
      {
        heading: "8. Изменения",
        body: [
          "{operator} может обновить настоящую политику. Дата вступления в силу выше показывает, когда была опубликована та версия, которую вы читаете.",
        ],
      },
    ],
  },
  uz: {
    title: "Maxfiylik siyosati",
    effectiveDate: "2026-yil 25-avgust",
    intro:
      "Ushbu Legion o'rnatmasini {operator} o'zi boshqaradigan infratuzilmada ishlatadi. Legion — bu {operator} o'rnatgan dastur; Legion'ni ishlab chiqaradigan kompaniya bu tizimni boshqarmaydi, unga kira olmaydi va undan hech qanday ma'lumot olmaydi. Ushbu siyosat bu o'rnatma nimalarni saqlashini, bu ma'lumotlar qayerga borishini va ular haqida kimga murojaat qilish kerakligini tushuntiradi.",
    sections: [
      {
        heading: "1. Bu o'rnatma nimani saqlaydi",
        body: [
          "Hisob yozuvlari: ismingiz, ish elektron pochtangiz, rolingiz va parolingiz — parol faqat bcrypt xesh ko'rinishida saqlanadi, hech qachon o'qib bo'ladigan matn sifatida emas.",
          "Ikki bosqichli tasdiqlash yoqilgan bo'lsa: autentifikator ilovangiz ishlatadigan maxfiy kalit va tiklash kodlari — ular ham xeshlangan holda saqlanadi.",
          "Sessiya yozuvlari: har bir faol kirish uchun u boshlangan IP manzil va brauzer user-agent'i hamda tugash vaqti. Aynan shu sizga o'z sessiyalaringizni ko'rish va bekor qilish imkonini beradi.",
          "Audit jurnali: kim, qachon va qaysi IP manzildan qanday ma'muriy amal bajargani.",
          "O'z tizimlaringizdan keladigan xavfsizlik ma'lumotlari: ogohlantirishlar, manba IP manzillari, host nomlari va ular asosida tuzilgan aktivlar ro'yxati. Legion aynan shuni tahlil qilish uchun mavjud va uning tarkibi tizimlaringiz nima yuborishiga bog'liq.",
        ],
      },
      {
        heading: "2. Bu ma'lumotlar qayerga boradi",
        body: [
          "Shu serverdagi PostgreSQL ma'lumotlar bazasiga — va boshqa hech qayerga. Legion'da analitika ham, telemetriya ham, foydalanish hisoboti ham, avtomatik yangilanish tekshiruvi ham yo'q. U ishlab chiqaruvchisiga hech qachon tarmoq ulanishi qilmaydi, ya'ni ma'lumotlaringiz unga yetib boradigan kanalning o'zi mavjud emas.",
          "Ma'lumot bu serverdan chiqishi mumkin bo'lgan aniq ikkita yo'l bor va ularning har birini yoqish yoki yoqmaslikni {operator} hal qiladi. Sozlanmagunicha ikkalasi ham o'chiq.",
          "Ixtiyoriy AI tahlili: {operator} tashqi AI xizmati uchun API kalit berishi mumkin — Legion OpenRouter va Groq'ni qo'llab-quvvatlaydi — u holda ogohlantirish matni tahlil uchun o'sha xizmatga yuboriladi va natija shu yerda saqlanadi. Kalit belgilanmagan bo'lsa, bunday so'rov umuman yuborilmaydi; standart holat aynan shunday. Bu yoqilgan joyda o'sha xizmat ogohlantirish matnidagi hamma narsaning qayta ishlovchisiga aylanadi, va qaysi xizmat ishlatilayotganini {operator} sizga ayta oladi. Legion unga faqat ogohlantirish matnini yuboradi — bu o'rnatmaning manzilini ham, tizimga kim kirganini ham emas.",
          "Ixtiyoriy elektron pochta xabarnomasi: agar {operator} chiquvchi pochta serverini sozlasa, ogohlantirish xabarnomalari o'sha server orqali yetkaziladi — uni ishlab chiqaruvchi emas, {operator} tanlaydi.",
        ],
      },
      {
        heading: "3. Cookie fayllari",
        body: [
          "Bu o'rnatma uchta cookie o'rnatadi, hammasi birinchi tomon cookie'lari va hammasi tizimda qolishingiz uchun zarur: legion_token (joriy sessiyangiz), legion_refresh (parolni qayta so'ramasdan uni yangilaydi) va legion_session (panel sessiya borligini bilishi uchun belgi).",
          "Bu yerda reklama cookie'lari ham, analitika cookie'lari ham, uchinchi tomon cookie'lari ham yo'q. Hech narsa sizni boshqa saytlarda kuzatmaydi.",
        ],
      },
      {
        heading: "4. Ma'lumotlar qancha saqlanadi",
        body: [
          "Sessiyalar o'zi tugaydi va muddati o'tganlari tozalab tashlanadi.",
          "Ogohlantirishlar, aktivlar va audit jurnali muddatsiz saqlanadi — bu dastur ularni jadval bo'yicha o'chirmaydi. Agar {operator} uchun qonun yoki ichki siyosat bo'yicha saqlash muddati qo'llanilsa, uni bevosita ma'lumotlar bazasida ta'minlash {operator} zimmasida.",
          "Barcha ma'lumot {operator} boshqaradigan bazada turgani uchun, {operator} ularning istalganini istalgan vaqtda o'chira oladi.",
        ],
      },
      {
        heading: "5. Ma'lumotlaringizni kim ko'ra oladi",
        body: [
          "{operator} bu o'rnatmada hisob ochib bergan odamlar — har biriga berilgan rol doirasida.",
          "Serverga yoki uning ma'lumotlar bazasiga ma'muriy huquqi bo'lgan har qanday shaxs; bu {operator} o'sha mashinani qanday himoyalashiga bog'liq.",
          "Ishlab chiqaruvchi — ko'ra olmaydi. Qo'llab-quvvatlash xizmati muammoni aniqlash uchun {operator}dan loglar yoki ekran rasmlarini so'rashi mumkin, va shu tarzda berilgan narsa {operator} shunday qaror qilgani uchun beriladi.",
        ],
      },
      {
        heading: "6. Xavfsizlik",
        body: [
          "Parollar bcrypt bilan xeshlanadi. Sessiya tokenlari xeshlangan holda saqlanadi va eskisini qayta ishlatish butun sessiya oilasini bekor qiladi. Ikki bosqichli tasdiqlash mavjud va kodlarni qayta ishlatib bo'lmaydi.",
          "Bu choralar dasturni himoya qiladi. Ular yangilanmagan, shifrlanmagan yoki internetdan HTTPS'siz ochiq turgan serverni himoya qila olmaydi — bu {operator} zimmasidagi qism, va Legion bilan birga keladigan ekspluatatsiya qo'llanmasi bunga nimalar kirishini bayon qiladi.",
        ],
      },
      {
        heading: "7. Sizning huquqlaringiz",
        body: [
          "Ma'lumotlaringizni ko'rish, tuzatish, eksport qilish yoki o'chirish so'rovlari {operator}ga yuboriladi — ma'lumotni u saqlaydi va bunday so'rovni bajara oladigan yagona tomon ham u.",
          "Legion'ni ishlab chiqaradigan kompaniya bu so'rovlarga javob bera olmaydi — siyosat sababli emas, balki aslida shunday: unda ma'lumotlarning nusxasi ham, bu tizimga kirish huquqi ham yo'q.",
        ],
      },
      {
        heading: "8. O'zgarishlar",
        body: [
          "{operator} ushbu siyosatni yangilashi mumkin. Yuqoridagi kuchga kirish sanasi siz o'qiyotgan versiya qachon chop etilganini ko'rsatadi.",
        ],
      },
    ],
  },
};
