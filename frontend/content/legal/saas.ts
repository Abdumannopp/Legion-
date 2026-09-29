import { LegalDoc } from "./privacy";
import type { Locale } from "@/lib/i18n/core";
import { DATA_LOCATION } from "@/lib/site";

/**
 * Legal pages for the HOSTED service (NEXT_PUBLIC_DEPLOYMENT_MODE=saas), where
 * {operator} is the seller — the company or sole proprietor who runs Legion
 * for paying customers — and Paddle.com is the Merchant of Record.
 *
 * These are a starting point written to match what the software actually
 * does. They are not legal advice: have them reviewed before relying on them.
 * English is the binding text (Paddle reviews it in English). The Russian and
 * Uzbek versions are convenience translations, and each says in its intro
 * that the English version prevails if they differ — keep them in step with
 * the English whenever it changes.
 *
 * {operator}, {supportEmail} and {dataLocation} are filled in at render time.
 */
const EFFECTIVE = "September 28, 2026";
const EFFECTIVE_RU = "28 сентября 2026 г.";
const EFFECTIVE_UZ = "2026-yil 28-sentabr";

export const saasTerms: Record<Locale, LegalDoc> = {
  en: {
    title: "Terms of Service",
    effectiveDate: EFFECTIVE,
    intro:
      "These terms are an agreement between you (the organisation that signs up, and the person accepting on its behalf) and {operator} (\"we\", \"us\"), who provides the Legion security operations service at this website. By creating an account or using the service you accept them.",
    sections: [
      {
        heading: "1. The Service",
        body: [
          "Legion is a hosted security operations console. It receives security alerts from systems you connect (such as a Wazuh manager), stores them in your workspace, explains them, and helps your team track them to resolution.",
          "The service is intended for businesses and professionals, not consumers. You must be at least 18 and able to bind the organisation you sign up for.",
        ],
      },
      {
        heading: "2. Accounts",
        body: [
          "You are responsible for everything done under your workspace's accounts. Keep passwords and two-factor devices private, give each person their own account, and remove people who leave.",
          "Tell us promptly at {supportEmail} if you believe an account has been compromised.",
        ],
      },
      {
        heading: "3. Acceptable Use",
        body: [
          "Connect only systems you own or are authorised to monitor, and send only data you are allowed to process.",
          "Do not use the service to break the law, to attack or probe systems you are not authorised to test, to try to access another customer's workspace, to overload the service, or to resell it without our written agreement.",
          "We may suspend accounts that put the service or other customers at risk. Where possible we will tell you first and give you a chance to fix the problem.",
        ],
      },
      {
        heading: "4. Free Trial",
        body: [
          "New workspaces get a free trial (the length is shown when you sign up). No payment details are needed for the trial. When it ends, the workspace is locked until you subscribe; your data is kept so you can continue where you left off.",
        ],
      },
      {
        heading: "5. Subscriptions, Payment and Our Reseller",
        body: [
          "Our order process is conducted by our online reseller Paddle.com. Paddle.com is the Merchant of Record for all our orders. Paddle provides all customer service inquiries and handles returns.",
          "Subscriptions renew automatically at the end of each billing period at the then-current price until cancelled. Prices, currency and applicable taxes are shown at checkout. We will give at least 30 days' notice of a price increase for existing subscriptions.",
          "You can cancel at any time from Billing → Manage subscription. Cancellation takes effect at the end of the current paid period; you keep access until then.",
          "If a payment fails, the workspace becomes read-only until it is settled, and is locked if the subscription ends. Refunds are described in our Refund Policy.",
        ],
      },
      {
        heading: "6. Your Data",
        body: [
          "Everything you and your systems put into your workspace remains yours. You give us permission to store and process it only to provide, secure and support the service for you.",
          "We do not sell your data or use it to advertise to anyone. How we handle it is described in our Privacy Policy.",
          "Each customer's data is kept in its own workspace, and our staff access it only when needed to operate the service, to resolve a support request you make, or when the law requires it.",
        ],
      },
      {
        heading: "7. AI Features",
        body: [
          "Explanations, suggested next steps and other AI-assisted output are aids to your judgement, not verified findings. They can be wrong or incomplete. Check them before acting, particularly before disruptive actions such as isolating a system.",
        ],
      },
      {
        heading: "8. Availability and Changes",
        body: [
          "We work to keep the service available and secure, but we do not guarantee uninterrupted or error-free operation, and the service does not replace your own security controls, backups or incident response obligations.",
          "We may improve or change features. If we make a change that materially reduces what you pay for, we will tell you in advance, and you may cancel.",
        ],
      },
      {
        heading: "9. Ending the Agreement",
        body: [
          "You may stop using the service and cancel at any time. We may end the agreement on 30 days' notice, or immediately for serious or repeated breach of these terms.",
          "After your subscription ends your workspace is locked, not erased. Ask us at {supportEmail} to delete it and we will do so within 30 days, except where the law requires us to keep something.",
        ],
      },
      {
        heading: "10. Liability",
        body: [
          "The service is provided \"as is\" to the extent the law allows. We are not liable for indirect or consequential losses, lost profits or lost data that proper backups would have preserved.",
          "Our total liability for any claim is limited to the amount you paid for the service in the 12 months before the claim arose. Nothing in these terms limits liability that cannot be limited by law.",
        ],
      },
      {
        heading: "11. Changes to These Terms, and Law",
        body: [
          "We may update these terms. For material changes we will notify workspace administrators by email at least 30 days before they take effect.",
          "These terms are governed by the laws of the Republic of Uzbekistan, without prejudice to mandatory rights you have under the law of your own country.",
        ],
      },
    ],
  },
  ru: {
    title: "Условия использования",
    effectiveDate: EFFECTIVE_RU,
    intro:
      "Настоящие условия являются соглашением между вами (организацией, которая регистрируется, и лицом, принимающим их от её имени) и {operator} («мы», «нас») — лицом, предоставляющим на этом сайте сервис Legion для операций информационной безопасности. Создавая аккаунт или пользуясь сервисом, вы принимаете настоящие условия. Это перевод для удобства; при расхождениях преимущественную силу имеет английская версия.",
    sections: [
      {
        heading: "1. Сервис",
        body: [
          "Legion — это размещаемая нами (облачная) консоль для операций информационной безопасности. Она получает оповещения безопасности от подключённых вами систем (например, от менеджера Wazuh), хранит их в вашем рабочем пространстве, объясняет их и помогает вашей команде отслеживать их до устранения.",
          "Сервис предназначен для организаций и специалистов, а не для потребителей. Вам должно быть не менее 18 лет, и вы должны иметь полномочия принимать обязательства от имени организации, которую регистрируете.",
        ],
      },
      {
        heading: "2. Аккаунты",
        body: [
          "Вы несёте ответственность за всё, что совершается с использованием аккаунтов вашего рабочего пространства. Не раскрывайте пароли и не передавайте устройства двухфакторной аутентификации, создавайте для каждого человека собственный аккаунт и удаляйте аккаунты тех, кто уходит.",
          "Незамедлительно сообщите нам по адресу {supportEmail}, если считаете, что аккаунт скомпрометирован.",
        ],
      },
      {
        heading: "3. Допустимое использование",
        body: [
          "Подключайте только те системы, которые принадлежат вам или мониторинг которых вам разрешён, и отправляйте только те данные, обработка которых вам разрешена.",
          "Не используйте сервис для нарушения закона, для атак на системы или их зондирования без полномочий на их тестирование, для попыток доступа к рабочему пространству другого клиента, для перегрузки сервиса или для его перепродажи без нашего письменного согласия.",
          "Мы можем приостановить аккаунты, которые создают риск для сервиса или других клиентов. По возможности мы сначала уведомим вас и дадим возможность устранить проблему.",
        ],
      },
      {
        heading: "4. Пробный период",
        body: [
          "Новые рабочие пространства получают бесплатный пробный период (его продолжительность указывается при регистрации). Для пробного периода платёжные данные не требуются. По его окончании рабочее пространство блокируется до оформления подписки; ваши данные сохраняются, чтобы вы могли продолжить с того места, где остановились.",
        ],
      },
      {
        heading: "5. Подписки, оплата и наш реселлер",
        body: [
          "Процесс оформления заказов осуществляет наш онлайн-реселлер Paddle.com. Paddle.com является официальным продавцом (Merchant of Record) по всем нашим заказам. Paddle отвечает на все обращения клиентов в службу поддержки и обрабатывает возвраты.",
          "Подписки автоматически продлеваются в конце каждого расчётного периода по действующей на тот момент цене, пока не будут отменены. Цены, валюта и применимые налоги указываются при оформлении заказа. О повышении цены для действующих подписок мы уведомляем не менее чем за 30 дней.",
          "Вы можете отменить подписку в любое время в разделе «Оплата → Управлять подпиской». Отмена вступает в силу в конце текущего оплаченного периода; до этого момента доступ сохраняется.",
          "Если платёж не прошёл, рабочее пространство переходит в режим только для чтения до погашения задолженности и блокируется, если подписка прекращается. Порядок возврата средств описан в нашей Политике возврата средств.",
        ],
      },
      {
        heading: "6. Ваши данные",
        body: [
          "Всё, что вы и ваши системы помещаете в рабочее пространство, остаётся вашим. Вы разрешаете нам хранить и обрабатывать эти данные только для того, чтобы предоставлять вам сервис, обеспечивать его безопасность и оказывать поддержку.",
          "Мы не продаём ваши данные и не используем их для показа рекламы кому-либо. То, как мы с ними обращаемся, описано в нашей Политике конфиденциальности.",
          "Данные каждого клиента хранятся в его собственном рабочем пространстве, и наши сотрудники получают к ним доступ только тогда, когда это необходимо для работы сервиса, для решения вашего запроса в поддержку или когда этого требует закон.",
        ],
      },
      {
        heading: "7. Функции ИИ",
        body: [
          "Объяснения, предлагаемые следующие шаги и другие результаты, полученные с помощью ИИ, служат подспорьем для вашего собственного суждения, а не проверенными выводами. Они могут быть ошибочными или неполными. Проверяйте их, прежде чем действовать, особенно перед действиями, способными нарушить работу, например перед изоляцией системы.",
        ],
      },
      {
        heading: "8. Доступность и изменения",
        body: [
          "Мы стремимся поддерживать доступность и безопасность сервиса, но не гарантируем его бесперебойную или безошибочную работу; сервис не заменяет ваши собственные средства защиты, резервные копии или обязательства по реагированию на инциденты.",
          "Мы можем улучшать или изменять функции. Если мы внесём изменение, которое существенно сократит то, за что вы платите, мы заранее сообщим вам об этом, и вы сможете отменить подписку.",
        ],
      },
      {
        heading: "9. Прекращение соглашения",
        body: [
          "Вы можете прекратить пользоваться сервисом и отменить подписку в любое время. Мы можем расторгнуть соглашение, уведомив вас за 30 дней, или немедленно — в случае серьёзного или повторного нарушения настоящих условий.",
          "После окончания подписки ваше рабочее пространство блокируется, но не удаляется. Чтобы удалить его, напишите нам на {supportEmail}, и мы сделаем это в течение 30 дней, за исключением случаев, когда закон обязывает нас что-либо сохранить.",
        ],
      },
      {
        heading: "10. Ответственность",
        body: [
          "В пределах, допускаемых законом, сервис предоставляется «как есть». Мы не несём ответственности за косвенные или последующие убытки, упущенную выгоду или утрату данных, которые были бы сохранены при надлежащем резервном копировании.",
          "Наша совокупная ответственность по любому требованию ограничена суммой, которую вы заплатили за сервис за 12 месяцев до возникновения требования. Ничто в настоящих условиях не ограничивает ответственность, которая не может быть ограничена по закону.",
        ],
      },
      {
        heading: "11. Изменение условий и применимое право",
        body: [
          "Мы можем обновлять настоящие условия. О существенных изменениях мы уведомим администраторов рабочих пространств по электронной почте не менее чем за 30 дней до их вступления в силу.",
          "Настоящие условия регулируются законодательством Республики Узбекистан без ущерба для обязательных прав, которые предоставляет вам законодательство вашей страны.",
        ],
      },
    ],
  },
  uz: {
    title: "Foydalanish shartlari",
    effectiveDate: EFFECTIVE_UZ,
    intro:
      "Ushbu shartlar siz (ro'yxatdan o'tayotgan tashkilot va uning nomidan shartlarni qabul qilayotgan shaxs) bilan ushbu veb-saytda Legion xavfsizlik operatsiyalari xizmatini taqdim etuvchi {operator} («biz») o'rtasidagi kelishuvdir. Hisob yaratish yoki xizmatdan foydalanish orqali siz ushbu shartlarni qabul qilasiz. Bu qulaylik uchun berilgan tarjima; matnlar o'rtasida tafovut bo'lsa, ingliz tilidagi matn ustun turadi.",
    sections: [
      {
        heading: "1. Xizmat",
        body: [
          "Legion — biz joylashtiradigan (bulutli) xavfsizlik operatsiyalari konsoli. U siz ulagan tizimlardan (masalan, Wazuh menejeridan) xavfsizlik ogohlantirishlarini qabul qiladi, ularni ish maydoningizda saqlaydi, tushuntiradi va jamoangizga ularni hal bo'lgunicha kuzatib borishda yordam beradi.",
          "Xizmat iste'molchilar uchun emas, balki biznes va mutaxassislar uchun mo'ljallangan. Yoshingiz kamida 18 da bo'lishi va ro'yxatdan o'tkazayotgan tashkilotingiz nomidan majburiyat olish vakolatiga ega bo'lishingiz kerak.",
        ],
      },
      {
        heading: "2. Hisoblar",
        body: [
          "Ish maydoningiz hisoblari orqali qilingan barcha harakatlar uchun siz javobgarsiz. Parollar va ikki bosqichli autentifikatsiya qurilmalarini boshqalarga bermang, har bir kishiga alohida hisob bering va ketgan xodimlarning hisoblarini o'chirib tashlang.",
          "Agar biror hisob buzilgan (begona qo'lga o'tgan) deb hisoblasangiz, darhol {supportEmail} manziliga xabar bering.",
        ],
      },
      {
        heading: "3. Ruxsat etilgan foydalanish",
        body: [
          "Faqat o'zingizga tegishli yoki monitoring qilishga vakolatingiz bo'lgan tizimlarni ulang va faqat qayta ishlashga ruxsatingiz bor ma'lumotlarni yuboring.",
          "Xizmatdan qonunni buzish, sinovdan o'tkazishga vakolatingiz bo'lmagan tizimlarga hujum qilish yoki ularni skanerlash, boshqa mijozning ish maydoniga kirishga urinish, xizmatni haddan tashqari yuklash yoki bizning yozma roziligimizsiz uni qayta sotish uchun foydalanmang.",
          "Xizmat yoki boshqa mijozlar uchun xavf tug'diradigan hisoblarni to'xtatib qo'yishimiz mumkin. Imkon qadar avval sizga xabar beramiz va muammoni tuzatish imkoniyatini beramiz.",
        ],
      },
      {
        heading: "4. Bepul sinov muddati",
        body: [
          "Yangi ish maydonlariga bepul sinov muddati beriladi (uning davomiyligi ro'yxatdan o'tishda ko'rsatiladi). Sinov muddati uchun to'lov ma'lumotlari talab qilinmaydi. U tugagach, obuna bo'lmaguningizcha ish maydoni bloklanadi; ma'lumotlaringiz saqlanadi, shuning uchun to'xtagan joyingizdan davom ettirishingiz mumkin.",
        ],
      },
      {
        heading: "5. Obunalar, to'lov va qayta sotuvchimiz",
        body: [
          "Buyurtma jarayonini onlayn qayta sotuvchimiz Paddle.com amalga oshiradi. Paddle.com barcha buyurtmalarimiz bo'yicha rasmiy sotuvchi (Merchant of Record) hisoblanadi. Mijozlarning barcha murojaatlariga Paddle xizmat ko'rsatadi va pulni qaytarish masalalarini ham Paddle hal qiladi.",
          "Obunalar bekor qilinmaguncha har bir hisob-kitob davri oxirida o'sha paytda amalda bo'lgan narx bo'yicha avtomatik ravishda yangilanadi. Narxlar, valyuta va tegishli soliqlar to'lov sahifasida ko'rsatiladi. Mavjud obunalar narxi oshirilishi haqida kamida 30 kun oldin xabar beramiz.",
          "Obunani istalgan vaqtda To'lovlar → Obunani boshqarish bo'limidan bekor qilishingiz mumkin. Bekor qilish joriy to'langan davr oxirida kuchga kiradi; shu vaqtgacha kirish huquqingiz saqlanib qoladi.",
          "Agar to'lov o'tmasa, qarz to'lanmaguncha ish maydoni faqat o'qish rejimiga o'tadi, obuna tugasa esa bloklanadi. Pulni qaytarish tartibi Pulni qaytarish siyosatimizda bayon qilingan.",
        ],
      },
      {
        heading: "6. Sizning ma'lumotlaringiz",
        body: [
          "Siz va tizimlaringiz ish maydoningizga kiritgan hamma narsa sizniki bo'lib qoladi. Siz bizga ularni faqat sizga xizmatni taqdim etish, uni himoyalash va qo'llab-quvvatlash maqsadida saqlash va qayta ishlashga ruxsat berasiz.",
          "Biz ma'lumotlaringizni sotmaymiz va ulardan hech kimga reklama ko'rsatish uchun foydalanmaymiz. Ular bilan qanday ishlashimiz Maxfiylik siyosatimizda bayon qilingan.",
          "Har bir mijozning ma'lumotlari uning alohida ish maydonida saqlanadi va xodimlarimiz ularga faqat xizmatning ishlashi uchun, siz yuborgan qo'llab-quvvatlash so'rovini hal qilish uchun zarur bo'lganda yoki qonun talab qilganda kiradi.",
        ],
      },
      {
        heading: "7. AI funksiyalari",
        body: [
          "Tushuntirishlar, tavsiya etilgan keyingi qadamlar va AI yordamida yaratilgan boshqa natijalar tasdiqlangan xulosalar emas, balki o'z mulohazangiz uchun yordamchi vositadir. Ular noto'g'ri yoki to'liq bo'lmasligi mumkin. Harakat qilishdan oldin, ayniqsa tizimni izolyatsiya qilish kabi ish jarayonini buzishi mumkin bo'lgan harakatlardan oldin ularni tekshiring.",
        ],
      },
      {
        heading: "8. Mavjudlik va o'zgarishlar",
        body: [
          "Biz xizmatning barqaror ishlashi va xavfsizligini ta'minlashga harakat qilamiz, lekin uning uzluksiz yoki xatosiz ishlashini kafolatlamaymiz; xizmat sizning o'z xavfsizlik vositalaringiz, zaxira nusxalaringiz yoki hodisalarga javob berish bo'yicha majburiyatlaringiz o'rnini bosmaydi.",
          "Biz funksiyalarni yaxshilashimiz yoki o'zgartirishimiz mumkin. Agar siz to'layotgan imkoniyatlarni sezilarli darajada qisqartiradigan o'zgarish kiritsak, bu haqda oldindan xabar beramiz va siz obunani bekor qilishingiz mumkin.",
        ],
      },
      {
        heading: "9. Kelishuvni tugatish",
        body: [
          "Siz xizmatdan foydalanishni istalgan vaqtda to'xtatib, obunani bekor qilishingiz mumkin. Biz kelishuvni 30 kun oldin ogohlantirib yoki ushbu shartlar jiddiy yoki takroran buzilgan taqdirda darhol tugatishimiz mumkin.",
          "Obunangiz tugagach, ish maydoningiz o'chirilmaydi, balki bloklanadi. Uni o'chirishni {supportEmail} manzili orqali so'rang — qonun biror narsani saqlashni talab qiladigan hollardan tashqari, biz buni 30 kun ichida bajaramiz.",
        ],
      },
      {
        heading: "10. Javobgarlik",
        body: [
          "Qonun ruxsat bergan darajada xizmat «qanday bo'lsa, shundayligicha» taqdim etiladi. Biz bilvosita yoki oqibatda yuzaga kelgan zararlar, boy berilgan foyda yoki to'g'ri zaxira nusxalash orqali saqlab qolinishi mumkin bo'lgan ma'lumotlar yo'qolishi uchun javobgar emasmiz.",
          "Har qanday da'vo bo'yicha umumiy javobgarligimiz da'vo yuzaga kelishidan oldingi 12 oy ichida xizmat uchun to'lagan summangiz bilan cheklanadi. Ushbu shartlardagi hech narsa qonunga ko'ra cheklab bo'lmaydigan javobgarlikni cheklamaydi.",
        ],
      },
      {
        heading: "11. Shartlarning o'zgarishi va qo'llaniladigan huquq",
        body: [
          "Biz ushbu shartlarni yangilashimiz mumkin. Muhim o'zgarishlar haqida ish maydoni administratorlariga ular kuchga kirishidan kamida 30 kun oldin elektron pochta orqali xabar beramiz.",
          "Ushbu shartlar O'zbekiston Respublikasi qonunchiligi bilan tartibga solinadi; bu o'z mamlakatingiz qonunchiligi bo'yicha sizga tegishli majburiy huquqlarga zarar yetkazmaydi.",
        ],
      },
    ],
  },
};

export const saasPrivacy: Record<Locale, LegalDoc> = {
  en: {
    title: "Privacy Policy",
    effectiveDate: EFFECTIVE,
    intro:
      "This policy explains what personal data {operator} (\"we\") processes when you use the Legion service, why, who helps us, and the choices you have. For the security data your systems send into your workspace, your organisation decides what is collected; we process it on your organisation's behalf.",
    sections: [
      {
        heading: "1. What We Store",
        body: [
          "Account data: your email address, the name of your organisation, your role, and your password — stored only as a bcrypt hash, never in readable form. If you turn on two-factor sign-in, the shared secret and hashed recovery codes.",
          "Session and security records: for each sign-in, the IP address and browser user-agent it came from; and an audit log of administrative actions (who, what, when, from which IP address).",
          "Workspace data: the alerts, IP addresses, hostnames and asset details your connected systems send. This can include personal data about people on your network; your organisation controls it.",
          "Billing status: whether your subscription is active, and the customer and subscription identifiers Paddle gives us. We never see or store your card details — Paddle does.",
          "Support messages you send us.",
        ],
      },
      {
        heading: "2. Why",
        body: [
          "To provide the service you signed up for (contract), to keep it and your account secure and prevent abuse (legitimate interest), to bill you through our reseller (contract), and to meet legal obligations such as tax records (legal obligation).",
          "We do not sell personal data, do not use your workspace data to train AI models, and do not use advertising or analytics trackers on the service.",
        ],
      },
      {
        heading: "3. Who Helps Us",
        body: [
          "Paddle.com — our reseller and Merchant of Record. When you buy, you give your billing details to Paddle, and Paddle's own privacy policy applies to them.",
          "Our hosting provider, which runs the servers your workspace is stored on, located in {dataLocation}.",
          "Our email delivery provider, which sends account emails (confirmation, password reset, invitations) and the alert notifications you enable. It receives the recipient address and the message content.",
          "An AI provider, only when AI analysis is switched on for the service: alert titles, descriptions, hostnames and IP addresses are then sent to it to produce explanations. When it is off, explanations are generated on our own servers and nothing is sent.",
          "Each of these processes data only to provide its part of the service.",
        ],
      },
      {
        heading: "4. Cookies",
        body: [
          "We use only the cookies needed to keep you signed in and to protect your session. The checkout and billing pages load Paddle's payment script, which may set its own cookies needed to process payments.",
        ],
      },
      {
        heading: "5. How Long We Keep It",
        body: [
          "Account and workspace data are kept while your account exists. After a subscription ends the workspace is locked but kept, so you can return; ask us to delete it and we will do so within 30 days. Deleted data can remain in backups for up to 14 days before those backups expire.",
          "Billing and tax records are kept by Paddle and by us for as long as the law requires.",
        ],
      },
      {
        heading: "6. Security",
        body: [
          "Connections are encrypted (HTTPS). Passwords and recovery codes are stored only as hashes, two-factor sign-in is available to every user, each customer's data is isolated in its own workspace, and administrative actions are recorded in an audit log.",
          "If a breach affecting your personal data occurs, we will notify affected workspace administrators without undue delay.",
        ],
      },
      {
        heading: "7. Your Rights",
        body: [
          "You can ask to access, correct, export or delete your personal data, or object to how it is used, by writing to {supportEmail}. For data inside a workspace, we will act on the instructions of that workspace's administrators.",
          "You also have the right to complain to your local data-protection authority.",
        ],
      },
      {
        heading: "8. Changes",
        body: [
          "If we change this policy materially, we will tell workspace administrators by email before the change takes effect.",
        ],
      },
    ],
  },
  ru: {
    title: "Политика конфиденциальности",
    effectiveDate: EFFECTIVE_RU,
    intro:
      "Настоящая политика объясняет, какие персональные данные {operator} («мы») обрабатывает, когда вы пользуетесь сервисом Legion, с какой целью, кто нам в этом помогает и какой у вас есть выбор. Что касается данных безопасности, которые ваши системы отправляют в ваше рабочее пространство, то решение о том, что собирается, принимает ваша организация; мы обрабатываем эти данные от её имени. Это перевод для удобства; при расхождениях преимущественную силу имеет английская версия.",
    sections: [
      {
        heading: "1. Что мы храним",
        body: [
          "Данные аккаунта: ваш адрес электронной почты, название вашей организации, ваша роль и пароль — он хранится только в виде bcrypt-хеша и никогда в читаемом виде. Если вы включите двухфакторный вход — общий секрет и хешированные коды восстановления.",
          "Записи о сеансах и безопасности: для каждого входа — IP-адрес и user-agent браузера, с которых он был выполнен; а также журнал аудита административных действий (кто, что, когда и с какого IP-адреса).",
          "Данные рабочего пространства: оповещения, IP-адреса, имена хостов и сведения об активах, которые присылают подключённые вами системы. Они могут включать персональные данные людей в вашей сети; их контролирует ваша организация.",
          "Статус оплаты: активна ли ваша подписка, а также идентификаторы клиента и подписки, которые передаёт нам Paddle. Мы никогда не видим и не храним данные вашей карты — это делает Paddle.",
          "Сообщения, которые вы отправляете в нашу поддержку.",
        ],
      },
      {
        heading: "2. Зачем",
        body: [
          "Чтобы предоставлять сервис, на который вы подписались (исполнение договора); чтобы обеспечивать безопасность сервиса и вашего аккаунта и предотвращать злоупотребления (законный интерес); чтобы выставлять вам счета через нашего реселлера (исполнение договора); и чтобы выполнять требования закона, например по ведению налоговой отчётности (юридическая обязанность).",
          "Мы не продаём персональные данные, не используем данные вашего рабочего пространства для обучения моделей ИИ и не используем в сервисе рекламные или аналитические трекеры.",
        ],
      },
      {
        heading: "3. Кто нам помогает",
        body: [
          "Paddle.com — наш реселлер и официальный продавец (Merchant of Record). При покупке вы передаёте свои платёжные данные Paddle, и к ним применяется собственная политика конфиденциальности Paddle.",
          "Наш хостинг-провайдер, обслуживающий серверы, на которых хранится ваше рабочее пространство. Местоположение серверов: {dataLocation}.",
          "Наш провайдер доставки электронной почты, который отправляет письма, связанные с аккаунтом (подтверждение, сброс пароля, приглашения), и включённые вами уведомления об оповещениях. Он получает адрес получателя и содержание письма.",
          "Провайдер ИИ — только если для сервиса включён ИИ-анализ: в этом случае ему передаются заголовки и описания оповещений, имена хостов и IP-адреса для подготовки объяснений. Если ИИ-анализ выключен, объяснения формируются на наших собственных серверах и никакие данные никуда не передаются.",
          "Каждый из них обрабатывает данные только для того, чтобы обеспечить свою часть сервиса.",
        ],
      },
      {
        heading: "4. Файлы cookie",
        body: [
          "Мы используем только те файлы cookie, которые необходимы для поддержания входа в систему и защиты вашего сеанса. Страницы оформления заказа и оплаты загружают платёжный скрипт Paddle, который может устанавливать собственные файлы cookie, необходимые для обработки платежей.",
        ],
      },
      {
        heading: "5. Сколько мы храним данные",
        body: [
          "Данные аккаунта и рабочего пространства хранятся, пока существует ваш аккаунт. После окончания подписки рабочее пространство блокируется, но сохраняется, чтобы вы могли вернуться; попросите нас удалить его, и мы сделаем это в течение 30 дней. Удалённые данные могут оставаться в резервных копиях до 14 дней, пока срок хранения этих копий не истечёт.",
          "Платёжные и налоговые записи хранятся у Paddle и у нас столько, сколько требует закон.",
        ],
      },
      {
        heading: "6. Безопасность",
        body: [
          "Соединения шифруются (HTTPS). Пароли и коды восстановления хранятся только в виде хешей, двухфакторный вход доступен каждому пользователю, данные каждого клиента изолированы в его собственном рабочем пространстве, а административные действия записываются в журнал аудита.",
          "В случае утечки, затрагивающей ваши персональные данные, мы без неоправданной задержки уведомим администраторов затронутых рабочих пространств.",
        ],
      },
      {
        heading: "7. Ваши права",
        body: [
          "Вы можете запросить доступ к своим персональным данным, их исправление, экспорт или удаление, а также возразить против того, как они используются, написав на {supportEmail}. В отношении данных внутри рабочего пространства мы действуем по указаниям администраторов этого рабочего пространства.",
          "Вы также вправе подать жалобу в орган по защите персональных данных вашей страны.",
        ],
      },
      {
        heading: "8. Изменения",
        body: [
          "Если мы существенно изменим настоящую политику, мы сообщим об этом администраторам рабочих пространств по электронной почте до вступления изменений в силу.",
        ],
      },
    ],
  },
  uz: {
    title: "Maxfiylik siyosati",
    effectiveDate: EFFECTIVE_UZ,
    intro:
      "Ushbu siyosat Legion xizmatidan foydalanganingizda {operator} («biz») qanday shaxsga doir ma'lumotlarni qayta ishlashini, nima maqsadda, bunda bizga kim yordam berishini va sizda qanday tanlov imkoniyatlari borligini tushuntiradi. Tizimlaringiz ish maydoningizga yuboradigan xavfsizlik ma'lumotlariga kelsak, nima yig'ilishini tashkilotingiz hal qiladi; biz bu ma'lumotlarni tashkilotingiz nomidan qayta ishlaymiz. Bu qulaylik uchun berilgan tarjima; matnlar o'rtasida tafovut bo'lsa, ingliz tilidagi matn ustun turadi.",
    sections: [
      {
        heading: "1. Biz nimani saqlaymiz",
        body: [
          "Hisob ma'lumotlari: elektron pochta manzilingiz, tashkilotingiz nomi, rolingiz va parolingiz — parol faqat bcrypt xesh ko'rinishida saqlanadi, hech qachon o'qib bo'ladigan shaklda emas. Ikki bosqichli kirishni yoqsangiz — umumiy maxfiy kalit va xeshlangan tiklash kodlari.",
          "Sessiya va xavfsizlik yozuvlari: har bir kirish uchun u amalga oshirilgan IP manzil va brauzer user-agent'i; shuningdek, ma'muriy amallar audit jurnali (kim, nima, qachon, qaysi IP manzildan).",
          "Ish maydoni ma'lumotlari: ulangan tizimlaringiz yuboradigan ogohlantirishlar, IP manzillar, host nomlari va aktivlar haqidagi ma'lumotlar. Ular tarmog'ingizdagi odamlarga oid shaxsga doir ma'lumotlarni o'z ichiga olishi mumkin; ularni tashkilotingiz nazorat qiladi.",
          "To'lov holati: obunangiz faol yoki faol emasligi, hamda Paddle bizga beradigan mijoz va obuna identifikatorlari. Biz karta ma'lumotlaringizni hech qachon ko'rmaymiz va saqlamaymiz — buni Paddle qiladi.",
          "Bizga yuboradigan qo'llab-quvvatlash xabarlaringiz.",
        ],
      },
      {
        heading: "2. Nima uchun",
        body: [
          "Siz ro'yxatdan o'tgan xizmatni taqdim etish uchun (shartnoma); xizmat va hisobingiz xavfsizligini ta'minlash hamda suiiste'molning oldini olish uchun (qonuniy manfaat); qayta sotuvchimiz orqali sizga hisob-kitob qilish uchun (shartnoma); va soliq hujjatlarini yuritish kabi qonuniy talablarni bajarish uchun (qonuniy majburiyat).",
          "Biz shaxsga doir ma'lumotlarni sotmaymiz, ish maydoningiz ma'lumotlaridan AI modellarini o'qitish uchun foydalanmaymiz va xizmatda reklama yoki analitika trekerlaridan foydalanmaymiz.",
        ],
      },
      {
        heading: "3. Bizga kim yordam beradi",
        body: [
          "Paddle.com — qayta sotuvchimiz va rasmiy sotuvchi (Merchant of Record). Xarid qilganingizda to'lov ma'lumotlaringizni Paddle'ga berasiz va ularga Paddle'ning o'z maxfiylik siyosati qo'llaniladi.",
          "Ish maydoningiz saqlanadigan serverlarni boshqaradigan hosting provayderimiz. Serverlar joylashgan joy: {dataLocation}.",
          "Hisob bilan bog'liq xatlarni (tasdiqlash, parolni tiklash, takliflar) va siz yoqqan ogohlantirish xabarnomalarini yuboradigan elektron pochta yetkazib berish provayderimiz. U qabul qiluvchining manzili va xabar mazmunini oladi.",
          "AI provayderi — faqat xizmat uchun AI tahlili yoqilgan bo'lsa: bunda tushuntirishlar tayyorlash uchun unga ogohlantirishlarning sarlavhalari, tavsiflari, host nomlari va IP manzillar yuboriladi. AI tahlili o'chirilgan bo'lsa, tushuntirishlar o'z serverlarimizda yaratiladi va hech narsa yuborilmaydi.",
          "Ularning har biri ma'lumotlarni faqat xizmatning o'ziga tegishli qismini taqdim etish uchun qayta ishlaydi.",
        ],
      },
      {
        heading: "4. Cookie fayllari",
        body: [
          "Biz faqat tizimda qolishingiz va sessiyangizni himoya qilish uchun zarur bo'lgan cookie fayllaridan foydalanamiz. To'lov va hisob-kitob sahifalari Paddle'ning to'lov skriptini yuklaydi; u to'lovlarni amalga oshirish uchun zarur bo'lgan o'z cookie fayllarini o'rnatishi mumkin.",
        ],
      },
      {
        heading: "5. Ma'lumotlarni qancha saqlaymiz",
        body: [
          "Hisob va ish maydoni ma'lumotlari hisobingiz mavjud ekan saqlanadi. Obuna tugagach, qaytib kelishingiz mumkin bo'lishi uchun ish maydoni bloklanadi, lekin saqlanib qoladi; uni o'chirishni so'rasangiz, biz buni 30 kun ichida bajaramiz. O'chirilgan ma'lumotlar zaxira nusxalarining muddati tugaguncha ularda 14 kungacha qolishi mumkin.",
          "To'lov va soliq yozuvlarini Paddle ham, biz ham qonun talab qiladigan muddat davomida saqlaymiz.",
        ],
      },
      {
        heading: "6. Xavfsizlik",
        body: [
          "Ulanishlar shifrlanadi (HTTPS). Parollar va tiklash kodlari faqat xesh ko'rinishida saqlanadi, ikki bosqichli kirish har bir foydalanuvchi uchun mavjud, har bir mijozning ma'lumotlari o'z ish maydonida alohida saqlanadi, ma'muriy amallar esa audit jurnaliga yoziladi.",
          "Shaxsga doir ma'lumotlaringizga daxldor ma'lumotlar sizib chiqishi yuz bersa, zarar ko'rgan ish maydonlari administratorlarini asossiz kechiktirmasdan xabardor qilamiz.",
        ],
      },
      {
        heading: "7. Sizning huquqlaringiz",
        body: [
          "{supportEmail} manziliga yozib, shaxsga doir ma'lumotlaringizni ko'rish, tuzatish, eksport qilish yoki o'chirishni so'rashingiz, yoki ulardan foydalanish usuliga e'tiroz bildirishingiz mumkin. Ish maydoni ichidagi ma'lumotlar bo'yicha biz o'sha ish maydoni administratorlarining ko'rsatmalariga muvofiq harakat qilamiz.",
          "Shuningdek, mamlakatingizdagi shaxsga doir ma'lumotlarni himoya qilish bo'yicha vakolatli organga shikoyat qilish huquqiga egasiz.",
        ],
      },
      {
        heading: "8. O'zgarishlar",
        body: [
          "Agar ushbu siyosatni sezilarli darajada o'zgartirsak, o'zgarish kuchga kirishidan oldin ish maydoni administratorlariga elektron pochta orqali xabar beramiz.",
        ],
      },
    ],
  },
};

export const saasRefunds: Record<Locale, LegalDoc> = {
  en: {
    title: "Refund Policy",
    effectiveDate: EFFECTIVE,
    intro:
      "Legion starts with a free trial so you can decide before paying anything. If you subscribe and it still isn't right for you, this policy explains how to get your money back.",
    sections: [
      {
        heading: "1. 14-Day Refund on Your First Payment",
        body: [
          "If you are not satisfied, request a refund within 14 days of your first subscription payment and you will receive a full refund of that payment. Your workspace is then locked.",
        ],
      },
      {
        heading: "2. Renewals",
        body: [
          "Renewal payments are not refunded, but you can cancel at any time from Billing → Manage subscription so that you are not charged again. You keep access until the end of the period already paid for.",
          "If you were charged in error — for example, a renewal after you had cancelled — tell us and we will put it right.",
        ],
      },
      {
        heading: "3. How to Ask",
        body: [
          "Email {supportEmail} from your account's email address, or use the link in the receipt Paddle sent you. Payments are handled by our reseller Paddle.com, which processes refunds back to the original payment method, usually within 5–10 business days depending on your bank.",
        ],
      },
      {
        heading: "4. Your Statutory Rights",
        body: [
          "Nothing in this policy limits rights you have under the consumer law of your country.",
        ],
      },
    ],
  },
  ru: {
    title: "Политика возврата средств",
    effectiveDate: EFFECTIVE_RU,
    intro:
      "Legion начинается с бесплатного пробного периода, чтобы вы могли принять решение, ничего не заплатив. Если вы оформили подписку, но сервис вам всё же не подходит, эта политика объясняет, как вернуть деньги. Это перевод для удобства; при расхождениях преимущественную силу имеет английская версия.",
    sections: [
      {
        heading: "1. Возврат в течение 14 дней после первого платежа",
        body: [
          "Если вы не удовлетворены, запросите возврат в течение 14 дней после первого платежа за подписку, и вам будет возвращена полная сумма этого платежа. После этого ваше рабочее пространство блокируется.",
        ],
      },
      {
        heading: "2. Продления",
        body: [
          "Платежи за продление подписки не возвращаются, но вы можете в любое время отменить подписку в разделе «Оплата → Управлять подпиской», чтобы с вас больше не списывались средства. Доступ сохраняется до конца уже оплаченного периода.",
          "Если с вас списали средства по ошибке — например, продлили подписку после того, как вы её отменили, — сообщите нам, и мы это исправим.",
        ],
      },
      {
        heading: "3. Как подать запрос",
        body: [
          "Напишите на {supportEmail} с адреса электронной почты вашего аккаунта или воспользуйтесь ссылкой в квитанции, которую прислал вам Paddle. Платежи обрабатывает наш реселлер Paddle.com, который возвращает средства на исходный способ оплаты, обычно в течение 5–10 рабочих дней в зависимости от вашего банка.",
        ],
      },
      {
        heading: "4. Ваши законные права",
        body: [
          "Ничто в настоящей политике не ограничивает права, которые предоставляет вам законодательство о защите прав потребителей вашей страны.",
        ],
      },
    ],
  },
  uz: {
    title: "Pulni qaytarish siyosati",
    effectiveDate: EFFECTIVE_UZ,
    intro:
      "Legion bepul sinov muddatidan boshlanadi, shuning uchun hech narsa to'lamasdan qaror qabul qilishingiz mumkin. Agar obuna bo'lsangiz-u, xizmat baribir sizga to'g'ri kelmasa, ushbu siyosat pulingizni qanday qaytarib olishni tushuntiradi. Bu qulaylik uchun berilgan tarjima; matnlar o'rtasida tafovut bo'lsa, ingliz tilidagi matn ustun turadi.",
    sections: [
      {
        heading: "1. Birinchi to'lov uchun 14 kun ichida pulni qaytarish",
        body: [
          "Agar qoniqmagan bo'lsangiz, obuna uchun birinchi to'lovdan keyin 14 kun ichida pulni qaytarishni so'rang va o'sha to'lov summasi sizga to'liq qaytariladi. Shundan so'ng ish maydoningiz bloklanadi.",
        ],
      },
      {
        heading: "2. Obunani yangilash",
        body: [
          "Obunani yangilash uchun to'lovlar qaytarilmaydi, ammo sizdan qayta pul yechilmasligi uchun obunani istalgan vaqtda To'lovlar → Obunani boshqarish bo'limidan bekor qilishingiz mumkin. Allaqachon to'langan davr oxirigacha kirish huquqingiz saqlanib qoladi.",
          "Agar sizdan xato tufayli pul yechilgan bo'lsa — masalan, obunani bekor qilganingizdan keyin u yangilangan bo'lsa — bizga xabar bering va biz buni tuzatamiz.",
        ],
      },
      {
        heading: "3. Qanday so'rash mumkin",
        body: [
          "Hisobingizga bog'langan elektron pochta manzilidan {supportEmail} manziliga yozing yoki Paddle sizga yuborgan kvitansiyadagi havoladan foydalaning. To'lovlarni qayta sotuvchimiz Paddle.com amalga oshiradi; u pulni dastlabki to'lov usuliga qaytaradi — odatda bankingizga qarab 5–10 ish kuni ichida.",
        ],
      },
      {
        heading: "4. Qonuniy huquqlaringiz",
        body: [
          "Ushbu siyosatdagi hech narsa mamlakatingizning iste'molchilar huquqlarini himoya qilish to'g'risidagi qonunchiligi bo'yicha sizga tegishli huquqlarni cheklamaydi.",
        ],
      },
    ],
  },
};

/** Fills {dataLocation}; resolveLegalDoc fills {operator} and {supportEmail}.
 *  Takes one language's document, e.g. `withDataLocation(saasPrivacy[locale])`. */
export function withDataLocation(doc: LegalDoc): LegalDoc {
  const fill = (t: string) => t.replace(/\{dataLocation\}/g, DATA_LOCATION);
  return { ...doc, intro: fill(doc.intro), sections: doc.sections.map((s) => ({ heading: fill(s.heading), body: s.body.map(fill) })) };
}
