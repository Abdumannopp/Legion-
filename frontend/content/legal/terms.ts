import { Locale } from "@/lib/i18n/translations";
import { LegalDoc } from "./privacy";

/**
 * These are the terms on which the operator offers *this installation* to the
 * people who log into it — not a service agreement with the vendor. The
 * commercial relationship between the operator and the vendor lives in the
 * LICENSE file at the root of the repository, and the two must not be
 * confused: the earlier version of this page described a hosted subscription
 * that does not exist in a self-hosted deployment.
 *
 * `{operator}` is substituted by `resolveLegalDoc`.
 */
export const termsContent: Record<Locale, LegalDoc> = {
  en: {
    title: "Terms of Use",
    effectiveDate: "August 25, 2026",
    intro:
      "This is a Legion installation operated by {operator}. These terms govern your use of it as someone {operator} has given an account. They are not an agreement with the company that makes Legion — that company does not run this system and is not a party to your use of it.",
    sections: [
      {
        heading: "1. What This Is",
        body: [
          "Legion is a security platform that collects alerts from your organisation's monitoring systems, groups and prioritises them, and helps analysts decide what to act on.",
          "It is a tool for trained people, not a replacement for them. Its analysis — including anything produced with AI assistance — can be incomplete or wrong, and no security product can guarantee that every threat is detected. Decisions remain yours.",
        ],
      },
      {
        heading: "2. Your Account",
        body: [
          "{operator} decides who gets an account and what each account may do. Accounts are personal: keep your password and your two-factor device to yourself, and do not let anyone else use your account.",
          "Tell {operator} promptly if you think someone else has used your account, or if you no longer need it.",
          "Everything done through your account is recorded in an audit log with the time and originating IP address.",
        ],
      },
      {
        heading: "3. Acceptable Use",
        body: [
          "Use this installation only for {operator}'s security work, and only within the access you have been given.",
          "Do not attempt to reach data belonging to accounts or areas you have not been granted, interfere with the system's operation, or use it to gain unauthorised access to anything else.",
          "The data here describes real systems and real incidents. Treat it as confidential to {operator} and do not copy it out except as {operator}'s own policies allow.",
        ],
      },
      {
        heading: "4. Data",
        body: [
          "The security events, alerts, and account records in this installation belong to {operator} and sit in a database {operator} controls.",
          "How that data is handled, how long it is kept, and who may see it are described in the Privacy Policy for this installation.",
        ],
      },
      {
        heading: "5. Availability",
        body: [
          "This installation runs on {operator}'s own infrastructure. Its uptime, backups, and maintenance windows are {operator}'s responsibility, and no availability is guaranteed here.",
          "Legion should not be relied on as the only means of detecting a security incident.",
        ],
      },
      {
        heading: "6. The Software Itself",
        body: [
          "The Legion software is licensed to {operator} by its vendor under a separate agreement, which is supplied with the software as the LICENSE file. That agreement governs {operator}'s right to run, copy, and modify Legion.",
          "Nothing on this page grants you any right in the software beyond using this installation as {operator} permits.",
        ],
      },
      {
        heading: "7. Changes and Access",
        body: [
          "{operator} may change these terms, change what your account can do, or withdraw your access — for example when your role changes or you leave the organisation.",
          "Questions about these terms, about your access, or about the data held here go to {operator} at {supportEmail}.",
        ],
      },
    ],
  },
  ru: {
    title: "Условия использования",
    effectiveDate: "25 августа 2026 г.",
    intro:
      "Это установка Legion, эксплуатируемая организацией {operator}. Настоящие условия регулируют её использование вами как человеком, которому {operator} выдала учётную запись. Они не являются соглашением с компанией-разработчиком Legion — эта компания не управляет данной системой и не является стороной в отношениях, связанных с её использованием вами.",
    sections: [
      {
        heading: "1. Что это такое",
        body: [
          "Legion — платформа безопасности, которая собирает оповещения из систем мониторинга вашей организации, группирует и приоритизирует их и помогает аналитикам решить, на что реагировать.",
          "Это инструмент для подготовленных людей, а не их замена. Его анализ — включая всё, что получено с помощью ИИ, — может быть неполным или ошибочным, и ни один продукт безопасности не может гарантировать обнаружение каждой угрозы. Решения остаются за вами.",
        ],
      },
      {
        heading: "2. Ваша учётная запись",
        body: [
          "{operator} решает, кто получает учётную запись и что каждая из них может делать. Учётные записи персональны: храните пароль и устройство двухфакторной аутентификации при себе и не позволяйте никому другому пользоваться вашей учётной записью.",
          "Незамедлительно сообщите организации {operator}, если считаете, что вашей учётной записью воспользовался кто-то другой, или если она вам больше не нужна.",
          "Всё, что делается через вашу учётную запись, записывается в журнал аудита с указанием времени и исходного IP-адреса.",
        ],
      },
      {
        heading: "3. Допустимое использование",
        body: [
          "Используйте эту установку только для работы по безопасности организации {operator} и только в пределах предоставленного вам доступа.",
          "Не пытайтесь получить доступ к данным учётных записей или разделов, которые вам не предоставлены, не вмешивайтесь в работу системы и не используйте её для несанкционированного доступа к чему-либо ещё.",
          "Данные здесь описывают реальные системы и реальные инциденты. Считайте их конфиденциальной информацией организации {operator} и не копируйте их вовне, кроме случаев, разрешённых внутренними правилами {operator}.",
        ],
      },
      {
        heading: "4. Данные",
        body: [
          "События безопасности, оповещения и учётные записи в этой установке принадлежат организации {operator} и находятся в базе данных, которой {operator} управляет.",
          "Как эти данные обрабатываются, сколько хранятся и кто может их видеть, описано в Политике конфиденциальности этой установки.",
        ],
      },
      {
        heading: "5. Доступность",
        body: [
          "Эта установка работает на собственной инфраструктуре организации {operator}. Её бесперебойность, резервное копирование и регламентные работы — зона ответственности {operator}; никакой доступности здесь не гарантируется.",
          "На Legion не следует полагаться как на единственное средство обнаружения инцидентов безопасности.",
        ],
      },
      {
        heading: "6. Само программное обеспечение",
        body: [
          "Программное обеспечение Legion лицензировано организации {operator} его разработчиком по отдельному соглашению, которое поставляется вместе с программой в виде файла LICENSE. Это соглашение определяет право {operator} запускать, копировать и изменять Legion.",
          "Ничто на этой странице не предоставляет вам никаких прав на программное обеспечение сверх использования данной установки в объёме, разрешённом организацией {operator}.",
        ],
      },
      {
        heading: "7. Изменения и доступ",
        body: [
          "{operator} может изменить настоящие условия, изменить возможности вашей учётной записи или отозвать ваш доступ — например, при изменении вашей роли или при уходе из организации.",
          "Вопросы об этих условиях, о вашем доступе или о хранящихся здесь данных направляйте организации {operator} по адресу {supportEmail}.",
        ],
      },
    ],
  },
  uz: {
    title: "Foydalanish shartlari",
    effectiveDate: "2026-yil 25-avgust",
    intro:
      "Bu — {operator} ishlatadigan Legion o'rnatmasi. Ushbu shartlar {operator} sizga hisob ochib bergan shaxs sifatida undan foydalanishingizni tartibga soladi. Bu Legion'ni ishlab chiqaradigan kompaniya bilan tuzilgan kelishuv emas — o'sha kompaniya bu tizimni boshqarmaydi va sizning undan foydalanishingizga taraf emas.",
    sections: [
      {
        heading: "1. Bu nima",
        body: [
          "Legion — tashkilotingizning monitoring tizimlaridan ogohlantirishlarni yig'adigan, ularni guruhlab muhimlik bo'yicha saralaydigan va tahlilchilarga nimaga javob qaytarish kerakligini hal qilishda yordam beradigan xavfsizlik platformasi.",
          "Bu — tayyorgarlikka ega odamlar uchun vosita, ularning o'rnini bosuvchi emas. Uning tahlili — jumladan AI yordamida olingan har qanday natija — to'liq bo'lmasligi yoki noto'g'ri bo'lishi mumkin, va hech bir xavfsizlik mahsuloti har bir tahdid aniqlanishini kafolatlay olmaydi. Qaror sizniki bo'lib qoladi.",
        ],
      },
      {
        heading: "2. Sizning hisobingiz",
        body: [
          "Kimga hisob berilishini va har bir hisob nima qila olishini {operator} hal qiladi. Hisoblar shaxsiy: parolingiz va ikki bosqichli tasdiqlash qurilmangizni o'zingizda saqlang va hisobingizdan boshqa hech kimni foydalantirmang.",
          "Hisobingizdan boshqa kimdir foydalangan deb o'ylasangiz yoki u endi sizga kerak bo'lmasa, {operator}ga darhol xabar bering.",
          "Hisobingiz orqali qilingan har bir amal vaqti va kelib chiqqan IP manzili bilan audit jurnaliga yoziladi.",
        ],
      },
      {
        heading: "3. Ruxsat etilgan foydalanish",
        body: [
          "Bu o'rnatmadan faqat {operator}ning xavfsizlik ishi uchun va faqat sizga berilgan huquq doirasida foydalaning.",
          "Sizga berilmagan hisoblar yoki bo'limlarning ma'lumotiga yetishga urinmang, tizim ishiga aralashmang va undan boshqa biror narsaga ruxsatsiz kirish uchun foydalanmang.",
          "Bu yerdagi ma'lumot haqiqiy tizimlar va haqiqiy hodisalarni tasvirlaydi. Uni {operator} uchun maxfiy deb biling va {operator}ning o'z qoidalari ruxsat bergan holatlardan tashqari tashqariga nusxalamang.",
        ],
      },
      {
        heading: "4. Ma'lumotlar",
        body: [
          "Bu o'rnatmadagi xavfsizlik hodisalari, ogohlantirishlar va hisob yozuvlari {operator}ga tegishli va {operator} boshqaradigan ma'lumotlar bazasida turadi.",
          "Bu ma'lumotlar qanday ishlanishi, qancha saqlanishi va kim ko'ra olishi shu o'rnatmaning Maxfiylik siyosatida bayon qilingan.",
        ],
      },
      {
        heading: "5. Mavjudlik",
        body: [
          "Bu o'rnatma {operator}ning o'z infratuzilmasida ishlaydi. Uning uzluksizligi, zaxira nusxalari va texnik xizmat oynalari {operator} zimmasida; bu yerda hech qanday mavjudlik kafolatlanmaydi.",
          "Legion xavfsizlik hodisasini aniqlashning yagona vositasi sifatida ishonch qilinmasligi kerak.",
        ],
      },
      {
        heading: "6. Dasturning o'zi",
        body: [
          "Legion dasturi {operator}ga ishlab chiqaruvchi tomonidan alohida kelishuv asosida litsenziyalangan; u dastur bilan birga LICENSE fayli sifatida beriladi. O'sha kelishuv {operator}ning Legion'ni ishga tushirish, nusxalash va o'zgartirish huquqini belgilaydi.",
          "Bu sahifadagi hech narsa sizga dasturga nisbatan {operator} ruxsat bergan doirada shu o'rnatmadan foydalanishdan boshqa hech qanday huquq bermaydi.",
        ],
      },
      {
        heading: "7. O'zgarishlar va kirish huquqi",
        body: [
          "{operator} ushbu shartlarni o'zgartirishi, hisobingiz imkoniyatlarini o'zgartirishi yoki kirish huquqingizni bekor qilishi mumkin — masalan, rolingiz o'zgarganda yoki tashkilotdan ketganingizda.",
          "Ushbu shartlar, kirish huquqingiz yoki bu yerda saqlanayotgan ma'lumotlar haqidagi savollarni {operator}ga {supportEmail} manzili orqali yuboring.",
        ],
      },
    ],
  },
};
