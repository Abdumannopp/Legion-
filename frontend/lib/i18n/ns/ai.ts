import { defineMessages } from "../core";

/**
 * AI provenance labels and the AI settings card (components/AiBadge.tsx,
 * components/AiSettingsSection.tsx), plus the realtime "N new alerts" notice.
 */
export const ai = defineMessages({
  en: {
    badge: {
      ai: "AI suggestion",
      aiHint: "Written by an AI model from alert text an attacker may control. Review it before acting — Legion takes no action on its own.",
      local: "Legion analysis",
      localHint: "Written by Legion's built-in rules, not by an AI model.",
    },
    settings: {
      heading: "AI analysis",
      intro: "Oracle explanations and Copilot answers can use an external AI provider. AI only advises: it cannot change alerts or run any action.",
      providerNone: "No AI provider is configured on this server, so all answers come from Legion's built-in analysis and no data leaves the server.",
      provider: (name: string) => `Provider: ${name}. With AI on, alert text is sent to this third party.`,
      enabled: "Use AI for this organisation",
      stateOn: "On",
      stateOff: "Off",
      stateDefault: (on: boolean) => `Server default (${on ? "on" : "off"})`,
      strict: "Strict data mode",
      strictHint: "Replace IP addresses, e-mail addresses and hostnames with placeholders before anything is sent. Answers still show the real values.",
      circuitOpen: "The AI provider has been failing, so Legion is answering from its built-in analysis for now.",
      saved: "Saved.",
      loadError: "Couldn't load the AI settings.",
      adminOnly: "Only administrators can change these settings.",
    },
    newAlertsNotice: (n: number) => `${n} new alerts`,
  },
  ru: {
    badge: {
      ai: "Предложение ИИ",
      aiHint: "Написано моделью ИИ на основе текста оповещения, который мог подготовить злоумышленник. Проверьте перед тем, как действовать — Legion ничего не делает сам.",
      local: "Анализ Legion",
      localHint: "Написано встроенными правилами Legion, а не моделью ИИ.",
    },
    settings: {
      heading: "Анализ с помощью ИИ",
      intro: "Объяснения Oracle и ответы Copilot могут использовать внешнего провайдера ИИ. ИИ только советует: он не может менять оповещения или выполнять действия.",
      providerNone: "На этом сервере не настроен провайдер ИИ, поэтому все ответы даёт встроенный анализ Legion, и данные не покидают сервер.",
      provider: (name: string) => `Провайдер: ${name}. Когда ИИ включён, текст оповещений отправляется этой третьей стороне.`,
      enabled: "Использовать ИИ в этой организации",
      stateOn: "Включено",
      stateOff: "Выключено",
      stateDefault: (on: boolean) => `По умолчанию сервера (${on ? "вкл." : "выкл."})`,
      strict: "Строгий режим данных",
      strictHint: "Перед отправкой заменять IP-адреса, адреса эл. почты и имена хостов на метки. В ответах по-прежнему видны реальные значения.",
      circuitOpen: "Провайдер ИИ сейчас даёт сбои, поэтому Legion временно отвечает с помощью встроенного анализа.",
      saved: "Сохранено.",
      loadError: "Не удалось загрузить настройки ИИ.",
      adminOnly: "Менять эти настройки могут только администраторы.",
    },
    newAlertsNotice: (n: number) => `Новых оповещений: ${n}`,
  },
  uz: {
    badge: {
      ai: "AI taklifi",
      aiHint: "Buni AI modeli yozgan — hujumchi tayyorlagan bo'lishi mumkin bo'lgan ogohlantirish matni asosida. Amal qilishdan oldin tekshiring: Legion o'zi hech narsa qilmaydi.",
      local: "Legion tahlili",
      localHint: "Buni AI modeli emas, Legion'ning o'rnatilgan qoidalari yozgan.",
    },
    settings: {
      heading: "AI tahlili",
      intro: "Oracle tushuntirishlari va Copilot javoblari tashqi AI provayderidan foydalanishi mumkin. AI faqat maslahat beradi: ogohlantirishlarni o'zgartira olmaydi va hech qanday amal bajarmaydi.",
      providerNone: "Bu serverda AI provayderi sozlanmagan, shuning uchun barcha javoblarni Legion'ning o'rnatilgan tahlili beradi va ma'lumot serverdan chiqmaydi.",
      provider: (name: string) => `Provayder: ${name}. AI yoqilganda ogohlantirish matni shu uchinchi tomonga yuboriladi.`,
      enabled: "Bu tashkilotda AI'dan foydalanish",
      stateOn: "Yoqilgan",
      stateOff: "O'chirilgan",
      stateDefault: (on: boolean) => `Server standarti (${on ? "yoqilgan" : "o'chirilgan"})`,
      strict: "Qat'iy ma'lumot rejimi",
      strictHint: "Yuborishdan oldin IP manzillar, email manzillar va xost nomlarini belgilar bilan almashtirish. Javoblarda haqiqiy qiymatlar ko'rinaveradi.",
      circuitOpen: "AI provayderi hozir ishlamayapti, shuning uchun Legion vaqtincha o'rnatilgan tahlil bilan javob bermoqda.",
      saved: "Saqlandi.",
      loadError: "AI sozlamalarini yuklab bo'lmadi.",
      adminOnly: "Bu sozlamalarni faqat administratorlar o'zgartira oladi.",
    },
    newAlertsNotice: (n: number) => `${n} ta yangi ogohlantirish`,
  },
});
