import { defineMessages } from "../core";

/**
 * Incident details (app/incident/[id]/page.tsx). Alert actions and the Oracle
 * explanation buttons come from `t.dashboard.alert`.
 */
export const incident = defineMessages({
  en: {
    backToAlerts: "Back to alerts",
    loadError: "Couldn't load this incident.",
    statusError: "Couldn't update status.",
    detail: {
      detected: "Detected",
      sourceIp: "Source IP",
      notApplicable: "Not applicable",
      target: "Target",
      notSpecified: "Not specified",
      notClassified: "Not classified",
      confidence: "Detection confidence",
      detectedBy: "Source",
    },
    aiExplanation: "AI explanation",
    suggestedActions: "Suggested actions",
    suggestedIntro:
      "Rule-based suggestions from the alert pattern — not AI-generated, so you can trust exactly why each one is here.",
    manualNote:
      "These are manual checklist items for now — automated execution (the Executor agent) isn't wired up yet.",
  },
  ru: {
    backToAlerts: "Назад к оповещениям",
    loadError: "Не удалось загрузить инцидент.",
    statusError: "Не удалось обновить статус.",
    detail: {
      detected: "Обнаружено",
      sourceIp: "IP-адрес источника",
      notApplicable: "Не применимо",
      target: "Цель",
      notSpecified: "Не указана",
      notClassified: "Не классифицировано",
      confidence: "Уверенность обнаружения",
      detectedBy: "Источник",
    },
    aiExplanation: "Объяснение ИИ",
    suggestedActions: "Рекомендуемые действия",
    suggestedIntro:
      "Рекомендации построены по правилам на основе характера оповещения, а не сгенерированы ИИ, поэтому всегда понятно, откуда взялась каждая из них.",
    manualNote:
      "Пока это пункты чек-листа для ручного выполнения — автоматическое выполнение (агент Executor) ещё не подключено.",
  },
  uz: {
    backToAlerts: "Ogohlantirishlarga qaytish",
    loadError: "Hodisani yuklab bo'lmadi.",
    statusError: "Holatni yangilab bo'lmadi.",
    detail: {
      detected: "Aniqlangan vaqt",
      sourceIp: "Manba IP manzili",
      notApplicable: "Tegishli emas",
      target: "Nishon",
      notSpecified: "Ko'rsatilmagan",
      notClassified: "Tasniflanmagan",
      confidence: "Aniqlash ishonchliligi",
      detectedBy: "Manba",
    },
    aiExplanation: "AI tushuntirishi",
    suggestedActions: "Tavsiya etilgan choralar",
    suggestedIntro:
      "Bu tavsiyalar AI tomonidan yaratilmagan — ular ogohlantirish turiga qarab qoidalar asosida beriladi, shuning uchun har biri nega bu yerda ekani aniq.",
    manualNote:
      "Hozircha bular qo'lda bajariladigan nazorat ro'yxati — avtomatik bajarish (Executor agenti) hali ulanmagan.",
  },
});
