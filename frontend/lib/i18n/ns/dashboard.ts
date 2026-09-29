import { defineMessages } from "../core";

/**
 * The alert dashboard (components/LegionDashboard.tsx). The `alert` group is
 * also used by the incident list and incident details pages, which show the
 * same alert actions and Oracle explanation.
 */
export const dashboard = defineMessages({
  en: {
    welcome: "Welcome back 👋",
    overview: "Legion Security Overview",
    kpi: {
      securityScore: "Security score",
      criticalAlerts: "Critical alerts",
      open: "Open",
      resolved: "Resolved",
    },
    searchPlaceholder: "Search alerts by ID or title",
    empty: "No alerts match this view.",
    alert: {
      aiConfidence: "AI confidence",
      fullDetails: "Full details",
      investigate: "Investigate",
      resolve: "Resolve",
      askOracle: "Ask Oracle to explain",
      oracleThinking: "Oracle is thinking…",
      otherLanguage: "This explanation is in another language.",
      explainInMyLanguage: "Explain in English",
      explainError: "Oracle couldn't explain this alert.",
      loadError: "Couldn't reach the Legion API. Is the backend running?",
    },
  },
  ru: {
    welcome: "С возвращением 👋",
    overview: "Обзор безопасности Legion",
    kpi: {
      securityScore: "Индекс безопасности",
      criticalAlerts: "Критические оповещения",
      open: "Открытые",
      resolved: "Решённые",
    },
    searchPlaceholder: "Поиск по ID или названию",
    empty: "Нет оповещений, подходящих под фильтр.",
    alert: {
      aiConfidence: "Уверенность ИИ",
      fullDetails: "Подробнее",
      investigate: "Расследовать",
      resolve: "Решить",
      askOracle: "Попросить Oracle объяснить",
      oracleThinking: "Oracle думает…",
      otherLanguage: "Это объяснение на другом языке.",
      explainInMyLanguage: "Объяснить на русском",
      explainError: "Oracle не смог объяснить это оповещение.",
      loadError: "Не удалось подключиться к API Legion. Сервер запущен?",
    },
  },
  uz: {
    welcome: "Xush kelibsiz 👋",
    overview: "Legion xavfsizlik holati",
    kpi: {
      securityScore: "Xavfsizlik bahosi",
      criticalAlerts: "Kritik ogohlantirishlar",
      open: "Ochiq",
      resolved: "Hal qilingan",
    },
    searchPlaceholder: "ID yoki nomi bo'yicha qidirish",
    empty: "Bu filtrga mos ogohlantirishlar yo'q.",
    alert: {
      aiConfidence: "AI ishonchliligi",
      fullDetails: "Batafsil",
      investigate: "Tekshirish",
      resolve: "Hal qilish",
      askOracle: "Oracle'dan tushuntirish so'rash",
      oracleThinking: "Oracle o'ylamoqda…",
      otherLanguage: "Bu tushuntirish boshqa tilda yozilgan.",
      explainInMyLanguage: "O'zbekcha tushuntirish",
      explainError: "Oracle bu ogohlantirishni tushuntira olmadi.",
      loadError: "Legion API'ga ulanib bo'lmadi. Server ishlayaptimi?",
    },
  },
});
