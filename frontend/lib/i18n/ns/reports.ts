import { defineMessages, plural } from "../core";

export const reports = defineMessages({
  en: {
    title: "Reports",
    subtitle: "Security posture summary, generated from live alert & asset data",
    kpi: {
      totalIncidents: "Total incidents",
      resolutionRate: "Resolution rate",
      avgConfidence: "Avg. AI confidence",
      assetsOnline: "Assets online",
    },
    bySeverity: "Incidents by severity",
    byStatus: "Incidents by status",
    byAgent: "Detections by agent",
    noIncidents: "No incidents yet.",
    oracleCoverage: "Oracle AI explanation coverage",
    explained: "Explained",
    coverageNote: (explained: number, total: number) =>
      `${explained} of ${total} incidents have an Oracle-generated explanation on file.`,
    recentlyResolved: "Recently resolved incidents",
    nothingResolved: "Nothing resolved yet.",
    loadError: "Couldn't reach the Legion API. Is the backend running?",
  },
  ru: {
    title: "Отчёты",
    subtitle: "Сводка состояния безопасности по актуальным данным об оповещениях и активах",
    kpi: {
      totalIncidents: "Всего инцидентов",
      resolutionRate: "Доля решённых",
      avgConfidence: "Ср. уверенность ИИ",
      assetsOnline: "Активы в сети",
    },
    bySeverity: "Инциденты по критичности",
    byStatus: "Инциденты по статусу",
    byAgent: "Обнаружения по агентам",
    noIncidents: "Инцидентов пока нет.",
    oracleCoverage: "Покрытие объяснениями Oracle AI",
    explained: "С объяснением",
    coverageNote: (explained: number, total: number) =>
      `Объяснение от Oracle есть у ${explained} из ${total} ${plural("ru", total, {
        one: "инцидента",
        other: "инцидентов",
      })}.`,
    recentlyResolved: "Недавно решённые инциденты",
    nothingResolved: "Пока ничего не решено.",
    loadError: "Не удалось связаться с API Legion. Запущен ли сервер?",
  },
  uz: {
    title: "Hisobotlar",
    subtitle: "Xavfsizlik holati bo'yicha xulosa — jonli ogohlantirish va aktiv ma'lumotlari asosida",
    kpi: {
      totalIncidents: "Jami hodisalar",
      resolutionRate: "Hal qilinganlar ulushi",
      avgConfidence: "O'rtacha AI ishonchliligi",
      assetsOnline: "Onlayn aktivlar",
    },
    bySeverity: "Jiddiylik darajasi bo'yicha hodisalar",
    byStatus: "Holat bo'yicha hodisalar",
    byAgent: "Agentlar bo'yicha aniqlashlar",
    noIncidents: "Hozircha hodisalar yo'q.",
    oracleCoverage: "Oracle AI izohlari qamrovi",
    explained: "Izohlangan",
    coverageNote: (explained: number, total: number) =>
      `${total} ta hodisadan ${explained} tasi uchun Oracle yaratgan izoh mavjud.`,
    recentlyResolved: "Yaqinda hal qilingan hodisalar",
    nothingResolved: "Hozircha hal qilingan hodisa yo'q.",
    loadError: "Legion API'ga ulanib bo'lmadi. Server ishlayaptimi?",
  },
});
