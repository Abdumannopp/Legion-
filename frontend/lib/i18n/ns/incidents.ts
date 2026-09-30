import { defineMessages, plural } from "../core";

/** Incident list (app/incidents/page.tsx). */
export const incidents = defineMessages({
  en: {
    title: "Incidents",
    summary: (total: number, open: number, investigating: number) =>
      `${plural("en", total, { one: `${total} incident`, other: `${total} incidents` })} · ${open} open · ${investigating} investigating`,
    searchPlaceholder: "Search incidents by title",
    allSeverities: "All severities",
    column: {
      incident: "Incident",
      severity: "Severity",
      status: "Status",
      detectedBy: "Source",
      when: "When",
    },
    empty: "No incidents match this view.",
  },
  ru: {
    title: "Инциденты",
    summary: (total: number, open: number, investigating: number) =>
      `${plural("ru", total, {
        one: `${total} инцидент`,
        few: `${total} инцидента`,
        many: `${total} инцидентов`,
        other: `${total} инцидента`,
      })} · открыто: ${open} · расследуется: ${investigating}`,
    searchPlaceholder: "Поиск инцидентов по названию",
    allSeverities: "Любая критичность",
    column: {
      incident: "Инцидент",
      severity: "Критичность",
      status: "Статус",
      detectedBy: "Источник",
      when: "Когда",
    },
    empty: "Нет инцидентов, подходящих под фильтр.",
  },
  uz: {
    title: "Hodisalar",
    summary: (total: number, open: number, investigating: number) =>
      `${total} ta hodisa · ${open} ta ochiq · ${investigating} ta tekshirilmoqda`,
    searchPlaceholder: "Hodisalarni nomi bo'yicha qidirish",
    allSeverities: "Barcha darajalar",
    column: {
      incident: "Hodisa",
      severity: "Jiddiylik",
      status: "Holat",
      detectedBy: "Manba",
      when: "Qachon",
    },
    empty: "Bu filtrga mos hodisalar yo'q.",
  },
});
