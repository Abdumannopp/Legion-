import { defineMessages, plural } from "../core";

export const assets = defineMessages({
  en: {
    title: "Assets",
    summary: (devices: number, online: number) =>
      `${plural("en", devices, { one: `${devices} device`, other: `${devices} devices` })} · ${online} online`,
    searchPlaceholder: "Search devices by name",
    columns: {
      device: "Device",
      status: "Status",
      risk: "Risk",
      os: "OS",
      ip: "IP address",
    },
    online: "Online",
    offline: "Offline",
    empty: "No devices match this view.",
    loadError: "Couldn't reach the Legion API. Is the backend running?",
  },
  ru: {
    title: "Активы",
    summary: (devices: number, online: number) =>
      `${plural("ru", devices, {
        one: `${devices} устройство`,
        few: `${devices} устройства`,
        many: `${devices} устройств`,
        other: `${devices} устройства`,
      })} · ${online} в сети`,
    searchPlaceholder: "Поиск устройств по имени",
    columns: {
      device: "Устройство",
      status: "Статус",
      risk: "Риск",
      os: "ОС",
      ip: "IP-адрес",
    },
    online: "В сети",
    offline: "Не в сети",
    empty: "Нет устройств, подходящих под этот фильтр.",
    loadError: "Не удалось связаться с API Legion. Запущен ли сервер?",
  },
  uz: {
    title: "Aktivlar",
    summary: (devices: number, online: number) => `${devices} ta qurilma · ${online} tasi onlayn`,
    searchPlaceholder: "Qurilmalarni nomi bo'yicha qidirish",
    columns: {
      device: "Qurilma",
      status: "Holat",
      risk: "Xavf",
      os: "OS",
      ip: "IP manzil",
    },
    online: "Onlayn",
    offline: "Oflayn",
    empty: "Bu filtrga mos qurilma topilmadi.",
    loadError: "Legion API'ga ulanib bo'lmadi. Server ishlayaptimi?",
  },
});
