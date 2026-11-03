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
});
