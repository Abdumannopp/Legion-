import { apiDate } from "@/lib/dates";
import type { SuggestedAction } from "@/lib/api";
import { INTL_TAG, Locale } from "./core";
import { translations } from "./translations";

type DateInput = string | Date;
const toDate = (value: DateInput) => (typeof value === "string" ? apiDate(value) : value);

// Browsers ship little or no Uzbek date data (Chrome prints "2026 M09 28"),
// so Uzbek dates are written out here in the standard form: 2026-yil 28-sentabr.
const UZ_MONTHS = ["yanvar", "fevral", "mart", "aprel", "may", "iyun", "iyul", "avgust", "sentabr", "oktabr", "noyabr", "dekabr"];
const pad = (n: number) => String(n).padStart(2, "0");
const uzDate = (d: Date) => `${d.getFullYear()}-yil ${d.getDate()}-${UZ_MONTHS[d.getMonth()]}`;
const uzTime = (d: Date) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;

/** "Sep 28, 2026" / "28 сент. 2026 г." / "2026-yil 28-sentabr" */
export function formatDate(value: DateInput, locale: Locale): string {
  const d = toDate(value);
  if (locale === "uz") return uzDate(d);
  return d.toLocaleDateString(INTL_TAG[locale], { dateStyle: "medium" });
}

/** Date and time, in the viewer's language and time zone. */
export function formatDateTime(value: DateInput, locale: Locale): string {
  const d = toDate(value);
  if (locale === "uz") return `${uzDate(d)}, ${uzTime(d)}`;
  return d.toLocaleString(INTL_TAG[locale], { dateStyle: "medium", timeStyle: "short" });
}

export function formatTime(value: DateInput, locale: Locale): string {
  const d = toDate(value);
  if (locale === "uz") return uzTime(d);
  return d.toLocaleTimeString(INTL_TAG[locale], { timeStyle: "short" });
}

export function formatNumber(value: number, locale: Locale): string {
  return value.toLocaleString(INTL_TAG[locale]);
}

/** Short relative time for lists: "5m ago" / "5 мин назад" / "5 daqiqa oldin". */
export function timeAgo(value: DateInput, locale: Locale, now: number = Date.now()): string {
  const t = translations[locale].common.time;
  const diff = now - toDate(value).getTime();
  const mins = Math.floor(diff / 60_000);
  if (!Number.isFinite(mins) || mins < 1) return t.justNow;
  if (mins < 60) return t.minutesAgo(mins);
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return t.hoursAgo(hrs);
  return t.daysAgo(Math.floor(hrs / 24));
}

/** One suggested next step for an alert, in the viewer's language. */
export function suggestedActionText(action: SuggestedAction, locale: Locale): string {
  const a = translations[locale].common.actions;
  return action.code === "block_source_ip" ? a.block_source_ip(action.ip) : a[action.code];
}
