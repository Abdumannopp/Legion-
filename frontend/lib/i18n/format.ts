import { apiDate } from "@/lib/dates";
import type { SuggestedAction } from "@/lib/api";
import { INTL_TAG, Locale } from "./core";
import { translations } from "./translations";

type DateInput = string | Date;
const toDate = (value: DateInput) => (typeof value === "string" ? apiDate(value) : value);

/**
 * How to present moments to this viewer. Defaults reproduce the behaviour
 * before these settings existed: the browser's own time zone, dates and
 * times as the language writes them. getMe() applies the person's choices
 * (Settings → Regional); the workspace's time zone is the organisation's
 * reference for reports and emails, not a display override.
 */
export type DateFormat = "locale" | "YYYY-MM-DD" | "DD.MM.YYYY" | "DD/MM/YYYY" | "MM/DD/YYYY";
export type TimeFormat = "locale" | "24h" | "12h";
export interface DisplaySettings { timeZone?: string; dateFormat: DateFormat; timeFormat: TimeFormat }
let display: DisplaySettings = { dateFormat: "locale", timeFormat: "locale" };
export function setDisplaySettings(next: Partial<DisplaySettings>): void {
  display = { ...display, ...next };
}
export function displaySettings(): DisplaySettings {
  return display;
}

/** Calendar fields of a moment in the display time zone. */
function partsOf(d: Date): { y: number; m: number; day: number; h: number; min: number } {
  const f = new Intl.DateTimeFormat("en-US", {
    timeZone: display.timeZone, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", hourCycle: "h23",
  });
  const get = (type: string) => Number(f.formatToParts(d).find((p) => p.type === type)?.value ?? 0);
  return { y: get("year"), m: get("month"), day: get("day"), h: get("hour") % 24, min: get("minute") };
}

// Browsers ship little or no Uzbek date data (Chrome prints "2026 M09 28"),
// so Uzbek dates are written out here in the standard form: 2026-yil 28-sentabr.
const UZ_MONTHS = ["yanvar", "fevral", "mart", "aprel", "may", "iyun", "iyul", "avgust", "sentabr", "oktabr", "noyabr", "dekabr"];
const pad = (n: number) => String(n).padStart(2, "0");
const uzDate = (d: Date) => { const p = partsOf(d); return `${p.y}-yil ${p.day}-${UZ_MONTHS[p.m - 1]}`; };

function fixedDate(d: Date): string | null {
  const p = partsOf(d);
  switch (display.dateFormat) {
    case "YYYY-MM-DD": return `${p.y}-${pad(p.m)}-${pad(p.day)}`;
    case "DD.MM.YYYY": return `${pad(p.day)}.${pad(p.m)}.${p.y}`;
    case "DD/MM/YYYY": return `${pad(p.day)}/${pad(p.m)}/${p.y}`;
    case "MM/DD/YYYY": return `${pad(p.m)}/${pad(p.day)}/${p.y}`;
    default: return null;
  }
}
function fixedTime(d: Date, locale: Locale): string {
  if (display.timeFormat === "12h") {
    return d.toLocaleTimeString(INTL_TAG[locale], { hour: "numeric", minute: "2-digit", hour12: true, timeZone: display.timeZone });
  }
  const p = partsOf(d);
  return `${pad(p.h)}:${pad(p.min)}`;
}
const hour12 = (): boolean | undefined => (display.timeFormat === "12h" ? true : display.timeFormat === "24h" ? false : undefined);

/** "Sep 28, 2026" / "28 сент. 2026 г." / "2026-yil 28-sentabr" — or the chosen fixed format. */
export function formatDate(value: DateInput, locale: Locale): string {
  const d = toDate(value);
  const fixed = fixedDate(d);
  if (fixed) return fixed;
  if (locale === "uz") return uzDate(d);
  return d.toLocaleDateString(INTL_TAG[locale], { dateStyle: "medium", timeZone: display.timeZone });
}

/** Date and time, in the viewer's language and time zone. */
export function formatDateTime(value: DateInput, locale: Locale): string {
  const d = toDate(value);
  const fixed = fixedDate(d);
  if (fixed || locale === "uz") return `${fixed ?? uzDate(d)}, ${formatTime(d, locale)}`;
  return d.toLocaleString(INTL_TAG[locale], { dateStyle: "medium", timeStyle: "short", timeZone: display.timeZone, hour12: hour12() });
}

export function formatTime(value: DateInput, locale: Locale): string {
  const d = toDate(value);
  if (locale === "uz" || display.timeFormat !== "locale") return fixedTime(d, locale);
  return d.toLocaleTimeString(INTL_TAG[locale], { timeStyle: "short", timeZone: display.timeZone });
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

/**
 * An amount of money in the viewer's language: "$29.00" / "29,00 $" /
 * "29,00 US$". Amounts arrive in minor units (cents), as the billing
 * provider sends them; the currency's own number of decimals is used.
 */
export function formatMoney(amountMinor: number, currency: string, locale: Locale): string {
  const code = currency.toUpperCase();
  let digits = 2;
  try {
    digits = new Intl.NumberFormat("en", { style: "currency", currency: code }).resolvedOptions().maximumFractionDigits ?? 2;
  } catch {
    return `${formatNumber(amountMinor / 100, locale)} ${code}`;
  }
  return new Intl.NumberFormat(INTL_TAG[locale], { style: "currency", currency: code }).format(amountMinor / 10 ** digits);
}
