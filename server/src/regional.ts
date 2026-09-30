/**
 * Global readiness: regions (data residency), time zones, date and time
 * formats, currencies.
 *
 * The API speaks UTC ISO-8601 on the wire, always; how a moment is SHOWN is a
 * presentation choice made from these settings (workspace default, personal
 * override). Money is an integer amount plus an ISO 4217 code — never a float
 * and never a currency implied by the locale.
 */
import { config } from "./config.js";

const ZONES: ReadonlySet<string> = new Set(["UTC", ...(Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf("timeZone")]);
export function isTimeZone(v: string): boolean {
  return typeof v === "string" && v.length <= 64 && ZONES.has(v);
}

export const DATE_FORMATS = ["YYYY-MM-DD", "DD.MM.YYYY", "DD/MM/YYYY", "MM/DD/YYYY"] as const;
export type DateFormat = (typeof DATE_FORMATS)[number];
export const TIME_FORMATS = ["24h", "12h"] as const;
export type TimeFormat = (typeof TIME_FORMATS)[number];

export interface RegionalSettings {
  timezone: string;
  locale: string;
  date_format: DateFormat;
  time_format: TimeFormat;
}

/** A person's effective settings: their own where set, else the workspace's. */
export function effectiveSettings(
  workspace: { timezone: string; locale: string; date_format: string; time_format: string },
  user: { timezone?: string | null; locale?: string | null; date_format?: string | null; time_format?: string | null },
): RegionalSettings {
  const pick = <T extends string>(u: string | null | undefined, w: string, allowed: readonly T[], fallback: T): T =>
    (allowed as readonly string[]).includes(u ?? "") ? (u as T) : (allowed as readonly string[]).includes(w) ? (w as T) : fallback;
  return {
    timezone: user.timezone && isTimeZone(user.timezone) ? user.timezone : isTimeZone(workspace.timezone) ? workspace.timezone : "UTC",
    locale: user.locale || workspace.locale || "en",
    date_format: pick(user.date_format, workspace.date_format, DATE_FORMATS, "YYYY-MM-DD"),
    time_format: pick(user.time_format, workspace.time_format, TIME_FORMATS, "24h"),
  };
}

// --- Data residency ------------------------------------------------------------

/** The region a workspace's data lives in (NULL: created before regions — this deployment's). */
export function regionOf(tenant: { region?: string | null }): string {
  return tenant.region || config.region;
}

/**
 * Whether this deployment may serve the workspace. A deployment serves only
 * its own region's workspaces: the database it is connected to holds only
 * them, and refusing is what keeps a misrouted request (or a sensor pointed at
 * the wrong region) from creating data in the wrong place.
 */
export function servesRegion(tenant: { region?: string | null }): boolean {
  return regionOf(tenant) === config.region;
}

/** Where to send a client for a workspace in another region, if known. */
export function regionUrl(region: string): string | null {
  return config.regionUrls[region] ?? null;
}

// --- Money -----------------------------------------------------------------------

/** Amounts are integer minor units (cents) with an ISO 4217 code. */
export interface Money { amount_minor: number; currency: string }

export function isSupportedCurrency(c: string): boolean {
  return config.supportedCurrencies.includes(c.toUpperCase());
}
