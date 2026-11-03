/**
 * Legion ships in English only (it is built for the global market).
 *
 * Every piece of interface text lives in a namespace file under ./ns, written
 * once per language with `defineMessages`. The English object defines the
 * shape. The `Locale` plumbing stays so another language can be added later.
 */

export type Locale = "en";

export const LOCALES: { code: Locale; label: string; short: string }[] = [
  { code: "en", label: "English", short: "EN" },
];

export const DEFAULT_LOCALE: Locale = "en";

/** Cookie (read by the server-rendered layout) and localStorage key. */
export const LOCALE_STORAGE_KEY = "legion-locale";

export function isLocale(value: unknown): value is Locale {
  return value === "en";
}

/** BCP 47 tag for Intl date and number formatting. */
export const INTL_TAG: Record<Locale, string> = {
  en: "en-US",
};

/**
 * The shape a translation must have: same keys as the English original,
 * strings stay strings, functions keep their parameters (for text with
 * numbers or names in it), arrays stay arrays.
 */
export type Messages<T> = T extends string
  ? string
  : T extends (...args: infer A) => string
  ? (...args: A) => string
  : T extends readonly (infer E)[]
  ? Messages<E>[]
  : { [K in keyof T]: Messages<T[K]> };

export function defineMessages<T>(m: {
  en: T;
}): Record<Locale, Messages<T>> {
  return m as Record<Locale, Messages<T>>;
}

/** Picks the right form for a count (English has two). */
export function plural(
  _locale: Locale,
  n: number,
  forms: { one: string; few?: string; many?: string; other: string }
): string {
  return n === 1 ? forms.one : forms.other;
}
