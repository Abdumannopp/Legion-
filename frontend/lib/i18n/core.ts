/**
 * The three languages Legion ships in, and the rule that keeps them complete.
 *
 * Every piece of interface text lives in a namespace file under ./ns, written
 * once per language with `defineMessages`. The English object defines the
 * shape; Russian and Uzbek must match it exactly — a missing key, an extra
 * key, or a function with different parameters is a TypeScript error, so
 * `npm run check` fails before an untranslated string can ship.
 */

export type Locale = "en" | "ru" | "uz";

export const LOCALES: { code: Locale; label: string; short: string }[] = [
  { code: "en", label: "English", short: "EN" },
  { code: "ru", label: "Русский", short: "RU" },
  { code: "uz", label: "O'zbekcha", short: "UZ" },
];

export const DEFAULT_LOCALE: Locale = "en";

/** Cookie (read by the server-rendered layout) and localStorage key. */
export const LOCALE_STORAGE_KEY = "legion-locale";

export function isLocale(value: unknown): value is Locale {
  return value === "en" || value === "ru" || value === "uz";
}

/** BCP 47 tag for Intl date and number formatting. */
export const INTL_TAG: Record<Locale, string> = {
  en: "en-US",
  ru: "ru-RU",
  uz: "uz-Latn-UZ",
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
  ru: Messages<T>;
  uz: Messages<T>;
}): Record<Locale, Messages<T>> {
  return m as Record<Locale, Messages<T>>;
}

/**
 * Picks the grammatically right form for a count. Russian has three
 * (1 минута, 2 минуты, 5 минут); English two; Uzbek never changes the noun
 * after a number, so it only needs `other`.
 */
export function plural(
  locale: Locale,
  n: number,
  forms: { one: string; few?: string; many?: string; other: string }
): string {
  if (locale === "ru") {
    const mod10 = n % 10;
    const mod100 = n % 100;
    if (mod10 === 1 && mod100 !== 11) return forms.one;
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return forms.few ?? forms.other;
    return forms.many ?? forms.other;
  }
  if (locale === "en") return n === 1 ? forms.one : forms.other;
  return forms.other;
}
