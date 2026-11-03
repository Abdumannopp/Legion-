"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { DEFAULT_LOCALE, isLocale, Locale, LOCALE_STORAGE_KEY } from "./core";
import { translations, Translations } from "./translations";
import { setApiLocale } from "@/lib/api";

type LanguageContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: Translations;
};

const LanguageContext = createContext<LanguageContextValue | null>(null);

const ONE_YEAR = 60 * 60 * 24 * 365;

function remember(locale: Locale) {
  try {
    window.localStorage.setItem(LOCALE_STORAGE_KEY, locale);
  } catch {
    // storage unavailable (private browsing) — the cookie below still works
  }
  // The cookie lets the server render the next page in this language straight
  // away, instead of flashing English first.
  document.cookie = `${LOCALE_STORAGE_KEY}=${locale}; path=/; max-age=${ONE_YEAR}; samesite=lax`;
}

/**
 * The site opens in English unless the visitor chose a language before. We do
 * not guess from the browser: a shared SOC workstation's browser language says
 * little about who is sitting at it, and the switcher is always one click away.
 */
export function LanguageProvider({
  children,
  initialLocale = DEFAULT_LOCALE,
}: {
  children: ReactNode;
  initialLocale?: Locale;
}) {
  const [locale, setLocaleState] = useState<Locale>(initialLocale);
  setApiLocale(locale);

  // Older visits stored the choice only in localStorage; carry it over.
  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(LOCALE_STORAGE_KEY);
      if (isLocale(saved) && saved !== initialLocale) {
        setLocaleState(saved);
        remember(saved);
      }
    } catch {
      // keep the server's choice
    }
  }, [initialLocale]);

  useEffect(() => {
    document.documentElement.lang = locale;
    setApiLocale(locale);
  }, [locale]);

  const setLocale = (next: Locale) => {
    setLocaleState(next);
    remember(next);
  };

  return (
    <LanguageContext.Provider value={{ locale, setLocale, t: translations[locale] }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const ctx = useContext(LanguageContext);
  if (!ctx) {
    throw new Error("useLanguage must be used within a LanguageProvider");
  }
  return ctx;
}
