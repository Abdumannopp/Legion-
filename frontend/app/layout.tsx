import type { Metadata } from "next";
import localFont from "next/font/local";
import { cookies } from "next/headers";
import "./globals.css";
import { LanguageProvider } from "@/lib/i18n/LanguageContext";
import { DEFAULT_LOCALE, isLocale, LOCALE_STORAGE_KEY } from "@/lib/i18n/core";
import { translations } from "@/lib/i18n/translations";
import { palette } from "@/lib/theme";

// Michroma (SIL Open Font License, app/fonts/Michroma-OFL.txt) — the wide
// geometric face of the Legion logo. Bundled rather than fetched from Google
// at build time, so an offline or firewalled server can still build Legion.
const display = localFont({
  src: "./fonts/Michroma-latin.woff2",
  variable: "--font-display",
  display: "swap",
  weight: "400",
});

// Michroma has no Cyrillic letters. Unbounded (also SIL OFL,
// app/fonts/Unbounded-OFL.txt) is a similarly wide face that covers them, so
// Russian headings keep the same look instead of dropping to the system font.
// Browsers take each character from the first font in the list that has it.
const displayCyrillic = localFont({
  src: "./fonts/Unbounded-cyrillic.woff2",
  variable: "--font-display-cyrillic",
  display: "swap",
  weight: "400",
  declarations: [{ prop: "unicode-range", value: "U+0400-045F, U+0490-0491, U+04B0-04B1, U+2116" }],
});

// Icons come from the file conventions in this folder: icon.svg (sharp
// favicon), icon.png, apple-icon.png.
async function savedLocale() {
  const saved = (await cookies()).get(LOCALE_STORAGE_KEY)?.value;
  return isLocale(saved) ? saved : DEFAULT_LOCALE;
}

export async function generateMetadata(): Promise<Metadata> {
  const m = translations[await savedLocale()].meta;
  return {
    title: m.title,
    description: m.description,
    applicationName: "Legion Cyber Intelligence", // i18n-ignore: product name
  };
}

export const viewport = { themeColor: palette.canvas, colorScheme: "dark" };

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // The visitor's chosen language, so the first paint is already in it.
  const locale = await savedLocale();
  return (
    <html lang={locale} className={`${display.variable} ${displayCyrillic.variable}`}>
      <body>
        <LanguageProvider initialLocale={locale}>{children}</LanguageProvider>
      </body>
    </html>
  );
}
