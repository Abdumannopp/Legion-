/**
 * All interface text, per language, assembled from the namespace files in
 * ./ns. Components read it through `useLanguage().t` — e.g. `t.nav.alerts`.
 * To add text: put it in the namespace file of the screen that shows it, in
 * all three languages (TypeScript refuses the build otherwise).
 */
import type { Locale, Messages } from "./core";
import { common } from "./ns/common";
import { nav } from "./ns/nav";
import { footer } from "./ns/footer";
import { legalPage } from "./ns/legalPage";
import { support } from "./ns/support";
import { dashboard } from "./ns/dashboard";
import { incidents } from "./ns/incidents";
import { incident } from "./ns/incident";
import { settings } from "./ns/settings";
import { mfa } from "./ns/mfa";
import { accessBanner } from "./ns/accessBanner";
import { assets } from "./ns/assets";
import { copilot } from "./ns/copilot";
import { ai } from "./ns/ai";
import { reports } from "./ns/reports";
import { billing } from "./ns/billing";
import { auth } from "./ns/auth";
import { login } from "./ns/login";
import { signup } from "./ns/signup";
import { verifyEmail } from "./ns/verifyEmail";
import { confirmNotification } from "./ns/confirmNotification";
import { forgotPassword } from "./ns/forgotPassword";
import { resetPassword } from "./ns/resetPassword";
import { acceptInvite } from "./ns/acceptInvite";
import { setup } from "./ns/setup";
import { site } from "./ns/site";
import { pricing } from "./ns/pricing";
import { notFound } from "./ns/notFound";
import { meta } from "./ns/meta";
import { workspaces } from "./ns/workspaces";
import { errors } from "./ns/errors";
import { agents } from "./ns/agents";
import { overview } from "./ns/overview";
import { connect } from "./ns/connect";

export { LOCALES, DEFAULT_LOCALE, isLocale } from "./core";
export type { Locale } from "./core";

const namespaces = {
  common,
  nav,
  footer,
  legal: legalPage,
  support,
  dashboard,
  incidents,
  incident,
  settings,
  mfa,
  accessBanner,
  assets,
  copilot,
  ai,
  reports,
  billing,
  auth,
  login,
  signup,
  verifyEmail,
  confirmNotification,
  forgotPassword,
  resetPassword,
  acceptInvite,
  setup,
  site,
  pricing,
  notFound,
  meta,
  workspaces,
  errors,
  agents,
  overview,
  connect,
};

type Namespaces = typeof namespaces;
export type Translations = { [K in keyof Namespaces]: Namespaces[K][Locale] };

function build(locale: Locale): Translations {
  const out: Record<string, unknown> = {};
  for (const [name, ns] of Object.entries(namespaces)) {
    out[name] = (ns as Record<Locale, unknown>)[locale];
  }
  return out as Translations;
}

export const translations: Record<Locale, Translations> = {
  en: build("en"),
  ru: build("ru"),
  uz: build("uz"),
};

export type { Messages };
