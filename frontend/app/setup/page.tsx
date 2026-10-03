"use client";

/**
 * First-run setup: creates the first administrator of a self-hosted install.
 *
 * Every install guide said "open the dashboard and create the first
 * administrator", but no screen existed to do it. It also now requires the
 * one-time setup token printed on the server's console, which is what stops a
 * stranger who finds the server first from claiming it.
 */
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { KeyRound, Loader2 } from "lucide-react";
import { completeSetup, getSetupStatus, login, ApiError } from "@/lib/api";
import LegionLogo from "@/components/brand/LegionLogo";
import { AuthLanguageSwitcher } from "@/components/AuthShell";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { useTurnstile } from "@/components/Turnstile";

const input =
  "w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink outline-none focus:border-brand-hover";

export default function SetupPage() {
  const router = useRouter();
  const { t } = useLanguage();
  const [checking, setChecking] = useState(true);
  const [setupToken, setSetupToken] = useState("");
  const [organisation, setOrganisation] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const captcha = useTurnstile("setup");

  useEffect(() => {
    // Already set up (or hosted mode): this screen has nothing to offer.
    getSetupStatus()
      .then((s) => (s.setup_required ? setChecking(false) : router.replace("/login")))
      .catch(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await completeSetup({ setupToken, organisation, email, password }, captcha.token);
      // A security-check token is single-use; with Turnstile on, signing in
      // needs a fresh one, so the person signs in on the login page.
      if (captcha.enabled) { router.push("/login"); return; }
      const result = await login(email, password);
      router.push(result.mfaRequired ? "/login" : "/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.common.genericError);
    } finally {
      captcha.reset();
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div className="min-h-screen bg-canvas flex items-center justify-center">
        <Loader2 size={18} className="animate-spin text-ink-faint" />
      </div>
    );
  }

  return (
    <div className="relative min-h-screen legion-backdrop flex items-center justify-center p-4 font-sans">
      <AuthLanguageSwitcher />
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <LegionLogo layout="stacked" size={112} />
          <p className="legion-eyebrow text-ink-faint mt-4">
            {t.setup.eyebrow}
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-surface border border-line rounded-2xl p-6 space-y-4"
        >
          <div className="flex items-center gap-2 text-ink text-sm font-medium">
            <KeyRound size={16} className="text-brand-bright" />
            {t.setup.heading}
          </div>
          <p className="text-ink-muted text-xs leading-relaxed">
            {t.setup.tokenHelpBefore}
            {/* i18n-ignore: file name */}
            <code className="text-ink-soft">.legion-setup-token</code>
            {t.setup.tokenHelpAfter}
          </p>

          <div>
            <label className="text-ink-muted text-xs mb-1.5 block">{t.setup.tokenLabel}</label>
            <input
              value={setupToken}
              onChange={(e) => setSetupToken(e.target.value)}
              required
              autoFocus
              autoComplete="off"
              spellCheck={false}
              // i18n-ignore: token prefix
              placeholder="lst_…"
              className={`${input} font-mono`}
            />
          </div>
          <div>
            <label className="text-ink-muted text-xs mb-1.5 block">{t.setup.organisationLabel}</label>
            <input value={organisation} onChange={(e) => setOrganisation(e.target.value)}
              required minLength={2} maxLength={100} className={input} />
          </div>
          <div>
            <label className="text-ink-muted text-xs mb-1.5 block">{t.setup.emailLabel}</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              required autoComplete="username" className={input} />
          </div>
          <div>
            <label className="text-ink-muted text-xs mb-1.5 block">{t.auth.passwordWithMin(8)}</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)}
              required minLength={8} maxLength={128} autoComplete="new-password" className={input} />
          </div>

          {captcha.element}
          {(error || captcha.failed) && (
            <p className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2">{error ?? t.common.captchaUnavailable}</p>
          )}

          <button
            type="submit"
            disabled={loading || !captcha.ready}
            className="w-full flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover shadow-glow disabled:opacity-60 text-white font-medium text-sm py-2.5 rounded-lg transition-colors"
          >
            {loading && <Loader2 size={14} className="animate-spin" />}
            {t.setup.submit}
          </button>
        </form>
      </div>
    </div>
  );
}
