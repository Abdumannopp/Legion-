"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Loader2, ShieldCheck } from "lucide-react";
import { getSetupStatus, login, resendVerification, verifyMfa, ApiError, DeploymentMode } from "@/lib/api";
import LegionLogo from "@/components/brand/LegionLogo";
import { AuthLanguageSwitcher } from "@/components/AuthShell";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export default function LoginPage() {
  const router = useRouter();
  const { t } = useLanguage();

  // A brand-new self-hosted install has no accounts to sign in to; send the
  // operator to first-run setup instead of a login form that cannot work.
  const [mode, setMode] = useState<DeploymentMode | null>(null);
  useEffect(() => {
    getSetupStatus()
      .then((s) => {
        if (s.setup_required) router.replace("/setup");
        setMode(s.deployment_mode ?? "self-hosted");
      })
      .catch(() => {});
  }, [router]);

  // Signed up but hasn't clicked the emailed link yet.
  const [unverified, setUnverified] = useState(false);
  const [resent, setResent] = useState(false);
  // Deliberately blank: pre-filling the demo account trains people to expect
  // it to exist, and it must not exist on a production install.
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Set once the password is accepted but a second factor is still needed.
  // Holding it in state (never in storage) means it dies with the page.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await login(email, password);
      if (result.mfaRequired) {
        setMfaToken(result.mfaToken);
        setPassword(""); // no longer needed; don't keep it in memory
      } else {
        router.push("/");
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.common.genericError);
      setUnverified(err instanceof ApiError && err.code === "email_unverified");
      setResent(false);
    } finally {
      setLoading(false);
    }
  }

  async function handleMfaSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await verifyMfa(mfaToken!, mfaCode.trim(), useRecovery ? "recovery" : "code");
      router.push("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.common.genericError);
      setMfaCode("");
      // The challenge token is short-lived; if it has expired the only way
      // forward is to start again rather than retry into a dead token.
      if (err instanceof ApiError && err.status === 401 && err.code === "mfa_expired") {
        setMfaToken(null);
      }
    } finally {
      setLoading(false);
    }
  }

  function backToPassword() {
    setMfaToken(null);
    setMfaCode("");
    setUseRecovery(false);
    setError(null);
  }

  return (
    <div className="relative min-h-screen legion-backdrop flex items-center justify-center p-4 font-sans">
      <AuthLanguageSwitcher />
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <LegionLogo layout="stacked" size={112} />
          <p className="legion-eyebrow text-ink-faint mt-4">
            {t.login.eyebrow}
          </p>
        </div>

        <div className="text-center mb-8">
          <h2 className="text-ink font-semibold text-2xl tracking-tight leading-snug">
            {t.login.headline.line1}
            <br />
            {t.login.headline.line2}
          </h2>
          <p className="text-ink-muted text-sm mt-3 leading-relaxed">
            {t.login.intro}
          </p>
        </div>

        {mfaToken ? (
          <form
            onSubmit={handleMfaSubmit}
            className="bg-surface border border-line rounded-2xl p-6 space-y-4"
          >
            <div className="flex items-center gap-2 text-ink text-sm font-medium">
              <ShieldCheck size={16} className="text-brand-bright" />
              {t.login.mfa.title}
            </div>
            <p className="text-ink-muted text-xs leading-relaxed">
              {useRecovery
                ? t.login.mfa.recoveryHelp
                : t.login.mfa.codeHelp}
            </p>

            <div>
              <label className="text-ink-muted text-xs mb-1.5 block">
                {useRecovery ? t.login.mfa.recoveryLabel : t.login.mfa.codeLabel}
              </label>
              <input
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                required
                autoFocus
                autoComplete="one-time-code"
                inputMode={useRecovery ? "text" : "numeric"}
                // i18n-ignore: code format mask, not words
                placeholder={useRecovery ? "XXXXX-XXXXX" : "000000"}
                maxLength={useRecovery ? 12 : 6}
                className="w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink outline-none focus:border-brand-hover tracking-[0.3em] text-center font-mono"
              />
            </div>

            {error && (
              <p className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover shadow-glow disabled:opacity-60 text-white font-medium text-sm py-2.5 rounded-lg transition-colors"
            >
              {loading && <Loader2 size={14} className="animate-spin" />}
              {t.login.mfa.verify}
            </button>

            <div className="flex items-center justify-between gap-3 pt-1">
              <button
                type="button"
                onClick={() => { setUseRecovery(!useRecovery); setMfaCode(""); setError(null); }}
                className="text-left text-ink-faint hover:text-ink-muted text-[11px] transition-colors"
              >
                {useRecovery ? t.login.mfa.useApp : t.login.mfa.useRecovery}
              </button>
              <button
                type="button"
                onClick={backToPassword}
                className="text-ink-faint hover:text-ink-muted text-[11px] transition-colors"
              >
                {t.common.back}
              </button>
            </div>
          </form>
        ) : (
          <form
            onSubmit={handleSubmit}
            className="bg-surface border border-line rounded-2xl p-6 space-y-4"
          >
            <div>
              <label className="text-ink-muted text-xs mb-1.5 block">{t.common.email}</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="username"
                className="w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink outline-none focus:border-brand-hover"
              />
            </div>
            <div>
              <label className="text-ink-muted text-xs mb-1.5 block">{t.common.password}</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                className="w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink outline-none focus:border-brand-hover"
              />
            </div>

            {error && (
              <div className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2">
                {error}
                {unverified && (
                  <button
                    type="button"
                    disabled={resent}
                    onClick={async () => { await resendVerification(email).catch(() => {}); setResent(true); }}
                    className="block mt-1.5 text-brand-bright hover:text-ink disabled:text-ink-muted"
                  >
                    {resent ? t.login.confirmationResent : t.login.resendConfirmation}
                  </button>
                )}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover shadow-glow disabled:opacity-60 text-white font-medium text-sm py-2.5 rounded-lg transition-colors"
            >
              {loading && <Loader2 size={14} className="animate-spin" />}
              {t.common.signIn}
            </button>
            <div className="flex justify-between gap-3 text-[11px] pt-1">
              <Link href="/forgot-password" className="text-ink-faint hover:text-ink-muted">{t.login.forgotPassword}</Link>
              {mode === "saas" && (
                <Link href="/signup" className="text-brand-bright hover:text-ink">{t.login.startTrial}</Link>
              )}
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
