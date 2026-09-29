"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { Loader2, MailCheck } from "lucide-react";
import AuthShell, { authButton, authInput } from "@/components/AuthShell";
import { ApiError, DeploymentMode, getSetupStatus, resendVerification, signUp } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export default function SignUpPage() {
  const { t } = useLanguage();
  const [mode, setMode] = useState<DeploymentMode | null>(null);
  const [trialDays, setTrialDays] = useState(14);
  const [company, setCompany] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [agreed, setAgreed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const [resent, setResent] = useState(false);

  useEffect(() => {
    getSetupStatus().then((s) => { setMode(s.deployment_mode ?? "self-hosted"); if (s.trial_days) setTrialDays(s.trial_days); }).catch(() => setMode("self-hosted"));
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await signUp({ company: company.trim(), email: email.trim(), password });
      setSentTo(email.trim());
      setPassword("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.signup.createFailed);
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    if (!sentTo) return;
    await resendVerification(sentTo).catch(() => {});
    setResent(true);
  }

  if (mode === "self-hosted") {
    return (
      <AuthShell title={t.signup.closed.title}>
        <p className="text-ink-muted text-sm leading-relaxed">
          {t.signup.closed.body}
        </p>
        <Link href="/login" className="block mt-5 text-brand-bright text-sm">{t.auth.goToSignIn} →</Link>
      </AuthShell>
    );
  }

  if (sentTo) {
    return (
      <AuthShell title={t.signup.checkEmail.title}>
        <div className="flex gap-3">
          <MailCheck size={20} className="text-brand-bright shrink-0 mt-0.5" />
          <p className="text-ink-muted text-sm leading-relaxed">
            {t.signup.checkEmail.sentBefore}
            <span className="text-ink">{sentTo}</span>
            {t.signup.checkEmail.sentAfter}
          </p>
        </div>
        <button onClick={resend} disabled={resent} className="mt-5 text-xs text-ink-faint hover:text-ink-muted disabled:opacity-60">
          {resent ? t.signup.checkEmail.resent : t.signup.checkEmail.resend}
        </button>
        <Link href="/login" className={`${authButton} mt-5`}>{t.auth.goToSignIn}</Link>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title={t.signup.title}
      footer={
        <p className="text-xs text-ink-faint">
          {t.signup.haveAccount} <Link href="/login" className="text-brand-bright">{t.common.signIn}</Link>
        </p>
      }
    >
      <p className="text-ink-muted text-xs leading-relaxed mb-5">
        {t.signup.trialNote(trialDays)}
      </p>
      <form onSubmit={submit} className="space-y-4">
        <div>
          <label htmlFor="company" className="text-ink-muted text-xs mb-1.5 block">{t.signup.companyLabel}</label>
          <input id="company" required minLength={2} maxLength={100} value={company}
            onChange={(e) => setCompany(e.target.value)} autoComplete="organization" className={authInput} />
        </div>
        <div>
          <label htmlFor="email" className="text-ink-muted text-xs mb-1.5 block">{t.signup.emailLabel}</label>
          <input id="email" type="email" required value={email}
            onChange={(e) => setEmail(e.target.value)} autoComplete="email" className={authInput} />
        </div>
        <div>
          <label htmlFor="password" className="text-ink-muted text-xs mb-1.5 block">{t.auth.passwordWithMin(8)}</label>
          <input id="password" type="password" required minLength={8} maxLength={128} value={password}
            onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" className={authInput} />
        </div>
        <label className="flex items-start gap-2 text-xs text-ink-muted leading-relaxed">
          <input type="checkbox" required checked={agreed} onChange={(e) => setAgreed(e.target.checked)}
            className="mt-0.5 accent-brand" />
          <span>
            {t.signup.agree.before}
            <Link href="/terms" className="text-brand-bright">{t.signup.agree.terms}</Link>
            {t.signup.agree.and}
            <Link href="/privacy" className="text-brand-bright">{t.signup.agree.privacy}</Link>
            {t.signup.agree.after}
          </span>
        </label>
        {error && <p className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2">{error}</p>}
        <button type="submit" disabled={busy || mode === null} className={authButton}>
          {busy && <Loader2 size={14} className="animate-spin" />}
          {t.signup.createAccount}
        </button>
      </form>
    </AuthShell>
  );
}
