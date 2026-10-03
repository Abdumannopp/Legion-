"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { Loader2 } from "lucide-react";
import AuthShell, { authButton, authInput } from "@/components/AuthShell";
import { ApiError, forgotPassword } from "@/lib/api";
import { useTurnstile } from "@/components/Turnstile";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export default function ForgotPasswordPage() {
  const { t } = useLanguage();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const captcha = useTurnstile("reset");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // The server answers the same whether or not the address exists.
      await forgotPassword(email.trim(), captcha.token);
      setSent(true);
    } catch (err) {
      // Only the security check is worth reporting; anything else keeps the
      // same answer as success, so the page never reveals whether an account exists.
      if (err instanceof ApiError && err.code?.startsWith("captcha_")) setError(err.message);
      else setSent(true);
    } finally {
      captcha.reset();
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title={t.forgotPassword.title}
      footer={<Link href="/login" className="text-xs text-ink-faint hover:text-ink-muted">← {t.auth.backToSignIn}</Link>}
    >
      {sent ? (
        <p className="text-ink-muted text-sm leading-relaxed">
          {t.forgotPassword.sentBefore}
          <span className="text-ink">{email}</span>
          {t.forgotPassword.sentAfter}
        </p>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <p className="text-ink-muted text-xs leading-relaxed">{t.forgotPassword.intro}</p>
          <input type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
            // i18n-ignore: example email address
            autoComplete="email" placeholder="you@company.com" className={authInput} />
          {captcha.element}
          {(error || captcha.failed) && (
            <p className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2">{error ?? t.common.captchaUnavailable}</p>
          )}
          <button type="submit" disabled={busy || !captcha.ready} className={authButton}>
            {busy && <Loader2 size={14} className="animate-spin" />}
            {t.forgotPassword.sendLink}
          </button>
        </form>
      )}
    </AuthShell>
  );
}
