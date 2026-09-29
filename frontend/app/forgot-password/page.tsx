"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { Loader2 } from "lucide-react";
import AuthShell, { authButton, authInput } from "@/components/AuthShell";
import { forgotPassword } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export default function ForgotPasswordPage() {
  const { t } = useLanguage();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    // The server answers the same whether or not the address exists.
    await forgotPassword(email.trim()).catch(() => {});
    setBusy(false);
    setSent(true);
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
          <button type="submit" disabled={busy} className={authButton}>
            {busy && <Loader2 size={14} className="animate-spin" />}
            {t.forgotPassword.sendLink}
          </button>
        </form>
      )}
    </AuthShell>
  );
}
