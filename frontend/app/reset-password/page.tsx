"use client";

import { FormEvent, Suspense, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { ApiError, resetPassword } from "@/lib/api";
import LegionLogo from "@/components/brand/LegionLogo";
import { AuthLanguageSwitcher } from "@/components/AuthShell";
import { useLanguage } from "@/lib/i18n/LanguageContext";

function ResetPasswordForm() {
  const router = useRouter();
  const { t } = useLanguage();
  const token = useSearchParams().get("token") || "";
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token) return setError(t.resetPassword.missingToken);
    setBusy(true);
    setError("");
    try {
      await resetPassword(token, password);
      router.replace("/login");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.resetPassword.failed);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="relative min-h-screen legion-backdrop flex flex-col items-center justify-center gap-8 p-6">
      <AuthLanguageSwitcher />
      <LegionLogo layout="stacked" size={84} tagline={false} />
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-line bg-surface p-6">
        <h1 className="legion-title text-ink mb-5">{t.resetPassword.title}</h1>
        <label className="block text-sm text-ink-soft mb-2" htmlFor="password">{t.resetPassword.newPassword}</label>
        <input id="password" type="password" minLength={8} required value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 text-ink outline-none focus:border-brand-hover" />
        {error && <p className="mt-3 text-sm text-critical">{error}</p>}
        <button disabled={busy || !token} className="mt-5 w-full rounded-lg bg-brand hover:bg-brand-hover py-2 text-white shadow-glow transition-colors disabled:opacity-50">
          {busy ? t.resetPassword.updating : t.resetPassword.update}
        </button>
      </form>
    </main>
  );
}

export default function ResetPasswordPage() {
  return <Suspense fallback={<main className="min-h-screen bg-canvas" />}><ResetPasswordForm /></Suspense>;
}
