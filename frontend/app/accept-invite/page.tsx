"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Loader2, CheckCircle2 } from "lucide-react";
import { getInvite, acceptInvite, InvitePreview, ApiError } from "@/lib/api";
import { palette } from "@/lib/theme";
import LegionLogo from "@/components/brand/LegionLogo";
import { AuthLanguageSwitcher } from "@/components/AuthShell";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const MIN_PASSWORD = 8;

function AcceptInviteForm() {
  const router = useRouter();
  const { t } = useLanguage();
  const token = useSearchParams().get("token") || "";

  const [invite, setInvite] = useState<InvitePreview | null>(null);
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // A message to show: the server's own (already translated) text, or which
  // of our fallbacks applies when the invitation could not be loaded.
  const [error, setError] = useState<string | { fallback: "missingToken" | "loadFailed" } | null>(null);
  const errorText =
    error === null ? null : typeof error === "string" ? error : t.acceptInvite[error.fallback];
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!token) {
      setError({ fallback: "missingToken" });
      setLoading(false);
      return;
    }
    getInvite(token)
      .then(setInvite)
      .catch((err) =>
        setError(
          err instanceof ApiError
            ? err.message
            : { fallback: "loadFailed" }
        )
      )
      .finally(() => setLoading(false));
  }, [token]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < MIN_PASSWORD) {
      setError(t.acceptInvite.passwordTooShort(MIN_PASSWORD));
      return;
    }
    if (password !== confirm) {
      setError(t.acceptInvite.passwordMismatch);
      return;
    }

    setSubmitting(true);
    try {
      await acceptInvite(token, password);
      setDone(true);
      setTimeout(() => router.push("/login"), 1800);
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : t.acceptInvite.setupFailed
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative min-h-screen legion-backdrop flex items-center justify-center p-4 font-sans">
      <AuthLanguageSwitcher />
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <LegionLogo layout="stacked" size={100} />
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-16 text-ink-faint">
            <Loader2 size={20} className="animate-spin" />
          </div>
        ) : done ? (
          <div className="bg-surface border border-line rounded-2xl p-6 text-center">
            <CheckCircle2 size={28} className="mx-auto mb-3" color={palette.success} />
            <h2 className="text-ink font-semibold text-lg">
              {t.acceptInvite.readyTitle}
            </h2>
            <p className="text-ink-muted text-sm mt-2">
              {t.acceptInvite.redirecting}
            </p>
          </div>
        ) : !invite ? (
          <div className="bg-surface border border-line rounded-2xl p-6 text-center">
            <h2 className="text-ink font-semibold text-lg">
              {t.acceptInvite.invalidTitle}
            </h2>
            <p className="text-ink-muted text-sm mt-2">
              {errorText || t.acceptInvite.invalidReason}
            </p>
            <p className="text-ink-faint text-xs mt-4">
              {t.acceptInvite.askAdmin}
            </p>
            <Link
              href="/login"
              className="inline-block mt-5 text-brand-bright text-sm hover:underline"
            >
              {t.auth.backToSignIn}
            </Link>
          </div>
        ) : (
          <>
            <div className="text-center mb-6">
              <h2 className="text-ink font-semibold text-xl tracking-tight">
                {t.acceptInvite.join(invite.tenant_name || "Legion")}
              </h2>
              <p className="text-ink-muted text-sm mt-2">
                {t.acceptInvite.intro.before}
                <span className="text-ink">{invite.email}</span>
                {t.acceptInvite.intro.middle}
                <span className="text-ink">{t.common.role[invite.role]}</span>
                {t.acceptInvite.intro.after}
              </p>
            </div>

            <form
              onSubmit={handleSubmit}
              className="bg-surface border border-line rounded-2xl p-6 space-y-4"
            >
              <div>
                <label className="text-ink-muted text-xs mb-1.5 block">
                  {t.common.password}
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  minLength={MIN_PASSWORD}
                  autoComplete="new-password"
                  className="w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink outline-none focus:border-brand-hover"
                />
                <p className="text-ink-faint text-[11px] mt-1.5">
                  {t.auth.passwordHint(MIN_PASSWORD)}
                </p>
              </div>

              <div>
                <label className="text-ink-muted text-xs mb-1.5 block">
                  {t.acceptInvite.confirmPassword}
                </label>
                <input
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  autoComplete="new-password"
                  className="w-full bg-canvas border border-line rounded-lg px-3 py-2.5 text-sm text-ink outline-none focus:border-brand-hover"
                />
              </div>

              {errorText && (
                <p className="text-critical text-xs bg-critical/10 rounded-lg px-3 py-2">
                  {errorText}
                </p>
              )}

              <button
                type="submit"
                disabled={submitting}
                className="w-full flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover shadow-glow text-white text-sm font-medium rounded-lg py-2.5 transition-colors disabled:opacity-60"
              >
                {submitting && <Loader2 size={14} className="animate-spin" />}
                {t.acceptInvite.submit}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

export default function AcceptInvitePage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-canvas flex items-center justify-center">
          <Loader2 size={20} className="animate-spin text-ink-faint" />
        </div>
      }
    >
      <AcceptInviteForm />
    </Suspense>
  );
}
