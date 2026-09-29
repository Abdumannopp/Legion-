"use client";

import Link from "next/link";
import { Suspense, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import AuthShell, { authButton } from "@/components/AuthShell";
import { ApiError, verifyEmail } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

function VerifyEmail() {
  const { t } = useLanguage();
  const token = useSearchParams().get("token") || "";
  const [state, setState] = useState<"working" | "done" | "failed">("working");
  // The server's own (already translated) message, or which fallback to show.
  const [message, setMessage] = useState<string | { fallback: "missingToken" | "failed" }>("");
  const started = useRef(false);

  useEffect(() => {
    // React may run effects twice in development; the link works only once.
    if (started.current) return;
    started.current = true;
    if (!token) {
      setState("failed");
      setMessage({ fallback: "missingToken" });
      return;
    }
    verifyEmail(token)
      .then(() => setState("done"))
      .catch((err) => {
        setState("failed");
        setMessage(err instanceof ApiError ? err.message : { fallback: "failed" });
      });
  }, [token]);

  if (state === "working") {
    return (
      <AuthShell title={t.verifyEmail.confirming}>
        <Loader2 size={20} className="animate-spin text-ink-faint" />
      </AuthShell>
    );
  }
  if (state === "done") {
    return (
      <AuthShell title={t.verifyEmail.confirmedTitle}>
        <div className="flex gap-3">
          <CheckCircle2 size={20} className="text-success shrink-0 mt-0.5" />
          <p className="text-ink-muted text-sm leading-relaxed">{t.verifyEmail.confirmedBody}</p>
        </div>
        <Link href="/login" className={`${authButton} mt-5`}>{t.common.signIn}</Link>
      </AuthShell>
    );
  }
  return (
    <AuthShell title={t.verifyEmail.invalidTitle}>
      <div className="flex gap-3">
        <XCircle size={20} className="text-critical shrink-0 mt-0.5" />
        <p className="text-ink-muted text-sm leading-relaxed">
          {typeof message === "string" ? message : t.verifyEmail[message.fallback]}
        </p>
      </div>
      <Link href="/login" className={`${authButton} mt-5`}>{t.verifyEmail.signInForNewLink}</Link>
    </AuthShell>
  );
}

export default function VerifyEmailPage() {
  return <Suspense fallback={<main className="min-h-screen bg-canvas" />}><VerifyEmail /></Suspense>;
}
