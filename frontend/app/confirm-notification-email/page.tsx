"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import AuthShell, { authButton } from "@/components/AuthShell";
import { ApiError, confirmNotificationEmail } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/**
 * The recipient of a "receive alerts?" email lands here. Confirmation takes a
 * click on purpose: mail scanners that open links must not be able to confirm
 * an address on the recipient's behalf.
 */
function ConfirmNotification() {
  const { t } = useLanguage();
  const token = useSearchParams().get("token") || "";
  const [state, setState] = useState<"ask" | "working" | "done" | "failed">(token ? "ask" : "failed");
  const [message, setMessage] = useState<string | null>(token ? null : t.confirmNotification.missingToken);

  async function confirm() {
    setState("working");
    try {
      await confirmNotificationEmail(token);
      setState("done");
    } catch (err) {
      setState("failed");
      setMessage(err instanceof ApiError ? err.message : t.confirmNotification.failed);
    }
  }

  if (state === "done") {
    return (
      <AuthShell title={t.confirmNotification.confirmedTitle}>
        <CheckCircle2 size={20} className="text-success" />
      </AuthShell>
    );
  }
  if (state === "failed") {
    return (
      <AuthShell title={t.confirmNotification.invalidTitle}>
        <div className="flex gap-3">
          <XCircle size={20} className="text-critical shrink-0 mt-0.5" />
          <p className="text-ink-muted text-sm leading-relaxed">{message ?? t.confirmNotification.failed}</p>
        </div>
      </AuthShell>
    );
  }
  return (
    <AuthShell title={t.confirmNotification.title}>
      <p className="text-ink-muted text-sm leading-relaxed">{t.confirmNotification.body}</p>
      <button type="button" onClick={confirm} disabled={state === "working"} className={`${authButton} mt-5`}>
        {state === "working" ? <Loader2 size={16} className="animate-spin" /> : t.confirmNotification.confirm}
      </button>
      <p className="text-ink-faint text-xs mt-4">{t.confirmNotification.ignoreHint}</p>
    </AuthShell>
  );
}

export default function ConfirmNotificationPage() {
  return <Suspense fallback={<main className="min-h-screen bg-canvas" />}><ConfirmNotification /></Suspense>;
}
