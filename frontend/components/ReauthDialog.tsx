"use client";

import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { ApiError, setReauthHandler, stepUp } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const input =
  "w-full bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover";

/**
 * Asks for the password (and the authenticator code when MFA is on) when the server refuses a dangerous
 * action with "reauth_required". Mounted once, in the root layout; lib/api.ts retries the action after
 * a successful confirmation. The password goes only to POST /auth/step-up and is never kept.
 */
export default function ReauthDialog() {
  const { t } = useLanguage();
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const settle = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    setReauthHandler(() => new Promise<boolean>((resolve) => {
      settle.current = resolve;
      setPassword(""); setCode(""); setError(""); setNeedCode(false); setOpen(true);
    }));
    return () => setReauthHandler(null);
  }, []);

  function finish(ok: boolean) {
    setOpen(false); setPassword(""); setCode("");
    settle.current?.(ok); settle.current = null;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError("");
    try {
      await stepUp(password, needCode ? code : undefined);
      finish(true);
    } catch (err) {
      if (err instanceof ApiError && err.code === "mfa_code_required") { setNeedCode(true); setError(t.reauth.needCode); }
      else if (err instanceof ApiError && err.status === 400) setError(t.reauth.wrongPassword);
      else setError(t.reauth.failed);
    } finally {
      setBusy(false);
    }
  }

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
      <form onSubmit={submit} className="w-full max-w-sm rounded-xl border border-line bg-surface p-5 space-y-3">
        <h2 id="reauth-title" className="flex items-center gap-2 text-sm font-semibold text-ink"><ShieldCheck size={16} /> {t.reauth.title}</h2>
        <p className="text-xs text-ink-muted">{t.reauth.intro}</p>
        <label className="block text-xs text-ink-muted">
          {t.reauth.password}
          <input type="password" autoComplete="current-password" autoFocus required className={input} value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {needCode && (
          <label className="block text-xs text-ink-muted">
            {t.reauth.code}
            <input inputMode="numeric" autoComplete="one-time-code" required className={input} value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
        )}
        {error && <p className="text-xs text-red-400" role="alert">{error}</p>}
        <div className="flex justify-end gap-2 pt-1">
          <button type="button" onClick={() => finish(false)} className="text-xs text-ink-faint hover:text-ink-muted px-3 py-2">{t.reauth.cancel}</button>
          <button type="submit" disabled={busy || !password} className="bg-brand hover:bg-brand-hover disabled:opacity-60 text-white text-xs font-medium px-3 py-2 rounded-lg">{t.reauth.confirm}</button>
        </div>
      </form>
    </div>
  );
}
