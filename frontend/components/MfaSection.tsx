"use client";

import { useCallback, useEffect, useState } from "react";
import { Loader2, ShieldCheck, ShieldOff, Copy, Check, AlertTriangle } from "lucide-react";
import {
  ApiError, MfaStatus, disableMfa, enableMfa, getMfaStatus,
  regenerateRecoveryCodes, startMfaSetup,
} from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const input =
  "w-full bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover";
const primary =
  "flex items-center justify-center gap-2 bg-brand hover:bg-brand-hover disabled:opacity-60 text-white font-medium text-xs px-3 py-2 rounded-lg transition-colors";
const ghost =
  "text-ink-faint hover:text-ink-muted text-[11px] transition-colors";

/**
 * Recovery codes are readable exactly once — the server keeps only bcrypt
 * hashes. This panel therefore refuses to disappear until the user confirms
 * they have saved them.
 */
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useLanguage();
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard can be blocked; the codes are on screen to copy by hand.
    }
  }

  return (
    <div className="rounded-xl border border-warning/40 bg-warning/5 p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <AlertTriangle size={14} color={palette.warning} />
        <h3 className="text-ink text-sm font-medium">{t.mfa.recovery.heading}</h3>
      </div>
      <p className="text-ink-muted text-[11px] leading-relaxed">
        {t.mfa.recovery.body}
      </p>

      <div className="grid grid-cols-2 gap-1.5 font-mono text-xs text-ink">
        {codes.map((code) => (
          <div key={code} className="bg-panel border border-line rounded px-2 py-1.5 text-center">
            {code}
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2">
        <button type="button" onClick={copy} className={primary}>
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? t.common.copied : t.mfa.recovery.copyAll}
        </button>
      </div>

      <label className="flex items-center gap-2 text-ink-muted text-[11px] cursor-pointer">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="accent-brand"
        />
        {t.mfa.recovery.confirmSaved}
      </label>

      <button type="button" onClick={onDone} disabled={!confirmed} className={primary}>
        {t.mfa.recovery.done}
      </button>
    </div>
  );
}

export default function MfaSection() {
  const { t } = useLanguage();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Enrolment
  const [setupUri, setSetupUri] = useState<string | null>(null);
  const [setupSecret, setSetupSecret] = useState<string | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  // Disable / regenerate
  const [password, setPassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [showDisable, setShowDisable] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setStatus(await getMfaStatus());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.mfa.errors.loadStatus);
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => { void refresh(); }, [refresh]);

  function reset() {
    setSetupUri(null); setSetupSecret(null); setConfirmCode("");
    setPassword(""); setDisableCode(""); setShowDisable(false);
    setError(null);
  }

  async function handleStartSetup() {
    setBusy(true); setError(null);
    try {
      const res = await startMfaSetup();
      setSetupUri(res.otpauth_uri);
      setSetupSecret(res.secret);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.mfa.errors.startSetup);
    } finally { setBusy(false); }
  }

  async function handleConfirm(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const res = await enableMfa(confirmCode.trim());
      setRecoveryCodes(res.recovery_codes);
      reset();
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.mfa.errors.enable);
    } finally { setBusy(false); }
  }

  async function handleDisable(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      await disableMfa(password, disableCode.trim());
      reset();
      setNotice(t.mfa.disabledNotice);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.mfa.errors.disable);
    } finally { setBusy(false); }
  }

  async function handleRegenerate(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const res = await regenerateRecoveryCodes(password);
      setRecoveryCodes(res.recovery_codes);
      reset();
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.mfa.errors.regenerate);
    } finally { setBusy(false); }
  }

  if (loading) {
    return (
      <div className="rounded-xl border border-line bg-surface p-4 flex items-center gap-2 text-ink-faint text-xs">
        <Loader2 size={14} className="animate-spin" /> {t.common.loading}
      </div>
    );
  }

  if (recoveryCodes) {
    return <RecoveryCodes codes={recoveryCodes} onDone={() => setRecoveryCodes(null)} />;
  }

  return (
    <div className="rounded-xl border border-line bg-surface p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        {status?.enabled
          ? <ShieldCheck size={14} color={palette.success} />
          : <ShieldOff size={14} color={palette.inkFaint} />}
        <h2 className="text-ink text-sm font-medium">{t.mfa.heading}</h2>
        {status?.enabled && (
          <span className="ml-auto text-[10px] text-success bg-success/10 px-2 py-0.5 rounded">
            {t.mfa.onBadge}
          </span>
        )}
      </div>

      {error && (
        <p className="text-critical text-[11px] bg-critical/10 rounded-lg px-3 py-2">{error}</p>
      )}
      {notice && (
        <p className="text-ink-muted text-[11px] bg-line/60 rounded-lg px-3 py-2">{notice}</p>
      )}

      {/* --- Not enabled --- */}
      {!status?.enabled && !setupUri && (
        <>
          <p className="text-ink-faint text-[11px] leading-relaxed">
            {t.mfa.intro}
          </p>
          <button type="button" onClick={handleStartSetup} disabled={busy} className={`${primary} self-start`}>
            {busy && <Loader2 size={12} className="animate-spin" />}
            {t.mfa.setUp}
          </button>
        </>
      )}

      {/* --- Enrolling --- */}
      {setupUri && (
        <form onSubmit={handleConfirm} className="flex flex-col gap-3">
          <p className="text-ink-muted text-[11px] leading-relaxed">
            {t.mfa.enrolHint}
          </p>

          <div>
            <p className="text-ink-faint text-[10px] mb-1">{t.mfa.setupKey}</p>
            <code className="block bg-panel border border-line rounded-lg px-3 py-2 text-[11px] text-ink font-mono break-all">
              {setupSecret}
            </code>
          </div>

          <input
            value={confirmCode}
            onChange={(e) => setConfirmCode(e.target.value)}
            placeholder="000000"
            required
            maxLength={6}
            inputMode="numeric"
            autoComplete="one-time-code"
            className={`${input} text-center tracking-[0.3em] font-mono`}
          />

          <div className="flex items-center gap-3">
            <button type="submit" disabled={busy} className={primary}>
              {busy && <Loader2 size={12} className="animate-spin" />}
              {t.mfa.verifyAndEnable}
            </button>
            <button type="button" onClick={reset} className={ghost}>{t.common.cancel}</button>
          </div>
        </form>
      )}

      {/* --- Enabled --- */}
      {status?.enabled && !showDisable && (
        <>
          <p className="text-ink-faint text-[11px]">
            {t.mfa.codesRemaining(status.recovery_codes_remaining)}
            {status.recovery_codes_remaining <= 2 && (
              <span className="text-warning"> {t.mfa.generateSoon}</span>
            )}
          </p>

          <form onSubmit={handleRegenerate} className="flex flex-col gap-2">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t.mfa.passwordForCodes}
              autoComplete="current-password"
              className={input}
            />
            <div className="flex items-center gap-3">
              <button type="submit" disabled={busy || !password} className={primary}>
                {busy && <Loader2 size={12} className="animate-spin" />}
                {t.mfa.newCodes}
              </button>
              <button type="button" onClick={() => { setShowDisable(true); setPassword(""); }} className={ghost}>
                {t.mfa.turnOff}
              </button>
            </div>
          </form>
        </>
      )}

      {/* --- Disabling --- */}
      {status?.enabled && showDisable && (
        <form onSubmit={handleDisable} className="flex flex-col gap-2">
          <p className="text-ink-muted text-[11px] leading-relaxed">
            {t.mfa.disableHint}
          </p>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t.common.password}
            required
            autoComplete="current-password"
            className={input}
          />
          <input
            value={disableCode}
            onChange={(e) => setDisableCode(e.target.value)}
            placeholder={t.mfa.codePlaceholder}
            required
            autoComplete="one-time-code"
            className={input}
          />
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={busy}
              className="flex items-center justify-center gap-2 bg-critical hover:bg-critical-hover disabled:opacity-60 text-white font-medium text-xs px-3 py-2 rounded-lg transition-colors"
            >
              {busy && <Loader2 size={12} className="animate-spin" />}
              {t.mfa.turnOffTwoFactor}
            </button>
            <button type="button" onClick={reset} className={ghost}>{t.common.cancel}</button>
          </div>
        </form>
      )}
    </div>
  );
}
