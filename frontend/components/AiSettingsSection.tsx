"use client";

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { ApiError, getAiSettings, updateAiSettings, type AiSettings } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/**
 * The organisation's control over AI analysis: whether its alert text may go to
 * the configured provider at all, and whether identifiers are masked first.
 * Everyone can see the state (and which third party would see the data); only
 * administrators can change it — the server enforces that, this only mirrors it.
 */
export default function AiSettingsSection({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useLanguage();
  const [s, setS] = useState<AiSettings | null>(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getAiSettings().then(setS).catch(() => setError(t.ai.settings.loadError));
  }, [t]);

  async function save(patch: { enabled?: boolean | null; data_mode?: "standard" | "strict" }) {
    setSaving(true);
    setMessage(null);
    setError(null);
    try {
      setS(await updateAiSettings(patch));
      setMessage(t.ai.settings.saved);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.ai.settings.loadError);
    } finally {
      setSaving(false);
    }
  }

  const choice = s ? (s.tenant_setting === null ? "default" : s.tenant_setting ? "on" : "off") : "default";

  return (
    <div className="rounded-xl border border-line bg-surface p-4 flex flex-col gap-3">
      <div>
        <h2 className="text-ink text-sm font-medium">{t.ai.settings.heading}</h2>
        <p className="text-ink-faint text-[11px] mt-1">{t.ai.settings.intro}</p>
      </div>

      {!s && !error && <Loader2 size={14} className="animate-spin text-ink-faint" />}
      {error && <p className="text-red-400 text-xs">{error}</p>}

      {s && (
        <>
          <p className="text-ink-muted text-xs">
            {s.provider ? t.ai.settings.provider(s.provider) : t.ai.settings.providerNone}
          </p>
          {s.circuit === "open" && <p className="text-amber-300 text-xs">{t.ai.settings.circuitOpen}</p>}

          <div>
            <label htmlFor="ai-enabled" className="text-ink-faint text-xs uppercase tracking-wide">
              {t.ai.settings.enabled}
            </label>
            <select
              id="ai-enabled"
              value={choice}
              disabled={!isAdmin || saving || !s.provider_configured}
              onChange={(e) => save({ enabled: e.target.value === "default" ? null : e.target.value === "on" })}
              className="mt-2 block bg-panel border border-line rounded-lg px-3 py-2 text-sm text-ink outline-none focus:border-brand-hover disabled:opacity-60"
            >
              <option value="default">{t.ai.settings.stateDefault(s.default_enabled)}</option>
              <option value="on">{t.ai.settings.stateOn}</option>
              <option value="off">{t.ai.settings.stateOff}</option>
            </select>
          </div>

          <label className="flex items-start gap-2 text-sm text-ink">
            <input
              type="checkbox"
              checked={s.data_mode === "strict"}
              disabled={!isAdmin || saving}
              onChange={(e) => save({ data_mode: e.target.checked ? "strict" : "standard" })}
              className="mt-1"
            />
            <span>
              {t.ai.settings.strict}
              <span className="block text-ink-faint text-[11px]">{t.ai.settings.strictHint}</span>
            </span>
          </label>

          {!isAdmin && <p className="text-ink-faint text-[11px]">{t.ai.settings.adminOnly}</p>}
          {message && <p className="text-ink-muted text-xs">{message}</p>}
        </>
      )}
    </div>
  );
}
