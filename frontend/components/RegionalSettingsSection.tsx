"use client";

import { useEffect, useMemo, useState } from "react";
import { Loader2 } from "lucide-react";
import {
  ApiError, getMe, getWorkspaceSettings, updatePreferences, updateWorkspaceSettings,
  type WorkspaceSettings,
} from "@/lib/api";
import { setDisplaySettings, type DateFormat, type TimeFormat } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const zones = (): string[] => {
  try {
    return ["UTC", ...(Intl as unknown as { supportedValuesOf(k: string): string[] }).supportedValuesOf("timeZone")];
  } catch {
    return ["UTC"];
  }
};

/**
 * Region and formats. The workspace's defaults (administrators) — its time
 * zone for reports and emails, how dates and times are written, the billing
 * currency — and this person's own overrides. The data region is shown,
 * never edited: moving a workspace between regions is a migration.
 */
export default function RegionalSettingsSection({ isAdmin }: { isAdmin: boolean }) {
  const { t } = useLanguage();
  const w = t.workspaces;
  const allZones = useMemo(zones, []);
  const [ws, setWs] = useState<WorkspaceSettings | null>(null);
  const [mine, setMine] = useState<{ timezone: string | null; date_format: string | null; time_format: string | null }>({ timezone: null, date_format: null, time_format: null });
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getWorkspaceSettings().then(setWs).catch(() => setError(w.saveFailed));
    getMe().then((me) => setMine({
      timezone: me.preferences?.timezone ?? null, date_format: me.preferences?.date_format ?? null, time_format: me.preferences?.time_format ?? null,
    })).catch(() => {});
  }, [w.saveFailed]);

  async function run(fn: () => Promise<void>) {
    setBusy(true); setMessage(null); setError(null);
    try { await fn(); setMessage(w.saved); } catch (err) { setError(err instanceof ApiError ? err.message : w.saveFailed); } finally { setBusy(false); }
  }
  const saveWorkspace = (patch: Parameters<typeof updateWorkspaceSettings>[0]) => run(async () => { setWs(await updateWorkspaceSettings(patch)); });
  const saveMine = (patch: Partial<typeof mine>) => run(async () => {
    const next = { ...mine, ...patch };
    const r = await updatePreferences(patch);
    setMine(next);
    setDisplaySettings({ timeZone: next.timezone ?? undefined, dateFormat: r.settings.date_format, timeFormat: r.settings.time_format });
  });

  const dateLabel = (f: DateFormat) => (f === "locale" ? w.followLanguage : f);
  const timeLabel = (f: TimeFormat) => (f === "locale" ? w.followLanguage : f === "24h" ? w.h24 : w.h12);
  const select = "bg-canvas border border-line rounded-md px-2 py-1 text-xs text-ink outline-none focus:border-brand-hover disabled:opacity-60";
  const row = "flex items-center justify-between gap-3 py-1.5";
  const label = "text-ink-faint text-xs";

  return (
    <div className="rounded-xl border border-line bg-surface p-4 flex flex-col gap-3">
      <div>
        <h2 className="text-ink text-sm font-medium">{w.regionalTitle}</h2>
        <p className="text-ink-faint text-[11px] mt-1">{w.regionalHint}</p>
      </div>
      {!ws && !error && <Loader2 size={14} className="animate-spin text-ink-faint" />}
      {ws && (
        <>
          <div className={row}>
            <span className={label}>{w.dataRegion}</span>
            <span className="text-ink-muted text-xs font-mono">{ws.region}</span>
          </div>

          <h3 className="text-ink-muted text-xs font-medium mt-1">{w.workspaceDefaults}</h3>
          <div className={row}>
            <span className={label}>{w.timezone}</span>
            <select className={select} disabled={!isAdmin || busy} value={ws.timezone} onChange={(e) => saveWorkspace({ timezone: e.target.value })}>
              {allZones.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </div>
          <div className={row}>
            <span className={label}>{w.dateFormat}</span>
            <select className={select} disabled={!isAdmin || busy} value={ws.date_format} onChange={(e) => saveWorkspace({ date_format: e.target.value as DateFormat })}>
              {ws.options.date_formats.map((f) => <option key={f} value={f}>{dateLabel(f)}</option>)}
            </select>
          </div>
          <div className={row}>
            <span className={label}>{w.timeFormat}</span>
            <select className={select} disabled={!isAdmin || busy} value={ws.time_format} onChange={(e) => saveWorkspace({ time_format: e.target.value as TimeFormat })}>
              {ws.options.time_formats.map((f) => <option key={f} value={f}>{timeLabel(f)}</option>)}
            </select>
          </div>
          <div className={row}>
            <span className={label}>{w.currency}</span>
            <select className={select} disabled={!isAdmin || busy} value={ws.currency} onChange={(e) => saveWorkspace({ currency: e.target.value })}>
              {ws.options.currencies.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>

          <h3 className="text-ink-muted text-xs font-medium mt-1">{w.myPreferences}</h3>
          <div className={row}>
            <span className={label}>{w.timezone}</span>
            <select className={select} disabled={busy} value={mine.timezone ?? ""} onChange={(e) => saveMine({ timezone: e.target.value || null })}>
              <option value="">{w.browserZone}</option>
              {allZones.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </div>
          <div className={row}>
            <span className={label}>{w.dateFormat}</span>
            <select className={select} disabled={busy} value={mine.date_format ?? ""} onChange={(e) => saveMine({ date_format: e.target.value || null })}>
              <option value="">{w.workspaceDefaults}</option>
              {ws.options.date_formats.map((f) => <option key={f} value={f}>{dateLabel(f)}</option>)}
            </select>
          </div>
          <div className={row}>
            <span className={label}>{w.timeFormat}</span>
            <select className={select} disabled={busy} value={mine.time_format ?? ""} onChange={(e) => saveMine({ time_format: e.target.value || null })}>
              <option value="">{w.workspaceDefaults}</option>
              {ws.options.time_formats.map((f) => <option key={f} value={f}>{timeLabel(f)}</option>)}
            </select>
          </div>
        </>
      )}
      {message && <p className="text-ink-muted text-xs">{message}</p>}
      {error && <p className="text-red-400 text-xs">{error}</p>}
    </div>
  );
}
