"use client";

import { useEffect, useState } from "react";
import { Building2, Check, Loader2, Plus } from "lucide-react";
import { ApiError, createWorkspace, getWorkspaces, switchWorkspace, type WorkspaceSummary } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/**
 * Which workspace this session acts in, and a way to move to another. A
 * switch starts a new session for that workspace (the server sets new
 * cookies); the page is reloaded so nothing from the previous workspace —
 * alerts, caches, the realtime connection — carries over.
 */
export default function WorkspaceSwitcher() {
  const { t } = useLanguage();
  const [list, setList] = useState<WorkspaceSummary[] | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getWorkspaces()
      .then((r) => { setList(r.workspaces); setCurrent(r.current); })
      .catch(() => setList(null));
  }, []);

  async function go(id: string) {
    if (id === current) return;
    setBusy(true);
    setError(null);
    try {
      await switchWorkspace(id);
      window.location.assign("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.workspaces.switchFailed);
      setBusy(false);
    }
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const created = await createWorkspace({ name: name.trim() });
      await go(created.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.workspaces.createFailed);
      setBusy(false);
    }
  }

  if (!list) return null;
  const active = list.filter((w) => w.status === "active");

  return (
    <div className="px-2">
      <label className="text-[10px] uppercase tracking-wide text-ink-faint flex items-center gap-1.5 mb-1">
        <Building2 size={11} /> {t.workspaces.label}
        {busy && <Loader2 size={11} className="animate-spin ml-auto" />}
      </label>
      <ul className="flex flex-col gap-0.5">
        {active.map((w) => (
          <li key={w.id}>
            <button
              type="button"
              disabled={busy}
              onClick={() => go(w.id)}
              aria-current={w.id === current ? "true" : undefined}
              className={`w-full flex items-center gap-2 text-left text-xs rounded-md px-2 py-1.5 transition-colors ${
                w.id === current ? "bg-surface text-ink" : "text-ink-muted hover:text-ink hover:bg-surface/60"
              }`}
            >
              <span className="truncate">{w.name}</span>
              {w.home && <span className="text-[9px] text-ink-faint">{t.workspaces.home}</span>}
              {w.id === current && <Check size={12} className="ml-auto shrink-0 text-brand-bright" />}
            </button>
          </li>
        ))}
        {list.filter((w) => w.status === "invited").map((w) => (
          <li key={w.id} className="text-[11px] text-ink-faint px-2 py-1 truncate">
            {w.name} · {t.workspaces.invited}
          </li>
        ))}
      </ul>
      {creating ? (
        <form onSubmit={create} className="mt-1.5 flex flex-col gap-1.5">
          <input
            autoFocus
            value={name}
            maxLength={100}
            onChange={(e) => setName(e.target.value)}
            placeholder={t.workspaces.namePlaceholder}
            className="w-full bg-canvas border border-line rounded-md px-2 py-1 text-xs text-ink outline-none focus:border-brand-hover"
          />
          <div className="flex gap-1.5">
            <button type="submit" disabled={busy} className="text-xs bg-brand hover:bg-brand-hover text-white rounded-md px-2 py-1">{t.workspaces.create}</button>
            <button type="button" onClick={() => setCreating(false)} className="text-xs text-ink-muted hover:text-ink px-2 py-1">{t.workspaces.cancel}</button>
          </div>
        </form>
      ) : (
        <button type="button" onClick={() => setCreating(true)} className="mt-1 flex items-center gap-1 text-[11px] text-ink-faint hover:text-ink-muted px-2 py-1">
          <Plus size={11} /> {t.workspaces.createNew}
        </button>
      )}
      {error && <p className="text-critical text-[11px] mt-1">{error}</p>}
    </div>
  );
}
