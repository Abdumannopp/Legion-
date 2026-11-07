"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Loader2, Pause, Play, Plus, Trash2 } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import { ConnectionInfo, createConnection, listConnections, removeConnection, setConnectionStatus } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { timeAgo } from "@/lib/i18n/format";

type Kind = "m365" | "guardduty" | "slack" | "jira";
type FieldType = "text" | "password" | "regions" | "severity";
interface Field { key: string; where: "config" | "secrets"; type: FieldType }
const KINDS: Kind[] = ["m365", "guardduty", "slack", "jira"];
// Technical identifiers: they must match the server's schema for each connector.
const FIELDS: Record<Kind, Field[]> = {
  m365: [{ key: "directory_id", where: "config", type: "text" }, { key: "client_id", where: "config", type: "text" }, { key: "client_secret", where: "secrets", type: "password" }],
  guardduty: [{ key: "regions", where: "config", type: "regions" }, { key: "access_key_id", where: "secrets", type: "text" }, { key: "secret_access_key", where: "secrets", type: "password" }],
  slack: [{ key: "webhook_url", where: "secrets", type: "password" }, { key: "min_severity", where: "config", type: "severity" }],
  jira: [{ key: "site", where: "config", type: "text" }, { key: "project_key", where: "config", type: "text" }, { key: "email", where: "secrets", type: "text" }, { key: "api_token", where: "secrets", type: "password" }, { key: "min_severity", where: "config", type: "severity" }],
};
const card = "rounded-xl border border-line bg-surface p-4";
const input = "w-full rounded-lg border border-line bg-canvas px-3 py-2 text-sm text-ink";

/** Pull (Defender XDR, GuardDuty) and outbound (Slack, Jira) connections: list, add, pause, remove. Administrators only. */
export default function ConnectionsSection({ isAdmin }: { isAdmin: boolean }) {
  const { t, locale } = useLanguage();
  const m = t.connections;
  const [list, setList] = useState<ConnectionInfo[] | null>(null);
  const [adding, setAdding] = useState<Kind | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { setList((await listConnections()).connections); } catch (err) { setError(err); }
  }, []);
  useEffect(() => { if (isAdmin) load(); }, [isAdmin, load]);

  if (!isAdmin) return <section className={card}><h2 className="text-ink text-sm font-semibold">{m.title}</h2><p className="text-ink-muted text-xs mt-1">{m.adminOnly}</p></section>;

  async function run(fn: () => Promise<void>) {
    setBusy(true); setError(null); setNotice(null);
    try { await fn(); } catch (err) { setError(err); } finally { setBusy(false); }
  }
  const save = () => run(async () => {
    if (!adding) return;
    const config: Record<string, unknown> = {}; const secrets: Record<string, string> = {};
    for (const f of FIELDS[adding]) {
      const v = (values[f.key] ?? "").trim();
      if (!v) continue;
      if (f.where === "secrets") secrets[f.key] = v;
      else config[f.key] = f.type === "regions" ? v.split(",").map((r) => r.trim()).filter(Boolean) : v;
    }
    if (adding === "slack" || adding === "jira") config.min_severity ??= "high"; // i18n-ignore: API value
    await createConnection({ kind: adding, name: m.kinds[adding].name, config, secrets });
    setAdding(null); setValues({}); setNotice(m.saved);
    await load();
  });
  const act = (c: ConnectionInfo, action: "pause" | "resume") => run(async () => { await setConnectionStatus(c.id, action); await load(); });
  const remove = (c: ConnectionInfo) => {
    if (!window.confirm(m.removeConfirm)) return;
    run(async () => { await removeConnection(c.id); await load(); });
  };

  return (
    <section className={card} data-testid="connections">
      <h2 className="text-ink text-sm font-semibold">{m.title}</h2>
      <p className="text-ink-muted text-xs mt-1">{m.intro}</p>
      <p className="text-ink-faint text-[11px] mt-1">{m.cannotAct}</p>
      <ErrorNotice error={error} />
      {notice && <p className="text-xs text-success flex items-center gap-1 mt-2"><CheckCircle2 size={13} />{notice}</p>}

      <ul className="mt-3 space-y-2">
        {list === null && <li className="text-ink-faint text-xs"><Loader2 size={13} className="animate-spin inline" /></li>}
        {list?.length === 0 && <li className="text-ink-faint text-xs">{m.empty}</li>}
        {list?.map((c) => (
          <li key={c.id} className="rounded-lg border border-line bg-canvas/40 px-3 py-2.5 flex flex-wrap items-center gap-2" data-testid="connection-row">
            <div className="min-w-0 flex-1">
              <p className="text-ink text-sm">{c.name} <span className="text-ink-faint text-[11px]">· {m.status[c.status]}</span></p>
              <p className="text-ink-muted text-[11px]">{c.last_success_at ? m.health.ok(timeAgo(c.last_success_at, locale)) : m.health.never}{c.failures > 0 ? ` · ${m.health.failing(c.failures)}` : ""}</p>
              {c.last_error && <p className="text-danger text-[11px] break-words">{c.last_error}</p>}
            </div>
            {c.status === "paused" || c.status === "error"
              ? <button disabled={busy} onClick={() => act(c, "resume")} className="text-xs px-2.5 py-1.5 rounded-lg border border-line text-ink-muted hover:text-ink flex items-center gap-1"><Play size={12} />{m.resume}</button>
              : <button disabled={busy} onClick={() => act(c, "pause")} className="text-xs px-2.5 py-1.5 rounded-lg border border-line text-ink-muted hover:text-ink flex items-center gap-1"><Pause size={12} />{m.pause}</button>}
            <button disabled={busy} onClick={() => remove(c)} className="text-xs px-2.5 py-1.5 rounded-lg border border-line text-danger flex items-center gap-1"><Trash2 size={12} />{m.remove}</button>
          </li>
        ))}
      </ul>

      {adding === null ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {KINDS.map((k) => (
            <button key={k} onClick={() => { setAdding(k); setValues({}); setError(null); }} className="text-xs px-3 py-1.5 rounded-lg border border-line text-ink-muted hover:text-ink flex items-center gap-1" data-testid={`add-${k}`}><Plus size={12} />{m.kinds[k].name}</button>
          ))}
        </div>
      ) : (
        <div className="mt-3 rounded-lg border border-line p-3 space-y-2.5">
          <p className="text-ink text-sm font-medium">{m.add}: {m.kinds[adding].name}</p>
          <p className="text-ink-muted text-xs">{m.kinds[adding].help}</p>
          {FIELDS[adding].map((f) => (
            <label key={f.key} className="block text-xs text-ink-muted">
              {m.fields[f.key as keyof typeof m.fields]}
              {f.type === "severity" ? (
                <select className={input} value={values[f.key] ?? "high"} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}>
                  {(["low", "medium", "high", "critical"] as const).map((s) => <option key={s} value={s}>{m.severities[s]}</option>)}
                </select>
              ) : (
                <input className={input} type={f.type === "password" ? "password" : "text"} autoComplete="off" value={values[f.key] ?? ""} onChange={(e) => setValues({ ...values, [f.key]: e.target.value })} />
              )}
            </label>
          ))}
          <div className="flex gap-2">
            <button disabled={busy} onClick={save} className="text-xs font-medium px-3 py-1.5 rounded-lg bg-brand text-white flex items-center gap-1" data-testid="connection-save">{busy && <Loader2 size={12} className="animate-spin" />}{busy ? m.saving : m.save}</button>
            <button disabled={busy} onClick={() => { setAdding(null); setValues({}); }} className="text-xs px-3 py-1.5 rounded-lg border border-line text-ink-muted">{m.cancel}</button>
          </div>
        </div>
      )}
    </section>
  );
}
