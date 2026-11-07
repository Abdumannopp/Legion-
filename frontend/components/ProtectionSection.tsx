"use client";

import { useCallback, useEffect, useState } from "react";
import { Bot, CheckCircle2, Loader2, OctagonX, ShieldCheck } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import {
  ProtectionMode, ProtectionReport, ProtectionState, SocApproval,
  decideSocApproval, getProtection, getProtectionReport, getSocApprovals, setActionsPaused, updateProtection,
} from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { timeAgo } from "@/lib/i18n/format";

const card = "bg-surface border border-line rounded-2xl p-5";
const MODES: ProtectionMode[] = ["manual", "hybrid", "automatic"];

/**
 * How much Legion may do on its own — chosen here by an administrator, never by default. Switching it on asks
 * for the notice to be accepted and (via lib/api.ts) the password again; switching it off, and the emergency
 * stop, never ask anything. Also where the people who must decide see what is waiting, and what Legion did.
 */
export default function ProtectionSection({ isAdmin }: { isAdmin: boolean }) {
  const { t, locale } = useLanguage();
  const p = t.protection;
  const [state, setState] = useState<ProtectionState | null>(null);
  const [report, setReport] = useState<ProtectionReport | null>(null);
  const [approvals, setApprovals] = useState<SocApproval[]>([]);
  const [mode, setMode] = useState<ProtectionMode>("manual");
  const [auto, setAuto] = useState<string[]>([]);
  const [agreed, setAgreed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [codes, setCodes] = useState<Record<string, string>>({});
  const [deciding, setDeciding] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const s = await getProtection();
      setState(s); setMode(s.protection.mode); setAuto(s.protection.auto_actions);
      getProtectionReport(7).then(setReport).catch(() => {});
      getSocApprovals().then((r) => setApprovals(r.approvals)).catch(() => {});
    } catch (err) { setError(err); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  if (!state) return error != null ? <ErrorNotice error={error} /> : null;
  const needsNotice = mode !== "manual" && !state.protection.acknowledged;
  const stale = state.protection.mode !== "manual" && !state.protection.acknowledged;
  const dirty = mode !== state.protection.mode || auto.slice().sort().join() !== state.protection.auto_actions.slice().sort().join();

  async function save() {
    setSaving(true); setSaved(false); setError(null);
    try {
      const r = await updateProtection({ mode, auto_actions: mode === "hybrid" ? auto : [], ...(agreed ? { acknowledge: true } : {}) });
      setState({ ...state!, protection: r.protection }); setAgreed(false); setSaved(true);
    } catch (err) { setError(err); } finally { setSaving(false); }
  }
  async function stop(paused: boolean) {
    try { await setActionsPaused(paused); setState({ ...state!, paused }); } catch (err) { setError(err); }
  }
  async function decide(a: SocApproval, decision: "approve" | "reject") {
    setDeciding(a.id); setError(null);
    try {
      await decideSocApproval(a, decision, codes[a.id] ? { mfa_code: codes[a.id] } : {});
      setApprovals((list) => list.filter((x) => x.id !== a.id));
      getProtectionReport(7).then(setReport).catch(() => {});
    } catch (err) { setError(err); } finally { setDeciding(null); }
  }

  const effective = state.protection.effective_mode;
  return (
    <section className={card} data-testid="protection">
      <h2 className="text-ink font-medium flex items-center gap-2 mb-1"><Bot size={16} color={palette.warning} />{p.title}</h2>
      <p className="text-ink-faint text-xs leading-relaxed mb-4">{p.intro}</p>

      <div className="rounded-lg border border-line p-3 mb-4 text-xs flex items-center gap-2" data-testid="protection-now">
        <ShieldCheck size={14} color={effective === "manual" ? palette.inkFaint : palette.success} />
        <span className="text-ink-muted">{stale ? p.now.needsNotice : p.now[effective]}</span>
      </div>

      {error != null && <div className="mb-3"><ErrorNotice error={error} /></div>}

      {/* Emergency stop: always one click, for anyone allowed to control actions. */}
      {isAdmin && (
        <div className="flex items-center justify-between gap-3 border border-line rounded-lg p-3 mb-4">
          <div className="text-xs">
            <p className="text-ink font-medium flex items-center gap-1.5"><OctagonX size={13} color={palette.critical} />{p.stop.title}</p>
            <p className="text-ink-faint mt-0.5">{state.paused ? p.stop.active : p.stop.help}</p>
          </div>
          <button onClick={() => stop(!state.paused)} data-testid="emergency-stop"
            className={`text-xs px-3 py-2 rounded-lg border ${state.paused ? "border-line text-ink-muted" : "border-red-500/50 text-red-400"}`}>
            {state.paused ? p.stop.lift : p.stop.press}
          </button>
        </div>
      )}

      <div className="grid sm:grid-cols-3 gap-2" role="radiogroup" aria-label={p.title}>
        {MODES.map((m) => (
          <label key={m} className={`border rounded-lg p-3 text-sm cursor-pointer ${mode === m ? "border-brand-hover bg-canvas" : "border-line"} ${!isAdmin ? "opacity-70 cursor-default" : ""}`}>
            <input type="radio" name="protection-mode" className="sr-only" checked={mode === m} disabled={!isAdmin || (m !== "manual" && !state.plan_allows)} onChange={() => { setMode(m); setSaved(false); }} />
            <span className="block text-ink font-medium">{p.modes[m].name}</span>
            <span className="block text-xs text-ink-faint mt-1 leading-relaxed">{p.modes[m].help}</span>
          </label>
        ))}
      </div>
      {!state.plan_allows && <p className="text-warning text-xs mt-2">{p.planLocked}</p>}

      {mode === "hybrid" && (
        <div className="mt-4">
          <p className="text-ink-muted text-xs mb-2">{p.actions.title}</p>
          <ul className="space-y-1.5">
            {state.live_actions.map((a) => (
              <li key={a.id}>
                <label className="flex items-start gap-2 text-sm text-ink-muted">
                  <input type="checkbox" className="mt-1" disabled={!isAdmin} checked={auto.includes(a.id)}
                    onChange={(e) => { setAuto(e.target.checked ? [...auto, a.id] : auto.filter((x) => x !== a.id)); setSaved(false); }} />
                  <span>{(p.actions as Record<string, string>)[a.id] ?? a.summary}{a.reversible ? <span className="text-ink-faint text-[11px]"> — {p.actions.reversible}</span> : null}</span>
                </label>
              </li>
            ))}
          </ul>
        </div>
      )}
      {mode !== "manual" && <p className="text-ink-faint text-[11px] leading-relaxed mt-3">{p.actions.other}</p>}

      {needsNotice && (
        <div className="mt-4 border border-line rounded-lg p-3 text-xs text-ink-muted leading-relaxed space-y-2" data-testid="protection-notice">
          <p className="text-ink font-medium">{p.notice.title}</p>
          {state.notice.lines.map((line, i) => <p key={i}>{line}</p>)}
          <label className="flex items-start gap-2 text-ink">
            <input type="checkbox" className="mt-0.5" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            <span>{p.notice.accept}</span>
          </label>
        </div>
      )}

      <div className="flex items-center gap-3 mt-4">
        {isAdmin ? (
          <button onClick={save} disabled={saving || !dirty && !needsNotice || (needsNotice && !agreed)} data-testid="protection-save"
            className="flex items-center gap-2 bg-brand hover:bg-brand-hover disabled:opacity-50 text-white text-xs font-medium px-4 py-2 rounded-lg">
            {saving && <Loader2 size={14} className="animate-spin" />}{p.save}
          </button>
        ) : <span className="text-xs text-ink-faint">{p.adminOnly}</span>}
        {saved && <span className="text-xs text-success flex items-center gap-1"><CheckCircle2 size={13} />{p.saved}</span>}
        {needsNotice && !agreed && <span className="text-xs text-ink-faint">{p.notice.required}</span>}
      </div>
      <p className="text-ink-faint text-[11px] mt-3">{p.limit(state.live_per_hour)}</p>

      {/* The human in the loop: what is waiting for a decision. */}
      <div className="mt-6 border-t border-line pt-4" data-testid="protection-approvals">
        <h3 className="text-ink text-sm font-medium mb-2">{p.approvals.title}</h3>
        {approvals.length === 0 ? <p className="text-ink-faint text-xs">{p.approvals.empty}</p> : (
          <ul className="divide-y divide-line">
            {approvals.map((a) => (
              <li key={a.id} className="py-3 text-sm" data-testid="soc-approval">
                <p className="text-ink">{a.summary}</p>
                <p className="text-ink-faint text-[11px] mt-0.5">
                  {a.risk_class} · {p.approvals.requestedBy(a.requested_by.agent ?? a.requested_by.kind)} · {p.approvals.expires} {timeAgo(a.expires_at, locale)}
                </p>
                {isAdmin && (
                  <div className="flex items-center gap-2 mt-2">
                    {a.require_mfa && <input inputMode="numeric" autoComplete="one-time-code" placeholder={p.approvals.code} value={codes[a.id] ?? ""}
                      onChange={(e) => setCodes({ ...codes, [a.id]: e.target.value })} className="bg-canvas border border-line rounded-lg px-2 py-1.5 text-xs text-ink w-44" />}
                    <button disabled={deciding === a.id} onClick={() => decide(a, "approve")} className="text-xs px-3 py-1.5 rounded-lg bg-brand hover:bg-brand-hover text-white disabled:opacity-50">{p.approvals.approve}</button>
                    <button disabled={deciding === a.id} onClick={() => decide(a, "reject")} className="text-xs px-3 py-1.5 rounded-lg border border-line text-ink-muted disabled:opacity-50">{p.approvals.reject}</button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* The record: what Legion did, in plain numbers, then the latest actions. */}
      {report && (
        <div className="mt-6 border-t border-line pt-4" data-testid="protection-report">
          <h3 className="text-ink text-sm font-medium mb-2">{p.report.title}</h3>
          <dl className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center">
            {([["automatic", report.totals.automatic], ["approved", report.totals.approved_by_person], ["byPerson", report.totals.by_person], ["waiting", report.totals.awaiting_approval], ["failed", report.totals.failed]] as const).map(([k, n]) => (
              <div key={k} className="border border-line rounded-lg p-2">
                <dd className="text-ink text-lg font-semibold">{n}</dd>
                <dt className="text-ink-faint text-[11px]">{p.report[k]}</dt>
              </div>
            ))}
          </dl>
          {report.recent.length === 0 ? <p className="text-ink-faint text-xs mt-3">{p.report.empty}</p> : (
            <ul className="divide-y divide-line mt-3">
              {report.recent.slice(0, 8).map((r) => (
                <li key={r.id} className="py-2 text-xs flex items-center justify-between gap-3">
                  <span className="text-ink-muted">{r.action_id} · {r.target ?? "—"} · {p.report.by[r.by] ?? r.by}</span>
                  <span className="text-ink-faint whitespace-nowrap">{p.report.status[r.status] ?? r.status} · {timeAgo(r.at, locale)}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
