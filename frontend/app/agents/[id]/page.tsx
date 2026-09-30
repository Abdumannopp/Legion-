"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft, CheckCircle2, Clock, Loader2, OctagonX, Pause, Play, ShieldAlert, ShieldOff, TriangleAlert,
} from "lucide-react";
import Sidebar from "@/components/Sidebar";
import ErrorNotice from "@/components/ErrorNotice";
import AgentApprovals from "@/components/AgentApprovals";
import AgentStatus from "@/components/AgentStatus";
import { PermissionPicker, PermissionSummary } from "@/components/AgentPermissions";
import {
  ApiError, emergencyStopAgent, getAgentDecisions, getAgentPermissions, getAgents, getApprovals, getMe, isLoggedIn,
  pauseAgent, resumeAgent, updateAgentPermissions,
  type AgentDecision, type AgentPermissionInfo, type AgentSummary, type ApprovalRequest, type CurrentUser,
} from "@/lib/api";
import { primaryRule, ruleGroup } from "@/lib/agentRules";
import { formatDateTime } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const DECISION_STYLE: Record<string, { Icon: typeof CheckCircle2; tone: string }> = {
  ALLOW: { Icon: CheckCircle2, tone: "text-success" },
  WARN: { Icon: TriangleAlert, tone: "text-info" },
  CONFIRM: { Icon: Clock, tone: "text-warning" },
  BLOCK: { Icon: ShieldOff, tone: "text-warning" },
  QUARANTINE: { Icon: ShieldAlert, tone: "text-critical" },
  KILL: { Icon: OctagonX, tone: "text-critical" },
};

/** One decision Legion made about this agent, with why and what to do when it wasn't a plain yes. */
function DecisionItem({ d }: { d: AgentDecision }) {
  const { t, locale } = useLanguage();
  const a = t.agents;
  // An action a person approved is recorded as allowed with the approval rule
  // turned into a warning; it is not "unusual", it is what someone said yes to.
  const approved = d.decision === "WARN" && (d.ruleHits ?? []).some((h) => h.effect === "WARN" && ruleGroup(h.id) === "needsApproval");
  const style = approved ? DECISION_STYLE.ALLOW : DECISION_STYLE[d.decision] ?? DECISION_STYLE.BLOCK;
  const rule = d.decision === "ALLOW" || approved ? null : primaryRule(d.ruleHits ?? []);
  const explained = rule ? a.rules[ruleGroup(rule)] : null;
  return (
    <li className="px-3 py-2.5" data-testid="decision">
      <div className="flex items-start gap-2">
        <style.Icon size={14} className={`${style.tone} shrink-0 mt-0.5`} />
        <div className="min-w-0 flex-1">
          <p className="text-xs text-ink">
            <span className={`font-medium ${style.tone}`}>{approved ? a.approvedLabel : a.decision[d.decision] ?? d.decision}</span>
            <span className="text-ink-muted"> · {d.permission ? a.permissions[d.permission] ?? d.permission : d.action}</span>
          </p>
          <p className="text-ink-faint text-[10px]">{formatDateTime(d.occurredAt, locale)}{d.destination ? ` · ${a.activity.destination(d.destination)}` : ""}</p>
          {d.decision !== "ALLOW" && (
            <div className="mt-1 space-y-0.5 text-[11px]">
              <p className="text-ink-muted">{approved ? a.approvedHint : a.decisionHint[d.decision]}</p>
              {explained && (
                <>
                  <p className="text-ink-soft"><span className="text-ink-faint">{a.activity.why}: </span>{explained.what}</p>
                  <p className="text-ink-soft"><span className="text-ink-faint">{a.activity.next}: </span>{explained.next}</p>
                </>
              )}
              <details className="text-ink-faint">
                <summary className="cursor-pointer hover:text-ink-muted">{a.technical}</summary>
                <p className="font-mono text-[10px] break-all mt-1">{d.action}</p>
                {(d.ruleHits ?? []).map((h) => <p key={h.id} className="font-mono text-[10px] break-all">{h.id} ({h.effect}) — {h.reason}</p>)}
                <p className="font-mono text-[10px] break-all">{d.decisionId}</p>
              </details>
            </div>
          )}
        </div>
      </div>
    </li>
  );
}

/** Emergency stop: two plain choices, and a reason for the security record. */
function StopDialog({ onClose, onStop }: { onClose: () => void; onStop: (reason: string, compromise: "suspected" | "confirmed") => Promise<void> }) {
  const { t } = useLanguage();
  const s = t.agents.stopDialog;
  const [compromise, setCompromise] = useState<"suspected" | "confirmed">("suspected");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const short = reason.trim().length < 10;
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (short) return;
    setBusy(true); setError(null);
    try { await onStop(reason.trim(), compromise); } catch (err) { setError(err); setBusy(false); }
  }
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="stop-title">
      <form onSubmit={submit} className="w-full max-w-md rounded-xl border border-critical/40 bg-panel p-5 space-y-3">
        <h2 id="stop-title" className="flex items-center gap-2 text-ink text-sm font-semibold"><OctagonX size={16} className="text-critical" /> {s.title}</h2>
        <p className="text-ink-muted text-xs">{s.intro}</p>
        {(["suspected", "confirmed"] as const).map((c) => (
          <label key={c} className={`block rounded-lg border px-3 py-2 cursor-pointer ${compromise === c ? "border-critical/60 bg-critical/10" : "border-line"}`}>
            <span className="flex items-center gap-2 text-xs text-ink font-medium">
              <input type="radio" name="compromise" checked={compromise === c} onChange={() => setCompromise(c)} className="accent-critical" /> {s[c].label}
            </span>
            <span className="block text-[11px] text-ink-faint mt-0.5 ml-5">{s[c].hint}</span>
          </label>
        ))}
        <label className="block text-xs text-ink-muted space-y-1">
          <span>{s.reason}</span>
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} rows={3} placeholder={s.reasonPlaceholder}
            className="w-full bg-canvas border border-line rounded-md px-2.5 py-1.5 text-sm text-ink outline-none focus:border-brand-hover" />
          {short && <span className="text-ink-faint text-[11px]">{s.reasonShort}</span>}
        </label>
        {error != null && <ErrorNotice error={error} compact isAdmin />}
        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="text-xs text-ink-muted hover:text-ink px-3 py-1.5">{s.cancel}</button>
          <button type="submit" disabled={busy || short} className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-critical hover:bg-critical-hover text-white disabled:opacity-50">
            {busy && <Loader2 size={12} className="animate-spin" />} {s.confirm}
          </button>
        </div>
      </form>
    </div>
  );
}

export default function AgentPage() {
  const router = useRouter();
  const { id } = useParams<{ id: string }>();
  const { t } = useLanguage();
  const a = t.agents;
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [agent, setAgent] = useState<AgentSummary | null>(null);
  const [catalogue, setCatalogue] = useState<{ permissions: AgentPermissionInfo[]; never: string[] } | null>(null);
  const [decisions, setDecisions] = useState<AgentDecision[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [tab, setTab] = useState<"permissions" | "activity" | "approvals">("permissions");
  const [editing, setEditing] = useState<string[] | null>(null);
  const [stopping, setStopping] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const isAdmin = me?.role === "admin";
  const isStaff = isAdmin || me?.role === "analyst";
  const isOwner = !!me && agent?.owner.userId === me.id;

  const load = useCallback(async () => {
    try {
      const [list, cat, dec, appr] = await Promise.all([getAgents(), getAgentPermissions(), getAgentDecisions(id), getApprovals("pending")]);
      const found = list.agents.find((x) => x.id === id) ?? null;
      setMissing(!found);
      setAgent(found);
      setCatalogue(cat);
      setDecisions(dec.decisions);
      setApprovals(appr.approvals.filter((r) => r.identityId === id));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { router.push("/login"); return; }
      setError(err);
    }
  }, [id, router]);

  useEffect(() => {
    if (!isLoggedIn()) { router.push("/login"); return; }
    getMe().then(setMe).catch(() => {});
    load();
  }, [load, router]);

  async function act(fn: () => Promise<unknown>, done: string) {
    setBusy(true); setError(null); setNotice(null);
    try { await fn(); setNotice(done); await load(); } catch (err) { setError(err); } finally { setBusy(false); }
  }

  const header = (
    <Link href="/agents" className="inline-flex items-center gap-1.5 text-ink-faint hover:text-ink text-xs"><ArrowLeft size={14} /> {a.back}</Link>
  );

  if (missing) {
    return (
      <div className="flex min-h-screen bg-canvas"><Sidebar />
        <div className="flex-1 p-4 sm:p-6"><div className="max-w-3xl mx-auto space-y-4">{header}
          <ErrorNotice error={new ApiError(t.errors.notFound.title, 404)} />
        </div></div>
      </div>
    );
  }

  const btn = "flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg disabled:opacity-60";

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-3xl mx-auto space-y-4">
          {header}
          {error != null && <ErrorNotice error={error} onRetry={load} isAdmin={isAdmin} />}
          {notice && <p role="status" className="flex items-center gap-2 text-success text-xs bg-success/10 rounded-lg px-3 py-2.5"><CheckCircle2 size={14} /> {notice}</p>}

          {!agent || !catalogue ? (
            error == null && <div className="flex justify-center py-12"><Loader2 size={18} className="animate-spin text-ink-faint" /></div>
          ) : (
            <>
              <header className="rounded-xl border border-line bg-surface px-4 py-4">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h1 className="text-ink text-lg font-semibold">{agent.name}</h1>
                      <AgentStatus agent={agent} />
                      <span className="text-[10px] text-ink-faint">{a.risk[agent.risk.overall]}</span>
                    </div>
                    {agent.description && <p className="text-ink-muted text-xs mt-1">{agent.description}</p>}
                    {agent.blockedBecause && <p className="text-critical text-xs mt-1.5">{a.blockedBecause[agent.blockedBecause] ?? agent.blockedBecause}</p>}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {agent.status === "active" && (isAdmin || isOwner) && (
                      <button type="button" disabled={busy} title={a.controls.pauseHint} onClick={() => act(() => pauseAgent(agent.id), a.controls.paused)} className={`${btn} border border-line text-ink-muted hover:text-ink`}>
                        <Pause size={12} /> {a.controls.pause}
                      </button>
                    )}
                    {agent.status === "suspended" && isAdmin && (
                      <button type="button" disabled={busy} title={a.controls.resumeHint} onClick={() => act(() => resumeAgent(agent.id), a.controls.resumed)} className={`${btn} border border-line text-ink-muted hover:text-ink`}>
                        <Play size={12} /> {a.controls.resume}
                      </button>
                    )}
                    {agent.status !== "revoked" && isAdmin && (
                      <button type="button" disabled={busy} title={a.controls.stopHint} onClick={() => setStopping(true)} className={`${btn} bg-critical hover:bg-critical-hover text-white`}>
                        <OctagonX size={12} /> {a.controls.stop}
                      </button>
                    )}
                  </div>
                </div>
              </header>

              <div className="flex gap-1 border-b border-line" role="tablist">
                {(["permissions", "activity", "approvals"] as const).map((k) => (
                  <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)}
                    className={`text-xs px-3 py-2 -mb-px border-b-2 ${tab === k ? "border-brand-hover text-ink" : "border-transparent text-ink-faint hover:text-ink-muted"}`}>
                    {a.tabs[k]}{k === "approvals" && approvals.length ? ` (${approvals.length})` : ""}
                  </button>
                ))}
              </div>

              {tab === "permissions" && (
                <section className="rounded-xl border border-line bg-surface p-4 space-y-3">
                  {editing ? (
                    <>
                      <PermissionPicker catalogue={catalogue.permissions} selected={editing} onChange={setEditing} disabled={busy} />
                      <p className="text-ink-faint text-[11px]">{a.ownerLimit}</p>
                      <div className="flex gap-2">
                        <button type="button" disabled={busy || editing.length === 0}
                          onClick={() => act(async () => { await updateAgentPermissions(agent.id, editing); setEditing(null); }, a.saved)}
                          className={`${btn} bg-brand hover:bg-brand-hover text-white`}>
                          {busy && <Loader2 size={12} className="animate-spin" />} {a.save}
                        </button>
                        <button type="button" onClick={() => setEditing(null)} className="text-xs text-ink-muted hover:text-ink px-3 py-1.5">{a.cancel}</button>
                      </div>
                    </>
                  ) : (
                    <>
                      <PermissionSummary catalogue={catalogue.permissions} never={catalogue.never} granted={agent.permissions.granted} />
                      {isAdmin && agent.status !== "revoked" && (
                        <button type="button" onClick={() => setEditing([...agent.permissions.granted])} className={`${btn} border border-line text-ink-muted hover:text-ink`}>
                          {a.edit}
                        </button>
                      )}
                    </>
                  )}
                </section>
              )}

              {tab === "activity" && (
                <section className="rounded-xl border border-line bg-surface">
                  {decisions.length === 0
                    ? <p className="text-ink-faint text-xs py-8 px-4 text-center">{a.activity.empty}</p>
                    : <ul className="divide-y divide-line">{decisions.map((d) => <DecisionItem key={d.decisionId} d={d} />)}</ul>}
                </section>
              )}

              {tab === "approvals" && (
                <section className="rounded-xl border border-line bg-surface p-4">
                  <AgentApprovals approvals={approvals} canAnswer={isStaff} onAnswered={load} />
                </section>
              )}
            </>
          )}
        </div>
      </div>
      {stopping && agent && (
        <StopDialog
          onClose={() => setStopping(false)}
          onStop={async (reason, compromise) => {
            await emergencyStopAgent(agent.id, reason, compromise);
            setStopping(false);
            setNotice(a.controls.stopped);
            await load();
          }}
        />
      )}
    </div>
  );
}
