"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { BrainCircuit, ChevronRight, KeyRound, Loader2, Plus, ShieldAlert } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import ErrorNotice from "@/components/ErrorNotice";
import CopyButton from "@/components/CopyButton";
import AgentApprovals from "@/components/AgentApprovals";
import AgentStatus from "@/components/AgentStatus";
import { PermissionPicker, PermissionSummary } from "@/components/AgentPermissions";
import {
  ApiError, agentTokenUrl, createAgent, getAgentPermissions, getAgents, getApprovals, getMe, isLoggedIn,
  type AgentPermissionInfo, type AgentSummary, type ApprovalRequest, type CurrentUser,
} from "@/lib/api";
import { AGENT_PRESETS } from "@/lib/agentRules";
import { timeAgo } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";

type Preset = "readOnly" | "triage" | "custom";

const RISK_STYLE: Record<AgentSummary["risk"]["overall"], string> = {
  low: "text-success", medium: "text-info", high: "text-warning", critical: "text-critical",
};

/** Add an agent: a name, a starting point (read-only first), and the key it signs in with — shown once. */
function CreateAgent({ catalogue, never, onCreated, onCancel }: {
  catalogue: AgentPermissionInfo[];
  never: string[];
  onCreated: (id: string) => void;
  onCancel: () => void;
}) {
  const { t } = useLanguage();
  const f = t.agents.form;
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [preset, setPreset] = useState<Preset>("readOnly");
  const [custom, setCustom] = useState<string[]>([...AGENT_PRESETS.readOnly]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [created, setCreated] = useState<{ id: string; secret: string } | null>(null);
  const permissions = preset === "custom" ? custom : [...AGENT_PRESETS[preset]];

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setProblem(null); setError(null);
    if (!name.trim()) { setProblem(f.nameRequired); return; }
    if (!permissions.length) { setProblem(f.pickOne); return; }
    setBusy(true);
    try {
      const r = await createAgent({ name: name.trim(), description: description.trim() || undefined, permissions });
      setCreated({ id: r.identity.id, secret: r.credential.secret });
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    const c = t.agents.created;
    return (
      <section className="rounded-xl border border-success/40 bg-surface p-4 space-y-3" data-testid="agent-created">
        <h2 className="text-ink text-sm font-semibold">{c.title}</h2>
        <div className="rounded-lg border border-warning/40 bg-warning/5 p-3 space-y-2">
          <p className="flex items-center gap-1.5 text-warning text-xs font-medium"><KeyRound size={13} /> {c.keyTitle}</p>
          <p className="text-ink-muted text-[11px]">{c.keyHint}</p>
          {([[c.idLabel, created.id], [c.secretLabel, created.secret]] as const).map(([label, value]) => (
            <div key={label} className="flex items-center gap-2">
              <span className="text-ink-faint text-[11px] w-20 shrink-0">{label}</span>
              <code className="flex-1 min-w-0 text-[11px] text-ink-soft bg-canvas border border-line rounded px-2 py-1 break-all">{value}</code>
              <CopyButton value={value} label={t.agents.copy} copiedLabel={t.agents.copied} />
            </div>
          ))}
          <p className="text-ink-faint text-[11px]">{c.signInAt} <code className="text-ink-soft break-all">{agentTokenUrl()}</code></p>
        </div>
        <button type="button" onClick={() => onCreated(created.id)} className="text-xs font-medium px-3 py-1.5 rounded-lg bg-brand hover:bg-brand-hover text-white">{c.done}</button>
      </section>
    );
  }

  const input = "w-full bg-canvas border border-line rounded-md px-2.5 py-1.5 text-sm text-ink outline-none focus:border-brand-hover";
  return (
    <form onSubmit={submit} className="rounded-xl border border-line bg-surface p-4 space-y-3">
      <h2 className="text-ink text-sm font-semibold">{f.title}</h2>
      <div className="grid sm:grid-cols-2 gap-3">
        <label className="text-xs text-ink-muted space-y-1 block">
          <span>{f.name}</span>
          <input value={name} maxLength={100} onChange={(e) => setName(e.target.value)} placeholder={f.namePlaceholder} className={input} />
        </label>
        <label className="text-xs text-ink-muted space-y-1 block">
          <span>{f.description}</span>
          <input value={description} maxLength={500} onChange={(e) => setDescription(e.target.value)} placeholder={f.descriptionPlaceholder} className={input} />
        </label>
      </div>
      <fieldset>
        <legend className="text-xs text-ink-muted mb-1.5">{f.start}</legend>
        <div className="grid sm:grid-cols-3 gap-2">
          {(["readOnly", "triage", "custom"] as const).map((p) => (
            <label key={p} className={`rounded-lg border px-3 py-2 cursor-pointer ${preset === p ? "border-brand-hover bg-brand/10" : "border-line"}`}>
              <span className="flex items-center gap-2 text-xs text-ink font-medium">
                <input type="radio" name="preset" checked={preset === p} onChange={() => { setPreset(p); if (p === "custom") setCustom(permissions); }} className="accent-brand" />
                {f.presets[p].label}
              </span>
              <span className="block text-[11px] text-ink-faint mt-0.5">{f.presets[p].hint}</span>
            </label>
          ))}
        </div>
      </fieldset>
      {preset === "custom"
        ? <PermissionPicker catalogue={catalogue} selected={custom} onChange={setCustom} />
        : <PermissionSummary catalogue={catalogue} never={never} granted={permissions} />}
      {problem && <p className="text-critical text-xs">{problem}</p>}
      {error != null && <ErrorNotice error={error} isAdmin />}
      <div className="flex gap-2">
        <button type="submit" disabled={busy} className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-brand hover:bg-brand-hover text-white disabled:opacity-60">
          {busy && <Loader2 size={12} className="animate-spin" />} {f.submit}
        </button>
        <button type="button" onClick={onCancel} className="text-xs text-ink-muted hover:text-ink px-3 py-1.5">{f.cancel}</button>
      </div>
    </form>
  );
}

/**
 * AI agents: who they are, whether they can act right now, what they did,
 * and what is waiting for a person — without needing to know the firewall.
 */
export default function AgentsPage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const a = t.agents;
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [agents, setAgents] = useState<AgentSummary[] | null>(null);
  const [catalogue, setCatalogue] = useState<{ permissions: AgentPermissionInfo[]; never: string[] } | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [tab, setTab] = useState<"list" | "approvals">("list");
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const isAdmin = me?.role === "admin";
  const isStaff = me?.role === "admin" || me?.role === "analyst";

  const load = useCallback(async () => {
    setError(null);
    try {
      const [list, cat] = await Promise.all([getAgents(), getAgentPermissions()]);
      setAgents(list.agents);
      setCatalogue(cat);
      setApprovals((await getApprovals("pending")).approvals);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { router.push("/login"); return; }
      setError(err);
    }
  }, [router]);

  useEffect(() => {
    if (!isLoggedIn()) { router.push("/login"); return; }
    if (new URLSearchParams(window.location.search).get("tab") === "approvals") setTab("approvals");
    getMe().then(setMe).catch(() => {});
    load();
  }, [load, router]);

  const names = Object.fromEntries((agents ?? []).map((x) => [x.id, x.name]));

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-3xl mx-auto space-y-4">
          <header className="flex items-start justify-between gap-3 flex-wrap">
            <div>
              <h1 className="legion-title text-ink flex items-center gap-2"><BrainCircuit size={18} /> {a.title}</h1>
              <p className="text-ink-muted text-sm mt-1.5 max-w-xl">{a.intro}</p>
            </div>
            {isAdmin && !adding && catalogue && (
              <button type="button" onClick={() => setAdding(true)} className="flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg bg-brand hover:bg-brand-hover text-white">
                <Plus size={13} /> {a.add}
              </button>
            )}
          </header>

          {me && !isAdmin && (
            <p className="flex items-center gap-2 text-ink-muted text-xs bg-panel rounded-lg px-3 py-2"><ShieldAlert size={13} /> {a.adminOnly}</p>
          )}
          {error != null && <ErrorNotice error={error} onRetry={load} isAdmin={isAdmin} />}

          {adding && catalogue && (
            <CreateAgent
              catalogue={catalogue.permissions}
              never={catalogue.never}
              onCancel={() => setAdding(false)}
              onCreated={(id) => router.push(`/agents/${id}`)}
            />
          )}

          <div className="flex gap-1 border-b border-line" role="tablist">
            {([["list", a.tabList], ["approvals", `${a.tabs.approvals}${approvals.length ? ` (${approvals.length})` : ""}`]] as const).map(([id, label]) => (
              <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
                className={`text-xs px-3 py-2 -mb-px border-b-2 ${tab === id ? "border-brand-hover text-ink" : "border-transparent text-ink-faint hover:text-ink-muted"}`}>
                {label}
              </button>
            ))}
          </div>

          {tab === "approvals" ? (
            <AgentApprovals approvals={approvals} agentNames={names} canAnswer={isStaff} onAnswered={load} />
          ) : !agents ? (
            error == null && <div className="flex justify-center py-12"><Loader2 size={18} className="animate-spin text-ink-faint" /></div>
          ) : agents.length === 0 ? (
            <div className="text-center py-12 px-6 rounded-xl border border-dashed border-line">
              <BrainCircuit size={22} className="mx-auto text-ink-faint mb-2" />
              <p className="text-ink text-sm font-medium">{a.empty}</p>
              <p className="text-ink-faint text-xs mt-1 max-w-md mx-auto">{a.emptyHint}</p>
            </div>
          ) : (
            <ul className="space-y-2">
              {agents.map((ag) => (
                <li key={ag.id}>
                  <Link href={`/agents/${ag.id}`} className="flex items-center gap-3 rounded-xl border border-line bg-surface px-4 py-3 hover:border-brand-hover/40" data-testid="agent-row">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-ink text-sm font-medium truncate">{ag.name}</span>
                        <AgentStatus agent={ag} />
                        <span className={`text-[10px] ${RISK_STYLE[ag.risk.overall]}`}>{a.risk[ag.risk.overall]}</span>
                      </div>
                      {ag.blockedBecause && <p className="text-ink-muted text-[11px] mt-0.5">{a.blockedBecause[ag.blockedBecause] ?? ag.blockedBecause}</p>}
                      <p className="text-ink-faint text-[11px] mt-0.5">
                        {ag.activity.lastActivityAt ? a.lastActive(timeAgo(ag.activity.lastActivityAt, locale)) : a.neverActive}
                        {" · "}{a.actionsInWindow(ag.activity.decisionsInWindow)}
                        {ag.risk.refusalsInWindow > 0 && ` · ${a.refusedInWindow(ag.risk.refusalsInWindow)}`}
                        {ag.risk.pendingApprovals > 0 && ` · ${a.waitingCount(ag.risk.pendingApprovals)}`}
                      </p>
                    </div>
                    <ChevronRight size={15} className="text-ink-faint shrink-0" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
