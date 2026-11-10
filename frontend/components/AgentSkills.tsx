"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Loader2 } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import {
  assignSkill, getSkillAssignments, getSkills, unassignSkill,
  type LegionAgentName, type SkillInfo,
} from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const ORDER: LegionAgentName[] = ["Sentinel", "Hunter", "Guardian", "Oracle", "Vanguard"];

/**
 * Which of Legion's skills this AI agent may use. Choosing a skill grants no
 * permission (the server says so too): when the agent still lacks what the
 * skill reads with, the row says which permission to grant.
 */
export default function AgentSkills({ agentId, granted, canEdit }: { agentId: string; granted: string[]; canEdit: boolean }) {
  const { t } = useLanguage();
  const m = t.team;
  const [skills, setSkills] = useState<SkillInfo[] | null>(null);
  const [assigned, setAssigned] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    try {
      const [cat, mine] = await Promise.all([getSkills(), getSkillAssignments(agentId)]);
      setSkills(cat.skills);
      setAssigned(new Set(mine.assignments.map((x) => x.skill)));
    } catch (err) {
      setError(err);
    }
  }, [agentId]);

  useEffect(() => { load(); }, [load]);

  async function toggle(skill: string, on: boolean) {
    const set = (value: boolean) => setAssigned((prev) => { const next = new Set(prev); if (value) next.add(skill); else next.delete(skill); return next; });
    setBusy(skill); setError(null); setSaved(false);
    set(on); // show the choice at once; undone below if the server refuses
    try {
      if (on) await assignSkill(agentId, skill); else await unassignSkill(agentId, skill);
      setSaved(true);
    } catch (err) {
      set(!on);
      setError(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="rounded-xl border border-line bg-surface p-4 space-y-4" data-testid="agent-skills">
      <p className="text-ink-muted text-xs leading-relaxed">{m.assign.intro}</p>
      {!canEdit && <p className="text-ink-faint text-[11px]">{m.assign.adminOnly}</p>}
      {error != null && <ErrorNotice error={error} onRetry={load} />}
      {saved && <p role="status" className="flex items-center gap-1.5 text-success text-xs"><CheckCircle2 size={13} /> {m.assign.saved}</p>}
      {!skills ? (
        error == null && <div className="flex justify-center py-6"><Loader2 size={16} className="animate-spin text-ink-faint" /></div>
      ) : (
        ORDER.map((agent) => (
          <fieldset key={agent}>
            <legend className="text-ink-muted text-[11px] uppercase tracking-wide mb-1.5">{agent} · {m.agents[agent]?.role}</legend>
            <ul className="space-y-1.5">
              {skills.filter((s) => s.agent === agent).map((s) => {
                const on = assigned.has(s.name);
                const lacking = s.requiredPermissions.filter((p) => !granted.includes(p));
                return (
                  <li key={s.name}>
                    <label className={`flex items-start gap-2.5 rounded-lg border border-line px-3 py-2 ${canEdit ? "cursor-pointer" : ""}`}>
                      <input
                        type="checkbox" className="accent-brand mt-0.5" checked={on} disabled={!canEdit || busy === s.name}
                        onChange={(e) => toggle(s.name, e.target.checked)} aria-label={`${m.assign.use}: ${s.title}`}
                      />
                      <span className="min-w-0 flex-1">
                        <span className="block text-ink text-sm font-medium">{s.title}</span>
                        <span className="block text-ink-muted text-xs mt-0.5 leading-relaxed">{m.skillLines[s.name] ?? s.description}</span>
                        {on && (lacking.length > 0
                          ? <span className="block text-warning text-[11px] mt-1">{m.assign.needs(lacking.map((p) => t.agents.permissions[p] ?? p).join(", "))}</span>
                          : <span className="block text-success text-[11px] mt-1">{m.assign.ready}</span>)}
                      </span>
                      {busy === s.name && <Loader2 size={13} className="animate-spin text-ink-faint mt-0.5" />}
                    </label>
                  </li>
                );
              })}
            </ul>
          </fieldset>
        ))
      )}
    </section>
  );
}
