"use client";

import { useState } from "react";
import { Ban, CheckCircle2, Hand, Lock } from "lucide-react";
import type { AgentPermissionInfo } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const TIER_STYLE: Record<number, string> = {
  0: "text-success bg-success/10",
  1: "text-info bg-info/10",
  2: "text-warning bg-warning/10",
};

/** In Legion (alerts, devices…) first, then tools and outside services. */
const isTool = (id: string) => id.startsWith("tool.");

export function TierBadge({ tier }: { tier: number }) {
  const { t } = useLanguage();
  const k = (tier === 0 || tier === 1 || tier === 2 ? tier : 2) as 0 | 1 | 2;
  return <span className={`text-[9px] px-1.5 py-0.5 rounded whitespace-nowrap ${TIER_STYLE[k]}`} title={t.agents.tier[k].hint}>{t.agents.tier[k].label}</span>;
}

/** Tick what an agent may do. Each line says it in words, how risky it is, and whether it asks first. */
export function PermissionPicker({ catalogue, selected, onChange, disabled }: {
  catalogue: AgentPermissionInfo[];
  selected: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
}) {
  const { t } = useLanguage();
  const a = t.agents;
  const toggle = (id: string) => onChange(selected.includes(id) ? selected.filter((p) => p !== id) : [...selected, id]);
  const groups: [string, AgentPermissionInfo[]][] = [
    [a.groups.legion, catalogue.filter((p) => !isTool(p.id))],
    [a.groups.tools, catalogue.filter((p) => isTool(p.id))],
  ];
  return (
    <div className="space-y-3">
      {groups.map(([title, list]) => (
        <fieldset key={title}>
          <legend className="text-ink-muted text-[11px] uppercase tracking-wide mb-1">{title}</legend>
          <div className="grid sm:grid-cols-2 gap-x-3 gap-y-1">
            {list.map((p) => (
              <label key={p.id} className="flex items-center gap-2 text-xs text-ink py-0.5 cursor-pointer">
                <input type="checkbox" disabled={disabled} checked={selected.includes(p.id)} onChange={() => toggle(p.id)} className="accent-brand" />
                <span className="flex-1 min-w-0">{a.permissions[p.id] ?? p.id}</span>
                {p.asks_first && <Hand size={11} className="text-warning shrink-0" aria-label={a.asksFirst} />}
                <TierBadge tier={p.tier} />
              </label>
            ))}
          </div>
        </fieldset>
      ))}
      <p className="text-ink-faint text-[10px] flex items-center gap-1"><Hand size={10} className="text-warning" /> {a.asksFirst} — {a.asksFirstHint}</p>
    </div>
  );
}

/** What this agent can do, what it asks you about first, and what it can't do — the last part always including the things no agent can ever do. */
export function PermissionSummary({ catalogue, never, granted }: { catalogue: AgentPermissionInfo[]; never: string[]; granted: string[] }) {
  const { t } = useLanguage();
  const a = t.agents;
  const [allNo, setAllNo] = useState(false);
  const info = new Map(catalogue.map((p) => [p.id, p]));
  const can = granted.filter((p) => !info.get(p)?.asks_first);
  const asks = granted.filter((p) => info.get(p)?.asks_first);
  const no = catalogue.filter((p) => !granted.includes(p.id)).map((p) => p.id);
  const shownNo = allNo ? no : no.slice(0, 5);
  const line = (id: string) => (
    <li key={id} className="flex items-center gap-2 text-xs text-ink-soft">
      <span className="flex-1 min-w-0">{a.permissions[id] ?? id}</span>
      {info.has(id) && <TierBadge tier={info.get(id)!.tier} />}
    </li>
  );
  return (
    <div className="grid sm:grid-cols-3 gap-3">
      <div>
        <h4 className="flex items-center gap-1.5 text-success text-[11px] uppercase tracking-wide mb-1.5"><CheckCircle2 size={12} /> {a.canDo}</h4>
        {can.length ? <ul className="space-y-1">{can.map(line)}</ul> : <p className="text-ink-faint text-xs">{a.noneGranted}</p>}
      </div>
      <div>
        <h4 className="flex items-center gap-1.5 text-warning text-[11px] uppercase tracking-wide mb-1.5"><Hand size={12} /> {a.asksFirst}</h4>
        {asks.length ? <ul className="space-y-1">{asks.map(line)}</ul> : <p className="text-ink-faint text-xs">{a.nothingAsks}</p>}
        {asks.length > 0 && <p className="text-ink-faint text-[10px] mt-1.5">{a.asksFirstHint}</p>}
      </div>
      <div>
        <h4 className="flex items-center gap-1.5 text-ink-muted text-[11px] uppercase tracking-wide mb-1.5"><Ban size={12} /> {a.cannotDo}</h4>
        <ul className="space-y-1">{shownNo.map((id) => <li key={id} className="text-xs text-ink-faint">{a.permissions[id] ?? id}</li>)}</ul>
        {no.length > 5 && (
          <button type="button" onClick={() => setAllNo(!allNo)} className="text-[11px] text-brand-bright hover:underline mt-1">
            {allNo ? a.showLess : a.showAll(no.length)}
          </button>
        )}
        <h5 className="flex items-center gap-1.5 text-ink-faint text-[10px] uppercase tracking-wide mt-3 mb-1"><Lock size={10} /> {a.neverTitle}</h5>
        <ul className="space-y-0.5">{never.map((id) => <li key={id} className="text-[11px] text-ink-faint">{a.never[id] ?? id}</li>)}</ul>
      </div>
    </div>
  );
}
