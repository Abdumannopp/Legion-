"use client";

import Link from "next/link";
import {
  AlertTriangle, Bot, CheckCircle2, Circle, Clock, Plug, ShieldAlert, ShieldCheck, ShieldOff,
} from "lucide-react";
import type { Overview } from "@/lib/api";
import { ruleGroup } from "@/lib/agentRules";
import { formatNumber, timeAgo } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const STATUS_STYLE: Record<Overview["status"], { Icon: typeof ShieldCheck; tone: string }> = {
  not_connected: { Icon: Plug, tone: "text-ink-muted border-line" },
  waiting_for_data: { Icon: Clock, tone: "text-brand-bright border-brand-hover/40" },
  attention: { Icon: ShieldAlert, tone: "text-warning border-warning/40" },
  protected: { Icon: ShieldCheck, tone: "text-success border-success/40" },
};

const STEP_HREF: Record<Overview["onboarding"]["steps"][number]["id"], string> = {
  connect: "/connect",
  first_event: "/connect",
  notifications: "/settings?tab=notifications",
  team: "/settings?tab=team",
  agent: "/agents",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-critical", high: "bg-warning", medium: "bg-info", low: "bg-ink-faint",
};

/**
 * The first screen: one honest status, then what is protected, what threats
 * are open, and what Legion blocked — each in a sentence a person can act on.
 */
export default function ProtectionOverview({ data }: { data: Overview }) {
  const { t, locale } = useLanguage();
  const o = t.overview;
  const s = STATUS_STYLE[data.status];
  const n = (v: number) => formatNumber(v, locale);
  const required = data.onboarding.steps.filter((x) => !x.optional);
  const done = required.filter((x) => x.done).length;

  return (
    <div className="space-y-3 mb-6">
      <section className={`rounded-xl border bg-surface px-4 py-4 ${s.tone}`} aria-live="polite">
        <div className="flex items-start gap-3">
          <s.Icon size={22} className="shrink-0 mt-0.5" />
          <div className="min-w-0 flex-1">
            <h2 className="text-ink text-base font-semibold" data-testid="protection-status">{o.status[data.status].title}</h2>
            <p className="text-ink-muted text-xs mt-1">{o.status[data.status].body}</p>
            {data.reasons.length > 0 && (
              <ul className="mt-2 space-y-1">
                {data.reasons.map((r) => (
                  <li key={r} className="text-ink-soft text-xs flex gap-1.5">
                    <span aria-hidden>•</span>{o.reasons[r] ?? r}
                  </li>
                ))}
              </ul>
            )}
          </div>
          {data.status === "not_connected" && (
            <Link href="/connect" className="shrink-0 text-xs font-medium px-3 py-2 rounded-lg bg-brand hover:bg-brand-hover text-white">
              {o.connectCta}
            </Link>
          )}
        </div>
      </section>

      {!data.onboarding.complete && (
        <section className="rounded-xl border border-line bg-surface px-4 py-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-ink text-sm font-medium">{o.checklist.title}</h2>
            <span className="text-ink-faint text-[11px]">{o.checklist.progress(done, required.length)}</span>
          </div>
          <ol className="space-y-2">
            {data.onboarding.steps.map((step) => {
              const copy = o.checklist.steps[step.id];
              return (
                <li key={step.id} className="flex items-start gap-2.5">
                  {step.done
                    ? <CheckCircle2 size={16} className="text-success shrink-0 mt-0.5" />
                    : <Circle size={16} className="text-ink-faint shrink-0 mt-0.5" />}
                  <div className="min-w-0 flex-1">
                    <p className={`text-xs font-medium ${step.done ? "text-ink-faint line-through" : "text-ink"}`}>
                      {copy.title}
                      {step.optional && <span className="ml-2 text-[10px] font-normal text-ink-faint no-underline">{o.checklist.optional}</span>}
                    </p>
                    {!step.done && <p className="text-ink-faint text-[11px] mt-0.5">{copy.hint}</p>}
                  </div>
                  {!step.done && (
                    <Link href={STEP_HREF[step.id]} className="text-[11px] font-medium text-brand-bright hover:underline shrink-0">
                      {copy.action}
                    </Link>
                  )}
                </li>
              );
            })}
          </ol>
        </section>
      )}

      <div className="grid gap-3 sm:grid-cols-3">
        <section className="rounded-xl border border-line bg-surface px-4 py-3.5">
          <h3 className="text-ink-muted text-[11px] uppercase tracking-wide mb-2">{o.protectedTitle}</h3>
          {data.protected.sources.length === 0 ? (
            <p className="text-ink-faint text-xs">{o.noSources}</p>
          ) : (
            <ul className="space-y-1.5">
              {data.protected.sources.map((src, i) => (
                <li key={`${src.kind}-${i}`} className="text-xs">
                  <p className="text-ink truncate">{src.name}</p>
                  <p className={`text-[11px] ${src.health === "receiving" ? "text-success" : src.health === "waiting" ? "text-ink-faint" : "text-warning"}`}>
                    {o.health[src.health]}
                    {src.last_event_at && src.health !== "waiting" ? ` · ${o.lastEvent(timeAgo(src.last_event_at, locale))}` : ""}
                  </p>
                </li>
              ))}
            </ul>
          )}
          <p className="text-ink-faint text-[11px] mt-2">{o.devices(data.protected.assets, data.protected.assets_online)}</p>
          <p className="text-ink-faint text-[11px]">{o.agentsLine(data.protected.agents.total, data.protected.agents.active)}</p>
        </section>

        <section className="rounded-xl border border-line bg-surface px-4 py-3.5">
          <h3 className="text-ink-muted text-[11px] uppercase tracking-wide mb-2">{o.threatsTitle}</h3>
          {data.threats.open_total === 0 ? (
            <p className="text-ink-faint text-xs flex items-center gap-1.5"><CheckCircle2 size={13} className="text-success" />{o.noThreats}</p>
          ) : (
            <>
              <div className="flex flex-wrap gap-x-3 gap-y-1 mb-2">
                {(["critical", "high", "medium", "low"] as const).filter((k) => data.threats.open[k] > 0).map((k) => (
                  <span key={k} className="flex items-center gap-1.5 text-xs text-ink">
                    <span className={`w-2 h-2 rounded-full ${SEVERITY_DOT[k]}`} />
                    {t.common.severity[k]} <span className="tabular-nums font-semibold">{n(data.threats.open[k])}</span>
                  </span>
                ))}
              </div>
              <ul className="space-y-1">
                {data.threats.top.map((a) => (
                  <li key={a.id}>
                    <Link href={`/incident/${a.id}`} className="text-[11px] text-ink-muted hover:text-brand-bright flex items-center gap-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEVERITY_DOT[a.severity]}`} />
                      <span className="truncate">{a.title}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </>
          )}
          <p className="text-ink-faint text-[11px] mt-2">{o.newToday(data.threats.new_last_24h)}</p>
        </section>

        <section className="rounded-xl border border-line bg-surface px-4 py-3.5">
          <h3 className="text-ink-muted text-[11px] uppercase tracking-wide mb-0.5">{o.blockedTitle}</h3>
          <p className="text-ink-faint text-[10px] mb-2">{o.blockedWindow(data.blocked.window_days)}</p>
          {data.protected.agents.total === 0 ? (
            <p className="text-ink-faint text-xs flex items-start gap-1.5"><Bot size={13} className="shrink-0 mt-0.5" />{o.noAgents}</p>
          ) : (
            <>
              <dl className="grid grid-cols-3 gap-1 mb-2 text-center">
                <div><dt className="text-[10px] text-ink-faint">{o.refused}</dt><dd className="text-ink text-lg font-semibold tabular-nums">{n(data.blocked.refused)}</dd></div>
                <div><dt className="text-[10px] text-ink-faint">{o.contained}</dt><dd className={`text-lg font-semibold tabular-nums ${data.blocked.contained ? "text-critical" : "text-ink"}`}>{n(data.blocked.contained)}</dd></div>
                <div><dt className="text-[10px] text-ink-faint">{o.waiting}</dt><dd className={`text-lg font-semibold tabular-nums ${data.blocked.approvals_pending ? "text-warning" : "text-ink"}`}>{n(data.blocked.approvals_pending)}</dd></div>
              </dl>
              {data.blocked.recent.length === 0 ? (
                <p className="text-ink-faint text-[11px]">{o.noBlocks}</p>
              ) : (
                <ul className="space-y-1.5">
                  {data.blocked.recent.slice(0, 3).map((d) => (
                    <li key={d.decision_id} className="text-[11px]">
                      <Link href={`/agents/${d.agent_id}`} className="group block">
                        <span className="flex items-center gap-1.5 text-ink group-hover:text-brand-bright">
                          {d.decision === "CONFIRM" ? <Clock size={11} className="text-warning shrink-0" /> : d.decision === "BLOCK" ? <ShieldOff size={11} className="text-warning shrink-0" /> : <AlertTriangle size={11} className="text-critical shrink-0" />}
                          <span className="truncate">{d.agent_name ?? o.unknownAgent}</span>
                        </span>
                        <span className="block text-ink-muted pl-4">{t.agents.decision[d.decision]}</span>
                        {d.rules[0] && <span className="block text-ink-faint pl-4">{t.agents.rules[ruleGroup(d.rules[0])].what}</span>}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
              {data.blocked.approvals_pending > 0 && (
                <Link href="/agents?tab=approvals" className="inline-block mt-2 text-[11px] font-medium text-brand-bright hover:underline">{o.review}</Link>
              )}
            </>
          )}
        </section>
      </div>
    </div>
  );
}
