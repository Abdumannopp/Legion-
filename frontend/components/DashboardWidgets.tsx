"use client";

import { AlertTriangle, Bot, Monitor, ShieldAlert } from "lucide-react";
import type { Overview } from "@/lib/api";
import { formatNumber } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { palette, severityColor } from "@/lib/theme";

/**
 * The dashboard's headline numbers, from GET /overview only. Nothing here is a sample: a number Legion does not
 * have is shown as "none yet", never invented (there is deliberately no "security score").
 */
export function KpiRow({ data }: { data: Overview }) {
  const { t, locale } = useLanguage();
  const k = t.dashboard.kpi;
  const n = (v: number) => formatNumber(v, locale);
  const a = data.protected;
  const cards = [
    { label: k.openThreats, value: n(data.threats.open_total), hint: k.newToday(data.threats.new_last_24h), Icon: ShieldAlert, color: data.threats.open_total ? palette.high : palette.success },
    { label: k.critical, value: n(data.threats.open.critical), hint: k.criticalHint, Icon: AlertTriangle, color: data.threats.open.critical ? palette.critical : palette.inkFaint },
    { label: k.endpoints, value: a.assets ? n(a.assets_online) : "—", hint: a.assets ? k.endpointsOf(a.assets_online, a.assets) : k.noEndpoints, Icon: Monitor, color: palette.brandBright },
    { label: k.agents, value: a.agents.total ? n(a.agents.active) : "—", hint: a.agents.total ? k.agentsOf(a.agents.active, a.agents.total) : k.noAgents, Icon: Bot, color: palette.brandBright },
  ];
  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mb-4" data-testid="kpi-row">
      {cards.map(({ label, value, hint, Icon, color }, i) => (
        <div key={label} className="lg-surface lg-interactive lg-enter p-4" style={{ animationDelay: `${i * 40}ms` }}>
          <div className="flex items-center gap-2 text-ink-muted text-xs">
            <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0" style={{ backgroundColor: `${color}1F` }}>
              <Icon size={15} color={color} />
            </span>
            <span className="truncate">{label}</span>
          </div>
          <p className="text-ink text-[28px] leading-none font-semibold tabular-nums mt-3">{value}</p>
          <p className="text-ink-faint text-[11px] mt-2 truncate">{hint}</p>
        </div>
      ))}
    </div>
  );
}

/** Open threats by severity as a ring: one segment per severity, the total in the middle, and a legend with counts. */
export function SeverityRing({ data }: { data: Overview }) {
  const { t, locale } = useLanguage();
  const open = data.threats.open;
  const order = ["critical", "high", "medium", "low"] as const;
  const total = order.reduce((s, k) => s + open[k], 0);
  const R = 52, C = 2 * Math.PI * R;
  let offset = 0;
  return (
    <section className="lg-surface p-5 lg-enter" aria-labelledby="sev-ring-title">
      <h2 id="sev-ring-title" className="text-ink text-sm font-semibold">{t.dashboard.severityTitle}</h2>
      {total === 0 ? (
        <p className="text-ink-muted text-xs mt-3">{t.dashboard.severityNone}</p>
      ) : (
        <div className="flex items-center gap-5 mt-4">
          <svg viewBox="0 0 140 140" width={128} height={128} role="img" aria-label={`${total} ${t.dashboard.severityTotal}`} className="shrink-0 -rotate-90">
            <circle cx="70" cy="70" r={R} fill="none" stroke={palette.line} strokeWidth="14" />
            {order.map((k) => {
              const len = (open[k] / total) * C;
              const seg = open[k] ? (
                <circle key={k} cx="70" cy="70" r={R} fill="none" stroke={severityColor[k]} strokeWidth="14"
                  strokeDasharray={`${Math.max(len - 2, 0.01)} ${C}`} strokeDashoffset={-offset} strokeLinecap="butt" />
              ) : null;
              offset += len;
              return seg;
            })}
            <text x="70" y="70" transform="rotate(90 70 70)" textAnchor="middle" dominantBaseline="central" fill={palette.ink} fontSize="26" fontWeight="600">{formatNumber(total, locale)}</text>
          </svg>
          <ul className="flex-1 space-y-2 text-xs">
            {order.map((k) => (
              <li key={k} className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: severityColor[k] }} aria-hidden />
                <span className="text-ink-soft flex-1">{t.common.severity[k]}</span>
                <span className="text-ink tabular-nums">{formatNumber(open[k], locale)}</span>
                <span className="text-ink-faint tabular-nums w-10 text-right">{Math.round((open[k] / total) * 100)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
