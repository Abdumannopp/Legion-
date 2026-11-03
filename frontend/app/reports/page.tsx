"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { BarChart3, Loader2, ShieldCheck, Monitor, Bot } from "lucide-react";
import { sourceLabel } from "@/lib/sources";
import Sidebar from "@/components/Sidebar";
import {
  Alert,
  AlertStats,
  Asset,
  getAlerts,
  getStats,
  getAssets,
  isLoggedIn,
  ApiError,
} from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const SEVERITY_ORDER: Alert["severity"][] = ["critical", "high", "medium", "low"];
const SEVERITY_COLOR: Record<Alert["severity"], string> = {
  critical: palette.critical,
  high: palette.warning,
  medium: palette.info,
  low: palette.inkFaint,
};

const STATUS_ORDER: Alert["status"][] = ["open", "investigating", "resolved"];
const STATUS_COLOR: Record<Alert["status"], string> = {
  open: palette.critical,
  investigating: palette.brandBright,
  resolved: palette.success,
};

const SOURCE_COLORS = [palette.info, palette.brandBright, palette.success, palette.warning, palette.critical];

function BarRow({
  label,
  count,
  total,
  color,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <span className="w-24 shrink-0 truncate text-ink-muted text-xs" title={label}>
        {label}
      </span>
      <div className="flex-1 h-2 rounded-full bg-panel overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span className="w-10 shrink-0 text-right text-ink text-xs tabular-nums">
        {count}
      </span>
    </div>
  );
}

function SummaryCard({
  label,
  value,
  color,
  Icon,
}: {
  label: string;
  value: string;
  color?: string;
  Icon: typeof BarChart3;
}) {
  return (
    <div className="flex-1 min-w-[140px] rounded-xl border border-line bg-surface px-4 py-3.5">
      <div className="flex items-center gap-2 mb-2">
        <Icon size={14} color={color || palette.inkMuted} strokeWidth={2.2} />
        <span className="text-ink-muted text-[11px] uppercase tracking-wide">{label}</span>
      </div>
      <p className="text-2xl font-semibold tabular-nums" style={{ color: color || palette.ink }}>
        {value}
      </p>
    </div>
  );
}

export default function ReportsPage() {
  const router = useRouter();
  const { t } = useLanguage();
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [statsData, alertsData, assetsData] = await Promise.all([
        getStats(),
        getAlerts(),
        getAssets(),
      ]);
      setStats(statsData);
      setAlerts(alertsData);
      setAssets(assetsData);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err instanceof ApiError ? err.message : t.reports.loadError);
    } finally {
      setLoading(false);
    }
  }, [router, t]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    load();
  }, [load, router]);

  const total = alerts.length;

  // Where detections came from (Wazuh, an integration, Legion itself).
  const sourceCounts = alerts.reduce<Record<string, number>>((acc, a) => {
    const label = sourceLabel(a.source, t) ?? t.reports.otherSource;
    acc[label] = (acc[label] || 0) + 1;
    return acc;
  }, {});
  const sources = Object.keys(sourceCounts).sort((a, b) => sourceCounts[b] - sourceCounts[a]);

  const explainedCount = alerts.filter((a) => a.ai_explanation).length;
  const avgConfidence =
    total > 0 ? Math.round(alerts.reduce((sum, a) => sum + a.confidence, 0) / total) : 0;

  const resolutionRate = total > 0 ? Math.round((stats!.resolved / total) * 100) : 0;

  const recentResolved = alerts
    .filter((a) => a.status === "resolved")
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  const onlineAssets = assets.filter((a) => a.online).length;

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-5xl mx-auto">
          <div className="mb-6">
            <h1 className="legion-title text-ink flex items-center gap-2">
              <BarChart3 size={20} color={palette.brandBright} />
              {t.reports.title}
            </h1>
            <p className="text-ink-faint text-[11px] tracking-[0.1em] uppercase mt-1.5">
              {t.reports.subtitle}
            </p>
          </div>

          {error && (
            <div className="mb-4 text-critical text-xs bg-critical/10 rounded-lg px-3 py-2.5">
              {error}
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <Loader2 size={20} className="animate-spin" />
            </div>
          ) : !stats ? null : (
            <div className="flex flex-col gap-4">
              {/* KPI row */}
              <div className="flex flex-wrap gap-3">
                <SummaryCard label={t.reports.kpi.totalIncidents} value={String(total)} Icon={ShieldCheck} />
                <SummaryCard
                  label={t.reports.kpi.resolutionRate}
                  value={`${resolutionRate}%`}
                  color={palette.success}
                  Icon={ShieldCheck}
                />
                <SummaryCard
                  label={t.reports.kpi.avgConfidence}
                  value={`${avgConfidence}%`}
                  color={palette.brandBright}
                  Icon={Bot}
                />
                <SummaryCard
                  label={t.reports.kpi.assetsOnline}
                  value={`${onlineAssets}/${assets.length}`}
                  color={palette.warning}
                  Icon={Monitor}
                />
              </div>

              <div className="grid md:grid-cols-2 gap-4">
                {/* Severity breakdown */}
                <div className="rounded-xl border border-line bg-surface p-4">
                  <h2 className="text-ink text-sm font-medium mb-4">
                    {t.reports.bySeverity}
                  </h2>
                  <div className="flex flex-col gap-3">
                    {SEVERITY_ORDER.map((sev) => (
                      <BarRow
                        key={sev}
                        label={t.common.severity[sev]}
                        count={stats.by_severity[sev] || 0}
                        total={total}
                        color={SEVERITY_COLOR[sev]}
                      />
                    ))}
                  </div>
                </div>

                {/* Status breakdown */}
                <div className="rounded-xl border border-line bg-surface p-4">
                  <h2 className="text-ink text-sm font-medium mb-4">
                    {t.reports.byStatus}
                  </h2>
                  <div className="flex flex-col gap-3">
                    <BarRow label={t.common.status.open} count={stats.open} total={total} color={STATUS_COLOR.open} />
                    <BarRow
                      label={t.common.status.investigating}
                      count={stats.investigating}
                      total={total}
                      color={STATUS_COLOR.investigating}
                    />
                    <BarRow
                      label={t.common.status.resolved}
                      count={stats.resolved}
                      total={total}
                      color={STATUS_COLOR.resolved}
                    />
                  </div>
                </div>

                {/* Detections by source */}
                <div className="rounded-xl border border-line bg-surface p-4">
                  <h2 className="text-ink text-sm font-medium mb-4">
                    {t.reports.byAgent}
                  </h2>
                  <div className="flex flex-col gap-3">
                    {sources.length === 0 ? (
                      <p className="text-ink-faint text-xs">{t.reports.noIncidents}</p>
                    ) : (
                      sources.map((source, i) => (
                        <BarRow
                          key={source}
                          label={source}
                          count={sourceCounts[source]}
                          total={total}
                          color={SOURCE_COLORS[i % SOURCE_COLORS.length]}
                        />
                      ))
                    )}
                  </div>
                </div>

                {/* Oracle coverage */}
                <div className="rounded-xl border border-line bg-surface p-4">
                  <h2 className="text-ink text-sm font-medium mb-4">
                    {t.reports.oracleCoverage}
                  </h2>
                  <BarRow
                    label={t.reports.explained}
                    count={explainedCount}
                    total={total}
                    color={palette.brandBright}
                  />
                  <p className="text-ink-faint text-[11px] mt-3">
                    {t.reports.coverageNote(explainedCount, total)}
                  </p>
                </div>
              </div>

              {/* Recently resolved */}
              <div className="rounded-xl border border-line bg-surface overflow-hidden">
                <div className="px-4 py-3 border-b border-line">
                  <h2 className="text-ink text-sm font-medium">
                    {t.reports.recentlyResolved}
                  </h2>
                </div>
                {recentResolved.length === 0 ? (
                  <p className="text-ink-faint text-sm px-4 py-6">
                    {t.reports.nothingResolved}
                  </p>
                ) : (
                  <table className="w-full text-sm">
                    <tbody>
                      {recentResolved.map((a) => (
                        <tr
                          key={a.id}
                          onClick={() => router.push(`/incident/${a.id}`)}
                          className="border-b border-line last:border-b-0 hover:bg-panel transition-colors cursor-pointer"
                        >
                          <td className="px-4 py-3">
                            <p className="text-ink font-medium">{a.title}</p>
                            <p className="text-ink-faint text-[11px] font-mono">{a.id}</p>
                          </td>
                          <td className="px-4 py-3 text-right">
                            <span
                              className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded"
                              style={{
                                color: SEVERITY_COLOR[a.severity],
                                backgroundColor: `${SEVERITY_COLOR[a.severity]}1A`,
                              }}
                            >
                              {t.common.severity[a.severity]}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
