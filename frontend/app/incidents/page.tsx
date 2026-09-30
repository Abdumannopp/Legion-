"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Search,
  Loader2,
  ClipboardList,
  ChevronRight,
  AlertTriangle,
  AlertCircle,
  Info,
  Radio,
} from "lucide-react";
import Sidebar from "@/components/Sidebar";
import { Alert, getAlerts, isLoggedIn, ApiError } from "@/lib/api";
import ErrorNotice from "@/components/ErrorNotice";
import { sourceLabel } from "@/lib/sources";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { timeAgo } from "@/lib/i18n/format";

// Labels come from t.common.severity / t.common.status.
const SEVERITY_STYLE: Record<
  Alert["severity"],
  { color: string; Icon: typeof AlertTriangle }
> = {
  critical: { color: palette.critical, Icon: AlertTriangle },
  high: { color: palette.warning, Icon: AlertCircle },
  medium: { color: palette.info, Icon: Info },
  low: { color: palette.inkFaint, Icon: Info },
};

const STATUS_COLOR: Record<Alert["status"], string> = {
  open: palette.critical,
  investigating: palette.brandBright,
  resolved: palette.success,
};

export default function IncidentsPage() {
  const router = useRouter();
  const { t, locale } = useLanguage();
  const [incidents, setIncidents] = useState<Alert[]>([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | Alert["status"]>("all");
  const [severityFilter, setSeverityFilter] = useState<"all" | Alert["severity"]>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await getAlerts({
        status: statusFilter === "all" ? undefined : statusFilter,
        severity: severityFilter === "all" ? undefined : severityFilter,
        q: query || undefined,
      });
      setIncidents(data);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [statusFilter, severityFilter, query, router, t]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    load();
  }, [load, router]);

  const statusCounts = {
    open: incidents.filter((i) => i.status === "open").length,
    investigating: incidents.filter((i) => i.status === "investigating").length,
    resolved: incidents.filter((i) => i.status === "resolved").length,
  };

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-5xl mx-auto">
          <div className="mb-6">
            <h1 className="legion-title text-ink flex items-center gap-2">
              <ClipboardList size={20} color={palette.brandBright} />
              {t.incidents.title}
            </h1>
            <p className="text-ink-faint text-[11px] tracking-[0.1em] uppercase mt-1.5">
              {t.incidents.summary(
                incidents.length,
                statusCounts.open,
                statusCounts.investigating
              )}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 mb-4">
            <div className="relative flex-1 min-w-[180px]">
              <Search
                size={15}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint"
              />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t.incidents.searchPlaceholder}
                className="w-full bg-surface border border-line rounded-lg pl-9 pr-3 py-2 text-sm text-ink placeholder:text-ink-disabled outline-none focus:border-brand-hover"
              />
            </div>

            {(["all", "open", "investigating", "resolved"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setStatusFilter(f)}
                className={`text-xs font-medium px-3 py-2 rounded-lg border transition-colors whitespace-nowrap ${
                  statusFilter === f
                    ? "border-brand-hover text-brand-bright bg-brand/10"
                    : "border-line text-ink-faint hover:text-ink-muted"
                }`}
              >
                {f === "all" ? t.common.all : t.common.status[f]}
              </button>
            ))}

            <select
              value={severityFilter}
              onChange={(e) =>
                setSeverityFilter(e.target.value as "all" | Alert["severity"])
              }
              className="bg-surface border border-line rounded-lg px-3 py-2 text-xs text-ink-muted outline-none focus:border-brand-hover"
            >
              <option value="all">{t.incidents.allSeverities}</option>
              <option value="critical">{t.common.severity.critical}</option>
              <option value="high">{t.common.severity.high}</option>
              <option value="medium">{t.common.severity.medium}</option>
              <option value="low">{t.common.severity.low}</option>
            </select>
          </div>

          {error != null && (
            <div className="mb-4"><ErrorNotice error={error} onRetry={load} /></div>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <Loader2 size={20} className="animate-spin" />
            </div>
          ) : (
            <div className="rounded-xl border border-line bg-surface overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left">
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium whitespace-nowrap">
                      {t.incidents.column.incident}
                    </th>
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium whitespace-nowrap">
                      {t.incidents.column.severity}
                    </th>
                    <th className="px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium whitespace-nowrap">
                      {t.incidents.column.status}
                    </th>
                    <th className="hidden sm:table-cell px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium whitespace-nowrap">
                      {t.incidents.column.detectedBy}
                    </th>
                    <th className="hidden sm:table-cell px-4 py-3 text-ink-faint text-[11px] uppercase tracking-wide font-medium whitespace-nowrap">
                      {t.incidents.column.when}
                    </th>
                    <th className="w-8" />
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((incident) => {
                    const sev = SEVERITY_STYLE[incident.severity];
                    const statusColor = STATUS_COLOR[incident.status];
                    const SevIcon = sev.Icon;
                    return (
                      <tr
                        key={incident.id}
                        onClick={() => router.push(`/incident/${incident.id}`)}
                        className="border-b border-line last:border-b-0 hover:bg-panel transition-colors cursor-pointer"
                      >
                        <td className="px-4 py-3">
                          <p className="text-ink font-medium">{incident.title}</p>
                          <p className="text-ink-faint text-[11px] font-mono">
                            {incident.id}
                          </p>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className="inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded whitespace-nowrap"
                            style={{ color: sev.color, backgroundColor: `${sev.color}1A` }}
                          >
                            <SevIcon size={11} />
                            {t.common.severity[incident.severity]}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className="text-xs font-medium whitespace-nowrap"
                            style={{ color: statusColor }}
                          >
                            {t.common.status[incident.status]}
                          </span>
                        </td>
                        <td className="hidden sm:table-cell px-4 py-3 text-ink-muted text-xs">
                          <span className="inline-flex items-center gap-1.5">
                            <Radio size={11} />
                            {sourceLabel(incident.source, t) ?? "—"}
                          </span>
                        </td>
                        <td className="hidden sm:table-cell px-4 py-3 text-ink-faint text-xs whitespace-nowrap">
                          {timeAgo(incident.created_at, locale)}
                        </td>
                        <td className="px-4 py-3">
                          <ChevronRight size={14} className="text-ink-disabled" />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {incidents.length === 0 && (
                <div className="text-center py-12 text-ink-faint text-sm">
                  {t.incidents.empty}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
