"use client";

import AiBadge from "@/components/AiBadge";
import { useState, useEffect, useCallback, useRef, type MouseEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  AlertTriangle,
  AlertCircle,
  Info,
  Search,
  Radio,
  Eye,
  CheckCircle2,
  ChevronRight,
  Activity,
  Loader2,
  Sparkles,
  LogOut,
  ExternalLink,
  ListChecks,
} from "lucide-react";
import {
  Alert,
  AlertStats,
  CurrentUser,
  Overview,
  getAlertFeed,
  getOverview,
  getStats,
  getMe,
  updateAlertStatus,
  reopenReason,
  explainAlert,
  isLoggedIn,
  logout,
  ApiError,
} from "@/lib/api";
import Sidebar from "@/components/Sidebar";
import AccessBanner from "@/components/AccessBanner";
import { useRealtimeAlerts, RealtimeEvent } from "@/hooks/useRealtimeAlerts";
import { sortAlerts, upsertAlert } from "@/lib/realtime/alert-feed";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { suggestedActionText, timeAgo } from "@/lib/i18n/format";
import ErrorNotice from "@/components/ErrorNotice";
import ProtectionOverview from "@/components/ProtectionOverview";
import { KpiRow, SeverityRing } from "@/components/DashboardWidgets";
import { isTestSource, sourceLabel } from "@/lib/sources";

type Severity = Alert["severity"];

// Palette from the Legion UI/UX Design Guide
const COLORS = {
  bg: palette.canvas,
  card: palette.surface,
  border: palette.line,
  primary: palette.brandBright,
  info: palette.info,
  success: palette.success,
  warning: palette.warning,
  critical: palette.critical,
  text: palette.ink,
  textMuted: palette.inkMuted,
  textFaint: palette.inkFaint,
};

// Labels come from t.common.severity / t.common.status.
const SEVERITY_STYLE: Record<
  Severity,
  { color: string; Icon: typeof AlertTriangle }
> = {
  critical: { color: COLORS.critical, Icon: AlertTriangle },
  high: { color: palette.high, Icon: AlertCircle },
  medium: { color: palette.warning, Icon: Info },
  low: { color: palette.low, Icon: Info },
};

const STATUS_COLOR: Record<Alert["status"], string> = {
  open: COLORS.critical,
  investigating: COLORS.primary,
  resolved: COLORS.success,
};

/** The page header. The numbers live in ProtectionOverview, from GET /overview. */
function TopBar() {
  const router = useRouter();
  const { t } = useLanguage();

  return (
    <div className="flex items-center justify-between flex-wrap gap-4 mb-4">
      <div>
        <h1 className="text-ink font-semibold tracking-tight text-2xl sm:text-[28px] leading-tight">
          {t.dashboard.welcome}
        </h1>
        <p className="legion-eyebrow text-brand-bright mt-2">
          {t.dashboard.overview}
        </p>
      </div>
      <button
        onClick={async () => {
          await logout();
          router.push("/login");
        }}
        className="flex items-center gap-1.5 text-ink-faint hover:text-ink text-xs transition-colors"
      >
        <LogOut size={13} />
        {t.common.signOut}
      </button>
    </div>
  );
}

function AlertRow({
  alert,
  fresh = false,
  expanded,
  onToggle,
  onResolve,
  onInvestigate,
  onExplain,
  explaining,
}: {
  alert: Alert;
  /** Just arrived live: one soft pulse (none with reduced motion). */
  fresh?: boolean;
  expanded: boolean;
  onToggle: () => void;
  onResolve: () => void;
  onInvestigate: () => void;
  onExplain: (force?: boolean) => void;
  explaining: boolean;
}) {
  const { t, locale } = useLanguage();
  const sev = SEVERITY_STYLE[alert.severity];
  const SevIcon = sev.Icon;
  const source = sourceLabel(alert.source, t);
  const steps = (alert.suggested_action_codes ?? []).slice(0, 3);
  // The stored explanation was written in another language: offer to
  // regenerate it (the server answers in the language the dashboard sends).
  const explanationInOtherLanguage =
    !!alert.ai_explanation &&
    !!alert.ai_explanation_locale &&
    alert.ai_explanation_locale !== locale;

  return (
    <div className={`lg-surface lg-interactive ${expanded ? "!border-brand-hover/50" : ""} ${fresh ? "lg-new" : ""}`} data-testid="alert-row">
      <div
        className="flex items-center gap-4 px-4 py-3.5 cursor-pointer"
        onClick={onToggle}
      >
        <div
          className="flex items-center justify-center w-8 h-8 rounded-lg shrink-0"
          style={{ backgroundColor: `${sev.color}1A` }}
        >
          <SevIcon size={16} color={sev.color} strokeWidth={2.3} />
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-ink text-sm font-medium truncate">
            {alert.title}
          </p>
          <div className="flex items-center gap-2 mt-1 min-w-0 text-[11px] text-ink-faint">
            <span className={`lg-status lg-status-${alert.severity} shrink-0`}>
              {t.common.severity[alert.severity]}
            </span>
            {isTestSource(alert.source) && (
              <span className="shrink-0 uppercase tracking-wide px-1.5 py-0.5 rounded bg-panel border border-line">
                {t.overview.testBadge}
              </span>
            )}
            {source && (
              <span className="hidden sm:inline-flex items-center gap-1 min-w-0 shrink">
                <Radio size={11} className="shrink-0" />
                <span className="truncate">{source}</span>
              </span>
            )}
            <span className="shrink-0 whitespace-nowrap">· {timeAgo(alert.created_at, locale)}</span>
            <span className="hidden md:inline font-mono truncate min-w-0" title={alert.id}>· {alert.id}</span>
          </div>
        </div>

        <span className={`lg-status ${alert.status === "resolved" ? "lg-status-healthy" : alert.status === "investigating" ? "lg-status-brand" : "lg-status-high"} hidden sm:inline-flex shrink-0`}>
          {t.common.status[alert.status]}
        </span>

        <ChevronRight
          size={16}
          className={`text-ink-faint shrink-0 transition-transform ${
            expanded ? "rotate-90" : ""
          }`}
        />
      </div>

      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-line ml-12">
          <p className="text-ink-muted text-sm leading-relaxed mb-3">
            {alert.summary}
          </p>

          {steps.length > 0 && alert.status !== "resolved" && (
            <div className="mb-3">
              <p className="flex items-center gap-1.5 text-ink-muted text-[11px] uppercase tracking-wide mb-1">
                <ListChecks size={12} /> {t.overview.whatToDo}
              </p>
              <ul className="space-y-0.5">
                {steps.map((a, i) => (
                  <li key={i} className="text-ink-soft text-xs flex gap-1.5">
                    <span aria-hidden>•</span>{suggestedActionText(a, locale)}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="mb-3">
            {alert.ai_explanation ? (
              <>
                <div className="flex gap-2 bg-panel border border-line rounded-lg p-3">
                  <Sparkles size={14} color={COLORS.primary} className="shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <div className="mb-1.5"><AiBadge aiGenerated={alert.ai_generated === true} /></div>
                    <p className="text-ink-soft text-xs leading-relaxed whitespace-pre-line">
                      {alert.ai_explanation}
                    </p>
                  </div>
                </div>
                {explanationInOtherLanguage && (
                  <div className="flex items-center flex-wrap gap-x-2 gap-y-1 mt-2">
                    <span className="text-ink-faint text-[11px]">
                      {t.dashboard.alert.otherLanguage}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onExplain(true);
                      }}
                      disabled={explaining}
                      className="flex items-center gap-1.5 text-[11px] font-medium text-brand-bright hover:underline disabled:opacity-60"
                    >
                      {explaining ? (
                        <Loader2 size={12} className="animate-spin" />
                      ) : (
                        <Sparkles size={12} />
                      )}
                      {explaining
                        ? t.dashboard.alert.oracleThinking
                        : t.dashboard.alert.explainInMyLanguage}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onExplain();
                }}
                disabled={explaining}
                className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-panel border border-line text-ink-muted hover:text-brand-bright hover:border-brand-hover/40 transition-colors disabled:opacity-60"
              >
                {explaining ? (
                  <Loader2 size={13} className="animate-spin" />
                ) : (
                  <Sparkles size={13} />
                )}
                {explaining ? t.dashboard.alert.oracleThinking : t.dashboard.alert.askOracle}
              </button>
            )}
          </div>

          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2">
              <span className="text-ink-faint text-xs">{t.dashboard.alert.aiConfidence}</span>
              <div className="w-24 h-1.5 rounded-full bg-panel overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${alert.confidence}%`, backgroundColor: sev.color }}
                />
              </div>
              <span className="text-ink text-xs font-medium tabular-nums">
                {alert.confidence}%
              </span>
            </div>
            <div className="flex gap-2 items-center">
              <Link
                href={`/incident/${alert.id}`}
                // Annotated explicitly: next 16.3.6 (the RCE fix) no longer
                // infers this parameter, and CI typechecks before it builds.
                onClick={(e: MouseEvent<HTMLAnchorElement>) => e.stopPropagation()}
                className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-panel border border-line text-ink-muted hover:text-brand-bright hover:border-brand-hover/40 transition-colors"
              >
                <ExternalLink size={13} /> {t.dashboard.alert.fullDetails}
              </Link>
              {alert.status !== "resolved" && (
                <>
                  {alert.status !== "investigating" && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onInvestigate();
                      }}
                      className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-panel text-ink-muted hover:text-ink hover:bg-line transition-colors"
                    >
                      <Eye size={13} /> {t.dashboard.alert.investigate}
                    </button>
                  )}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onResolve();
                    }}
                    className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg text-white transition-colors"
                    style={{ backgroundColor: palette.brand }}
                  >
                    <CheckCircle2 size={13} /> {t.dashboard.alert.resolve}
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function LegionDashboard() {
  const router = useRouter();
  const { t } = useLanguage();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [explainingId, setExplainingId] = useState<string | null>(null);
  const [freshIds, setFreshIds] = useState<Set<string>>(new Set());
  // Drives the subscription banner. Fetched separately from the alert list so
  // a 402 on /alerts still leaves us able to explain *why* it happened.
  const [me, setMe] = useState<CurrentUser | null>(null);

  // The socket only says "something changed"; the database is the truth. So the
  // list is loaded together with the cursor it corresponds to, and the feed
  // (hooks/useRealtimeAlerts) is responsible for every change after that cursor.
  const statsTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // A burst of events (or a catch-up after being away) is one stats request, not one each.
  const refreshStats = useCallback(() => {
    if (statsTimer.current) return;
    statsTimer.current = setTimeout(() => {
      statsTimer.current = null;
      getStats().then(setStats).catch(() => {});
      getOverview().then(setOverview).catch(() => {});
    }, 500);
  }, []);
  useEffect(() => () => { if (statsTimer.current) clearTimeout(statsTimer.current); }, []);

  // Realtime: merge pushed alerts into the list already on screen, honouring
  // the same severity/search filters the server applies to GET /alerts, so a
  // live alert never appears in a view it would be filtered out of. Events
  // arrive de-duplicated and in version order, but the list does not rely on
  // that: an alert goes where the server's ordering would put it, and an older
  // version never replaces a newer one.
  const handleRealtime = useCallback(
    (event: RealtimeEvent) => {
      const incoming = event.alert;
      setAlerts((prev) => {
        if (!prev.some((a) => a.id === incoming.id)) {
          if (event.type !== "new_alert") return prev;
          if (filter !== "all" && incoming.severity !== filter) return prev;
          const q = query.trim().toLowerCase();
          if (
            q &&
            !incoming.id.toLowerCase().includes(q) &&
            !incoming.title.toLowerCase().includes(q)
          ) {
            return prev;
          }
        }
        return upsertAlert(prev, incoming);
      });
      if (event.type === "new_alert") {
        setFreshIds((prev) => new Set(prev).add(incoming.id));
        setTimeout(() => setFreshIds((prev) => { const next = new Set(prev); next.delete(incoming.id); return next; }), 2000);
      }
      refreshStats();
    },
    [filter, query, refreshStats]
  );

  // The list reload is what the feed asks for when it has fallen too far behind
  // to catch up by paging. `loadRef` breaks the cycle (load uses the hook).
  const loadRef = useRef<() => Promise<void>>(async () => {});
  const { setBaseline, isConnected } = useRealtimeAlerts(handleRealtime, () => loadRef.current());

  // Only the latest load may install its result: a slow response for an old
  // filter must not overwrite a newer one (or hand the feed an old cursor).
  const loadSeq = useRef(0);
  const load = useCallback(async () => {
    const mine = ++loadSeq.current;
    setError(null);
    try {
      const [feed, statData] = await Promise.all([
        getAlertFeed({
          severity: filter === "all" ? undefined : filter,
          q: query || undefined,
        }),
        getStats(),
      ]);
      if (mine !== loadSeq.current) return;
      setAlerts(sortAlerts(feed.alerts));
      setStats(statData);
      // The list and its cursor were read together; from here the feed owns
      // every later change.
      setBaseline(feed.cursor);
    } catch (err) {
      if (mine !== loadSeq.current) return;
      if (err instanceof ApiError && err.status === 401) {
        router.push("/login");
        return;
      }
      setError(err);
    } finally {
      if (mine === loadSeq.current) setLoading(false);
    }
  }, [filter, query, router, setBaseline]);
  useEffect(() => { loadRef.current = load; }, [load]);

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    getMe()
      .then(setMe)
      .catch(() => {
        // Non-fatal: the banner is an explanation, not a gate.
      });
    // Also non-fatal: the alert list below works without it.
    getOverview().then(setOverview).catch(() => {});
    load();
  }, [load, router]);

  async function changeStatus(id: string, status: Alert["status"]) {
    setError(null);
    try {
      const reason = reopenReason(alerts.find((a) => a.id === id)?.status, status);
      if (reason === null) return;
      const updated = await updateAlertStatus(id, status, reason);
      setAlerts((prev) => upsertAlert(prev, updated, { insert: false }));
      refreshStats();
    } catch (err) {
      setError(err);
    }
  }

  async function handleExplain(id: string, force = false) {
    setExplainingId(id);
    try {
      const updated = await explainAlert(id, force);
      setAlerts((prev) => upsertAlert(prev, updated, { insert: false }));
    } catch (err) {
      setError(err);
    } finally {
      setExplainingId(null);
    }
  }

  const counts = {
    critical: stats?.by_severity?.critical ?? 0,
    high: stats?.by_severity?.high ?? 0,
    medium: stats?.by_severity?.medium ?? 0,
    low: stats?.by_severity?.low ?? 0,
  };

  return (
    <div className="flex min-h-screen lg-app-bg">
      <Sidebar />
      <div className="flex-1 min-w-0 p-4 sm:p-6 lg:p-8">
        <div className="max-w-6xl mx-auto">
          <TopBar />
          {me && (
            <AccessBanner
              state={me.access_state}
              trialEndsAt={me.trial_ends_at}
              isAdmin={me.role === "admin"}
            />
          )}
          {overview && <KpiRow data={overview} />}
          <div className="grid lg:grid-cols-[minmax(0,1fr)_320px] gap-5 items-start">
          <div className="min-w-0">
          {overview && <ProtectionOverview data={overview} />}
          <h2 className="text-ink text-sm font-semibold mb-3 flex items-center gap-2">
            {t.dashboard.alertsTitle}
            {isConnected && <span className="lg-status lg-status-healthy !text-[10px] !py-0.5">{t.dashboard.live}</span>}
          </h2>

          <div className="flex flex-wrap items-center gap-2 mb-4">
            <div className="relative flex-1 min-w-[180px]">
              <Search
                size={15}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint"
              />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t.dashboard.searchPlaceholder}
                className="lg-input !pl-9 text-sm"
              />
            </div>
            {(["all", "critical", "high", "medium", "low"] as const).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                aria-pressed={filter === f}
                className={`text-xs font-medium px-3 py-2 rounded-full border transition-colors whitespace-nowrap ${
                  filter === f
                    ? "border-brand-hover/60 text-ink bg-brand/20 shadow-violet"
                    : "border-line text-ink-faint hover:text-ink-muted hover:border-line-strong"
                }`}
              >
                {f === "all"
                  ? `${t.common.all} ${stats?.total ?? ""}`
                  : `${t.common.severity[f]} ${counts[f]}`}
              </button>
            ))}
          </div>

          {error != null && (
            <div className="mb-4">
              <ErrorNotice error={error} onRetry={load} isAdmin={me?.role === "admin"} />
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-16 text-ink-faint">
              <Loader2 size={20} className="animate-spin" />
            </div>
          ) : (
            <div className="space-y-2">
              {alerts.map((alert) => (
                <AlertRow
                  key={alert.id}
                  alert={alert}
                  fresh={freshIds.has(alert.id)}
                  expanded={expandedId === alert.id}
                  onToggle={() =>
                    setExpandedId(expandedId === alert.id ? null : alert.id)
                  }
                  onResolve={() => changeStatus(alert.id, "resolved")}
                  onInvestigate={() => changeStatus(alert.id, "investigating")}
                  onExplain={(force) => handleExplain(alert.id, force)}
                  explaining={explainingId === alert.id}
                />
              ))}
              {alerts.length === 0 && (
                <div className="text-center py-12 text-ink-faint text-sm flex flex-col items-center gap-2">
                  <Activity size={22} />
                  {t.dashboard.empty}
                </div>
              )}
            </div>
          )}
          </div>
          <aside className="space-y-4 lg:sticky lg:top-6">
            {overview && <SeverityRing data={overview} />}
          </aside>
          </div>
        </div>
      </div>
    </div>
  );
}
