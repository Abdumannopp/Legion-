"use client";

import AiBadge from "@/components/AiBadge";
import { useState, useEffect } from "react";
import { useRouter, useParams } from "next/navigation";
import {
  ArrowLeft,
  Clock,
  Globe,
  Crosshair,
  Target,
  Gauge,
  Sparkles,
  Loader2,
  Eye,
  CheckCircle2,
  Radio,
  ShieldAlert,
} from "lucide-react";
import Sidebar from "@/components/Sidebar";
import {
  Alert,
  getAlert,
  explainAlert,
  updateAlertStatus,
  isLoggedIn,
  ApiError,
  SuggestedAction,
} from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import { formatDateTime, suggestedActionText } from "@/lib/i18n/format";
import ErrorNotice from "@/components/ErrorNotice";
import { sourceLabel } from "@/lib/sources";

const SEVERITY_COLOR: Record<Alert["severity"], string> = {
  critical: palette.critical,
  high: palette.warning,
  medium: palette.info,
  low: palette.inkFaint,
};

// Labels come from t.common.status.
const STATUS_COLOR: Record<Alert["status"], string> = {
  open: palette.critical,
  investigating: palette.brandBright,
  resolved: palette.success,
};

/** Stable key for a suggested step (the checklist remembers which are done). */
function actionKey(action: SuggestedAction): string {
  return action.code === "block_source_ip" ? `${action.code}:${action.ip}` : action.code;
}

function DetailRow({
  Icon,
  label,
  value,
}: {
  Icon: typeof Clock;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-start gap-3 py-3 border-b border-line last:border-b-0">
      <Icon size={15} className="text-ink-faint mt-0.5 shrink-0" />
      <div className="min-w-0">
        <p className="text-ink-faint text-[11px] uppercase tracking-wide">{label}</p>
        <p className="text-ink text-sm mt-0.5 break-words">{value}</p>
      </div>
    </div>
  );
}

export default function IncidentDetailsPage() {
  const router = useRouter();
  const params = useParams();
  const id = params.id as string;
  const { t, locale } = useLanguage();

  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [explaining, setExplaining] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [doneActions, setDoneActions] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!isLoggedIn()) {
      router.push("/login");
      return;
    }
    getAlert(id)
      .then(setAlert)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          router.push("/login");
          return;
        }
        setError(err);
      })
      .finally(() => setLoading(false));
  }, [id, router, t]);

  async function handleExplain(force = false) {
    if (!alert) return;
    setExplaining(true);
    try {
      const updated = await explainAlert(alert.id, force);
      setAlert(updated);
    } catch (err) {
      setError(err);
    } finally {
      setExplaining(false);
    }
  }

  async function handleStatusChange(status: Alert["status"]) {
    if (!alert) return;
    setUpdating(true);
    try {
      const updated = await updateAlertStatus(alert.id, status);
      setAlert(updated);
    } catch (err) {
      setError(err);
    } finally {
      setUpdating(false);
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen bg-canvas">
        <Sidebar />
        <div className="flex-1 flex items-center justify-center">
          <Loader2 size={20} className="animate-spin text-ink-faint" />
        </div>
      </div>
    );
  }

  if (error != null && !alert) {
    return (
      <div className="flex min-h-screen bg-canvas">
        <Sidebar />
        <div className="flex-1 flex flex-col items-center justify-center gap-3">
          <div className="max-w-md w-full px-4"><ErrorNotice error={error} /></div>
          <button
            onClick={() => router.push("/")}
            className="text-brand-bright text-sm flex items-center gap-1.5"
          >
            <ArrowLeft size={14} /> {t.incident.backToAlerts}
          </button>
        </div>
      </div>
    );
  }

  if (!alert) return null;

  const sevColor = SEVERITY_COLOR[alert.severity];
  const statusColor = STATUS_COLOR[alert.status];
  // The stored explanation was written in another language: offer to
  // regenerate it (the server answers in the language the dashboard sends).
  const explanationInOtherLanguage =
    !!alert.ai_explanation &&
    !!alert.ai_explanation_locale &&
    alert.ai_explanation_locale !== locale;

  return (
    <div className="flex min-h-screen bg-canvas">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-4xl mx-auto">
          <button
            onClick={() => router.push("/")}
            className="flex items-center gap-1.5 text-ink-faint hover:text-ink text-xs mb-4 transition-colors"
          >
            <ArrowLeft size={14} /> {t.incident.backToAlerts}
          </button>

          <div className="flex items-start justify-between flex-wrap gap-3 mb-6">
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-ink-faint text-xs font-mono">{alert.id}</span>
                <span
                  className="text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded"
                  style={{ color: sevColor, backgroundColor: `${sevColor}1A` }}
                >
                  {t.common.severity[alert.severity]}
                </span>
                <span className="text-xs font-medium" style={{ color: statusColor }}>
                  {t.common.status[alert.status]}
                </span>
              </div>
              <h1 className="legion-title text-ink">
                {alert.title}
              </h1>
            </div>

            {alert.status !== "resolved" && (
              <div className="flex gap-2">
                {alert.status !== "investigating" && (
                  <button
                    onClick={() => handleStatusChange("investigating")}
                    disabled={updating}
                    className="flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg bg-surface border border-line text-ink-muted hover:text-ink transition-colors disabled:opacity-60"
                  >
                    <Eye size={13} /> {t.dashboard.alert.investigate}
                  </button>
                )}
                <button
                  onClick={() => handleStatusChange("resolved")}
                  disabled={updating}
                  className="flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg text-white transition-colors disabled:opacity-60"
                  style={{ backgroundColor: palette.brand }}
                >
                  <CheckCircle2 size={13} /> {t.dashboard.alert.resolve}
                </button>
              </div>
            )}
          </div>

          {error != null && (
            <div className="mb-4"><ErrorNotice error={error} /></div>
          )}

          <div className="grid md:grid-cols-2 gap-4">
            {/* Left: technical details */}
            <div className="rounded-xl border border-line bg-surface px-4">
              <DetailRow
                Icon={Clock}
                label={t.incident.detail.detected}
                value={formatDateTime(alert.created_at, locale)}
              />
              <DetailRow
                Icon={Globe}
                label={t.incident.detail.sourceIp}
                value={alert.source_ip || t.incident.detail.notApplicable}
              />
              <DetailRow
                Icon={Crosshair}
                label={t.incident.detail.target}
                value={alert.target || t.incident.detail.notSpecified}
              />
              <DetailRow
                Icon={ShieldAlert}
                // i18n-ignore: framework name, stays in English in every language
                label="MITRE ATT&CK"
                value={alert.mitre_technique || t.incident.detail.notClassified}
              />
              <DetailRow
                Icon={Gauge}
                label={t.incident.detail.confidence}
                value={`${alert.confidence}%`}
              />
              <DetailRow Icon={Radio} label={t.incident.detail.detectedBy} value={sourceLabel(alert.source, t) ?? t.incident.detail.notSpecified} />
            </div>

            {/* Right: AI explanation */}
            <div className="rounded-xl border border-line bg-surface p-4">
              <div className="flex items-center gap-2 mb-3">
                <Sparkles size={14} color={palette.brandBright} />
                <h2 className="text-ink text-sm font-medium">{t.incident.aiExplanation}</h2>
              </div>

              <p className="text-ink-muted text-sm leading-relaxed mb-4">{alert.summary}</p>

              {alert.ai_explanation ? (
                <>
                  <div className="bg-panel border border-line rounded-lg p-3">
                    <div className="mb-2"><AiBadge aiGenerated={alert.ai_generated === true} /></div>
                    <p className="text-ink-soft text-sm leading-relaxed whitespace-pre-line">
                      {alert.ai_explanation}
                    </p>
                  </div>
                  {explanationInOtherLanguage && (
                    <div className="flex items-center flex-wrap gap-x-2 gap-y-1 mt-2">
                      <span className="text-ink-faint text-[11px]">
                        {t.dashboard.alert.otherLanguage}
                      </span>
                      <button
                        onClick={() => handleExplain(true)}
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
                  onClick={() => handleExplain()}
                  disabled={explaining}
                  className="flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg bg-panel border border-line text-ink-muted hover:text-brand-bright hover:border-brand-hover/40 transition-colors disabled:opacity-60"
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
          </div>

          {/* Suggested Actions */}
          <div className="mt-4 rounded-xl border border-line bg-surface p-4">
            <div className="flex items-center gap-2 mb-3">
              <Target size={14} color={palette.warning} />
              <h2 className="text-ink text-sm font-medium">{t.incident.suggestedActions}</h2>
            </div>
            <p className="text-ink-faint text-[11px] mb-3">{t.incident.suggestedIntro}</p>
            <div className="flex flex-wrap gap-2">
              {/* Older API responses have no suggested_action_codes. */}
              {(alert.suggested_action_codes ?? []).map((action) => {
                const key = actionKey(action);
                const done = doneActions.has(key);
                return (
                  <button
                    key={key}
                    onClick={() =>
                      setDoneActions((prev) => {
                        const next = new Set(prev);
                        done ? next.delete(key) : next.add(key);
                        return next;
                      })
                    }
                    className={`flex items-center gap-1.5 text-xs font-medium px-3 py-2 rounded-lg border transition-colors ${
                      done
                        ? "bg-success/10 border-success/40 text-success"
                        : "bg-panel border-line text-ink-muted hover:text-ink hover:border-brand-hover/40"
                    }`}
                  >
                    <CheckCircle2 size={13} className="shrink-0" />
                    {suggestedActionText(action, locale)}
                  </button>
                );
              })}
            </div>
            <p className="text-ink-disabled text-[10px] mt-3">{t.incident.manualNote}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
