"use client";

import Link from "next/link";
import { AlertTriangle, RotateCw } from "lucide-react";
import { describeError } from "@/lib/errors";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/**
 * An error, explained: what happened (with the server's own words), why, and
 * what to do next — with the one action that helps, when there is one.
 */
export default function ErrorNotice({ error, onRetry, isAdmin, compact = false }: {
  error: unknown;
  onRetry?: () => void;
  isAdmin?: boolean;
  compact?: boolean;
}) {
  const { t } = useLanguage();
  if (!error) return null;
  const x = describeError(error, t, { isAdmin });
  return (
    <div role="alert" className={`rounded-lg border border-critical/30 bg-critical/10 ${compact ? "px-3 py-2" : "px-4 py-3"} text-xs`}>
      <div className="flex items-start gap-2">
        <AlertTriangle size={14} className="text-critical shrink-0 mt-0.5" />
        <div className="min-w-0 space-y-1">
          <p className="text-ink font-medium">{x.title}</p>
          {x.detail && x.detail !== x.title && <p className="text-ink-muted">{x.detail}</p>}
          {!compact && (
            <>
              <p className="text-ink-muted"><span className="text-ink-faint">{t.errors.whyLabel}: </span>{x.why}</p>
              <p className="text-ink-muted"><span className="text-ink-faint">{t.errors.nextLabel}: </span>{x.next}</p>
            </>
          )}
          {(x.action || (x.retryable && onRetry)) && (
            <div className="flex gap-3 pt-1">
              {x.action && (x.action.href.startsWith("http")
                ? <a href={x.action.href} className="text-brand-bright font-medium hover:underline">{x.action.label}</a>
                : <Link href={x.action.href} className="text-brand-bright font-medium hover:underline">{x.action.label}</Link>)}
              {x.retryable && onRetry && (
                <button type="button" onClick={onRetry} className="flex items-center gap-1 text-brand-bright font-medium hover:underline">
                  <RotateCw size={11} /> {t.errors.retry}
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
