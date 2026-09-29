"use client";

import Link from "next/link";
import { AlertTriangle, Clock } from "lucide-react";
import type { AccessState } from "@/lib/api";
import { palette } from "@/lib/theme";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/** Days remaining before a trial lapses, rounded up so "1 day left" covers
 *  everything under 24 hours. */
function daysLeft(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86_400_000);
}

const TRIAL_NUDGE_DAYS = 5;

/**
 * Surfaces subscription state at the top of the app.
 *
 * Renders nothing in the normal case — a banner that is always present stops
 * being read. It appears when the workspace is blocked, read-only, or the
 * trial is close enough to matter.
 */
export default function AccessBanner({
  state,
  trialEndsAt,
  isAdmin,
}: {
  state: AccessState;
  trialEndsAt?: string | null;
  isAdmin: boolean;
}) {
  const { t } = useLanguage();
  const trialDays =
    state === "ok" && trialEndsAt ? daysLeft(trialEndsAt) : null;
  const showTrial =
    trialDays !== null && trialDays <= TRIAL_NUDGE_DAYS && trialDays > 0;

  if (state === "ok" && !showTrial) return null;

  const blocked = state === "blocked";
  const readonly = state === "readonly";

  const tone = blocked
    ? { color: palette.critical, Icon: AlertTriangle }
    : readonly
      ? { color: palette.warning, Icon: AlertTriangle }
      : { color: palette.brandBright, Icon: Clock };

  const message = blocked
    ? t.accessBanner.blocked
    : readonly
      ? t.accessBanner.readonly
      : t.accessBanner.trialEnds(trialDays ?? 0);

  return (
    <div
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-lg px-3 py-2.5 mb-4 text-xs"
      style={{ backgroundColor: `${tone.color}1A`, color: tone.color }}
      role="status"
    >
      <tone.Icon size={14} className="shrink-0" />
      <span className="flex-1 min-w-[12rem] leading-relaxed">{message}</span>
      {isAdmin ? (
        <Link
          href="/billing"
          className="font-medium underline underline-offset-2 whitespace-nowrap"
        >
          {blocked || readonly ? t.accessBanner.manageBilling : t.accessBanner.choosePlan}
        </Link>
      ) : (
        <span className="text-[11px] opacity-80 whitespace-nowrap">
          {t.accessBanner.askAdmin}
        </span>
      )}
    </div>
  );
}
