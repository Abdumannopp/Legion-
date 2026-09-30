"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  Monitor,
  ClipboardList,
  Bot,
  BarChart3,
  Settings,
  CreditCard,
} from "lucide-react";
import { useLanguage } from "@/lib/i18n/LanguageContext";
import LanguageSwitcher from "@/components/LanguageSwitcher";
import WorkspaceSwitcher from "@/components/WorkspaceSwitcher";
import LegionLogo from "@/components/brand/LegionLogo";

export default function Sidebar() {
  const pathname = usePathname();
  const { t } = useLanguage();

  const NAV_ITEMS = [
    { label: t.nav.dashboard, Icon: LayoutDashboard, href: "/" },
    { label: t.nav.alerts, Icon: AlertTriangle, href: "/" },
    { label: t.nav.assets, Icon: Monitor, href: "/assets" },
    { label: t.nav.incidents, Icon: ClipboardList, href: "/incidents" },
    { label: t.nav.copilot, Icon: Bot, href: "/copilot" },
    { label: t.nav.reports, Icon: BarChart3, href: "/reports" },
    { label: t.nav.billing, Icon: CreditCard, href: "/billing" },
    { label: t.nav.settings, Icon: Settings, href: "/settings" },
  ];

  const LEGAL_LINKS = [
    { label: t.footer.privacy, href: "/privacy" },
    { label: t.footer.terms, href: "/terms" },
    { label: t.footer.support, href: "/support" },
  ];

  return (
    <aside className="hidden md:flex flex-col w-56 shrink-0 border-r border-line bg-panel/60 min-h-screen py-5 px-3">
      <Link href="/" className="px-2 mb-8 block" aria-label={`Legion — ${t.nav.dashboard}`}>
        <LegionLogo layout="horizontal" size={34} tagline={false} />
      </Link>

      <nav className="flex flex-col gap-1">
        {NAV_ITEMS.map(({ label, Icon, href }, index) => {
          // Dashboard and Alerts share "/"; highlight only the first match.
          const active =
            href !== null && pathname === href && NAV_ITEMS.findIndex((i) => i.href === href) === index;
          const disabled = href === null;

          const content = (
            <>
              <Icon size={16} strokeWidth={2} />
              {label}
              {disabled && (
                <span className="ml-auto text-[9px] uppercase tracking-wide text-ink-disabled bg-panel border border-line rounded px-1.5 py-0.5">
                  {t.nav.soon}
                </span>
              )}
            </>
          );

          const className = `group relative flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors text-left ${
            active
              ? "text-ink bg-surface font-medium before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-[3px] before:rounded-full before:bg-brand-hover before:shadow-glow [&>svg]:text-brand-bright"
              : disabled
              ? "text-ink-disabled cursor-not-allowed"
              : "text-ink-muted hover:text-ink hover:bg-surface/60"
          }`;

          if (disabled) {
            return (
              <button key={label} disabled title={t.nav.soon} className={className}>
                {content}
              </button>
            );
          }

          return (
            <Link key={label} href={href!} className={className}>
              {content}
            </Link>
          );
        })}
      </nav>

      <div className="mt-auto pt-4 flex flex-col gap-3">
        <WorkspaceSwitcher />
        <LanguageSwitcher compact />
        <div className="flex flex-col gap-0.5 px-2">
          {LEGAL_LINKS.map(({ label, href }) => (
            <Link
              key={href}
              href={href}
              className="text-[11px] text-ink-faint hover:text-ink-muted transition-colors py-0.5"
            >
              {label}
            </Link>
          ))}
        </div>
      </div>
    </aside>
  );
}
