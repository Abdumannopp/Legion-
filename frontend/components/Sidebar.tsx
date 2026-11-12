"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  LayoutDashboard,
  AlertTriangle,
  Monitor,
  ClipboardList,
  Bot,
  BarChart3,
  Settings,
  CreditCard,
  Plug,
  BrainCircuit,
  ShieldAlert,
  Network,
  MoreHorizontal,
  X,
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
    { label: t.nav.connect, Icon: Plug, href: "/connect" },
    { label: t.nav.alerts, Icon: AlertTriangle, href: "/" },
    { label: t.nav.assets, Icon: Monitor, href: "/assets" },
    { label: t.nav.agents, Icon: BrainCircuit, href: "/agents" },
    { label: t.nav.incidents, Icon: ClipboardList, href: "/incidents" },
    { label: t.nav.defense, Icon: ShieldAlert, href: "/defense" },
    { label: t.nav.team, Icon: Network, href: "/team" },
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

  const isActive = (href: string, index: number) =>
    (pathname === href || (href !== "/" && pathname.startsWith(`${href}/`))) && NAV_ITEMS.findIndex((i) => i.href === href) === index;
  // Grouped like the design: the work itself, then the workspace's system pages.
  const SYSTEM_HREFS = new Set(["/team", "/billing", "/settings"]);
  const groups = [
    { title: t.nav.workspace, items: NAV_ITEMS.map((n, i) => ({ ...n, i })).filter((n) => !SYSTEM_HREFS.has(n.href)) },
    { title: t.nav.system, items: NAV_ITEMS.map((n, i) => ({ ...n, i })).filter((n) => SYSTEM_HREFS.has(n.href)) },
  ];

  return (
    <>
    <aside className="hidden md:flex flex-col w-60 shrink-0 border-r border-line/70 bg-panel/70 min-h-screen py-5 px-3 sticky top-0 h-screen overflow-y-auto">
      <Link href="/" className="px-2 mb-7 block" aria-label={`Legion — ${t.nav.dashboard}`}>
        <LegionLogo layout="horizontal" size={38} tagline={false} />
      </Link>

      <nav className="flex flex-col gap-4" aria-label={t.nav.mainNav}>
        {groups.map((g) => (
          <div key={g.title}>
            <p className="lg-eyebrow px-3 mb-2">{g.title}</p>
            <div className="flex flex-col gap-0.5">
              {g.items.map(({ label, Icon, href, i }) => {
                const active = isActive(href, i);
                return (
                  <Link
                    key={label}
                    href={href}
                    aria-current={active ? "page" : undefined}
                    className={`flex items-center gap-2.5 px-3 py-2 rounded-xl text-sm border transition-colors ${
                      active
                        ? "text-ink font-medium border-brand-hover/40 bg-gradient-to-r from-brand/25 to-brand/5 shadow-violet [&>svg]:text-brand-bright"
                        : "text-ink-muted border-transparent hover:text-ink hover:bg-surface-hover/60"
                    }`}
                  >
                    <Icon size={16} strokeWidth={2} />
                    {label}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
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
    <MobileBottomNav items={NAV_ITEMS} isActive={isActive} />
    </>
  );
}

/**
 * Phones: the four places used most, always within thumb reach, and "More" for everything else (a sheet with
 * every page). Buttons and links, not gestures, so it works with a keyboard and a screen reader too.
 */
function MobileBottomNav({ items, isActive }: { items: { label: string; Icon: typeof LayoutDashboard; href: string }[]; isActive: (href: string, i: number) => boolean }) {
  const { t } = useLanguage();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  useEffect(() => { setOpen(false); }, [pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);
  const PRIMARY = ["/", "/incidents", "/copilot", "/defense"];
  const primary = PRIMARY.map((href) => ({ ...items[items.findIndex((n) => n.href === href)]!, i: items.findIndex((n) => n.href === href) }));
  const moreActive = !primary.some((p) => isActive(p.href, p.i));
  return (
    <>
      {open && (
        <div className="md:hidden fixed inset-0 z-40 bg-black/60" onClick={() => setOpen(false)}>
          <div
            role="dialog"
            aria-modal="true"
            aria-label={t.nav.menu}
            className="lg-glass lg-enter absolute left-3 right-3 bottom-[calc(76px+env(safe-area-inset-bottom))] p-3 max-h-[70vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-2 pb-2">
              <p className="lg-eyebrow">{t.nav.menu}</p>
              <button onClick={() => setOpen(false)} aria-label={t.nav.close} className="p-2 -m-2 text-ink-muted hover:text-ink"><X size={18} /></button>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              {items.map(({ label, Icon, href }, i) => (
                <Link key={label} href={href} aria-current={isActive(href, i) ? "page" : undefined}
                  className={`flex items-center gap-2.5 px-3 py-3 rounded-xl text-sm border ${isActive(href, i) ? "border-brand-hover/40 bg-brand/15 text-ink" : "border-line/60 text-ink-soft"}`}>
                  <Icon size={16} />{label}
                </Link>
              ))}
            </div>
            <div className="mt-3 px-1 flex flex-col gap-2"><WorkspaceSwitcher /><LanguageSwitcher compact /></div>
          </div>
        </div>
      )}
      <nav
        aria-label={t.nav.mainNav}
        className="lg-bottom-nav md:hidden fixed bottom-0 inset-x-0 z-40 border-t border-line/70 bg-panel/90 backdrop-blur-xl pb-[env(safe-area-inset-bottom)]"
      >
        <div className="grid grid-cols-5">
          {primary.map(({ label, Icon, href, i }) => {
            const active = isActive(href, i);
            return (
              <Link key={href} href={href} aria-current={active ? "page" : undefined}
                className={`flex flex-col items-center justify-center gap-1 min-h-[60px] text-[10px] ${active ? "text-brand-bright" : "text-ink-faint"}`}>
                <Icon size={19} strokeWidth={active ? 2.3 : 1.9} />
                <span className="truncate max-w-full px-1">{label}</span>
              </Link>
            );
          })}
          <button onClick={() => setOpen((v) => !v)} aria-expanded={open}
            className={`flex flex-col items-center justify-center gap-1 min-h-[60px] text-[10px] ${open || moreActive ? "text-brand-bright" : "text-ink-faint"}`}>
            <MoreHorizontal size={19} />
            {t.nav.more}
          </button>
        </div>
      </nav>
    </>
  );
}
