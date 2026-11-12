"use client";

/**
 * Legion's five agents and the skills each one has. Read-only: skills are
 * tools an administrator can give to the organisation's own AI agents; this
 * page shows what exists and what each one is for.
 */
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Crosshair, Eye, Loader2, Network, Scale, ShieldCheck, Sparkles, type LucideIcon } from "lucide-react";
import Sidebar from "@/components/Sidebar";
import ErrorNotice from "@/components/ErrorNotice";
import { ApiError, getSkills, isLoggedIn, type LegionAgentName, type SkillInfo } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const ORDER: LegionAgentName[] = ["Sentinel", "Hunter", "Guardian", "Oracle", "Vanguard"];
const ICON: Record<LegionAgentName, LucideIcon> = { Sentinel: Eye, Hunter: Crosshair, Guardian: ShieldCheck, Oracle: Sparkles, Vanguard: Scale };

export default function TeamPage() {
  const router = useRouter();
  const { t } = useLanguage();
  const m = t.team;
  const [skills, setSkills] = useState<SkillInfo[] | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!isLoggedIn()) { router.push("/login"); return; }
    getSkills().then((r) => setSkills(r.skills)).catch((err) => {
      if (err instanceof ApiError && err.status === 401) { router.push("/login"); return; }
      setError(err);
    });
  }, [router]);

  return (
    <div className="flex min-h-screen lg-app-bg">
      <Sidebar />
      <div className="flex-1 p-4 sm:p-6">
        <div className="max-w-4xl mx-auto space-y-5">
          <div>
            <h1 className="legion-title text-ink flex items-center gap-2"><Network size={18} />{m.title}</h1>
            <p className="text-ink-muted text-sm mt-2 leading-relaxed max-w-3xl">{m.intro}</p>
            <p className="text-ink-faint text-xs mt-2 leading-relaxed max-w-3xl">{m.onlyRecommends}</p>
          </div>

          {error != null && <ErrorNotice error={error} />}

          {!skills ? (
            error == null && <div className="flex justify-center py-16"><Loader2 size={18} className="animate-spin text-ink-faint" /></div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {ORDER.map((agent) => {
                const Icon = ICON[agent];
                const mine = skills.filter((s) => s.agent === agent);
                const text = m.agents[agent];
                return (
                  <section key={agent} className="lg-surface p-5" data-testid={`team-${agent}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2.5">
                        <span className="w-9 h-9 rounded-lg bg-brand/10 flex items-center justify-center shrink-0"><Icon size={17} className="text-brand-bright" /></span>
                        <div>
                          <h2 className="text-ink font-medium leading-tight">{agent}</h2>
                          <p className="text-ink-faint text-xs">{text?.role}</p>
                        </div>
                      </div>
                      <span className="text-ink-faint text-xs shrink-0">{m.skills(mine.length)}</span>
                    </div>
                    <p className="text-ink-muted text-sm mt-3 leading-relaxed">{text?.job}</p>
                    <ul className="mt-3 pt-3 border-t border-line space-y-2.5">
                      {mine.map((s) => (
                        <li key={s.name}>
                          <p className="text-ink text-sm font-medium">{s.title}</p>
                          <p className="text-ink-muted text-xs mt-0.5 leading-relaxed">{m.skillLines[s.name] ?? s.description}</p>
                        </li>
                      ))}
                    </ul>
                  </section>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
