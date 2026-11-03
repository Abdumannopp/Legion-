"use client";

import type { AgentSummary } from "@/lib/api";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/** "Working" in green only when the agent can act right now; anything else in red. */
export default function AgentStatus({ agent }: { agent: AgentSummary }) {
  const { t } = useLanguage();
  const active = agent.status === "active" && agent.canActNow;
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded whitespace-nowrap ${active ? "bg-success/15 text-success" : "bg-critical/15 text-critical"}`} data-testid="agent-status">
      {t.agents.status[agent.status] ?? agent.status}
    </span>
  );
}
