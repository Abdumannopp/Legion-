"use client";

import { useState } from "react";
import { Check, Hand, Loader2, X } from "lucide-react";
import ErrorNotice from "@/components/ErrorNotice";
import { answerApproval, type ApprovalRequest } from "@/lib/api";
import { ruleGroup } from "@/lib/agentRules";
import { formatDateTime } from "@/lib/i18n/format";
import { useLanguage } from "@/lib/i18n/LanguageContext";

/**
 * Actions an agent stopped and asked about. Approving lets it do exactly that
 * action once (the server binds the approval to the action's digest and checks
 * every other rule again when the agent retries).
 */
export default function AgentApprovals({ approvals, agentNames, onAnswered, canAnswer }: {
  approvals: ApprovalRequest[];
  agentNames?: Record<string, string>;
  onAnswered: () => void;
  canAnswer: boolean;
}) {
  const { t, locale } = useLanguage();
  const a = t.agents;
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function answer(id: string, verdict: "approve" | "deny") {
    setBusy(id); setError(null); setNotice(null);
    try {
      await answerApproval(id, verdict);
      setNotice(verdict === "approve" ? a.approvals.approved : a.approvals.denied);
      onAnswered();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-2">
      <p className="text-ink-faint text-xs">{a.approvals.intro}</p>
      {error != null && <ErrorNotice error={error} compact />}
      {notice && <p role="status" className="text-success text-xs">{notice}</p>}
      {approvals.length === 0 ? (
        <p className="text-ink-faint text-xs py-4 text-center">{a.approvals.empty}</p>
      ) : (
        <ul className="space-y-2">
          {approvals.map((r) => {
            const rule = r.ruleIds[0];
            return (
              <li key={r.id} className="rounded-lg border border-warning/30 bg-warning/5 px-3 py-2.5" data-testid="approval">
                <div className="flex items-start gap-2">
                  <Hand size={14} className="text-warning shrink-0 mt-0.5" />
                  <div className="min-w-0 flex-1 space-y-0.5">
                    {agentNames?.[r.identityId] && <p className="text-ink-faint text-[11px]">{agentNames[r.identityId]}</p>}
                    <p className="text-ink text-xs">
                      <span className="text-ink-faint">{a.approvals.wants}: </span>
                      {r.permission ? a.permissions[r.permission] ?? r.permission : r.action}
                    </p>
                    {r.resourceId && <p className="text-ink-muted text-[11px] break-all">{a.approvals.on(`${r.resourceType ?? ""} ${r.resourceId}`.trim())}</p>}
                    {rule && <p className="text-ink-muted text-[11px]">{a.rules[ruleGroup(rule)].what}</p>}
                    <p className="text-ink-faint text-[10px]">{a.approvals.expires(formatDateTime(r.expiresAt, locale))}</p>
                  </div>
                  {canAnswer && (
                    <div className="flex flex-col sm:flex-row gap-1.5 shrink-0">
                      <button type="button" disabled={busy !== null} onClick={() => answer(r.id, "approve")} className="flex items-center gap-1 text-[11px] font-medium px-2.5 py-1 rounded-md bg-brand hover:bg-brand-hover text-white disabled:opacity-60">
                        {busy === r.id ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />} {a.approvals.approve}
                      </button>
                      <button type="button" disabled={busy !== null} onClick={() => answer(r.id, "deny")} className="flex items-center gap-1 text-[11px] font-medium px-2.5 py-1 rounded-md border border-line text-ink-muted hover:text-ink disabled:opacity-60">
                        <X size={11} /> {a.approvals.deny}
                      </button>
                    </div>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
