/**
 * Agent security events become Legion alerts — stored, versioned, emailed
 * and pushed through the same durable pipeline as a Wazuh alert
 * (outbox.insertAlertAndNotify), so they reach the SOC even when nobody is
 * looking at the agents pages.
 *
 *   - the firewall quarantined or killed an agent        → high / critical
 *   - an agent is waiting for a person's approval         → medium
 *   - an agent was stopped by a person or the monitor     → by severity
 *   - an agent's behaviour became HIGH_RISK / CRITICAL    → high / critical
 *
 * Each alert id is derived from the event (decision, approval, security
 * event, behaviour change), so a retried hook or a second instance adds it
 * once. Text an agent influenced (its name, the action, rule reasons) is
 * clipped; it is displayed, never executed.
 */
import type { ActionRequest, BehaviorChange, FirewallContext, FirewallDecision, SecurityEventRow } from "@legion/agent-identity";
import * as outbox from "./outbox.js";
import type { Alert, Severity } from "./types.js";

type Frame = (alert: Alert) => unknown;
const clip = (s: string, n = 200) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

async function raise(tenantId: string, id: string, title: string, severity: Severity, summary: string, frame?: Frame): Promise<Alert | null> {
  return outbox.insertAlertAndNotify({
    id, tenant_id: tenantId, title: clip(title, 300), severity, agent: "Guardian", status: "open", summary: clip(summary, 4000),
    confidence: 95, ai_explanation: null, explained_at: null, source_ip: null, target: null, mitre_technique: null, source: "legion-agent-security",
  }, { realtime: frame });
}

export async function alertForFirewallDecision(ctx: FirewallContext, req: ActionRequest, d: FirewallDecision, frame?: Frame): Promise<Alert | null> {
  const p = ctx.principal;
  const who = `${p.type === "ai_agent" ? "AI agent" : "Service account"} "${clip(p.displayName, 80)}" (${p.id})`;
  const rules = d.hits.filter((h) => h.effect !== "WARN");
  const why = rules.map((h) => `${h.id}: ${clip(h.reason, 300)}`).join("\n");
  if (d.decision === "QUARANTINE" || d.decision === "KILL") {
    const contained = d.response?.applied
      ? d.decision === "KILL"
        ? "It was stopped and its credentials and delegations revoked before it received the answer."
        : "It was suspended before it received the answer; a person must review it before it can act again."
      : `Containment could NOT be applied (${d.response?.error ?? "unknown"}); stop it manually from the kill switch.`;
    return raise(p.tenantId, `AGENT-FW-${d.decisionId}`,
      `Agent firewall ${d.decision === "KILL" ? "killed" : "quarantined"} ${who}`,
      d.decision === "KILL" || !d.response?.applied ? "critical" : "high",
      `${who} attempted ${clip(req.action, 200)}. ${contained}\n\nRules:\n${why}\n\nDecision ${d.decisionId} (risk ${d.riskScore}).`, frame);
  }
  if (d.decision === "CONFIRM" && d.approval?.status === "pending") {
    return raise(p.tenantId, `AGENT-APPROVAL-${d.approval.id}`,
      `Approval needed: ${who} wants to ${clip(req.action, 120)}`, "medium",
      `${who} asked to ${clip(req.action, 200)}${req.resource?.id ? ` on ${clip(`${req.resource.type} ${req.resource.id}`, 200)}` : ""}. ` +
      `It will not run unless a person approves this exact action before ${d.approval.expiresAt}.\n\n` +
      `Review: GET /firewall/approvals/${d.approval.id} — approve: POST /firewall/approvals/${d.approval.id}/approve — deny: POST /firewall/approvals/${d.approval.id}/deny\n\nWhy:\n${why}`, frame);
  }
  return null;
}

export async function alertForSecurityEvent(e: Omit<SecurityEventRow, "seq">, frame?: Frame): Promise<Alert | null> {
  // The firewall's own containment is already an alert (with the reason).
  if (e.actorId === "legion-agent-firewall") return null;
  const verb = { agent_killed: "stopped by the kill switch", agent_suspended: "suspended", agent_revoked: "revoked", agent_auto_suspended: "suspended automatically" }[e.kind];
  return raise(e.tenantId, `AGENT-SEC-${e.eventId}`,
    `${e.identityKind === "ai_agent" ? "AI agent" : "Service account"} "${clip(e.identityName, 80)}" ${verb}`,
    e.severity === "critical" ? "critical" : e.severity === "high" ? "high" : "medium",
    `By ${e.actorType} ${clip(e.actorId, 100)}; compromise: ${e.compromise}. Reason: ${clip(e.reason ?? "none given", 500)}. ` +
    `Cut off: ${JSON.stringify(e.details.cutOff)}.`, frame);
}

export async function alertForBehaviorChange(c: BehaviorChange, frame?: Frame): Promise<Alert | null> {
  if (c.to !== "HIGH_RISK" && c.to !== "CRITICAL") return null;
  const signals = c.assessment.signals.slice(0, 8).map((s) => `${s.id}: ${clip(s.detail, 200)}`).join("\n");
  return raise(c.tenantId, `AGENT-BEHAVIOR-${c.identityId}-${Math.floor(Date.now() / 60_000)}`,
    `AI agent "${clip(c.identityName, 80)}" behaviour is ${c.to}`, c.to === "CRITICAL" ? "critical" : "high",
    `Behaviour moved from ${c.from} to ${c.to} (score ${c.assessment.score}).${c.autoSuspended ? " It was suspended automatically." : ""}\n\nSignals:\n${signals}`, frame);
}
