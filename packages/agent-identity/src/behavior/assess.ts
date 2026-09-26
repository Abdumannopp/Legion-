import { ATTACK_INDICATORS, destinationKey, isExternal, isPeer } from "./keys.js";
import { levelOf, type Assessment, type BehaviorProfile, type Signal, type SignalCategory, type WindowEvent } from "./types.js";

/*
 * Compares an agent's recent activity with its own normal behaviour.
 *
 * Two kinds of evidence:
 *   - Deviation from the baseline (volume, new tools, new destinations,
 *     failure and sensitivity rates, new peers, unusual hours). Only
 *     counted once the agent has an established baseline — without one,
 *     "new" means nothing.
 *   - Intent indicators that need no baseline: attempts on other tenants,
 *     internal addresses, interpreters, protected tables, laundering; many
 *     distinct denials (probing); malicious content reaching the agent.
 *
 * The score sums the strongest signal per category (capped at 100), so
 * independent deviations add up and one noisy dimension cannot on its own
 * push an agent to CRITICAL.
 */

export interface AssessInput {
  profile: BehaviorProfile;
  events: WindowEvent[];
  windowStart: Date;
  windowEnd: Date;
  /** Operations that ran and failed (audit outcome "failure"), in the window. */
  failures: number;
  /** Prompt-injection state from the content guard. */
  content?: { malicious: number; suspicious: number };
}

/** Does this action change state or act outside Legion (as opposed to reading)? */
export function isUnsafeAction(action: string): boolean {
  if (action.startsWith("egress:") || action === "agents:message") return true;
  const m = /^tool:(\w+)\.(.+)$/.exec(action);
  if (!m) return false;
  const op = m[2]!;
  const reads = /^(?:select|read|list|navigate|screenshot|search|get|head)(?:_|$)/i.test(op) ||
    /(?::|\.|\/)(?:get|list|describe|head|lookup|search|read|view|query|scan|batchget)[a-z]*$/i.test(op);
  return m[1] === "shell" || !reads;
}

function share(n: number, d: number): number {
  return d ? n / d : 0;
}
const top = (xs: Iterable<string>, n = 10) => [...new Set(xs)].slice(0, n);

export function isAttackIndicator(ruleId: string): boolean {
  return ATTACK_INDICATORS.has(ruleId) || /\.secret_in_/.test(ruleId);
}

export function assess(input: AssessInput): Assessment {
  const { profile: p, events } = input;
  const signals: Signal[] = [];
  const sig = (category: SignalCategory, id: string, points: number, detail: string, evidence?: string[]) =>
    signals.push({ category, id, points, detail, ...(evidence?.length ? { evidence } : {}) });

  const minutes = Math.max(1, (input.windowEnd.getTime() - input.windowStart.getTime()) / 60_000);
  const perHour = (events.length * 60) / minutes;
  const blocks = events.filter((e) => e.decision === "BLOCK" && !e.ruleIds.every((r) => r.startsWith("behavior.")));
  const est = p.established;

  // ---- Request volume --------------------------------------------------------
  if (est) {
    const normalMax = Math.max(3 * p.hourly.p95, p.hourly.mean + 4 * p.hourly.std, 30);
    if (perHour > 3 * normalMax) sig("volume", "volume.extreme", 35, `${Math.round(perHour)} actions/hour against a normal ${Math.round(p.hourly.p95)} (p95).`);
    else if (perHour > normalMax) sig("volume", "volume.spike", 20, `${Math.round(perHour)} actions/hour against a normal ${Math.round(p.hourly.p95)} (p95).`);
  } else if (perHour > 600) {
    sig("volume", "volume.high_unbaselined", 20, `${Math.round(perHour)} actions/hour from an agent without a baseline.`);
  }

  // ---- Tool usage --------------------------------------------------------------
  if (est) {
    const newActions = top(events.map((e) => e.action).filter((a) => !(a in p.actions)));
    const newUnsafe = newActions.filter(isUnsafeAction);
    if (newUnsafe.length) sig("tools", "tools.new_unsafe", Math.min(35, 25 + 5 * (newUnsafe.length - 1)), "Uses state-changing or outward-facing tools it has never used.", newUnsafe);
    else if (newActions.length) sig("tools", "tools.new", Math.min(20, 10 + 5 * (newActions.length - 1)), "Uses actions it has never used.", newActions);
  }

  // ---- Accessed resources -------------------------------------------------------
  if (est) {
    const newTypes = top(events.map((e) => e.resourceType).filter((r): r is string => !!r && !(r in p.resourceTypes)));
    if (newTypes.length) sig("resources", "resources.new_types", Math.min(20, 10 * newTypes.length), "Touches kinds of resource it has never touched.", newTypes);
  }

  // ---- External destinations ------------------------------------------------------
  const extKeys = events.map((e) => destinationKey(e.destination)).filter((k): k is string => isExternal(k));
  if (est) {
    const fresh = top(extKeys.filter((k) => !(k in p.externalDestinations)), 20);
    if (fresh.length >= 10) sig("destinations", "destinations.fan_out", 40, `${fresh.length} new external destinations in one window (possible exfiltration).`, fresh);
    else if (fresh.length >= 3) sig("destinations", "destinations.many_new", 25, `${fresh.length} new external destinations.`, fresh);
    else if (fresh.length) sig("destinations", "destinations.new", 10, "Contacts an external destination it never used.", fresh);
  } else {
    const distinct = top(extKeys, 20);
    if (distinct.length >= 10) sig("destinations", "destinations.fan_out_unbaselined", 20, `${distinct.length} distinct external destinations from an agent without a baseline.`, distinct);
  }

  // ---- Failed operations ------------------------------------------------------------
  const blockRate = share(blocks.length, events.length);
  if (events.length >= 10) {
    const high = Math.max(0.3, 3 * p.blockRate);
    if (blockRate >= Math.max(0.6, high)) sig("failures", "failures.mostly_blocked", 30, `${Math.round(blockRate * 100)}% of its actions were blocked.`);
    else if (blockRate >= high) sig("failures", "failures.block_rate", 20, `${Math.round(blockRate * 100)}% blocked, against a normal ${Math.round(p.blockRate * 100)}%.`);
  }
  const distinctDenials = top(blocks.flatMap((e) => e.ruleIds.filter((r) => !r.startsWith("behavior.") && !r.startsWith("risk."))), 20);
  if (distinctDenials.length >= 4) sig("probing", "failures.probing", 20, `${distinctDenials.length} different rules stopped it — it is testing boundaries.`, distinctDenials);
  if (input.failures >= 20 && share(input.failures, events.length) >= 0.5) {
    sig("failures", "failures.errors", 15, `${input.failures} of its operations failed.`);
  }

  // ---- Intent indicators (no baseline needed) ------------------------------------------
  const indicators = top(events.flatMap((e) => e.ruleIds.filter(isAttackIndicator)), 20);
  if (indicators.length) {
    sig("attack_indicators", "attack.indicators", Math.min(45, 15 * indicators.length), "Attempted actions that a legitimate agent does not attempt.", indicators);
  }

  // ---- Sensitive data requests ------------------------------------------------------
  const sensitive = events.filter((e) => e.sensitivity === "confidential" || e.sensitivity === "restricted");
  if (events.some((e) => e.sensitivity === "restricted")) {
    sig("sensitive_data", "sensitive.restricted_attempt", 25, "Asked for restricted data (never available to agents).");
  } else if (est && events.length >= 10) {
    const rate = share(sensitive.length, events.length);
    if (rate >= 0.5 && rate >= 3 * p.sensitiveRate + 0.2) {
      sig("sensitive_data", "sensitive.increase", 20, `${Math.round(rate * 100)}% of its actions touch confidential data, against a normal ${Math.round(p.sensitiveRate * 100)}%.`);
    }
  }

  // ---- Agent-to-agent communication -----------------------------------------------
  const peerKeys = events.map((e) => destinationKey(e.destination)).filter((k): k is string => isPeer(k));
  if (est) {
    const newPeers = top(peerKeys.filter((k) => !(k in p.peers)));
    if (newPeers.length) sig("agent_communication", "a2a.new_peers", Math.min(25, 10 + 5 * (newPeers.length - 1)), "Messages agents it never talked to.", newPeers);
    const msgPerHour = (peerKeys.length * 60) / minutes;
    if (!newPeers.length && peerKeys.length >= 10 && msgPerHour > 5 * Math.max(p.messagesPerHour, 2)) {
      sig("agent_communication", "a2a.burst", 15, `${Math.round(msgPerHour)} agent messages/hour against a normal ${Math.round(p.messagesPerHour)}.`);
    }
  }
  if (events.some((e) => e.viaMessage) && events.filter((e) => e.viaMessage && e.decision === "BLOCK").length >= 3) {
    sig("agent_communication", "a2a.blocked_on_behalf", 15, "Repeatedly blocked while acting on another agent's request.");
  }

  // ---- Changes in timing -------------------------------------------------------------
  if (est && p.hourly.activeHours >= 24) {
    const odd = events.filter((e) => (p.hoursOfDay[new Date(e.occurredAt).getUTCHours()] ?? 0) === 0);
    if (odd.length >= 5) sig("timing", "timing.unusual_hours", 10, `${odd.length} actions at hours it is never active.`);
  }

  // ---- Delegation -----------------------------------------------------------------------
  if (est) {
    const newUsers = top(events.map((e) => e.delegatedUser).filter((u): u is string => !!u && !(u in p.delegatedUsers)));
    if (newUsers.length) sig("delegation", "delegation.new_users", 10, "Acts for people it never acted for.", newUsers);
  }

  // ---- External content reaching the agent -------------------------------------------
  if (input.content?.malicious) sig("external_content", "content.malicious", 30, "Unreviewed malicious external content reached this agent.");
  else if (input.content?.suspicious) sig("external_content", "content.suspicious", 10, "Suspicious external content reached this agent recently.");

  const strongest = new Map<SignalCategory, number>();
  for (const s of signals) strongest.set(s.category, Math.max(strongest.get(s.category) ?? 0, s.points));
  const score = Math.min(100, [...strongest.values()].reduce((a, b) => a + b, 0));

  // Guard: without a baseline, only intent evidence may raise an agent above
  // SUSPICIOUS — a new agent doing new things is not, by itself, an attack.
  const intent = signals.some((s) => ["attack_indicators", "probing", "failures", "external_content"].includes(s.category));
  const capped = !est && !intent ? Math.min(score, 59) : score;

  return {
    level: levelOf(capped),
    score: capped,
    established: est,
    window: {
      start: input.windowStart.toISOString(),
      end: input.windowEnd.toISOString(),
      events: events.length,
      blocks: blocks.length,
      failures: input.failures,
      perHour: Math.round(perHour * 10) / 10,
    },
    signals,
  };
}
