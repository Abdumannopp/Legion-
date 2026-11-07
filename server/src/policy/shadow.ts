/**
 * Shadow evaluation: an existing code path keeps doing exactly what it did,
 * and the policy engine records what it WOULD have decided. Used to compare
 * the engine against today's behaviour before it is ever trusted to enforce.
 *
 * `shadowEvaluate` returns nothing and never throws: a slow or failing policy
 * store cannot delay, change or break the action it observes.
 */
import { config } from "../config.js";
import { digestOf } from "./canonical.js";
import { catalogEntry } from "./catalog.js";
import { evaluatePolicy } from "./evaluate.js";
import { getActivePolicy, recordDecision } from "./store.js";
import type { ActorRef, Origin } from "./types.js";

export interface ShadowCall {
  call_site: string;
  action_id: string;
  actor: ActorRef;
  origin: Origin;
  input: Record<string, unknown>;
  /** What the existing code did, in a word ("blocked", "skipped:allowlisted"…). */
  legacy_outcome: string;
}

const pending = new Set<Promise<void>>();
let failures = 0;

export function shadowEvaluate(tenantId: string, call: ShadowCall): void {
  if (config.policyEngineMode !== "shadow") return;
  const p = (async () => {
    const started = process.hrtime.bigint();
    try {
      const active = await getActivePolicy(tenantId);
      const outcome = evaluatePolicy({ action_id: call.action_id, actor: call.actor, origin: call.origin, mode: "shadow" }, active?.document ?? null);
      const entry = catalogEntry(call.action_id);
      let target: string | null = null;
      try { target = entry ? entry.targetOf(call.input) : null; } catch { target = null; }
      await recordDecision(tenantId, outcome, {
        enforcement: "shadow", call_site: call.call_site, actor: call.actor, origin: call.origin, mode: "shadow",
        target, input_digest: digestOf(call.input), legacy_outcome: call.legacy_outcome,
        latency_us: Number((process.hrtime.bigint() - started) / 1000n),
        policy: active ? { version: active.version, hash: active.hash } : null,
      });
    } catch {
      failures++;
    }
  })();
  pending.add(p);
  void p.finally(() => pending.delete(p));
}

/** For tests and graceful shutdown: wait until every shadow write has finished. */
export async function flushShadow(): Promise<void> {
  while (pending.size) await Promise.allSettled([...pending]);
}

export const shadowFailures = (): number => failures;
