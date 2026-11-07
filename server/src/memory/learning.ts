/**
 * Learning foundation: how people decided on agents' proposals, counted per
 * action, and suggestions derived from those counts.
 *
 * Deterministic and advisory only. A suggestion is text for a person; nothing
 * here writes a policy, grants a permission or changes an autonomy level.
 * Critical and high-risk actions (R3/R4) are never suggested for more
 * autonomy — their approval floors cannot be lowered anyway.
 */
import type pg from "pg";
import { queryAll } from "../db/pool.js";
import { catalogEntry } from "../policy/catalog.js";
import { riskRank } from "../policy/types.js";

export type Signal = "approved" | "rejected" | "expired" | "cancelled";

/** Counted in the same transaction as the state change it describes. */
export async function recordSignal(client: pg.PoolClient, tenantId: string, actionId: string, signal: Signal): Promise<void> {
  await client.query(
    `INSERT INTO learning_signals (tenant_id, action_id, signal, count) VALUES ($1, $2, $3, 1)
     ON CONFLICT (tenant_id, action_id, signal) DO UPDATE SET count = learning_signals.count + 1, last_at = now()`,
    [tenantId, actionId.slice(0, 64), signal],
  );
}

export interface Suggestion { action_id: string; kind: "consider_more_autonomy" | "review_detection"; text: string; approved: number; rejected: number; applied: false }

export const MIN_DECISIONS = 20;

export async function learningSummary(tenantId: string): Promise<{ signals: Array<{ action_id: string; signal: Signal; count: number; last_at: string }>; suggestions: Suggestion[] }> {
  const rows = await queryAll<{ action_id: string; signal: Signal; count: number; last_at: Date }>(
    "SELECT action_id, signal, count, last_at FROM learning_signals WHERE tenant_id = $1 ORDER BY action_id, signal", [tenantId],
  );
  const by = new Map<string, Record<Signal, number>>();
  for (const r of rows) {
    const m = by.get(r.action_id) ?? { approved: 0, rejected: 0, expired: 0, cancelled: 0 };
    m[r.signal] = Number(r.count);
    by.set(r.action_id, m);
  }
  const suggestions: Suggestion[] = [];
  for (const [action_id, c] of by) {
    const entry = catalogEntry(action_id);
    const decided = c.approved + c.rejected;
    if (!entry || decided < MIN_DECISIONS) continue;
    const rate = c.approved / decided;
    if (rate >= 0.95 && riskRank(entry.class) <= riskRank("R2")) {
      suggestions.push({ action_id, kind: "consider_more_autonomy", approved: c.approved, rejected: c.rejected, applied: false,
        text: `People approved ${c.approved} of ${decided} proposals of ${action_id}. An administrator may consider more autonomy for it in the policy.` });
    } else if (rate <= 0.5) {
      suggestions.push({ action_id, kind: "review_detection", approved: c.approved, rejected: c.rejected, applied: false,
        text: `People rejected ${c.rejected} of ${decided} proposals of ${action_id}. The detections behind them may be too noisy.` });
    }
  }
  return { signals: rows.map((r) => ({ ...r, count: Number(r.count), last_at: r.last_at.toISOString() })), suggestions };
}
