/**
 * Pure list logic for the live alert feed: where an alert belongs, and whether a
 * pushed version should replace what is on screen. No React, no network — so the
 * rules that keep the list correct can be tested on their own.
 *
 * Order: newest first by `created_at`, arrival order (`seq`) among equals. It is
 * the same order the server's list uses, so an alert inserted live lands where a
 * reload would put it, whatever order the events arrived in.
 */
export interface VersionedAlert {
  id: string;
  /** This alert's version: per-tenant, bumped by every change on the server. */
  seq: number;
  created_at: string;
}

function time(iso: string): number {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? t : 0;
}

/** Negative when `a` belongs before `b` (newest first). */
export function compareAlerts(a: VersionedAlert, b: VersionedAlert): number {
  const dt = time(b.created_at) - time(a.created_at);
  if (dt !== 0) return dt;
  return b.seq - a.seq;
}

export function sortAlerts<T extends VersionedAlert>(alerts: readonly T[]): T[] {
  return [...alerts].sort(compareAlerts);
}

/**
 * Adds or updates `incoming` in an already-sorted list.
 *
 *  - unknown id            → inserted in its sorted position (`insert: true`);
 *  - known id, newer seq   → replaced in place;
 *  - known id, same/older  → ignored: a duplicate, or an event that arrived
 *                            late. The SAME array is returned so React can skip
 *                            the render.
 *
 * `insert: false` refuses to add an alert that is not already listed (an update
 * to something the current filter hides).
 */
export function upsertAlert<T extends VersionedAlert>(list: readonly T[], incoming: T, opts: { insert?: boolean } = {}): T[] {
  const insert = opts.insert ?? true;
  const index = list.findIndex((a) => a.id === incoming.id);
  if (index !== -1) {
    if (incoming.seq <= list[index]!.seq) return list as T[];
    const next = list.slice();
    next[index] = incoming;
    // A changed alert keeps its created_at, so it normally stays put; re-sort
    // only if the server ever moved it.
    return compareAlerts(incoming, list[index]!) === 0 ? next : sortAlerts(next);
  }
  if (!insert) return list as T[];
  let at = list.length;
  for (let i = 0; i < list.length; i++) {
    if (compareAlerts(incoming, list[i]!) < 0) { at = i; break; }
  }
  const next = list.slice();
  next.splice(at, 0, incoming);
  return next;
}
