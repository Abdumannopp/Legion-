/**
 * Refreshing the session without tabs tripping over each other.
 *
 * The access and refresh cookies are shared by every tab. When the access
 * token expires, every open tab gets a 401 at about the same moment and each
 * calls POST /auth/refresh with the SAME refresh cookie. The server rotates the
 * token on the first call and, correctly, treats the second presentation of
 * the spent token as theft: it revokes the whole session, signing the analyst
 * out of every tab.
 *
 * So refresh is serialised across tabs with the Web Locks API. A tab that gets
 * the lock after another tab has just refreshed does not refresh again — the
 * cookies it shares are already new — and a tab that does refresh sends the
 * CURRENT cookie, never a spent one. Within one tab, concurrent callers share
 * one attempt. Free of React and the DOM so it can be tested in Node.
 */

export interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export interface RefresherDeps {
  /** Performs POST /auth/refresh; true when the server issued new cookies. */
  refresh: () => Promise<boolean>;
  /** navigator.locks, when the browser has it. */
  locks?: LockManagerLike | null;
  /** localStorage, when available: where tabs note their last successful refresh. */
  storage?: StorageLike | null;
  now?: () => number;
}

export const REFRESH_LOCK = "legion-session-refresh";
export const REFRESHED_AT_KEY = "legion:session-refreshed-at";

export function createRefresher(deps: RefresherDeps): () => Promise<boolean> {
  const now = deps.now ?? Date.now;
  let inFlight: Promise<boolean> | null = null;

  const readRefreshedAt = (): number => {
    try { return Number(deps.storage?.getItem(REFRESHED_AT_KEY)) || 0; } catch { return 0; }
  };
  const markRefreshed = (): void => {
    try { deps.storage?.setItem(REFRESHED_AT_KEY, String(now())); } catch { /* private mode: the lock still serialises */ }
  };

  async function underLock(startedAt: number): Promise<boolean> {
    // Another tab refreshed while this one waited: its new cookies are ours too.
    if (readRefreshedAt() >= startedAt) return true;
    const ok = await deps.refresh().catch(() => false);
    if (ok) markRefreshed();
    return ok;
  }

  return function refreshSession(): Promise<boolean> {
    if (!inFlight) {
      const startedAt = now();
      const run = deps.locks
        ? deps.locks.request(REFRESH_LOCK, () => underLock(startedAt))
        : underLock(startedAt);
      inFlight = Promise.resolve(run)
        .catch(() => false)
        .finally(() => {
          // Cleared on the next tick so callers awaiting this promise all see
          // the same result before a new attempt can start.
          setTimeout(() => { inFlight = null; }, 0);
        });
    }
    return inFlight;
  };
}
