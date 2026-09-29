import { describe, expect, it } from "vitest";
import { createRefresher, type LockManagerLike, type StorageLike } from "./session-refresh";

/**
 * A fake server with the real server's rule: a refresh token works once, and a
 * spent one presented again revokes the whole session. The "cookie jar" is
 * shared, as it is between the tabs of one browser.
 */
function fakeBrowser() {
  let generation = 0;           // which token the shared cookie jar holds
  let revoked = false;
  const spent = new Set<number>();
  const calls: number[] = [];
  // Each tab reads the cookie when its request starts; the response arrives later.
  const refresh = async () => {
    const presented = generation;
    calls.push(presented);
    await new Promise((r) => setTimeout(r, 5));
    if (revoked || spent.has(presented)) { revoked = true; return false; }
    spent.add(presented);
    generation = presented + 1;
    return true;
  };
  const locks: LockManagerLike = (() => {
    let tail: Promise<unknown> = Promise.resolve();
    return {
      request<T>(_name: string, cb: () => Promise<T>): Promise<T> {
        const run = tail.then(cb, cb);
        tail = run.catch(() => undefined);
        return run;
      },
    };
  })();
  const store = new Map<string, string>();
  const storage: StorageLike = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => void store.set(k, v) };
  return { refresh, locks, storage, calls, get revoked() { return revoked; } };
}

describe("session refresh across tabs", () => {
  it("WITHOUT coordination, two tabs refreshing at once revoke the session (the bug)", async () => {
    const b = fakeBrowser();
    const tabA = createRefresher({ refresh: b.refresh });
    const tabB = createRefresher({ refresh: b.refresh });
    const results = await Promise.all([tabA(), tabB()]);
    expect(results).toContain(false);
    expect(b.revoked).toBe(true);
  });

  it("WITH the cross-tab lock, both tabs stay signed in and only one refresh is sent", async () => {
    const b = fakeBrowser();
    const tabA = createRefresher({ refresh: b.refresh, locks: b.locks, storage: b.storage });
    const tabB = createRefresher({ refresh: b.refresh, locks: b.locks, storage: b.storage });
    const tabC = createRefresher({ refresh: b.refresh, locks: b.locks, storage: b.storage });
    expect(await Promise.all([tabA(), tabB(), tabC()])).toEqual([true, true, true]);
    expect(b.revoked).toBe(false);
    expect(b.calls).toHaveLength(1);
  });

  it("with the lock but no storage (private mode), refreshes are sequential and never present a spent token", async () => {
    const b = fakeBrowser();
    const tabA = createRefresher({ refresh: b.refresh, locks: b.locks, storage: null });
    const tabB = createRefresher({ refresh: b.refresh, locks: b.locks, storage: null });
    expect(await Promise.all([tabA(), tabB()])).toEqual([true, true]);
    expect(b.revoked).toBe(false);
    expect(new Set(b.calls).size).toBe(b.calls.length); // every call used a different, current token
  });

  it("within one tab, concurrent callers share one attempt", async () => {
    const b = fakeBrowser();
    const tab = createRefresher({ refresh: b.refresh, locks: b.locks, storage: b.storage });
    expect(await Promise.all([tab(), tab(), tab(), tab()])).toEqual([true, true, true, true]);
    expect(b.calls).toHaveLength(1);
  });

  it("a later expiry refreshes again (the marker only skips a refresh that raced)", async () => {
    const b = fakeBrowser();
    let t = 1_000;
    const tab = createRefresher({ refresh: b.refresh, locks: b.locks, storage: b.storage, now: () => t });
    await tab();
    await new Promise((r) => setTimeout(r, 1));
    t += 15 * 60_000;
    await tab();
    expect(b.calls).toEqual([0, 1]);
  });
});
