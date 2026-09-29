/**
 * Keeps a client's view of the alert feed correct, whatever happens to the
 * connection.
 *
 * THE RULE: PostgreSQL is the source of truth. A WebSocket frame is only a
 * hint that something changed (and, for speed, a copy of it). Nothing here
 * trusts the socket to be complete: the client remembers a CURSOR — the newest
 * change it is certain to have — and asks the server for everything after it
 * (GET /alerts/sync) on connect, on reconnect, when a heartbeat says the server
 * is ahead, when a gap is seen, when the tab comes back to the foreground, and
 * on a timer. Missing a frame, for any reason, costs at most one interval.
 *
 * What makes the cursor trustworthy:
 *  - it only advances when that is safe: contiguously (seq n+1 after n), or by an
 *    authoritative sync answer. A live frame with a higher seq is shown at once
 *    but does NOT move the cursor past a hole — otherwise one skipped frame would
 *    be skipped forever;
 *  - a change carries its version (`seq`). One that is not newer than what was
 *    already applied for that alert — a duplicate, a replay, a frame that arrived
 *    late — is dropped, so the list never shows an older state over a newer one;
 *  - a snapshot (the list) and its cursor are read together by the server, and
 *    `setBaseline` installs them together, so there is no window in which a
 *    change belongs to neither the list nor the sync.
 *
 * Deliberately free of React, `window` and globals: the socket, the fetch, the
 * clock, the randomness and the page-visibility signal are injected, which is
 * what lets every failure mode be replayed in a test.
 *
 * Multiple tabs: each tab runs its own instance with its own in-memory cursor.
 * They never share one — a cursor is only meaningful with the alerts it
 * accounts for, and another tab does not have this tab's alerts — so tabs are
 * independent and each converges on the database by itself.
 */
import type { VersionedAlert } from "./alert-feed";

/** Close code the server uses when the session behind a socket has ended (realtime.ts CLOSE_SESSION_REVOKED). */
export const SESSION_ENDED = 4401;

export interface SyncedAlert extends VersionedAlert {
  /** The seq the alert was created with. Above the baseline = new to this client. */
  created_seq: number;
}

export interface SyncResponse<T> {
  alerts: T[];
  cursor: number;
  has_more: boolean;
  /** The client's cursor is unusable: reload the list instead. */
  reset: boolean;
}

export type FeedEvent<T> = {
  /** "new_alert": created after this client's snapshot. "alert.status_updated": a change to one it already has. */
  type: "new_alert" | "alert.status_updated";
  alert: T;
  /** Where it came from. Anything that is not "live" was missed while away. */
  source: "live" | "sync";
};

/** The parts of a WebSocket the client uses. */
export interface SocketLike {
  readyState: number;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: unknown) => void) | null;
  onerror: ((ev: unknown) => void) | null;
  close(code?: number, reason?: string): void;
}

export interface SyncState {
  connected: boolean;
  syncing: boolean;
  /** Newest change known to be applied. */
  cursor: number;
  /** null until the first snapshot has been installed. */
  ready: boolean;
  lastSyncAt: number | null;
  lastError: string | null;
}

export interface Clock {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
  random(): number;
}

export interface AlertSyncOptions<T extends SyncedAlert> {
  /** Opens a new socket to the alert stream. */
  connect: () => SocketLike;
  /** GET /alerts/sync. Must reject on any failure. */
  fetchSync: (after: number, signal: AbortSignal) => Promise<SyncResponse<T>>;
  onEvent: (event: FeedEvent<T>) => void;
  /** The client fell too far behind (or its cursor is from another era):
   *  reload the list and call `setBaseline` with the cursor that came with it.
   *  Called again on later reconciliations until that happens. */
  onReset: () => void | Promise<void>;
  onState?: (state: SyncState) => void;
  clock?: Clock;
  /** Reconcile with the server at least this often while connected. */
  reconcileMs?: number;
  /** ...and this often while NOT connected (the socket may be blocked, not down). */
  offlinePollMs?: number;
  /** No frame at all for this long on an open socket means it is dead: replace it. */
  watchdogMs?: number;
  backoffBaseMs?: number;
  backoffMaxMs?: number;
  /** Wait this long after seeing a gap for the missing frames to arrive before asking. */
  gapGraceMs?: number;
  /** Whether the page is in the foreground; and a way to hear when that changes. */
  isVisible?: () => boolean;
  subscribeVisibility?: (cb: () => void) => () => void;
  /** Hears when the browser regains its network connection. */
  subscribeOnline?: (cb: () => void) => () => void;
}

const OPEN = 1;
const CONNECTING = 0;
/** Bounds the per-alert version memory; older entries are dropped first. */
const MAX_REMEMBERED = 20_000;

const realClock: Clock = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
  random: () => Math.random(),
};

export class AlertSyncClient<T extends SyncedAlert> {
  private readonly o: Required<Pick<AlertSyncOptions<T>, "reconcileMs" | "offlinePollMs" | "watchdogMs" | "backoffBaseMs" | "backoffMaxMs" | "gapGraceMs">> & AlertSyncOptions<T>;
  private readonly clock: Clock;

  private socket: SocketLike | null = null;
  private stopped = true;
  private attempt = 0;
  private reconnectTimer: unknown = null;
  private watchdogTimer: unknown = null;
  private reconcileTimer: unknown = null;
  private gapTimer: unknown = null;
  private retryTimer: unknown = null;
  private syncFailures = 0;
  private unsubscribes: Array<() => void> = [];

  /** Newest change this client is certain to have applied. */
  private cursor = 0;
  /** The cursor of the snapshot the list was loaded at; null = none installed yet. */
  private baseline: number | null = null;
  /** Changes applied ahead of the cursor (past a hole), so the cursor can catch up when the hole fills. */
  private ahead = new Set<number>();
  /** Newest version applied per alert id. */
  private latest = new Map<string, number>();

  private syncing: Promise<void> | null = null;
  private syncAgain = false;
  private abort: AbortController | null = null;
  private lastSyncAt: number | null = null;
  private lastError: string | null = null;
  private resetPending = false;

  constructor(options: AlertSyncOptions<T>) {
    this.o = {
      reconcileMs: 60_000, offlinePollMs: 10_000, watchdogMs: 45_000,
      backoffBaseMs: 1_000, backoffMaxMs: 30_000, gapGraceMs: 400,
      ...options,
    };
    this.clock = options.clock ?? realClock;
  }

  // --- lifecycle -----------------------------------------------------------------

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    if (this.o.subscribeVisibility) this.unsubscribes.push(this.o.subscribeVisibility(() => this.onVisibility()));
    if (this.o.subscribeOnline) this.unsubscribes.push(this.o.subscribeOnline(() => this.onOnline()));
    this.openSocket();
    this.scheduleReconcile();
  }

  stop(): void {
    this.stopped = true;
    for (const t of [this.reconnectTimer, this.watchdogTimer, this.reconcileTimer, this.gapTimer, this.retryTimer]) {
      if (t !== null) this.clock.clearTimeout(t);
    }
    this.reconnectTimer = this.watchdogTimer = this.reconcileTimer = this.gapTimer = this.retryTimer = null;
    this.abort?.abort();
    this.unsubscribes.forEach((u) => u());
    this.unsubscribes = [];
    this.detachSocket();
    this.emitState();
  }

  /**
   * Installs a snapshot: the list the owner just loaded, together with the
   * cursor the server read in the SAME snapshot. From here on this client is
   * responsible for everything with a higher seq. Call it every time the list is
   * (re)loaded, including after `onReset`.
   */
  setBaseline(cursor: number): void {
    this.baseline = cursor;
    this.cursor = cursor;
    this.ahead.clear();
    this.latest.clear();
    this.resetPending = false;
    this.emitState();
    void this.syncNow("baseline");
  }

  get state(): SyncState {
    return {
      connected: this.socket?.readyState === OPEN,
      syncing: this.syncing !== null,
      cursor: this.cursor,
      ready: this.baseline !== null,
      lastSyncAt: this.lastSyncAt,
      lastError: this.lastError,
    };
  }

  // --- socket --------------------------------------------------------------------

  private openSocket(): void {
    if (this.stopped || this.socket) return;
    let ws: SocketLike;
    try {
      ws = this.o.connect();
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.socket = ws;

    ws.onopen = () => {
      if (this.socket !== ws) return;
      this.attempt = 0; // reset the backoff only after a genuinely successful open
      this.armWatchdog();
      this.scheduleReconcile(); // connected: back to the relaxed cadence
      this.emitState();
      // Whatever happened while there was no connection, ask the database.
      void this.syncNow("open");
    };
    ws.onmessage = (ev) => {
      if (this.socket !== ws) return;
      this.armWatchdog();
      this.handleFrame(ev.data);
    };
    ws.onerror = () => {
      if (this.socket !== ws) return;
      // onclose owns the reconnect, so there is exactly one path.
      try { ws.close(); } catch { /* already closing */ }
    };
    ws.onclose = (ev) => {
      if (this.socket !== ws) return;
      this.socket = null;
      if (this.watchdogTimer !== null) { this.clock.clearTimeout(this.watchdogTimer); this.watchdogTimer = null; }
      this.scheduleReconcile(); // not connected: poll faster
      this.emitState();
      // 4401: the server ended the socket because the access token behind it
      // expired or was revoked. Sync over HTTP first — that request refreshes
      // the session cookie (or sends a signed-out user to the login page) —
      // so the reconnect below presents a valid one.
      if ((ev as { code?: number } | undefined)?.code === SESSION_ENDED) void this.syncNow("session");
      this.scheduleReconnect();
    };
    this.emitState();
  }

  private detachSocket(): void {
    const ws = this.socket;
    this.socket = null;
    if (!ws) return;
    ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null;
    if (ws.readyState === OPEN || ws.readyState === CONNECTING) {
      try { ws.close(); } catch { /* ignore */ }
    }
  }

  /** Exponential backoff with full jitter: many tabs whose server just restarted must not all knock at once. */
  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer !== null) return;
    const ceiling = Math.min(this.o.backoffBaseMs * 2 ** this.attempt, this.o.backoffMaxMs);
    const delay = Math.round(ceiling / 2 + (this.clock.random() * ceiling) / 2);
    this.attempt += 1;
    this.reconnectTimer = this.clock.setTimeout(() => {
      this.reconnectTimer = null;
      this.openSocket();
    }, delay);
  }

  /** A connection that stops delivering frames without closing (a dropped network, a stalled proxy) looks open forever. */
  private armWatchdog(): void {
    if (this.watchdogTimer !== null) this.clock.clearTimeout(this.watchdogTimer);
    this.watchdogTimer = this.clock.setTimeout(() => {
      this.watchdogTimer = null;
      const ws = this.socket;
      if (!ws) return;
      // Replace it; the reconnect path (and its catch-up sync) takes over.
      this.detachSocket();
      this.emitState();
      this.scheduleReconnect();
    }, this.o.watchdogMs);
  }

  // --- frames --------------------------------------------------------------------

  private handleFrame(raw: unknown): void {
    let frame: { type?: unknown; cursor?: unknown; alert?: unknown };
    try {
      frame = JSON.parse(String(raw));
    } catch {
      return; // a malformed frame must not break the stream
    }
    if (!frame || typeof frame.type !== "string") return;

    switch (frame.type) {
      case "hello":
      case "ping":
        // The server's cursor, read from Postgres. Ahead of ours = we missed something.
        if (typeof frame.cursor === "number" && frame.cursor > this.cursor) void this.syncNow(frame.type);
        return;
      case "resync":
        void this.syncNow("resync");
        return;
      case "new_alert":
      case "alert.status_updated": {
        const alert = frame.alert as T | undefined;
        if (!alert || typeof alert.id !== "string" || !Number.isFinite(alert.seq)) {
          // Not versioned, so it cannot be ordered or de-duplicated. Its content is
          // not trusted; the database is asked instead.
          void this.syncNow("unversioned");
          return;
        }
        this.acceptLive(alert);
        return;
      }
    }
  }

  private acceptLive(alert: T): void {
    if (this.baseline === null) return; // no snapshot yet; the sync after setBaseline covers it
    if (!this.deliver(alert, "live")) return;
    if (alert.seq === this.cursor + 1) {
      this.cursor = alert.seq;
      this.advanceThroughAhead();
    } else if (alert.seq > this.cursor + 1) {
      // A hole below this change. Show it now, but do not move the cursor past
      // the hole; give the missing frames a moment, then ask the database.
      this.ahead.add(alert.seq);
      this.scheduleGapSync();
    }
    this.emitState();
  }

  private advanceThroughAhead(): void {
    while (this.ahead.has(this.cursor + 1)) {
      this.ahead.delete(this.cursor + 1);
      this.cursor += 1;
    }
  }

  private scheduleGapSync(): void {
    if (this.gapTimer !== null) return;
    this.gapTimer = this.clock.setTimeout(() => {
      this.gapTimer = null;
      if (this.ahead.size > 0) void this.syncNow("gap");
    }, this.o.gapGraceMs);
  }

  /**
   * The single place an alert becomes an event. Returns whether it was
   * delivered. Drops what is not news: at or below the cursor, at or below the
   * snapshot, or not newer than the version already applied for that alert.
   */
  private deliver(alert: T, source: "live" | "sync"): boolean {
    const baseline = this.baseline;
    if (baseline === null) return false;
    if (alert.seq <= baseline) return false; // the snapshot already has this or newer
    if (source === "live" && alert.seq <= this.cursor) return false; // already accounted for
    const known = this.latest.get(alert.id);
    if (known !== undefined && alert.seq <= known) return false; // duplicate, or arrived out of order

    this.latest.delete(alert.id); // re-insert so the oldest entry is the least recently changed
    this.latest.set(alert.id, alert.seq);
    if (this.latest.size > MAX_REMEMBERED) this.latest.delete(this.latest.keys().next().value as string);

    this.o.onEvent({ type: alert.created_seq > baseline ? "new_alert" : "alert.status_updated", alert, source });
    return true;
  }

  // --- sync ----------------------------------------------------------------------

  /**
   * Asks the database for everything after the cursor. One at a time: a request
   * that arrives while one is running is folded into a single follow-up, so a
   * burst of hints (a heartbeat, a gap, a reconnect) is one round trip.
   */
  syncNow(_reason = "manual"): Promise<void> {
    if (this.stopped || this.baseline === null) {
      // Nothing to sync against yet — but a needed reload must not be forgotten.
      if (!this.stopped && this.resetPending) void this.requestReset();
      return Promise.resolve();
    }
    if (this.syncing) {
      this.syncAgain = true;
      return this.syncing;
    }
    this.syncing = this.runSync().finally(() => {
      this.syncing = null;
      this.emitState();
      if (this.syncAgain && !this.stopped) {
        this.syncAgain = false;
        void this.syncNow("follow-up");
      }
    });
    this.emitState();
    return this.syncing;
  }

  private async runSync(): Promise<void> {
    this.abort = new AbortController();
    const signal = this.abort.signal;
    try {
      for (;;) {
        const res = await this.o.fetchSync(this.cursor, signal);
        if (this.stopped) return;

        if (res.reset) {
          // Our position is not usable. Do NOT adopt the server's cursor: without a
          // list to go with it that would skip everything in between. Wait for the
          // owner to reload and hand us a matching baseline.
          this.baseline = null;
          this.resetPending = true;
          this.ahead.clear();
          this.latest.clear();
          await this.requestReset();
          return;
        }

        for (const alert of res.alerts) this.deliver(alert, "sync"); // seq order, oldest first
        // Everything up to res.cursor is now applied (this page, or already had it).
        if (res.cursor > this.cursor) this.cursor = res.cursor;
        for (const s of this.ahead) if (s <= this.cursor) this.ahead.delete(s);
        this.advanceThroughAhead();
        this.lastSyncAt = this.clock.now();
        this.lastError = null;
        this.syncFailures = 0;
        this.emitState();
        if (!res.has_more) return;
      }
    } catch (error) {
      if (this.stopped || signal.aborted) return;
      this.lastError = error instanceof Error ? error.message.slice(0, 200) : "sync failed";
      this.scheduleSyncRetry();
    }
  }

  private async requestReset(): Promise<void> {
    try {
      await this.o.onReset();
    } catch {
      // The next reconciliation asks again.
    }
  }

  private scheduleSyncRetry(): void {
    if (this.stopped || this.retryTimer !== null) return;
    const ceiling = Math.min(this.o.backoffBaseMs * 2 ** this.syncFailures, this.o.backoffMaxMs);
    this.syncFailures += 1;
    const delay = Math.round(ceiling / 2 + (this.clock.random() * ceiling) / 2);
    this.retryTimer = this.clock.setTimeout(() => {
      this.retryTimer = null;
      void this.syncNow("retry");
    }, delay);
  }

  // --- reconciliation --------------------------------------------------------------

  /** The backstop that does not depend on the socket at all. */
  private scheduleReconcile(): void {
    if (this.stopped) return;
    if (this.reconcileTimer !== null) this.clock.clearTimeout(this.reconcileTimer);
    const connected = this.socket?.readyState === OPEN;
    this.reconcileTimer = this.clock.setTimeout(() => {
      this.reconcileTimer = null;
      // A hidden tab's timers are throttled by the browser anyway; it reconciles
      // the moment it becomes visible, so it does not spend requests in between.
      if (this.o.isVisible ? this.o.isVisible() : true) void this.syncNow("interval");
      this.scheduleReconcile();
    }, connected ? this.o.reconcileMs : this.o.offlinePollMs);
  }

  private onVisibility(): void {
    if (this.stopped || !(this.o.isVisible ? this.o.isVisible() : true)) return;
    if (!this.socket) this.reconnectNow();
    void this.syncNow("visible");
  }

  private onOnline(): void {
    if (this.stopped) return;
    if (!this.socket) this.reconnectNow();
    void this.syncNow("online");
  }

  private reconnectNow(): void {
    if (this.reconnectTimer !== null) { this.clock.clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    this.attempt = 0;
    this.openSocket();
  }

  private emitState(): void {
    this.o.onState?.(this.state);
  }
}
