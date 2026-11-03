/**
 * Test harness for the alert feed: a fake socket, a manual clock and an
 * in-memory "database" that answers /alerts/sync the way the server does.
 * Test-only; nothing in the app imports it.
 */
import { sortAlerts, upsertAlert, type VersionedAlert } from "./alert-feed";
import {
  AlertSyncClient, type AlertSyncOptions, type FeedEvent, type SocketLike, type SyncResponse, type SyncedAlert,
} from "./alert-sync";

export interface TestAlert extends SyncedAlert {
  title: string;
  status: "open" | "investigating" | "resolved";
}

/** The server's side of the contract: per-tenant seq, bumped by every change. */
export class FakeDb {
  cursor = 0;
  readonly alerts = new Map<string, TestAlert>();
  maxCatchup = 1_000;
  syncCalls: number[] = [];
  private tick = 0;

  insert(id: string, over: Partial<TestAlert> = {}): TestAlert {
    const seq = ++this.cursor;
    const alert: TestAlert = { id, title: `alert ${id}`, status: "open", seq, created_seq: seq, created_at: new Date(Date.UTC(2026, 8, 29, 0, 0, ++this.tick)).toISOString(), ...over };
    this.alerts.set(id, alert);
    return alert;
  }
  update(id: string, patch: Partial<TestAlert>): TestAlert {
    const old = this.alerts.get(id)!;
    const next = { ...old, ...patch, seq: ++this.cursor };
    this.alerts.set(id, next);
    return next;
  }
  /** All alerts, in the order the list shows them. */
  list(): TestAlert[] { return sortAlerts([...this.alerts.values()]); }

  sync(after: number, limit = 200): SyncResponse<TestAlert> {
    this.syncCalls.push(after);
    if (after > this.cursor || this.cursor - after > this.maxCatchup) return { alerts: [], cursor: this.cursor, has_more: false, reset: true };
    const rows = [...this.alerts.values()].filter((a) => a.seq > after && a.seq <= this.cursor).sort((a, b) => a.seq - b.seq);
    const page = rows.slice(0, limit);
    const hasMore = rows.length > limit;
    return { alerts: page, cursor: hasMore ? page[page.length - 1]!.seq : this.cursor, has_more: hasMore, reset: false };
  }
}

export class FakeSocket implements SocketLike {
  readyState = 0;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: unknown) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  closed = false;
  constructor(readonly id: number) {}
  /** The server accepts the connection. */
  open(): void { this.readyState = 1; this.onopen?.({}); }
  /** The server sends a frame. */
  push(frame: unknown): void { this.onmessage?.({ data: typeof frame === "string" ? frame : JSON.stringify(frame) }); }
  /** The connection dies (server restart, network drop). */
  drop(code?: number): void { this.readyState = 3; this.onclose?.(code === undefined ? {} : { code }); }
  close(): void { this.closed = true; if (this.readyState !== 3) { this.readyState = 3; this.onclose?.({}); } }
}

interface Timer { at: number; fn: () => void; id: number }
export class FakeClock {
  time = 1_000_000;
  private timers: Timer[] = [];
  private seq = 0;
  /** Deterministic "random" so backoff jitter is reproducible. */
  rnd = 0.5;
  now = () => this.time;
  setTimeout = (fn: () => void, ms: number) => { const t = { at: this.time + ms, fn, id: ++this.seq }; this.timers.push(t); return t.id; };
  clearTimeout = (h: unknown) => { this.timers = this.timers.filter((t) => t.id !== h); };
  random = () => this.rnd;
  get pending(): number { return this.timers.length; }
  /** Runs everything due within `ms`, in order, letting promises settle between. */
  async advance(ms: number): Promise<void> {
    const end = this.time + ms;
    for (;;) {
      await flush();
      const next = this.timers.filter((t) => t.at <= end).sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (!next) break;
      this.timers = this.timers.filter((t) => t !== next);
      this.time = Math.max(this.time, next.at);
      next.fn();
    }
    this.time = end;
    await flush();
  }
}

export const flush = async (n = 25) => { for (let i = 0; i < n; i++) await Promise.resolve(); };

/** A client wired to a FakeDb, with a "view" that mimics the dashboard's list. */
export class Harness {
  readonly clock = new FakeClock();
  readonly sockets: FakeSocket[] = [];
  readonly events: FeedEvent<TestAlert>[] = [];
  view: TestAlert[] = [];
  resets = 0;
  reloadOnReset = true;
  failSync = false;
  visible = true;
  visibilityListeners: Array<() => void> = [];
  onlineListeners: Array<() => void> = [];
  readonly client: AlertSyncClient<TestAlert>;

  constructor(readonly db: FakeDb, over: Partial<AlertSyncOptions<TestAlert>> = {}) {
    this.client = new AlertSyncClient<TestAlert>({
      connect: () => { const s = new FakeSocket(this.sockets.length + 1); this.sockets.push(s); return s; },
      fetchSync: async (after, signal) => {
        if (this.failSync) throw new Error("sync unavailable");
        if (signal.aborted) throw new Error("aborted");
        return this.db.sync(after);
      },
      onEvent: (e) => {
        this.events.push(e);
        this.view = upsertAlert(this.view, e.alert, { insert: e.type === "new_alert" });
      },
      onReset: async () => { this.resets++; if (this.reloadOnReset) this.load(); },
      clock: this.clock,
      isVisible: () => this.visible,
      subscribeVisibility: (cb) => { this.visibilityListeners.push(cb); return () => { this.visibilityListeners = this.visibilityListeners.filter((l) => l !== cb); }; },
      subscribeOnline: (cb) => { this.onlineListeners.push(cb); return () => { this.onlineListeners = this.onlineListeners.filter((l) => l !== cb); }; },
      ...over,
    });
  }

  /** What the dashboard does: read the list and its cursor together, show it, hand the cursor over. */
  load(): void {
    this.view = this.db.list();
    this.client.setBaseline(this.db.cursor);
  }
  get socket(): FakeSocket { return this.sockets[this.sockets.length - 1]!; }
  /** The server delivers the change as a live frame. */
  frame(alert: TestAlert, type: "new_alert" | "alert.status_updated" = "new_alert"): void { this.socket.push({ type, alert }); }
  setVisible(v: boolean): void { this.visible = v; this.visibilityListeners.forEach((l) => l()); }
  /** Started, connected, loaded: the normal state. */
  async up(): Promise<void> { this.client.start(); this.socket.open(); this.load(); await flush(); }
  get delivered(): string[] { return this.events.map((e) => `${e.alert.id}@${e.alert.seq}`); }
  /** The list the view shows equals what a fresh reload would show. */
  converged(): boolean { return JSON.stringify(this.view) === JSON.stringify(this.db.list()); }
}

export type { VersionedAlert };
