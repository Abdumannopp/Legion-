/**
 * Realtime alert delivery.
 *
 * The socket registry is per-process by nature — a WebSocket belongs to the pod
 * that accepted it. That was fine while Legion ran as a single instance, and it
 * silently broke when it stopped: an alert ingested by pod A was only ever
 * pushed to clients connected to pod A. Nothing errored. The dashboard simply
 * missed alerts, which for a security product is the worst possible way to
 * fail.
 *
 * Redis Pub/Sub carries the event to every pod, and each pod delivers to the
 * sockets it owns.
 *
 * Delivery is at-most-once and deliberately so: Pub/Sub is a live signal, not
 * the source of truth. A client that misses a message while reconnecting
 * recovers by re-reading from Postgres — which is why losing a realtime frame
 * must never mean losing an alert.
 *
 * What makes that recovery happen without anyone noticing a problem:
 *   - every alert frame carries the alert's `seq` (its version, see
 *     alerts_assign_seq in schema.sql), so a client can tell "duplicate",
 *     "out of order" and "I skipped one";
 *   - `hello` on connect and a periodic `ping` carry the tenant's current
 *     cursor, READ FROM POSTGRES. A client behind it fetches /alerts/sync. The
 *     ping does not depend on Redis, so any frame lost for any reason — Redis
 *     down, a restart, a dropped socket — is repaired within one interval;
 *   - `resync` is sent when this instance's Redis subscription comes back,
 *     because frames published during the outage are gone for good.
 */
import { createClient, type RedisClientType } from "redis";
import { WebSocket } from "ws";
import { config } from "./config.js";

const CHANNEL = "legion:realtime";

/** tenant_id -> sockets held by THIS process. */
const local = new Map<string, Set<WebSocket>>();

let publisher: RedisClientType | null = null;
let subscriber: RedisClientType | null = null;
let ready = false;
/** True once the subscription has connected at least once, so a later "ready"
 *  means it came back from an outage. */
let everReady = false;

interface Envelope {
  tenant_id: string;
  payload: unknown;
}

export function realtimeConnected(): boolean {
  return ready;
}

export function localConnectionCount(): number {
  let total = 0;
  for (const set of local.values()) total += set.size;
  return total;
}

function makeClient(): RedisClientType {
  return createClient({
    url: config.redisUrl,
    socket: { reconnectStrategy: (retries) => Math.min(retries * 100, 3_000) },
  }) as RedisClientType;
}

/**
 * Connects the pub/sub pair. Bounded, like the rate-limit store: realtime is a
 * live convenience, and losing it must not stop the API from starting.
 */
export async function initRealtime(): Promise<void> {
  if (!config.redisUrl) {
    if (config.isProduction) {
      console.warn(
        "WARNING: REDIS_URL is not set. Realtime alerts reach only the clients " +
        "connected to this instance, so a second replica would silently miss them."
      );
    }
    return;
  }

  publisher = makeClient();
  // A connection in subscriber mode cannot run ordinary commands, so the
  // publisher and subscriber must be separate connections.
  subscriber = makeClient();

  for (const [name, redis] of [["publisher", publisher], ["subscriber", subscriber]] as const) {
    redis.on("error", (error: Error) => {
      if (ready) console.error(`Realtime ${name} error:`, error.message);
      ready = false;
    });
  }

  subscriber.on("ready", () => {
    ready = true;
    console.info("Realtime: Redis Pub/Sub connected (alerts fan out across instances).");
    // Frames published while the subscription was down were never delivered to
    // this instance's sockets. Tell them to ask Postgres what they missed.
    if (everReady) notifyResync();
    everReady = true;
  });

  const connect = Promise.all([publisher.connect(), subscriber.connect()])
    .then(async () => {
      await subscriber!.subscribe(CHANNEL, (message: string) => {
        try {
          const envelope = JSON.parse(message) as Envelope;
          if (envelope?.tenant_id) deliver(envelope.tenant_id, JSON.stringify(envelope.payload));
        } catch {
          // A malformed frame must not take down the subscriber.
        }
      });
      return true;
    })
    .catch((error) => {
      console.error("Realtime connection failed:", error instanceof Error ? error.message : error);
      return false;
    });

  const timeout = new Promise<false>((resolve) => {
    setTimeout(() => resolve(false), 3_000).unref();
  });
  await Promise.race([connect, timeout]);

  if (!ready) {
    console.warn(
      "Realtime: Redis not reachable — this instance will deliver only to its own " +
      "clients until it reconnects."
    );
  }
}

/**
 * quit() waits for the server to acknowledge, so with Redis down it never
 * returns — and a shutdown during a Redis outage would sit there until the
 * hard kill. Give it a moment, then tear the connection down regardless.
 */
async function closeClient(client: RedisClientType | null): Promise<void> {
  if (!client?.isOpen) return;
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      client.quit(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("quit timed out")), 1_500); }),
    ]);
  } catch {
    // Not answering: drop the connection (and any reconnect attempts) outright.
    try { client.destroy(); } catch { /* already closed */ }
  } finally {
    clearTimeout(timer);
  }
}

export async function closeRealtime(): Promise<void> {
  ready = false;
  everReady = false;
  await Promise.allSettled([closeClient(subscriber), closeClient(publisher)]);
  publisher = null;
  subscriber = null;
}

/**
 * Who a socket was authorized for, and on what terms. A socket is checked once
 * at the handshake; this is what lets it be checked again afterwards, so a
 * deactivated, demoted or signed-out-everywhere user — or a tenant whose access
 * was blocked — stops receiving that tenant's events (see revalidateOnce).
 */
export interface SocketGrant {
  userId: string;
  tokenVersion: number;
  /** When the access token that opened the socket expires (ms). The socket may
   *  not outlive it: HTTP stops accepting that token then, so must this. */
  expiresAt?: number;
  /** SHA-256 of that access token, so a logout can close exactly its sockets. */
  tokenHash?: string;
}
const grants = new WeakMap<WebSocket, SocketGrant>();
const expiryTimers = new WeakMap<WebSocket, NodeJS.Timeout>();
const grantKey = (tenantId: string, g: SocketGrant) => `${tenantId}\u0000${g.userId}\u0000${g.tokenVersion}`;

/** 4401: the session behind this socket is no longer valid. The client reconnects, is refused, and signs in again. */
export const CLOSE_SESSION_REVOKED = 4401;

export function register(tenantId: string, socket: WebSocket, grant?: SocketGrant): void {
  if (!local.has(tenantId)) local.set(tenantId, new Set());
  local.get(tenantId)!.add(socket);
  alive.set(socket, true);
  socket.on?.("pong", () => alive.set(socket, true));
  if (grant) {
    grants.set(socket, grant);
    if (grant.expiresAt !== undefined) {
      const timer = setTimeout(() => revoke(tenantId, socket), Math.max(0, grant.expiresAt - Date.now()));
      timer.unref?.();
      expiryTimers.set(socket, timer);
    }
  }
}

function revoke(tenantId: string, socket: WebSocket): void {
  unregister(tenantId, socket);
  const timer = expiryTimers.get(socket);
  if (timer) clearTimeout(timer);
  try { socket.close(CLOSE_SESSION_REVOKED, "session no longer valid"); } catch { /* already closing */ }
}

/** Closes this process's sockets opened with one particular access token (logout). */
export function closeTokenSockets(tokenHash: string): number {
  let closed = 0;
  for (const [tenantId, set] of local) {
    for (const socket of [...set]) {
      if (grants.get(socket)?.tokenHash === tokenHash) { revoke(tenantId, socket); closed++; }
    }
  }
  return closed;
}

/** Closes this process's sockets for one user at once (deactivation, role change, password reset). */
export function closeUserSockets(userId: string, onlyTenantId?: string): number {
  let closed = 0;
  for (const [tenantId, set] of local) {
    if (onlyTenantId && tenantId !== onlyTenantId) continue;
    for (const socket of [...set]) {
      if (grants.get(socket)?.userId === userId) { revoke(tenantId, socket); closed++; }
    }
  }
  return closed;
}

export interface GrantCheck extends SocketGrant { tenantId: string }

/**
 * Re-authorizes every socket this process holds against the source of truth.
 * `stillValid` answers, for a batch, which grants still hold (by grantKey). A
 * socket with no grant, or whose grant no longer holds, is closed. If the check
 * itself fails (a database blip) nothing is closed: availability over a
 * best-effort check, and the next round tries again.
 */
export async function revalidateOnce(stillValid: (checks: GrantCheck[]) => Promise<Set<string>>): Promise<number> {
  const checks: GrantCheck[] = [];
  for (const [tenantId, set] of local) {
    for (const socket of set) {
      const g = grants.get(socket);
      if (g) checks.push({ tenantId, ...g });
    }
  }
  let valid: Set<string>;
  try {
    valid = checks.length ? await stillValid(checks) : new Set();
  } catch {
    return 0;
  }
  let closed = 0;
  const now = Date.now();
  for (const [tenantId, set] of [...local]) {
    for (const socket of [...set]) {
      const g = grants.get(socket);
      const expired = g?.expiresAt !== undefined && g.expiresAt <= now;
      if (!g || expired || !valid.has(grantKey(tenantId, g))) { revoke(tenantId, socket); closed++; }
    }
  }
  return closed;
}
export { grantKey };

let revalidateTimer: NodeJS.Timeout | null = null;
export function startRevalidation(stillValid: (checks: GrantCheck[]) => Promise<Set<string>>, intervalMs: number): void {
  stopRevalidation();
  revalidateTimer = setInterval(() => void revalidateOnce(stillValid), intervalMs);
  revalidateTimer.unref();
}
export function stopRevalidation(): void {
  if (revalidateTimer) clearInterval(revalidateTimer);
  revalidateTimer = null;
}

export function unregister(tenantId: string, socket: WebSocket): void {
  const set = local.get(tenantId);
  if (!set) return;
  set.delete(socket);
  if (set.size === 0) local.delete(tenantId);
}

/** Asks every socket this process owns to reconcile with Postgres now. */
export function notifyResync(): void {
  const frame = JSON.stringify({ type: "resync" });
  for (const tenantId of local.keys()) deliver(tenantId, frame);
}

/**
 * One heartbeat: each tenant with a socket here is sent its current cursor. The
 * cursor comes from `fetchCursors` (Postgres), never from anything a pub/sub
 * message said, so this repairs whatever pub/sub lost.
 */
export async function heartbeatOnce(fetchCursors: (tenantIds: string[]) => Promise<Map<string, number>>): Promise<void> {
  const tenants = [...local.keys()];
  if (tenants.length === 0) return;
  let cursors: Map<string, number>;
  try {
    cursors = await fetchCursors(tenants);
  } catch {
    return; // a database blip: the next beat tries again
  }
  for (const tenantId of tenants) {
    const cursor = cursors.get(tenantId);
    if (cursor !== undefined) deliver(tenantId, JSON.stringify({ type: "ping", cursor }));
  }
}

let heartbeatTimer: NodeJS.Timeout | null = null;
export function startHeartbeat(fetchCursors: (tenantIds: string[]) => Promise<Map<string, number>>, intervalMs: number): void {
  stopHeartbeat();
  heartbeatTimer = setInterval(() => void heartbeatOnce(fetchCursors), intervalMs);
  heartbeatTimer.unref();
}
export function stopHeartbeat(): void {
  if (heartbeatTimer) clearInterval(heartbeatTimer);
  heartbeatTimer = null;
}

/**
 * Most bytes a socket may have queued and unsent. A client that stops reading
 * (a frozen tab, a deliberately slow reader) would otherwise make this process
 * buffer every frame for it, without limit. Past this it is disconnected; it
 * reconnects and catches up from Postgres (/alerts/sync), so nothing is lost.
 */
export const MAX_BUFFERED_BYTES = 1024 * 1024;

/** Sends to the sockets this process owns. */
function deliver(tenantId: string, message: string): void {
  for (const socket of local.get(tenantId) || []) {
    if (socket.readyState !== WebSocket.OPEN) continue;
    if (socket.bufferedAmount + Buffer.byteLength(message) > MAX_BUFFERED_BYTES) {
      unregister(tenantId, socket);
      try { socket.terminate(); } catch { /* already gone */ }
      continue;
    }
    socket.send(message);
  }
}

// --- connection limits and liveness ----------------------------------------------------

/** Open sockets this process holds for one user, and for one tenant. */
export function connectionCounts(tenantId: string, userId: string): { user: number; tenant: number } {
  const set = local.get(tenantId);
  if (!set) return { user: 0, tenant: 0 };
  let user = 0;
  for (const socket of set) if (grants.get(socket)?.userId === userId) user++;
  return { user, tenant: set.size };
}

const alive = new WeakMap<WebSocket, boolean>();

/**
 * One liveness round: a socket that did not answer the previous ping is
 * terminated; every other one is pinged. Without this, a connection whose
 * client vanished (laptop lid closed, network gone) stays registered —
 * holding memory and a slot of its user's connection cap — until a send
 * happens to fail.
 */
export function livenessOnce(): number {
  let terminated = 0;
  for (const [tenantId, set] of [...local]) {
    for (const socket of [...set]) {
      if (alive.get(socket) === false) {
        unregister(tenantId, socket);
        try { socket.terminate(); } catch { /* already gone */ }
        terminated++;
        continue;
      }
      alive.set(socket, false);
      try { socket.ping(); } catch { /* the next round terminates it */ }
    }
  }
  return terminated;
}

let livenessTimer: NodeJS.Timeout | null = null;
export function startLiveness(intervalMs: number): void {
  stopLiveness();
  livenessTimer = setInterval(() => void livenessOnce(), intervalMs);
  livenessTimer.unref();
}
export function stopLiveness(): void {
  if (livenessTimer) clearInterval(livenessTimer);
  livenessTimer = null;
}

/**
 * Publishes an event to every instance.
 *
 * With Redis, this pod does NOT deliver locally here — it publishes, and its
 * own subscriber delivers along with every other pod's. One code path for all
 * instances means a bug cannot show up only in the multi-pod case, which is
 * exactly the class of bug this module exists to fix.
 */
export async function publish(tenantId: string, payload: unknown): Promise<void> {
  if (publisher && ready) {
    try {
      await publisher.publish(CHANNEL, JSON.stringify({ tenant_id: tenantId, payload }));
      return;
    } catch (error) {
      console.error("Realtime publish failed, delivering locally only:", (error as Error).message);
    }
  }
  // No Redis, or publish failed: at least reach this instance's clients.
  deliver(tenantId, JSON.stringify(payload));
}

/**
 * Publish for the outbox worker: same fan-out as publish(), but a Redis
 * failure is reported instead of swallowed, so the job is retried and other
 * instances still get the frame once Redis is back.
 *
 * On failure this instance's own clients are served immediately anyway; the
 * retry may then reach them a second time, which the dashboard ignores (it
 * de-duplicates frames by alert id). Without REDIS_URL there is no other
 * instance to reach, so local delivery is complete delivery.
 */
export async function publishOrThrow(tenantId: string, payload: unknown): Promise<void> {
  if (!config.redisUrl) {
    deliver(tenantId, JSON.stringify(payload));
    return;
  }
  if (!publisher || !ready) {
    deliver(tenantId, JSON.stringify(payload));
    throw new Error("Redis is not connected");
  }
  try {
    await publisher.publish(CHANNEL, JSON.stringify({ tenant_id: tenantId, payload }));
  } catch (error) {
    deliver(tenantId, JSON.stringify(payload));
    // The message only: a Redis client error can carry the connection URL.
    throw new Error(`Redis publish failed: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}
