/**
 * Rate limiting.
 *
 * The default express-rate-limit store counts in process memory. That is
 * correct for one instance and quietly wrong for several: with three replicas
 * behind a load balancer, an attacker gets three times the allowance, because
 * each replica only sees the requests it happened to receive.
 *
 * Postgres made Legion horizontally scalable, so the limiter has to be shared
 * state too. Redis is that shared state — but it is NOT allowed to be a hard
 * dependency:
 *
 *  - Redis unreachable at boot must not stop the API from starting.
 *  - Redis failing at runtime must degrade to per-instance counting, never to
 *    "no limit at all".
 *  - Redis coming back must be picked up without a restart.
 *
 * `ResilientStore` below is what enforces all three.
 */
import { createHmac } from "node:crypto";
import type { Request } from "express";
import { rateLimit, type ClientRateLimitInfo, type Options, type Store } from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { createClient, type RedisClientType } from "redis";
import { config } from "./config.js";
import { BoundedCounter } from "./bounded-counter.js";

/** How long boot is allowed to wait for a first connection. */
const CONNECT_TIMEOUT_MS = 3_000;

let connected = false;

export function redisEnabled(): boolean {
  return Boolean(config.redisUrl);
}

export function redisConnected(): boolean {
  return connected;
}

const client: RedisClientType | null = config.redisUrl
  ? (createClient({
      url: config.redisUrl,
      socket: {
        // Escalating backoff capped at 3s. This returns a NUMBER forever, never
        // an Error, so the client keeps trying to reconnect for the lifetime of
        // the process — which is what we want, as long as nothing awaits it.
        reconnectStrategy: (retries) => Math.min(retries * 100, 3_000),
      },
    }) as RedisClientType)
  : null;

/**
 * Counts in this process, bounded (see bounded-counter.ts). Always written, so
 * the limit holds whatever Redis is doing.
 */
class BoundedMemoryStore implements Store {
  private counter: BoundedCounter | null = null;
  localKeys = true;
  init(options: Options): void { this.counter = new BoundedCounter(options.windowMs, config.rateLimitMaxKeys); }
  private get c(): BoundedCounter { if (!this.counter) throw new Error("store not initialised"); return this.counter; }
  async get(key: string): Promise<ClientRateLimitInfo | undefined> { void key; return undefined; }
  async increment(key: string): Promise<ClientRateLimitInfo> { return this.c.increment(key); }
  async decrement(key: string): Promise<void> { this.c.decrement(key); }
  async resetKey(key: string): Promise<void> { this.c.reset(key); }
}

/** After a Redis failure, leave it alone this long instead of paying its timeout on every request. */
const REDIS_COOLDOWN_MS = 5_000;

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Redis call exceeded ${ms}ms`)), ms);
    timer.unref?.();
  });
  // If the timeout wins, the losing call must not surface as an unhandled rejection.
  work.catch(() => {});
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

/**
 * A Store that shares counts through Redis without depending on it.
 *
 * Every hit is counted in bounded local memory FIRST and the answer is
 * max(local, shared). So:
 *  - Redis healthy: the shared count governs (it is >= any one replica's).
 *  - Redis down, slow, or throwing: the local count governs. A brute-force
 *    attack is throttled per instance rather than not at all.
 *  - Redis slow: each call is capped at `redisTimeoutMs` and then skipped for a
 *    cooldown, so a hanging Redis cannot stall the login endpoint.
 */
export class ResilientStore implements Store {
  private remote: Store | null = null;
  private readonly memory = new BoundedMemoryStore();
  private options: Options | null = null;
  private downUntil = 0;
  localKeys = false;
  readonly prefix: string;

  constructor(prefix: string, private readonly opts: { redisTimeoutMs?: number; cooldownMs?: number } = {}) {
    this.prefix = `legion:rl:${prefix}:`;
    stores.add(this);
  }

  private get timeoutMs(): number { return this.opts.redisTimeoutMs ?? config.rateLimitRedisTimeoutMs; }

  init(options: Options): void {
    this.options = options;
    this.memory.init(options);
    if (connected) this.attach();
  }

  /** Builds the Redis-backed store. Runs on boot if Redis is up, and on every later 'ready'. */
  attach(): void {
    if (!client || !this.options) return;
    const store = new RedisStore({
      prefix: this.prefix,
      sendCommand: (...args: string[]) => client.sendCommand(args),
    }) as unknown as Store;
    store.init?.(this.options);
    this.remote = store;
    this.downUntil = 0;
  }

  /** Tests: plug in any Store as the shared backend. */
  attachRemote(store: Store): void {
    if (this.options) store.init?.(this.options);
    this.remote = store;
    this.downUntil = 0;
  }

  detach(): void { this.remote = null; }

  private async viaRemote<T>(call: (s: Store) => Promise<T> | T): Promise<T | undefined> {
    const remote = this.remote;
    if (!remote || Date.now() < this.downUntil) return undefined;
    const work = Promise.resolve().then(() => call(remote));
    try {
      return await withTimeout(work, this.timeoutMs);
    } catch (error) {
      this.downUntil = Date.now() + (this.opts.cooldownMs ?? REDIS_COOLDOWN_MS);
      console.error("Rate limit: Redis unavailable, counting locally:", (error as Error).message);
      // A reply that was only late (a busy process, not a dead Redis) proves
      // Redis is answering: go back to the shared count at once instead of
      // counting per instance for the whole cooldown. Otherwise a burst of
      // slow requests would quietly multiply every limit by the number of
      // instances (validation 2026-10-01, RED-1).
      work.then(() => { if (this.remote === remote) this.downUntil = 0; }, () => {});
      return undefined;
    }
  }

  async increment(key: string): Promise<ClientRateLimitInfo> {
    const local = await this.memory.increment(key);
    const shared = await this.viaRemote((s) => s.increment(key));
    if (shared && shared.totalHits > local.totalHits) return shared;
    return local;
  }

  async decrement(key: string): Promise<void> {
    await this.memory.decrement(key);
    await this.viaRemote((s) => s.decrement(key));
  }

  async resetKey(key: string): Promise<void> {
    await this.memory.resetKey(key);
    await this.viaRemote((s) => s.resetKey(key));
  }
}

const stores = new Set<ResilientStore>();

client?.on("error", (error: Error) => {
  if (connected) {
    console.error("Redis error — rate limits fall back to per-instance counting:", error.message);
  }
  connected = false;
  for (const store of stores) store.detach();
});

client?.on("ready", () => {
  connected = true;
  console.info("Rate limiting: Redis connected (shared across instances).");
  for (const store of stores) store.attach();
});

/**
 * Opens the connection without blocking boot.
 *
 * The previous version awaited `client.connect()` directly. With a
 * reconnectStrategy that returns a number forever, that promise never settles
 * when Redis is down — so the process hung before ever binding a port. A
 * degraded-mode dependency had silently become a hard one.
 */
export async function initRateLimitStore(): Promise<void> {
  if (!client) {
    if (config.isProduction) {
      console.warn(
        "WARNING: REDIS_URL is not set. Rate limits are counted per instance, " +
        "so running more than one replica multiplies every limit. Set REDIS_URL " +
        "before scaling beyond a single instance."
      );
    }
    return;
  }

  // Attached immediately so a later failure is never an unhandled rejection.
  const attempt = client.connect().then(() => true).catch((error) => {
    console.error("Redis connection failed:", error instanceof Error ? error.message : error);
    return false;
  });

  const timeout = new Promise<false>((resolve) => {
    setTimeout(() => resolve(false), CONNECT_TIMEOUT_MS).unref();
  });

  await Promise.race([attempt, timeout]);

  if (!connected) {
    console.warn(
      `Redis not reachable within ${CONNECT_TIMEOUT_MS}ms — starting anyway with ` +
      "per-instance rate limits. Reconnection continues in the background."
    );
  }
}

export async function closeRateLimitStore(): Promise<void> {
  connected = false;
  if (!client?.isOpen) return;
  // QUIT waits for a reply. With Redis dead or frozen none ever comes, and a
  // shutdown that waits on it never finishes — so give it a second, then cut the socket.
  let timer: NodeJS.Timeout | undefined;
  const gone = await Promise.race([
    client.quit().then(() => true, () => false),
    new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), 1_000); timer.unref?.(); }),
  ]);
  clearTimeout(timer);
  if (!gone && client.isOpen) { try { client.destroy(); } catch { /* already closed */ } }
}

interface LimiterOptions {
  windowMs: number;
  limit: number;
  prefix: string;
  /** Count only failed responses (status >= 400). For credential guessing. */
  failuresOnly?: boolean;
  /** What to count against. Defaults to the client address. */
  key?: (req: Request) => string;
  message?: string;
  store?: Store;
}

/**
 * The suite drives many requests from one address, so limiting is off under
 * NODE_ENV=test — except for the tests OF the limiter, which turn it on.
 */
const bypassed = () => process.env.NODE_ENV === "test" && process.env.LEGION_ENFORCE_RATE_LIMITS !== "1";

export function makeLimiter({ windowMs, limit, prefix, failuresOnly, key, message, store }: LimiterOptions) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    // JSON like every other error, so the dashboard can show it (translated
    // by localizeResponses) instead of a bare "Too Many Requests".
    message: { detail: message ?? "Too many attempts. Wait a minute and try again." },
    // Always a ResilientStore: without Redis it is simply the bounded local
    // counter, so an unbounded MemoryStore is never in play.
    store: store ?? new ResilientStore(prefix),
    skipSuccessfulRequests: Boolean(failuresOnly),
    // "Busy, retry shortly" (503, passwords.ts) is not a failed attempt: it
    // must not count against the account it was trying to sign in to.
    requestWasSuccessful: (_req, res) => res.statusCode < 400 || res.statusCode === 503,
    // Backstop only. A limiter bug must not take the API down with it.
    passOnStoreError: true,
    skip: bypassed,
    // Not `req.ip`-derived unless asked: the caller decides what an "identity" is.
    ...(key ? { keyGenerator: key } : {}),
    // The default key IS req.ip, whose value follows TRUSTED_PROXIES.
    validate: { keyGeneratorIpFallback: false },
  });
}

/** A stable, non-reversible identity for an account, safe to put in Redis. */
export function accountKey(kind: string, id: string): string {
  return `${kind}:${createHmac("sha256", config.jwtSecret).update(id.toLowerCase()).digest("hex").slice(0, 32)}`;
}

/**
 * Auth endpoints: login, registration, password reset, invitations.
 *
 * Keyed by client address. Address limits alone are not enough against
 * a distributed guesser, which is what `loginAccountLimiter` and
 * `mfaAccountLimiter` below are for.
 */
export const authLimiter = makeLimiter({
  windowMs: 60_000,
  limit: config.authRateLimit,
  prefix: "auth",
});

/**
 * Failed logins per ACCOUNT, from any address. Successful logins are not counted.
 *
 * Trade-off, stated plainly: someone who knows an address can spend these
 * failures to make that user wait out the window. That is the price of stopping
 * a botnet from guessing one account's password from a thousand addresses; the
 * window is short and the response is a plain 429 with Retry-After.
 */
export const loginAccountLimiter = makeLimiter({
  windowMs: 15 * 60_000,
  limit: config.loginAccountFailures,
  prefix: "login-acct",
  failuresOnly: true,
  message: "Too many failed sign-in attempts for this account. Try again later.",
  key: (req) => accountKey("login", String((req.body as { username?: unknown } | undefined)?.username ?? "")),
});

/**
 * Failed second-factor attempts per user. A six-digit code has a million
 * values; five tries per window makes guessing one hopeless.
 * `whoIs` maps the request to a user id, or undefined when the token is bad
 * (then the limiter falls back to the address).
 */
export function makeMfaLimiter(whoIs: (req: Request) => string | undefined) {
  return makeLimiter({
    windowMs: 5 * 60_000,
    limit: config.mfaAccountFailures,
    prefix: "mfa-acct",
    failuresOnly: true,
    message: "Too many incorrect codes. Sign in again in a few minutes.",
    key: (req) => {
      const user = whoIs(req);
      return user ? accountKey("mfa", user) : `mfa-ip:${req.ip ?? "unknown"}`;
    },
  });
}

/**
 * Step-up checks by a signed-in user (current password to change it or turn
 * off MFA, a code to turn MFA on). A stolen session must not be a way to
 * guess the password behind it at the general API rate: failures only, per
 * user, across instances.
 */
export function makeStepUpLimiter(whoIs: (req: Request) => string | undefined) {
  return makeLimiter({
    windowMs: 15 * 60_000,
    limit: config.stepUpFailures,
    prefix: "stepup-acct",
    failuresOnly: true,
    message: "Too many incorrect attempts. Wait a few minutes and try again.",
    key: (req) => {
      const user = whoIs(req);
      return user ? accountKey("stepup", user) : `stepup-ip:${req.ip ?? "unknown"}`;
    },
  });
}

/**
 * Emails sent to one address on request (password reset, verification
 * resend). Every request counts, whatever the answer — the answer never says
 * whether the address exists, so neither does the limit.
 */
export const mailPerAddressLimiter = makeLimiter({
  windowMs: 60 * 60_000,
  limit: config.mailPerAddressHourly,
  prefix: "mail-addr",
  message: "Too many emails requested for this address. Try again later.",
  key: (req) => accountKey("mail", String((req.body as { email?: unknown } | undefined)?.email ?? "").trim()),
});

/** Everything else. Generous — a dashboard polling several endpoints must not
 *  trip it — but it caps outright abuse. */
export const apiLimiter = makeLimiter({
  windowMs: 60_000,
  limit: config.apiRateLimit,
  prefix: "api",
});
