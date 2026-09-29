import { parseKeyring } from "./keyring-parse.js";
import { parseOrigins, parseTrustedProxies } from "./edge-parse.js";
import "dotenv/config";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

/**
 * The version customers see in /health and in support tickets.
 *
 * Read from package.json rather than written here: a hardcoded string drifted
 * to 2.0.0 while every package.json said 1.0.0, which would have made every
 * bug report ambiguous about which build was actually running.
 *
 * `..` resolves to server/ both from src/ under tsx and from dist/ after a
 * build, so one candidate covers both; the second is a cheap safety net for an
 * unusual layout.
 */
function readVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const candidate of [
    join(here, "..", "package.json"),
    join(here, "..", "..", "package.json"),
  ]) {
    try {
      const parsed = JSON.parse(readFileSync(candidate, "utf8")) as { version?: string };
      if (parsed.version) return parsed.version;
    } catch {
      // Try the next candidate; an unknown version must never stop a boot.
    }
  }
  return "unknown";
}

const paddleEnvironment =
  process.env.PADDLE_ENVIRONMENT === "production" ? "production" : "sandbox";

const isProduction = process.env.NODE_ENV === "production";
const deploymentMode = (process.env.DEPLOYMENT_MODE || "self-hosted") as
  | "self-hosted"
  | "saas";

export const config = {
  isProduction,
  version: readVersion(),
  port: Number(process.env.PORT || 8000),
  /**
   * Which network interface the API listens on. Defaults to loopback-only:
   * with no reverse proxy or container runtime standing between this process
   * and the network, `0.0.0.0` would put a bare `npm start` install straight
   * on every interface the machine has, including a public one. Set this to
   * `0.0.0.0` only on a trusted internal network without its own firewall.
   */
  bindAddress: process.env.LEGION_BIND_ADDRESS || "127.0.0.1",
  frontendUrl: process.env.FRONTEND_URL || "http://localhost:3000",
  jwtSecret: process.env.JWT_SECRET || "local-development-secret-change-me-please",
  /** Earlier JWT_SECRET values, comma-separated, accepted for VERIFICATION only
   *  while their tokens run out — rotation without signing everyone out. */
  jwtPreviousSecrets: (process.env.JWT_PREVIOUS_SECRETS || "").split(",").map((s) => s.trim()).filter(Boolean),
  cookieSecure: process.env.COOKIE_SECURE === "true",
  /**
   * How this installation is run.
   *
   * "self-hosted" — the customer runs Legion on their own server. There is no
   *   subscription to check, billing is off, and registration closes once the
   *   first administrator exists.
   * "saas"        — we run it for many tenants: trials, subscription gating and
   *   Paddle are all live, and anyone may sign up.
   *
   * Self-hosted is the default because it is the shipped product; SaaS is the
   * deliberate opt-in.
   */
  deploymentMode,

  // --- Postgres ---
  databaseUrl:
    process.env.DATABASE_URL ||
    "postgresql://legion:legion@localhost:5432/legion",
  dbPoolMax: Number(process.env.DB_POOL_MAX || 10),
  dbSsl: process.env.DB_SSL === "true",
  /** PEM contents, or a path to a CA bundle, for providers whose certificate
   *  Node cannot chain to a public root. */
  dbSslCa: process.env.DB_SSL_CA || "",
  /** Escape hatch that disables certificate verification. Refused in
   *  production — an unverified TLS connection to the database is a
   *  man-in-the-middle away from every tenant's data. */
  dbSslInsecure: process.env.DB_SSL_INSECURE === "true",
  /** Escape hatch for the boot check that refuses a superuser (or similarly
   *  privileged) database role in production. See db/provision.ts. */
  dbAllowPrivilegedRole: process.env.DB_ALLOW_PRIVILEGED_ROLE === "true",

  // --- Redis (rate limiting across instances) ---
  // Optional for a single instance; required before scaling past one.
  redisUrl: process.env.REDIS_URL || "",
  authRateLimit: Number(process.env.AUTH_RATE_LIMIT || 10),
  apiRateLimit: Number(process.env.API_RATE_LIMIT || 300),

  // --- MFA ---
  // Shown as the account name in the user's authenticator app.
  mfaIssuer: process.env.MFA_ISSUER || "Legion",

  // --- Sessions ---
  // Access tokens are stateless and cannot be revoked, so they are kept short;
  // the refresh token below is the revocable half.
  accessTokenMinutes: Number(process.env.ACCESS_TOKEN_MINUTES || 15),
  refreshTokenDays: Number(process.env.REFRESH_TOKEN_DAYS || 30),
  /** Hard ceiling on one login's life, however actively it is used (1–365 days). */
  sessionAbsoluteDays: Math.min(365, Math.max(1, Math.floor(Number(process.env.SESSION_ABSOLUTE_DAYS || 30)) || 30)),
  /**
   * OFF by default (0). When set (1–60 s), a just-rotated refresh token that the
   * same browser presents again within this window is accepted once instead of
   * revoking the session. That tolerates tabs racing on clients without the
   * dashboard's cross-tab lock — but a thief who replays within the window with
   * a copied user agent is then not detected. The dashboard serialises refresh
   * across tabs itself (frontend/lib/api.ts), so the default keeps strict
   * reuse detection.
   */
  refreshReuseGraceSeconds: Math.min(60, Math.max(0, Math.floor(Number(process.env.REFRESH_REUSE_GRACE_SECONDS ?? 0)) || 0)),
  /** Legacy JSON store, read only by the one-shot import script. */
  dataFile: process.env.DATA_FILE || "./data/legion.json",
  /**
   * DEPRECATED — no longer authenticates anything. Webhook credentials are
   * per tenant and random (webhook-credentials.ts). Kept only as the key that
   * derives alert ids from sensor event ids, so an event re-sent after an
   * upgrade is still recognised as a duplicate. Safe to leave unset on a new
   * install.
   */
  webhookSecret: process.env.SECURITY_EVENT_WEBHOOK_SECRET || "",

  // --- Sensor webhook authentication ---
  /** Requests whose timestamp is further than this from the server's clock
   *  are refused. Clamped to 30–900 s: shorter breaks on ordinary clock
   *  drift, longer only enlarges the replay-nonce table. */
  webhookMaxSkewSeconds: Math.min(900, Math.max(30, Math.floor(Number(process.env.WEBHOOK_MAX_SKEW_SECONDS || 300)) || 300)),
  /** How long the old credential keeps working after a rotation, unless the
   *  administrator asks for something else (0–168 h). */
  webhookRotationOverlapHours: Math.min(168, Math.max(0, Number(process.env.WEBHOOK_ROTATION_OVERLAP_HOURS ?? 24) || 0)),
  /** Largest sensor event accepted, in bytes (64 KB–4 MB). The body is held as
   *  raw bytes and only parsed AFTER its signature checks out. */
  webhookMaxBodyBytes: Math.min(4 * 1024 * 1024, Math.max(64 * 1024, Math.floor(Number(process.env.WEBHOOK_MAX_BODY_BYTES || 1024 * 1024)) || 1024 * 1024)),
  /** Failed webhook authentications one client address may make per minute
   *  before it is refused without any database work. Successful (signed)
   *  deliveries are never counted, so a busy sensor is never throttled. */
  webhookFailedAuthPerMinute: Math.max(5, Math.floor(Number(process.env.WEBHOOK_FAILED_AUTH_PER_MINUTE || 60)) || 60),
  /**
   * Encrypts webhook secrets at rest (AES-256-GCM via HKDF). Keep it out of
   * the database and its backups. When unset it falls back to a key derived
   * from JWT_SECRET — which works, but ties the two together: changing
   * JWT_SECRET would then make every stored webhook secret unreadable.
   */
  webhookEncryptionKey: process.env.WEBHOOK_ENCRYPTION_KEY || "",

  // --- AI (optional, off unless a key is supplied) -----------------------------
  // Two providers are supported and neither is required. With no key at all,
  // Oracle and Copilot fall back to deterministic local analysis and nothing
  // about an alert ever leaves the customer's server.
  //
  // Which one is used is resolved by resolveProvider() in ai.ts, not here, so
  // the rule can be exercised by tests without a live key.
  /** Forces a provider: "openrouter" | "groq". Empty means "whichever key is set". */
  aiProvider: process.env.AI_PROVIDER || "",
  openrouterApiKey: process.env.OPENROUTER_API_KEY || "",
  /**
   * Deliberately has no default. OpenRouter's catalogue changes, and shipping a
   * hardcoded model id means every install breaks on the day that id retires.
   * Left empty, the request omits the field and OpenRouter uses the account's
   * own default model — which the customer sets where they can see the prices.
   */
  openrouterModel: process.env.OPENROUTER_MODEL || "",
  groqApiKey: process.env.GROQ_API_KEY || "",
  groqModel: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",

  // --- Realtime alert sync (store.syncAlerts, realtime.ts) ---
  /** A client further behind than this many changes is told to reload the list
   *  instead of paging through all of them. */
  alertSyncMaxCatchup: Math.max(50, Math.floor(Number(process.env.ALERT_SYNC_MAX_CATCHUP || 1_000)) || 1_000),
  /** How often each connected socket is sent the tenant's current cursor, read
   *  from Postgres. A client that has fallen behind (a dropped frame, a Redis
   *  outage) notices within one interval and catches up. 5–120 s. */
  /** Concurrent live-alert sockets one user / one tenant may hold per instance. */
  wsMaxPerUser: Math.max(1, Math.floor(Number(process.env.WS_MAX_PER_USER || 20)) || 20),
  wsMaxPerTenant: Math.max(1, Math.floor(Number(process.env.WS_MAX_PER_TENANT || 1000)) || 1000),
  wsHeartbeatSeconds: Math.min(120, Math.max(5, Math.floor(Number(process.env.WS_HEARTBEAT_SECONDS || 20)) || 20)),

  // --- AI safety limits (ai.ts) ---
  /** Give up on the provider after this long and use the deterministic
   *  fallback. Covers connecting AND reading the answer. 2–60 s. */
  aiTimeoutMs: Math.min(60_000, Math.max(2_000, Math.floor(Number(process.env.AI_TIMEOUT_MS || 15_000)) || 15_000)),
  /** Most characters of prompt that may leave the server in one request.
   *  Builders trim to fit; a request that still does not fit is not sent. */
  aiMaxInputChars: Math.min(100_000, Math.max(2_000, Math.floor(Number(process.env.AI_MAX_INPUT_CHARS || 24_000)) || 24_000)),
  /** Longest AI answer that is stored or shown; the rest is cut. */
  aiMaxOutputChars: Math.min(20_000, Math.max(500, Math.floor(Number(process.env.AI_MAX_OUTPUT_CHARS || 6_000)) || 6_000)),
  /** After this many consecutive provider failures, stop calling it for the
   *  cool-down and answer from the local fallback at once. */
  aiBreakerThreshold: Math.max(1, Math.floor(Number(process.env.AI_BREAKER_THRESHOLD || 5)) || 5),
  aiBreakerCooldownSeconds: Math.max(5, Math.floor(Number(process.env.AI_BREAKER_COOLDOWN_SECONDS || 60)) || 60),
  /** Provider calls one organisation may trigger per minute (per instance). */
  aiRateLimitPerMinute: Math.max(1, Math.floor(Number(process.env.AI_RATE_LIMIT_PER_MINUTE || 30)) || 30),
  /**
   * Whether an organisation that has never chosen gets AI. "on" / "off";
   * empty = by deployment: a self-hosted operator who configured a provider
   * decided for their own data (on), a hosted tenant's data would leave the
   * platform for a third party without anyone there having agreed (off until
   * an administrator turns it on).
   */
  aiTenantDefault: (process.env.AI_TENANT_DEFAULT || "").trim().toLowerCase(),

  /** Days of full access a brand-new tenant gets before it has to subscribe. */
  trialDays: Number(process.env.TRIAL_DAYS || 14),
  /** How long an emailed team invite stays valid. */
  inviteDays: Number(process.env.INVITE_DAYS || 7),
  /**
   * The demo workspace ships with a published password (admin@legion.demo /
   * legion123), so it must never appear on a real installation.
   *
   * Keying this on NODE_ENV alone was not enough: a self-hosted customer runs
   * with NODE_ENV unset, so a fresh install seeded the demo account, which
   * then closed first-run registration before they could create their own
   * administrator — and left a well-known login on their server.
   */
  // Opt-in in every mode, never in production. Hosted mode used to default to
  // ON outside NODE_ENV=production, which put the published demo login on any
  // hosted server started without NODE_ENV set. index/seed also refuse to seed
  // unless the API listens on loopback only (see demoSeedAllowed).
  seedDemoData: process.env.SEED_DEMO_DATA === "true" && !isProduction,

  // --- Paddle Billing ---
  paddleApiKey: process.env.PADDLE_API_KEY || "",
  paddleWebhookSecret: process.env.PADDLE_WEBHOOK_SECRET || "",
  paddleEnvironment,
  // Overridable so the billing paths can be exercised against a stub.
  paddleApiBase:
    process.env.PADDLE_API_BASE ||
    (paddleEnvironment === "production"
      ? "https://api.paddle.com"
      : "https://sandbox-api.paddle.com"),

  // --- SMTP / email ---
  smtpHost: process.env.SMTP_HOST || "",
  smtpPort: Number(process.env.SMTP_PORT || 587),
  smtpUser: process.env.SMTP_USER || "",
  smtpPassword: process.env.SMTP_PASSWORD || "",
  smtpSecure: process.env.SMTP_SECURE === "true",
  smtpFrom: process.env.SMTP_FROM || "Legion <no-reply@legion.local>",
  // Alerts at or above this severity trigger an email. "off" disables them.
  alertEmailMinSeverity: (process.env.ALERT_EMAIL_MIN_SEVERITY || "high") as
    | "critical"
    | "high"
    | "medium"
    | "low"
    | "off",

  // --- Notification delivery (outbox) ---
  // A failed alert email is retried with exponential backoff: base, 2×base,
  // 4×base … capped at 1 hour, up to this many attempts, then marked 'dead'
  // (visible to admins at GET /notifications/deliveries).
  notifyMaxAttempts: Math.max(1, Number(process.env.NOTIFY_MAX_ATTEMPTS || 8)),
  notifyRetryBaseSeconds: Math.max(1, Number(process.env.NOTIFY_RETRY_BASE_SECONDS || 30)),
  /** How often the background worker looks for due notifications. */
  notifyPollSeconds: Math.max(1, Number(process.env.NOTIFY_POLL_SECONDS || 15)),
  // The realtime "new alert" frame goes through the same outbox, so a Redis
  // outage delays it instead of dropping it. A dashboard frame is only worth
  // retrying for a few minutes (the page re-reads from Postgres anyway), so
  // it gets its own, shorter schedule: 5, 10, 20, 40, 80 s, then 'dead'.
  realtimeMaxAttempts: Math.max(1, Number(process.env.REALTIME_MAX_ATTEMPTS || 6)),
  realtimeRetryBaseSeconds: Math.max(1, Number(process.env.REALTIME_RETRY_BASE_SECONDS || 5)),
  /**
   * Bearer token for GET /health/outbox (queue depth across all tenants, for
   * monitoring). Unset means the endpoint does not exist: the numbers reveal
   * platform-wide alert volume, so they are not public.
   */
  healthMetricsToken: process.env.HEALTH_METRICS_TOKEN || "",
  // Abuse caps on email this platform sends on a tenant's behalf (per tenant, per hour).
  alertEmailHourlyCap: Math.max(1, Math.floor(Number(process.env.ALERT_EMAIL_HOURLY_CAP || 100)) || 100),
  notificationTestHourlyCap: 5,
  notificationConfirmHourlyCap: 5,
  inviteHourlyCap: Math.max(1, Math.floor(Number(process.env.INVITE_HOURLY_CAP || 50)) || 50),
  // Where ops/backup.sh records its outcome (see backup-health.ts). Empty = the
  // API does not report on backups; monitoring then relies on ops/check-backup.sh.
  backupStatusFile: process.env.BACKUP_STATUS_FILE || "",
  backupMaxAgeHours: Math.max(1, Number(process.env.BACKUP_MAX_AGE_HOURS || 30) || 30),
  restoreTestMaxAgeDays: Math.max(1, Number(process.env.RESTORE_TEST_MAX_AGE_DAYS || 8) || 8),
  backupRequireOffsite: process.env.BACKUP_REQUIRE_OFFSITE === "true",

  // --- Encryption at rest (secret-box.ts) ---
  /**
   * The keyring that encrypts secrets Legion must read back (TOTP seeds,
   * webhook signing secrets): "id:key,id:key", 32 random bytes each. Used for
   * nothing else, and kept out of the database and its backups. The first entry
   * (or LEGION_ENCRYPTION_KEY_ID) encrypts; every entry can decrypt.
   */
  encryptionKeys: process.env.LEGION_ENCRYPTION_KEYS || "",
  encryptionKeyActive: process.env.LEGION_ENCRYPTION_KEY_ID || "",
  // --- Network edge (edge.ts) ---
  /** Which proxies may speak for a client's address (X-Forwarded-For). Default: loopback only. */
  trustedProxies: process.env.TRUSTED_PROXIES ?? "",
  /** Web origins allowed to call the API with credentials, besides FRONTEND_URL's. Exact origins only. */
  corsOrigins: process.env.CORS_ORIGINS || "",
  /** Accept a WebSocket upgrade that carries no Origin header. Browsers always send one,
   *  so only non-browser tooling needs this. Off by default. */
  wsAllowMissingOrigin: process.env.WS_ALLOW_MISSING_ORIGIN === "true",
  /** HSTS lifetime in seconds (HTTPS production only). */
  hstsMaxAgeSeconds: Math.max(0, Math.floor(Number(process.env.HSTS_MAX_AGE_SECONDS ?? 31_536_000)) || 0),
  /** Add the "preload" directive. A commitment that is hard to undo: leave off until you mean it. */
  hstsPreload: process.env.HSTS_PRELOAD === "true",
  /** Bounded in-memory rate-limit table: the most distinct clients tracked at once per limiter. */
  rateLimitMaxKeys: Math.max(1_000, Math.floor(Number(process.env.RATE_LIMIT_MAX_KEYS || 50_000)) || 50_000),
  /** A Redis call slower than this is abandoned and counted locally instead. */
  rateLimitRedisTimeoutMs: Math.max(50, Math.floor(Number(process.env.RATE_LIMIT_REDIS_TIMEOUT_MS || 250)) || 250),
  /** Failed logins for one account (any address) before it is slowed down, per 15 minutes. */
  loginAccountFailures: Math.max(3, Math.floor(Number(process.env.LOGIN_ACCOUNT_FAILURES || 20)) || 20),
  /** Wrong current-password / code answers by one signed-in user, per 15 minutes. */
  stepUpFailures: Math.max(3, Math.floor(Number(process.env.STEP_UP_FAILURES || 10)) || 10),
  /** Reset / verification emails one address can be sent per hour. */
  mailPerAddressHourly: Math.max(1, Math.floor(Number(process.env.MAIL_PER_ADDRESS_HOURLY || 5)) || 5),
  /** Wrong second-factor codes for one account before it is slowed down, per 5 minutes. */
  mfaAccountFailures: Math.max(3, Math.floor(Number(process.env.MFA_ACCOUNT_FAILURES || 5)) || 5),
  /**
   * The Path of the refresh cookie. It must be the path the API is REACHED at: "/auth"
   * when the API has its own host or port, "/api/auth" behind the bundled nginx
   * (which serves it under /api). `npm run setup --domain` writes this.
   */
  refreshCookiePath: process.env.REFRESH_COOKIE_PATH || "/auth",

  /**
   * Development only: print password-reset and invitation links to the server
   * log when there is no SMTP to send them. Off by default — a log line holding
   * a live reset link is an account takeover for anyone who can read the logs.
   * Ignored in production.
   */
  devLogAuthLinks: !isProduction && process.env.DEV_LOG_AUTH_LINKS === "true",
};

/**
 * The signing key must never be the shipped placeholder.
 *
 * This is checked outside the production block on purpose. A self-hosted
 * customer runs `npm start` with NODE_ENV unset — that is production to
 * *them*, and the placeholder is published in this repository. Anyone could
 * forge a session token for every installation still using it.
 *
 * The escape hatch is an explicit NODE_ENV of development or test, which is
 * what `npm run dev` and the suite set.
 */
export const BUILTIN_DEV_JWT_SECRET = "local-development-secret-change-me-please";

/**
 * Is this signing secret one that someone other than the operator could know?
 * Covers: unset, too short, the built-in development default, the value shipped
 * in server/.env.example (which used to pass: 33 characters, no "local-"
 * prefix), and anything that reads like a template ("replace-with…",
 * "change-me", "your-secret"…) or is too repetitive to be random.
 */
const TEMPLATE_SECRET = /replace[-_ ]?(?:with|me)|change[-_ ]?me|changeme|your[-_ ]?(?:jwt[-_ ]?)?secret|placeholder|example|long[-_ ]?random[-_ ]?string|^secret$/i;

export function isWeakJwtSecret(secret: string): boolean {
  const s = secret.trim();
  if (s.length < 32) return true;
  if (s.startsWith("local-")) return true;
  if (TEMPLATE_SECRET.test(s)) return true;
  // 32 random hex characters contain ~15 distinct symbols; a typed phrase or a
  // repeated character does not.
  if (new Set(s).size < 10) return true;
  return false;
}

const usingPlaceholderSecret = isWeakJwtSecret(config.jwtSecret);
export const loopbackBind = ["127.0.0.1", "::1", "localhost"].includes(config.bindAddress);
const explicitDevOrTest =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";

// A malformed keyring is wrong in every mode: it would either fail every MFA
// login or, worse, be "fixed" by someone generating a new key and orphaning
// every stored secret.
if (config.encryptionKeys.trim()) {
  const ring = parseKeyring(config.encryptionKeys, config.encryptionKeyActive);
  if (!ring.ok) throw new Error(`Refusing to start: ${ring.error}`);
}
// Same reasoning as the JWT placeholder below: a self-hosted server run with
// NODE_ENV unset is production to its owner. Without a dedicated key, TOTP seeds
// and webhook secrets would be encrypted under a key derived from JWT_SECRET —
// one leaked secret away from all of them.
// The two allow-lists that decide whom the API believes. Wrong in every mode.
{
  const trust = parseTrustedProxies(config.trustedProxies);
  if (!trust.ok) throw new Error(`Refusing to start: ${trust.error}`);
  const origins = parseOrigins(config.corsOrigins);
  if (!origins.ok) throw new Error(`Refusing to start: ${origins.error}`);
  if (!/^\/[A-Za-z0-9_\-./]*$/.test(config.refreshCookiePath) || config.refreshCookiePath.includes("..")) {
    throw new Error("Refusing to start: REFRESH_COOKIE_PATH must be a plain absolute path such as /auth or /api/auth");
  }
}
// Development without a keyring is tolerated only on a loopback-bound laptop.
if (!config.encryptionKeys.trim() && !(process.env.NODE_ENV === "test" || (process.env.NODE_ENV === "development" && loopbackBind))) {
  throw new Error(
    "Refusing to start: LEGION_ENCRYPTION_KEYS is not set.\n" +
    "  It encrypts two-factor secrets and webhook secrets at rest. Re-run npm run setup\n" +
    "  (existing secrets are kept), or add to server/.env:\n" +
    "    LEGION_ENCRYPTION_KEYS=k1:$(openssl rand -hex 32)\n" +
    "  Keep this value out of database backups, and never change it without keeping\n" +
    "  the old entry in the list (see INSTALL.md, \"Encryption keys\")."
  );
}

// NODE_ENV=development is an escape hatch for `npm run dev` on a laptop — not
// a way to run a reachable server with a published key. Development may use a
// weak secret only while the API listens on loopback, and never a template
// value copied from .env.example (that file used to set NODE_ENV=development
// as well, which is exactly how a real server ended up running on it).
const copiedTemplate = TEMPLATE_SECRET.test(config.jwtSecret) && config.jwtSecret !== BUILTIN_DEV_JWT_SECRET;
const weakSecretTolerated =
  process.env.NODE_ENV === "test" ||
  (process.env.NODE_ENV === "development" && loopbackBind && !copiedTemplate);
// A previous secret is still a verification key: a weak one would let anyone
// forge tokens for as long as it is listed.
if (config.jwtPreviousSecrets.some(isWeakJwtSecret) && !weakSecretTolerated) {
  throw new Error("Refusing to start: JWT_PREVIOUS_SECRETS contains a weak or placeholder value. List only real, previously used secrets.");
}
if (usingPlaceholderSecret && !weakSecretTolerated) {
  throw new Error(
    "Refusing to start: JWT_SECRET is unset, too weak, or a placeholder copied from an example file.\n" +
    "  Run npm run setup to generate one, or set JWT_SECRET to 32+ random characters:\n" +
    "    openssl rand -hex 32"
  );
}

/**
 * Combinations that are wrong in EVERY mode.
 *
 * The block below only runs when NODE_ENV=production, which a self-hosted
 * customer never sets — they just run `npm start`. That gap has already
 * produced two defects in this codebase (the shipped JWT placeholder and the
 * demo account), so the checks that cannot be legitimate anywhere live here
 * instead of there.
 *
 * They are deliberately narrow: broad checks would also fire during local
 * evaluation (`npm run try`), which is a real and supported way to run Legion.
 * Each one below describes a state with no valid interpretation.
 */
/** The subset of settings these checks look at — so they can be exercised
 *  directly instead of only by starting a whole server. */
export interface SafetyInputs {
  frontendUrl: string;
  cookieSecure: boolean;
  dbSslInsecure: boolean;
  databaseUrl: string;
}

export function unsafeConfigProblems(input: SafetyInputs): string[] {
  const problems: string[] = [];

  // Serving the dashboard over HTTPS while telling the browser the session
  // cookie may travel unencrypted. There is no deployment where this is intended.
  if (input.frontendUrl.startsWith("https://") && !input.cookieSecure) {
    problems.push(
      "FRONTEND_URL is https:// but COOKIE_SECURE is not 'true' — the session cookie " +
      "would be sent without the Secure flag, which is exactly what HTTPS is meant to prevent"
    );
  }

  // Skipping certificate verification is defensible against a database on this
  // machine and indefensible against one across a network.
  if (input.dbSslInsecure) {
    let dbHost = "";
    try { dbHost = new URL(input.databaseUrl).hostname; } catch { dbHost = ""; }
    const localDb = ["localhost", "127.0.0.1", "::1", ""].includes(dbHost);
    if (!localDb) {
      problems.push(
        `DB_SSL_INSECURE=true with a remote database (${dbHost}) — the connection is encrypted ` +
        "but unauthenticated, so anyone between here and the database can impersonate it. " +
        "Supply DB_SSL_CA instead"
      );
    }
  }

  return problems;
}

/**
 * Settings whose raw value must be well-formed. Before this, a typo was read
 * silently: DEPLOYMENT_MODE=selfhosted is not "self-hosted", so a customer's
 * private install switched to the hosted behaviour — open public sign-up —
 * and ACCESS_TOKEN_MINUTES=15m became NaN, an invalid token lifetime.
 */
const INTEGER_SETTINGS: Record<string, [min: number, max: number]> = {
  PORT: [1, 65_535],
  ACCESS_TOKEN_MINUTES: [1, 60],
  REFRESH_TOKEN_DAYS: [1, 365],
  TRIAL_DAYS: [0, 365],
  INVITE_DAYS: [1, 30],
  DB_POOL_MAX: [1, 200],
  AUTH_RATE_LIMIT: [1, 10_000],
  API_RATE_LIMIT: [1, 1_000_000],
  SMTP_PORT: [1, 65_535],
};

export function settingProblems(env: Record<string, string | undefined>): string[] {
  const problems: string[] = [];
  const mode = env.DEPLOYMENT_MODE;
  if (mode !== undefined && mode !== "" && mode !== "self-hosted" && mode !== "saas") {
    problems.push(`DEPLOYMENT_MODE must be "self-hosted" or "saas" (got "${mode.slice(0, 40)}")`);
  }
  for (const [name, [min, max]] of Object.entries(INTEGER_SETTINGS)) {
    const raw = env[name];
    if (raw === undefined || raw === "") continue;
    const n = Number(raw);
    if (!/^\d+$/.test(raw.trim()) || !Number.isInteger(n) || n < min || n > max) {
      problems.push(`${name} must be a whole number from ${min} to ${max} (got "${raw.slice(0, 40)}")`);
    }
  }
  // The billing API key is sent to this base URL: https only (a loopback stub
  // for tests and local development is the one exception).
  if (env.PADDLE_API_BASE) {
    let u: URL | null = null;
    try { u = new URL(env.PADDLE_API_BASE); } catch { u = null; }
    const loopbackStub = u?.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
    if (!u || (u.protocol !== "https:" && !loopbackStub) || u.username || u.password) {
      problems.push("PADDLE_API_BASE must be an https:// URL without credentials");
    }
  }
  if (env.ALERT_EMAIL_MIN_SEVERITY && !["critical", "high", "medium", "low", "off"].includes(env.ALERT_EMAIL_MIN_SEVERITY)) {
    problems.push("ALERT_EMAIL_MIN_SEVERITY must be one of critical, high, medium, low, off");
  }
  return problems;
}

{
  const malformed = settingProblems(process.env);
  if (malformed.length) throw new Error(`Refusing to start with malformed settings:\n  - ${malformed.join("\n  - ")}`);
}

const alwaysWrong = unsafeConfigProblems(config);

if (alwaysWrong.length) {
  throw new Error(
    `Refusing to start with an unsafe configuration:\n  - ${alwaysWrong.join("\n  - ")}`
  );
}

/**
 * Fail fast on configurations that are safe locally but dangerous in
 * production. Refusing to boot is deliberate: a misconfigured security
 * product that silently starts is worse than one that doesn't.
 */
if (isProduction) {
  const problems: string[] = [];

  if (isWeakJwtSecret(config.jwtSecret)) {
    problems.push("JWT_SECRET must be a long random value (32+ chars), not a placeholder");
  }
  if (config.webhookEncryptionKey && config.webhookEncryptionKey.length < 32) {
    problems.push("WEBHOOK_ENCRYPTION_KEY must be 32+ random characters (openssl rand -hex 32)");
  }
  if (!config.cookieSecure) {
    problems.push(
      "COOKIE_SECURE must be 'true' so the auth cookie is never sent over plain HTTP"
    );
  }
  if (config.frontendUrl.startsWith("http://")) {
    problems.push("FRONTEND_URL must use https:// in production");
  }
  if (!config.smtpHost) {
    problems.push(
      "SMTP_HOST is required in production — password resets and team invites are undeliverable without it"
    );
  }
  if (config.smtpHost && config.smtpUser && !config.smtpPassword) {
    problems.push("SMTP_USER is set but SMTP_PASSWORD is empty — every email would be refused by the mail server");
  }
  if (!process.env.DATABASE_URL) {
    problems.push("DATABASE_URL must be set explicitly in production");
  }
  if (config.dbSslInsecure) {
    problems.push(
      "DB_SSL_INSECURE=true disables database certificate verification and is not allowed in production — " +
      "supply DB_SSL_CA instead if your provider needs a custom CA bundle"
    );
  }

  if (problems.length) {
    throw new Error(
      `Refusing to start with an unsafe production configuration:\n  - ${problems.join("\n  - ")}`
    );
  }
}

/**
 * Hosted-service settings that are not fatal but leave customers stuck:
 * without Paddle, a trial can end with no way to pay. Warned rather than
 * refused because the site has to be live (for Paddle's own website review)
 * before Paddle hands out live keys.
 */
export function saasWarnings(c: Pick<typeof config, "deploymentMode" | "paddleApiKey" | "paddleWebhookSecret" | "paddleEnvironment" | "smtpHost">): string[] {
  if (c.deploymentMode !== "saas") return [];
  const out: string[] = [];
  if (!c.paddleApiKey || !c.paddleWebhookSecret) {
    out.push("Paddle is not configured (PADDLE_API_KEY / PADDLE_WEBHOOK_SECRET): trials will end with no way to subscribe.");
  } else if (c.paddleEnvironment !== "production") {
    out.push("Paddle is in SANDBOX mode: checkouts use test cards and no real money is collected. Set PADDLE_ENVIRONMENT=production for launch.");
  }
  if (!c.smtpHost) {
    out.push("SMTP is not configured: new sign-ups cannot receive their confirmation email.");
  }
  return out;
}
