import express, { type NextFunction, type Request, type Response } from "express";
import cookieParser from "cookie-parser";
import { apiLimiter, authLimiter, closeRateLimitStore, initRateLimitStore, loginAccountLimiter, mailPerAddressLimiter, makeMfaLimiter, makeStepUpLimiter } from "./ratelimit.js";
import { hashForComparison, notifyAccountOwner, networkOf, recentLoginFailures, rememberLoginDevice } from "./account-security.js";
import { backupHealthReport } from "./backup-health.js";
import { applyTrustedProxies, checkWebSocketOrigin, clientAddress, corsMiddleware, originGuard, securityHeaders, upgradeRateLimited } from "./edge.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { WebSocketServer, WebSocket } from "ws";
import { z } from "zod";
import { config, saasWarnings } from "./config.js";
import * as store from "./store.js";
import { closePool, currentRoleAttributes, migrate, transaction } from "./db/pool.js";
import { databaseRoleDecision } from "./db/provision.js";
import { SETUP_LOCK_KEY, consumeSetupToken, ensureSetupToken, removeSetupTokenFile, setupBanner } from "./setup-token.js";
import { WEBHOOK_REJECTION_DETAIL, isKeyId } from "./webhook-auth.js";
import { webhookFailureGate } from "./webhook-guard.js";
import * as webhookCredentials from "./webhook-credentials.js";
import { hashOneTimeToken, newOneTimeToken } from "./auth-tokens.js";
import { describeReport, migrateSecretsAtRest } from "./secrets-migration.js";
import { keyringStatus } from "./secret-box.js";
import * as outbox from "./outbox.js";
import { seedDemoIfEmpty } from "./seed.js";
import { inviteEmail, mailEnabled, notificationConfirmEmail, passwordResetEmail, sendMail, testNotificationEmail, verifyEmailEmail, verifyMail } from "./mailer.js";
import { actionText, copilotFallback, isLocale, localExplanation, localizeResponses, requestLocale, suggestedActions, validationMessage, type Locale } from "./i18n.js";
import { createPortalSession, paddleConfigured, verifyPaddleSignature } from "./paddle.js";
import { aiCircuit, aiConfigWarnings, aiEnabled, aiProviderName, copilotAnswerSafe, explainAlertSafe } from "./ai.js";
import { aiAuditDetail, aiPolicy, consumeAiQuota, type AiWhy } from "./ai-policy.js";
import { clip, isIp } from "./ai-safety.js";
import * as mfa from "./mfa.js";
import * as sessions from "./sessions.js";
import * as realtime from "./realtime.js";
import { createAgentLayer } from "./agents.js";
import type { AccessState, Alert, Role, Severity, Subscription, User } from "./types.js";

export const app = express();
export const httpServer = createServer(app);
const now = () => new Date().toISOString();

// Who counts as a proxy is an explicit setting (TRUSTED_PROXIES), never a guess:
// `req.ip`, the rate limiters, the audit log and the WebSocket handshake all
// derive the client address from it, so a forged X-Forwarded-For from anyone
// who is not a named proxy is ignored.
export const trustedProxies = applyTrustedProxies(app);
app.disable("x-powered-by");
app.use(securityHeaders());
app.use(corsMiddleware());
// Machine endpoints authenticated by signature; they are not browsers.
app.use(originGuard(/^\/(security-events\/webhook|billing\/webhook)$/));
// Paddle signs the RAW bytes, so keep a copy before JSON.parse rewrites them.
// The sensor webhook is parsed by its own route instead (below): its body is
// kept as raw bytes and only parsed AFTER the signature over those bytes checks
// out, so an unauthenticated sender never gets its JSON parsed at all.
export const WEBHOOK_PATH = "/security-events/webhook";
const jsonBody = express.json({
  limit: "256kb",
  verify: (req, _res, buf) => { (req as Request & { rawBody?: Buffer }).rawBody = buf; },
});
app.use((req, res, next) => (req.path === WEBHOOK_PATH ? next() : jsonBody(req, res, next)));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(cookieParser());
// Error messages and confirmations in the reader's language (Accept-Language).
// Before the rate limiter so its "too many attempts" answer is covered too.
app.use(localizeResponses);

/**
 * Paths the general API limiter must not touch.
 *
 * Sensor ingestion is the important one: a busy SOC can exceed any per-minute
 * cap that is comfortable for a dashboard, and throttling it would silently
 * drop the customer's security telemetry. It is authenticated by HMAC, so it
 * is not an open door. Webhooks and health checks are excluded for the same
 * reason — their callers are authenticated or trivial, and rate limiting them
 * breaks the integration rather than protecting it.
 */
const RATE_LIMIT_EXEMPT = /^\/(health|security-events\/webhook|billing\/webhook)$/;
app.use((req, res, next) => {
  if (RATE_LIMIT_EXEMPT.test(req.path)) return next();
  return apiLimiter(req, res, next);
});

// AI agents and service accounts (packages/agent-identity, see agents.ts).
// Every request is resolved to exactly one principal here; people keep their
// existing session (asked through resolveSessionUser, never reimplemented),
// machines authenticate with their own credentials and are confined to
// /agent/v1, where every action passes the agent firewall.
export const agentLayer = createAgentLayer(
  {
    resolveSessionUser,
    accessState,
    onAlertUpdated: (alert) => broadcast(alert.tenant_id, { type: "alert.status_updated", alert: outputAlert(alert) }),
  },
  { withModel: aiEnabled() },
);
app.use(agentLayer.identity.principal);
agentLayer.mount(app);

type Token = { sub: string; tenant_id: string; token_version: number; purpose?: string; exp?: number };
type AuthedRequest = Request & { user?: User };

function sign(user: User): string {
  return jwt.sign(
    { sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version },
    config.jwtSecret,
    { algorithm: "HS256", expiresIn: `${config.accessTokenMinutes}m` }
  );
}

const ACCESS_COOKIE_MS = () => config.accessTokenMinutes * 60_000;
const REFRESH_COOKIE_MS = () => config.refreshTokenDays * 86_400_000;

function cookieBase() {
  // Lax, not Strict, for the access and "session exists" cookies: Strict drops them
  // on a top-level navigation from another site (a link in an email), which would
  // bounce a signed-in user to the login page. State-changing requests are
  // protected separately by the Origin guard.
  return { secure: config.cookieSecure, sameSite: "lax" as const, path: "/" };
}

/**
 * Sets the three cookies a session needs.
 *
 * The refresh cookie is scoped to REFRESH_COOKIE_PATH (the path the BROWSER
 * sees: /auth directly, /api/auth behind the bundled nginx) so it is not attached to every API
 * call — the long-lived credential should travel as rarely as possible.
 */
function setSessionCookies(res: Response, accessToken: string, refreshToken: string): void {
  res.cookie("legion_token", accessToken, { ...cookieBase(), httpOnly: true, maxAge: ACCESS_COOKIE_MS() });
  // Strict: it is only ever sent by fetch() to POST /auth/refresh, from our own pages.
  res.cookie("legion_refresh", refreshToken, { ...cookieBase(), sameSite: "strict", httpOnly: true, path: config.refreshCookiePath, maxAge: REFRESH_COOKIE_MS() });
  // Readable by the dashboard so it knows a session exists. Carries no
  // authority of its own — it only drives the redirect-to-login decision.
  res.cookie("legion_session", "1", { ...cookieBase(), httpOnly: false, maxAge: REFRESH_COOKIE_MS() });
}

function clearSessionCookies(res: Response): void {
  const base = { secure: config.cookieSecure, httpOnly: true };
  res.clearCookie("legion_token", { ...base, sameSite: "lax", path: "/" });
  // The configured path, and the legacy one, so a deployment that changes
  // REFRESH_COOKIE_PATH does not strand a refresh token in the browser.
  for (const path of new Set([config.refreshCookiePath, "/auth"])) {
    res.clearCookie("legion_refresh", { ...base, sameSite: "strict", path });
  }
  res.clearCookie("legion_session", { secure: config.cookieSecure, sameSite: "lax", path: "/" });
}

function tokenFrom(req: Request): string | undefined {
  const bearer = req.header("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  return bearer || req.cookies?.legion_token;
}

function verifyToken(raw?: string): Token | null {
  if (!raw) return null;
  try { return jwt.verify(raw, config.jwtSecret, { algorithms: ["HS256"] }) as Token; }
  catch { return null; }
}

/** Constant-time compare for secrets that arrive from a request. */
function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * A one-time link reached the server log only when an operator explicitly
 * asked for it on a development machine (DEV_LOG_AUTH_LINKS). By default the
 * log says that a link was generated and where it went, never the link.
 */
function logUnsentLink(kind: "password reset" | "invitation" | "notification address confirmation", url: string, reason: string): void {
  if (config.devLogAuthLinks) console.info(`[DEV_LOG_AUTH_LINKS] ${kind} link (SMTP ${reason}): ${url}`);
  else console.info(`Legion: a ${kind} link was generated but not e-mailed (SMTP ${reason}). Configure SMTP, or set DEV_LOG_AUTH_LINKS=true on a development machine to print it.`);
}

/** The answer to a TOTP check, whatever state the stored seed is in. An
 *  unreadable seed is refused — never treated as "no MFA". */
async function checkTotp(user: User, code: string): Promise<"ok" | "wrong" | "unavailable"> {
  const seed = await mfa.secretFor(user);
  if (!seed.ok) return seed.reason === "unreadable" ? "unavailable" : "wrong";
  return (await mfa.verifyCode(user.id, seed.secret, user.email, code)) ? "ok" : "wrong";
}

// --- Subscription access control ---------------------------------------------
// Paths that must stay reachable no matter what the subscription says: a tenant
// that cannot log in or open the billing portal can never start paying again.
const ACCESS_EXEMPT = /^\/(auth|billing|health)(\/|$)/;

export const isSelfHosted = (): boolean => config.deploymentMode === "self-hosted";

export async function accessState(tenantId: string): Promise<AccessState> {
  // A self-hosted install has no subscription to check — the customer already
  // owns it. Without this, the SaaS trial would expire on their own server and
  // lock them out of their own data, demanding a subscription that does not
  // exist.
  if (isSelfHosted()) return "ok";

  const sub = await store.getSubscription(tenantId);
  if (sub) {
    if (sub.status === "active" || sub.status === "trialing") return "ok";
    // Unpaid invoice: keep the data visible but stop new work. Hiding a live
    // security incident over billing would be the wrong trade.
    if (sub.status === "past_due") return "readonly";
    return "blocked"; // paused | canceled
  }
  const tenant = await store.getTenant(tenantId);
  if (!tenant) return "blocked";
  if (!tenant.trial_ends_at) return "ok";
  return new Date(tenant.trial_ends_at) > new Date() ? "ok" : "blocked";
}

async function enforceAccess(req: AuthedRequest, res: Response): Promise<boolean> {
  if (ACCESS_EXEMPT.test(req.path)) return true;
  const state = await accessState(req.user!.tenant_id);
  if (state === "ok") return true;
  if (state === "readonly" && req.method === "GET") return true;
  res.status(402).json({
    detail: state === "readonly"
      ? "Your subscription payment is past due. Legion is read-only until it is settled."
      : "This workspace does not have an active Legion subscription.",
    access_state: state,
  });
  return false;
}

/**
 * The signed-in person, by exactly the rules `authenticate` applies below
 * (no purpose-scoped tokens, current token version, active account), without
 * sending a response. The agent module asks this — it never reads cookies or
 * JWTs itself.
 */
async function resolveSessionUser(req: Request): Promise<User | null> {
  const payload = verifyToken(tokenFrom(req));
  if (!payload || payload.purpose) return null;
  const user = await store.findUserById(payload.sub);
  if (!user || payload.tenant_id !== user.tenant_id || payload.token_version !== user.token_version) return null;
  return user.status === "active" ? user : null;
}

async function authenticate(req: AuthedRequest, res: Response): Promise<boolean> {
  const payload = verifyToken(tokenFrom(req));
  // Purpose-scoped tokens (the MFA challenge, the Paddle checkout context) are
  // signed with the same key and carry the same claims. Without this check a
  // half-authenticated MFA token would be accepted as a full session — which
  // would make the second factor optional for anyone who noticed.
  if (payload?.purpose) {
    res.status(401).json({ detail: "Authentication required" });
    return false;
  }
  const user = payload ? await store.findUserById(payload.sub) : null;
  if (!user || payload?.tenant_id !== user.tenant_id || payload.token_version !== user.token_version) {
    res.status(401).json({ detail: "Authentication required" });
    return false;
  }
  // An invited-but-not-accepted or deactivated account holds no access, even
  // if it is somehow presenting a structurally valid token.
  if (user.status !== "active") {
    res.status(401).json({ detail: "This account is not active" });
    return false;
  }
  req.user = user;
  return enforceAccess(req, res);
}

async function auth(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  if (await authenticate(req, res)) next();
}

const rank: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };
function requireRole(minimum: Role) {
  return async (req: AuthedRequest, res: Response, next: NextFunction): Promise<void> => {
    if (!(await authenticate(req, res))) return;
    if (rank[req.user!.role] < rank[minimum]) {
      res.status(403).json({ detail: "Insufficient permissions" });
      return;
    }
    next();
  };
}

function parse<T>(schema: z.ZodType<T>, value: unknown, res: Response): T | null {
  const result = schema.safeParse(value);
  if (!result.success) { res.status(422).json({ detail: validationMessage(result.error.issues[0]) }); return null; }
  return result.data;
}

function publicUser(user: User) { return { id: user.id, email: user.email, role: user.role, status: user.status, tenant_id: user.tenant_id, created_at: user.created_at }; }
/** An alert as the API returns it. The suggested next steps go out twice:
 *  as English text (existing API clients) and as codes the dashboard renders
 *  in the viewer's language — the same payload is also broadcast to every
 *  connected analyst, whatever language each of them reads. */
function outputAlert(alert: Alert) {
  const codes = suggestedActions(alert);
  return {
    ...alert,
    // True only when a model wrote the stored explanation; Legion's own
    // fallback text is not "AI" and is not labelled as if it were.
    ai_generated: alert.ai_explanation_source === "ai",
    suggested_actions: codes.map((a) => actionText(a, "en")), suggested_action_codes: codes,
  };
}
const localeOf = (res: Response): Locale => (isLocale(res.locals.locale) ? res.locals.locale : "en");

async function log(req: AuthedRequest, action: string, resource_type: string | null = null, resource_id: string | null = null, detail: string | null = null) {
  const user = req.user!;
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action, resource_type, resource_id, detail, ip_address: req.ip || null });
}

/**
 * Which live-socket grants still hold — the same rules the handshake applies
 * (active user, same tenant, same token version, tenant not blocked), read from
 * Postgres so every instance reaches the same answer.
 */
export async function socketGrantsStillValid(checks: realtime.GrantCheck[]): Promise<Set<string>> {
  const users = new Map((await store.userAuthStates([...new Set(checks.map((c) => c.userId))])).map((u) => [u.id, u]));
  const access = new Map<string, AccessState>();
  const ok = new Set<string>();
  for (const c of checks) {
    const u = users.get(c.userId);
    if (!u || u.status !== "active" || u.tenant_id !== c.tenantId || u.token_version !== c.tokenVersion) continue;
    if (!access.has(c.tenantId)) access.set(c.tenantId, await accessState(c.tenantId));
    if (access.get(c.tenantId) === "blocked") continue;
    ok.add(realtime.grantKey(c.tenantId, c));
  }
  return ok;
}

/** Ends every session of a user: refresh tokens everywhere, and this instance's
 *  live sockets now (other instances close theirs on their next revalidation). */
async function revokeUserEverywhere(userId: string): Promise<void> {
  await sessions.revokeAllForUser(userId);
  realtime.closeUserSockets(userId);
}

/** Fans an event out to every instance (see realtime.ts). Fire-and-forget:
 *  a realtime hiccup must never fail the request that produced the alert —
 *  the alert is already committed and the client recovers from the database. */
function broadcast(tenantId: string, payload: unknown): void {
  void realtime.publish(tenantId, payload).catch((error) => {
    console.error("Realtime broadcast failed:", error instanceof Error ? error.message : error);
  });
}

/** The dashboard frame for a new alert. Queued in the alert's own
 *  transaction (outbox.ts) and published by the worker, with retries — so a
 *  Redis outage or a crash right after commit delays it rather than losing it. */
const newAlertFrame = (alert: Alert) => ({ type: "new_alert", alert: outputAlert(alert) });

app.get("/health", async (_req, res) => {
  // A health check that doesn't touch the database will happily report "ok"
  // while every request 500s.
  try {
    await store.getTenant("00000000-0000-0000-0000-000000000000");
    return res.json({
      status: "ok",
      runtime: "node",
      version: config.version,
      mode: config.deploymentMode,
      database: "up",
      ai: aiEnabled(),
      // Names the third party that sees alert text, or null when none does.
      // An operator should be able to confirm this without reading .env.
      ai_provider: aiProviderName(),
    });
  } catch {
    return res.status(503).json({ status: "degraded", database: "down" });
  }
});

/**
 * Platform-wide outbox depth, for monitoring (Prometheus blackbox, uptime
 * checks). Numbers only — no tenant ids, recipients or payloads. Not public:
 * it exists only when HEALTH_METRICS_TOKEN is set, and requires it.
 */
app.get("/health/outbox", async (req, res) => {
  const expected = config.healthMetricsToken;
  if (!expected) return res.status(404).json({ detail: "Not found" });
  const given = (req.header("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!safeEqual(given, expected)) return res.status(401).json({ detail: "Authentication required" });
  try {
    return res.json(await outbox.queueMetrics());
  } catch {
    return res.status(503).json({ detail: "Service unavailable" });
  }
});

/**
 * Backup health for uptime monitors: 200 when the newest backup is fresh,
 * encrypted and restore-tested; 503 (with reasons) when it is stale, failed or
 * untested. Same token as /health/outbox; absent unless both it and
 * BACKUP_STATUS_FILE are configured.
 */
app.get("/health/backup", async (req, res) => {
  const expected = config.healthMetricsToken;
  if (!expected || !config.backupStatusFile) return res.status(404).json({ detail: "Not found" });
  const given = (req.header("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!safeEqual(given, expected)) return res.status(401).json({ detail: "Authentication required" });
  const report = await backupHealthReport(config.backupStatusFile, {
    maxAgeHours: config.backupMaxAgeHours,
    restoreMaxDays: config.restoreTestMaxAgeDays,
    requireOffsite: config.backupRequireOffsite,
  });
  return res.status(report.healthy ? 200 : 503).json(report);
});

const passwordField = z.string().min(8).max(128);

const registerSchema = z.object({
  email: z.string().email().max(254).transform((v) => v.toLowerCase()),
  password: passwordField,
  tenant_name: z.string().min(2).max(100),
  // Self-hosted first-run only; ignored in hosted mode.
  setup_token: z.string().max(200).optional(),
});

/** Lets the dashboard decide whether to show the first-run setup screen.
 *  Reveals only what POST /auth/register would already reveal. */
app.get("/auth/setup-status", async (_req, res) => {
  const setupRequired = isSelfHosted() && !(await store.hasAnyTenant());
  // The mode tells the sign-in page whether to offer "Create an account";
  // /health already says the same thing publicly.
  res.json({ setup_required: setupRequired, deployment_mode: config.deploymentMode, trial_days: isSelfHosted() ? null : config.trialDays });
});

// --- Email verification (hosted sign-up) ------------------------------------
// Anyone can sign up on the hosted service, so an address is not trusted until
// its owner follows the emailed link: no session, trial use or password reset
// for an account whose email nobody has proven. Only a SHA-256 of the token
// is stored.

const VERIFY_HOURS = 24;
const tokenHash = hashOneTimeToken; // same scheme as reset and invitation links

async function sendVerificationEmail(user: User, locale: Locale): Promise<void> {
  const token = randomBytes(32).toString("base64url");
  await store.updateUser(user.id, {
    verify_token_hash: tokenHash(token),
    verify_expires: new Date(Date.now() + VERIFY_HOURS * 3_600_000).toISOString(),
  });
  const verifyUrl = `${config.frontendUrl}/verify-email?token=${token}`;
  const mail = await sendMail({ to: user.email, ...verifyEmailEmail(verifyUrl, VERIFY_HOURS, locale) });
  // Development without SMTP: the link has to reach someone. Production
  // refuses to boot without SMTP, so this never prints there.
  if (!mail.sent && !config.isProduction) {
    console.info(`Email verification URL for ${user.email} (SMTP ${mail.reason}): ${verifyUrl}`);
  }
}

app.post("/auth/verify-email", authLimiter, async (req, res) => {
  const body = parse(z.object({ token: z.string().min(20).max(200) }), req.body, res); if (!body) return;
  const user = await store.consumeVerifyToken(hashOneTimeToken(body.token));
  if (!user) return res.status(400).json({ detail: "This confirmation link is invalid or has expired. Request a new one from the sign-in page." });
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.email_verified", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
  return res.json({ message: "Email confirmed. You can sign in now." });
});

/** Always the same answer, so it cannot be used to learn which addresses exist. */
app.post("/auth/resend-verification", authLimiter, mailPerAddressLimiter, async (req, res) => {
  const email = String(req.body?.email || "").toLowerCase().slice(0, 254);
  const user = email ? await store.findUserByEmail(email) : null;
  if (user && !user.email_verified_at && user.status === "active" && !isSelfHosted()) {
    await sendVerificationEmail(user, requestLocale(req));
  }
  res.status(202).json({ message: "If that account is waiting for confirmation, a new link has been sent." });
});

app.post("/auth/register", authLimiter, async (req, res) => {
  const body = parse(registerSchema, req.body, res); if (!body) return;

  if (isSelfHosted()) return registerFirstAdmin(body, req, res);

  const passwordHash = await bcrypt.hash(body.password, 12);
  try {
    // Uniqueness is enforced by a database constraint rather than a prior
    // SELECT, so concurrent registrations for one address cannot both succeed.
    const locale = requestLocale(req);
    const { user } = await store.createTenantWithAdmin(body.tenant_name, body.email, passwordHash, { emailVerified: false, locale });
    await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.register", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
    await sendVerificationEmail(user, locale);
    return res.status(201).json({ ...publicUser(user), verification_required: true });
  } catch (error) {
    if (store.isUniqueViolation(error)) {
      return res.status(400).json({ detail: "Email is already registered" });
    }
    throw error;
  }
});

/**
 * Self-hosted first-run: creates the first administrator, and nothing else ever.
 *
 * Two defects this closes, both demonstrated before the fix:
 *  - Anyone who reached this endpoint first became the administrator. Now the
 *    one-time setup token printed on the server's console is required.
 *  - "Is anyone set up yet?" was checked, then a ~250 ms password hash ran,
 *    then the insert happened. Ten simultaneous requests produced four
 *    administrators. Now the check, the token and the insert all happen in one
 *    transaction under a database lock, so exactly one can succeed.
 */
async function registerFirstAdmin(
  body: z.infer<typeof registerSchema>,
  req: Request,
  res: Response
) {
  // Hash before taking the lock: the lock should be held for milliseconds.
  const passwordHash = await bcrypt.hash(body.password, 12);

  const outcome = await transaction(async (client) => {
    await client.query("SELECT pg_advisory_xact_lock($1)", [SETUP_LOCK_KEY]);
    const setUp = await client.query("SELECT 1 FROM tenants LIMIT 1");
    if (setUp.rowCount) return { kind: "already-set-up" as const };
    if (!(await consumeSetupToken(client, body.setup_token))) return { kind: "bad-token" as const };
    const created = await store.createTenantWithAdminTx(client, body.tenant_name, body.email, passwordHash, { locale: requestLocale(req) });
    return { kind: "created" as const, user: created.user };
  });

  if (outcome.kind === "already-set-up") {
    return res.status(403).json({
      detail: "This Legion installation is already set up. Ask an administrator to invite you.",
    });
  }
  if (outcome.kind === "bad-token") {
    // No tenant exists yet, so there is no audit_log to write to (every row
    // belongs to a tenant). The server log is the only record available.
    console.warn(`Legion: refused first-run setup from ${req.ip || "unknown"}: missing or wrong setup token`);
    return res.status(403).json({
      detail: "A valid setup token is required. It is printed in the Legion server's console on startup.",
    });
  }

  const { user } = outcome;
  await removeSetupTokenFile();
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.setup_completed", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
  return res.status(201).json(publicUser(user));
}

app.post("/auth/login", authLimiter, loginAccountLimiter, async (req, res) => {
  const body = req.body ?? {};
  const email = String(body.username || "").toLowerCase();
  const user = await store.findUserByEmail(email);
  // Always one full-cost bcrypt comparison: against the user's own hash, or a
  // real dummy hash when the address is unknown or has no password yet, so
  // the response time does not reveal whether the address exists.
  const { hash, real } = hashForComparison(user);
  const ok = (await bcrypt.compare(String(body.password || "").slice(0, 128), hash)) && real;
  if (!user || !ok) {
    // Recorded against a real account only (an unknown address has no tenant
    // to audit into): the owner's administrators see guessing, and a later
    // success after many failures is flagged (see completeSignIn).
    if (user) {
      await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.login_failed", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null }).catch(() => {});
    }
    return res.status(401).json({ detail: "Invalid email or password" });
  }
  if (user.status === "invited") return res.status(403).json({ detail: "Finish setting up your account from the invitation email first" });
  if (user.status !== "active") return res.status(403).json({ detail: "This account has been deactivated" });
  if (!user.email_verified_at && !isSelfHosted()) {
    return res.status(403).json({
      detail: "Confirm your email address first — we sent you a link when you signed up.",
      code: "email_unverified",
    });
  }

  // Password was correct but it is only the first factor. Hand back a
  // short-lived, purpose-scoped token rather than a session; `authenticate`
  // rejects anything carrying a purpose, so this cannot be used as one.
  if (user.mfa_enabled) {
    await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.mfa_challenged", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
    return res.json({
      mfa_required: true,
      mfa_token: jwt.sign(
        { sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version, purpose: "mfa" },
        config.jwtSecret,
        { algorithm: "HS256", expiresIn: "5m" }
      ),
    });
  }

  const accessToken = await startSession(req, res, user);
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.login", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
  await completeSignIn(req, user);
  return res.json({ access_token: accessToken, token_type: "bearer" });
});

/**
 * Suspicious sign-in detection, after a sign-in has fully succeeded (both
 * factors). Flags a device this account has never used, and a success that
 * follows a burst of failed passwords (a guessed or stuffed credential). A
 * flagged sign-in is audited and its owner emailed. Never blocks the sign-in:
 * the second factor is the control, this is the alarm.
 */
async function completeSignIn(req: Request, user: User): Promise<void> {
  try {
    const newDevice = await rememberLoginDevice(user.id, req);
    const failures = await recentLoginFailures(user);
    const reasons = [newDevice ? "new device" : "", failures >= 5 ? `${failures} failed attempts in the previous 15 minutes` : ""].filter(Boolean);
    if (!reasons.length) return;
    const network = networkOf(req.ip);
    const detail = `${reasons.join("; ")}${network ? `; network ${network}` : ""}`;
    await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.login_suspicious", resource_type: "user", resource_id: user.id, detail, ip_address: req.ip || null });
    notifyAccountOwner(user, "new_device_login", req, detail);
  } catch (error) {
    console.error("Legion: sign-in risk check failed:", error instanceof Error ? error.message : "unknown error");
  }
}

/** Starts a session. One place, so every path that creates one (password
 *  login, MFA completion) stays consistent. */
async function startSession(req: Request, res: Response, user: User): Promise<string> {
  const accessToken = sign(user);
  const refreshToken = await sessions.issue(user.id, {
    userAgent: req.header("user-agent"),
    ip: req.ip || null,
  });
  setSessionCookies(res, accessToken, refreshToken);
  return accessToken;
}

// --- MFA ---------------------------------------------------------------------

/** Validates an MFA challenge token and returns the user it belongs to. */
async function userFromMfaToken(raw: string): Promise<User | null> {
  const payload = verifyToken(raw);
  if (!payload || payload.purpose !== "mfa") return null;
  const user = await store.findUserById(payload.sub);
  if (!user || user.token_version !== payload.token_version || user.status !== "active") return null;
  return user;
}

/** Second step of login: exchange the challenge token for a real session. */
const mfaAccountLimiter = makeMfaLimiter((req) => {
  const token = (req.body as { mfa_token?: unknown } | undefined)?.mfa_token;
  const payload = typeof token === "string" ? verifyToken(token) : null;
  return payload?.purpose === "mfa" ? payload.sub : undefined;
});

/** Wrong current passwords / codes by a signed-in user (ratelimit.ts). */
const stepUpLimiter = makeStepUpLimiter((req) => {
  const payload = verifyToken(tokenFrom(req));
  return payload && !payload.purpose ? payload.sub : undefined;
});

app.post("/auth/mfa/verify", authLimiter, mfaAccountLimiter, async (req, res) => {
  const body = parse(z.object({
    mfa_token: z.string().min(10),
    code: z.string().min(6).max(20).optional(),
    recovery_code: z.string().min(6).max(20).optional(),
  }).refine((v) => v.code || v.recovery_code, { message: "A code is required" }), req.body, res);
  if (!body) return;

  const user = await userFromMfaToken(body.mfa_token);
  if (!user || !user.mfa_enabled) return res.status(401).json({ detail: "This sign-in attempt has expired. Please log in again.", code: "mfa_expired" });

  let usedRecovery = false;
  if (body.code) {
    const verdict = await checkTotp(user, body.code);
    // The seed exists but cannot be decrypted (a key problem on the server).
    // Refuse — MFA stays on, nothing is reset — and say it is not the code.
    // Recovery codes are hashed, not encrypted, so they still work.
    if (verdict === "unavailable") return res.status(503).json({ detail: "Two-factor sign-in is temporarily unavailable. Use a recovery code, or contact your administrator.", code: "mfa_unavailable" });
    if (verdict !== "ok") {
      await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.mfa_failed", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
      return res.status(401).json({ detail: "That code is not valid" });
    }
  } else {
    if (!(await mfa.consumeRecoveryCode(user.id, body.recovery_code!))) {
      await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.mfa_failed", resource_type: "user", resource_id: user.id, detail: "recovery", ip_address: req.ip || null });
      return res.status(401).json({ detail: "That recovery code is not valid" });
    }
    usedRecovery = true;
  }

  const accessToken = await startSession(req, res, user);
  const remaining = usedRecovery ? await mfa.countRecoveryCodes(user.id) : null;
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.login", resource_type: "user", resource_id: user.id, detail: usedRecovery ? "mfa:recovery" : "mfa:totp", ip_address: req.ip || null });
  await completeSignIn(req, user);
  return res.json({
    access_token: accessToken, token_type: "bearer",
    used_recovery_code: usedRecovery,
    // Surfaced so the UI can nag before the user runs out entirely.
    recovery_codes_remaining: remaining,
  });
});

app.get("/auth/mfa", auth, async (req: AuthedRequest, res) => {
  res.json({
    enabled: req.user!.mfa_enabled,
    enrolled_at: req.user!.mfa_enrolled_at,
    recovery_codes_remaining: req.user!.mfa_enabled ? await mfa.countRecoveryCodes(req.user!.id) : 0,
  });
});

/** Starts enrolment: mints a secret and returns the provisioning URI. MFA is
 *  not active until /auth/mfa/enable confirms the user can produce a code —
 *  otherwise a mis-scanned QR would lock them out. */
app.post("/auth/mfa/setup", auth, async (req: AuthedRequest, res) => {
  const user = req.user!;
  if (user.mfa_enabled) return res.status(400).json({ detail: "Two-factor authentication is already enabled" });

  // Sealed before it is stored; the plaintext exists only in this response,
  // which is the one moment the user needs it (to scan it).
  const secret = await mfa.beginEnrolment(user.id);
  if (!secret) return res.status(400).json({ detail: "Two-factor authentication is already enabled" });
  await log(req, "auth.mfa_setup_started", "user", user.id);
  res.setHeader("Cache-Control", "no-store");
  return res.json({
    secret,
    otpauth_uri: mfa.provisioningUri(secret, user.email),
  });
});

app.post("/auth/mfa/enable", authLimiter, stepUpLimiter, auth, async (req: AuthedRequest, res) => {
  const body = parse(z.object({ code: z.string().min(6).max(10) }), req.body, res); if (!body) return;
  const user = req.user!;
  if (user.mfa_enabled) return res.status(400).json({ detail: "Two-factor authentication is already enabled" });
  if (!user.mfa_secret_enc && !user.mfa_secret_legacy) return res.status(400).json({ detail: "Start setup first" });

  const verdict = await checkTotp(user, body.code);
  if (verdict === "unavailable") return res.status(503).json({ detail: "Two-factor sign-in is temporarily unavailable. Use a recovery code, or contact your administrator.", code: "mfa_unavailable" });
  if (verdict !== "ok") {
    return res.status(400).json({ detail: "That code is not valid — check your authenticator app's clock" });
  }

  // Turning MFA on ends every other session — including any opened with the
  // password alone before it was on — and starts a fresh one for this browser.
  const enabled = await store.updateUser(user.id, { mfa_enabled: true, mfa_enrolled_at: new Date().toISOString(), bump_token_version: true });
  await revokeUserEverywhere(user.id);
  await startSession(req, res, enabled!);
  const recoveryCodes = await mfa.regenerateRecoveryCodes(user.id);
  await log(req, "auth.mfa_enabled", "user", user.id);
  notifyAccountOwner(user, "mfa_enabled", req);
  // The only time these are readable. Only hashes are stored.
  res.setHeader("Cache-Control", "no-store");
  return res.json({ enabled: true, recovery_codes: recoveryCodes });
});

app.post("/auth/mfa/disable", authLimiter, stepUpLimiter, auth, async (req: AuthedRequest, res) => {
  const body = parse(z.object({
    password: z.string().min(1).max(128),
    code: z.string().min(6).max(20).optional(),
  }), req.body, res); if (!body) return;
  const user = req.user!;
  if (!user.mfa_enabled) return res.status(400).json({ detail: "Two-factor authentication is not enabled" });

  // Password AND a current code: turning off a security control should be at
  // least as hard as using it, so a borrowed session alone is not enough.
  if (!(await bcrypt.compare(body.password, user.password_hash))) {
    return res.status(400).json({ detail: "Password is incorrect" });
  }
  const codeOk = body.code
    && ((await checkTotp(user, body.code)) === "ok"
      || await mfa.consumeRecoveryCode(user.id, body.code));
  if (!codeOk) return res.status(400).json({ detail: "A valid authentication or recovery code is required" });

  await mfa.disableMfa(user.id);
  // Same as enabling: every other session ends, this one continues.
  const updated = await store.updateUser(user.id, { bump_token_version: true });
  await revokeUserEverywhere(user.id);
  await startSession(req, res, updated!);
  await log(req, "auth.mfa_disabled", "user", user.id);
  notifyAccountOwner(user, "mfa_disabled", req);
  return res.json({ enabled: false });
});

app.post("/auth/mfa/recovery-codes", authLimiter, stepUpLimiter, auth, async (req: AuthedRequest, res) => {
  const body = parse(z.object({ password: z.string().min(1).max(128) }), req.body, res); if (!body) return;
  const user = req.user!;
  if (!user.mfa_enabled) return res.status(400).json({ detail: "Two-factor authentication is not enabled" });
  if (!(await bcrypt.compare(body.password, user.password_hash))) {
    return res.status(400).json({ detail: "Password is incorrect" });
  }
  // Regenerating invalidates every previous code — the point when a list may
  // have been exposed.
  const recoveryCodes = await mfa.regenerateRecoveryCodes(user.id);
  await log(req, "auth.mfa_recovery_regenerated", "user", user.id);
  notifyAccountOwner(user, "recovery_codes_regenerated", req);
  res.setHeader("Cache-Control", "no-store");
  return res.json({ recovery_codes: recoveryCodes });
});

app.post("/auth/logout", async (req, res) => {
  // Revoke server-side as well as clearing cookies: a refresh token that is
  // only "forgotten" by the browser still works for anyone holding a copy.
  const refresh = req.cookies?.legion_refresh;
  if (refresh) await sessions.revoke(refresh).catch(() => { /* clear cookies regardless */ });
  // Live sockets opened with this browser's access token end with the session
  // (on this instance at once; elsewhere when that token expires).
  const access = tokenFrom(req);
  if (access) realtime.closeTokenSockets(createHash("sha256").update(access).digest("hex"));
  clearSessionCookies(res);
  res.status(204).end();
});

/**
 * Exchanges the refresh cookie for a new access token.
 *
 * Unauthenticated by design — the refresh cookie IS the credential, and the
 * access token it replaces has usually expired by the time this is called.
 */
app.post("/auth/refresh", async (req, res) => {
  const presented = req.cookies?.legion_refresh;
  if (!presented) return res.status(401).json({ detail: "No session to refresh" });

  const result = await sessions.rotate(presented, {
    userAgent: req.header("user-agent"), ip: req.ip || null,
  });

  if (!result.ok) {
    clearSessionCookies(res);
    if (result.reason === "reused") {
      // The whole family was just revoked. Someone replayed a spent token, so
      // both the real user and whoever else holds it are signed out.
      return res.status(401).json({ detail: "Session reuse detected. Please log in again." });
    }
    return res.status(401).json({ detail: "Session expired. Please log in again." });
  }

  const user = await store.findUserById(result.userId);
  // A password change, role change or deactivation since the token was issued
  // must not be survivable by refreshing.
  if (!user || user.status !== "active") {
    await revokeUserEverywhere(result.userId);
    clearSessionCookies(res);
    return res.status(401).json({ detail: "This account is no longer active" });
  }

  const accessToken = sign(user);
  setSessionCookies(res, accessToken, result.token);
  return res.json({ access_token: accessToken, token_type: "bearer" });
});

app.get("/auth/me", auth, async (req: AuthedRequest, res) => {
  const tenant = await store.getTenant(req.user!.tenant_id);
  res.json({
    ...publicUser(req.user!),
    tenant_name: tenant?.name || null,
    trial_ends_at: tenant?.trial_ends_at || null,
    access_state: await accessState(req.user!.tenant_id),
    deployment_mode: config.deploymentMode,
  });
});

app.post("/auth/forgot-password", authLimiter, mailPerAddressLimiter, async (req, res) => {
  const email = String(req.body.email || "").toLowerCase();
  const user = await store.findUserByEmail(email);
  if (user && user.status === "active") {
    // Only the hash is stored; the token exists in the e-mail and nowhere else.
    // A new request replaces the previous link.
    const { token, hash } = newOneTimeToken();
    await store.updateUser(user.id, {
      reset_token_hash: hash,
      reset_expires: new Date(Date.now() + 3_600_000).toISOString(),
    });
    const resetUrl = `${config.frontendUrl}/reset-password?token=${token}`;
    // Not awaited: waiting on SMTP only for addresses that exist would let the
    // response time say which addresses do.
    const locale = requestLocale(req);
    void sendMail({ to: user.email, ...passwordResetEmail(resetUrl, locale) })
      .then((mail) => { if (!mail.sent) logUnsentLink("password reset", resetUrl, mail.reason); })
      .catch(() => {});
  }
  res.status(202).json({ message: "If that email is registered, a reset link has been generated." });
});

app.post("/auth/reset-password", authLimiter, async (req, res) => {
  const body = parse(z.object({ token: z.string().min(20), new_password: passwordField }), req.body, res); if (!body) return;
  // Hash the new password first, then consume the token and set the password in
  // ONE statement: an unknown, expired or already-used token changes nothing,
  // and two requests racing with the same token cannot both succeed.
  const passwordHash = await bcrypt.hash(body.new_password, 12);
  const user = await store.consumeResetToken(hashOneTimeToken(body.token), passwordHash);
  if (!user) return res.status(400).json({ detail: "Token is invalid or has expired" });
  // token_version kills access tokens; this kills the refresh tokens that
  // would otherwise mint new ones. A password reset must end every session.
  await revokeUserEverywhere(user.id);
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "auth.password_reset", resource_type: "user", resource_id: user.id, detail: null, ip_address: req.ip || null });
  notifyAccountOwner(user, "password_changed", req);
  return res.json({ message: "Password updated. Please log in again." });
});

/** Password change for a signed-in user. Bumps token_version, which signs out
 *  every other session — the point of changing a password under suspicion. */
app.post("/auth/change-password", authLimiter, stepUpLimiter, auth, async (req: AuthedRequest, res) => {
  const body = parse(z.object({ current_password: z.string().min(1).max(128), new_password: passwordField }), req.body, res); if (!body) return;
  const user = req.user!;
  if (!(await bcrypt.compare(body.current_password, user.password_hash))) {
    return res.status(400).json({ detail: "Current password is incorrect" });
  }
  await store.updateUser(user.id, {
    password_hash: await bcrypt.hash(body.new_password, 12),
    bump_token_version: true,
  });
  await revokeUserEverywhere(user.id);
  await log(req, "auth.password_changed", "user", user.id);
  notifyAccountOwner(user, "password_changed", req);
  res.clearCookie("legion_token", { path: "/" });
  res.clearCookie("legion_session", { path: "/" });
  return res.json({ message: "Password updated. Please log in again." });
});

/** Completes a team invitation: the invitee sets a password and joins the
 *  EXISTING tenant. Deliberately separate from /auth/register, which always
 *  creates a new tenant. */
app.post("/auth/accept-invite", authLimiter, async (req, res) => {
  const body = parse(z.object({ token: z.string().min(20), password: passwordField }), req.body, res); if (!body) return;
  const passwordHash = await bcrypt.hash(body.password, 12);
  const user = await store.consumeInviteToken(hashOneTimeToken(body.token), passwordHash);
  if (!user) return res.status(400).json({ detail: "This invitation is invalid or has expired" });
  await store.audit({ tenant_id: user.tenant_id, user_id: user.id, user_email: user.email, action: "user.invite_accepted", resource_type: "user", resource_id: user.id, detail: user.role, ip_address: req.ip || null });
  return res.json({ message: "Your account is ready. Please log in." });
});

/** Read-only preview so the accept-invite page can greet the invitee by
 *  workspace name without exposing anything about the tenant's data.
 *  POST, with the token in the body: the former GET /auth/invite/:token put a
 *  live invitation into the URL, and so into every proxy's access log. */
app.post("/auth/invite/preview", authLimiter, async (req, res) => {
  const body = parse(z.object({ token: z.string().min(20).max(200) }), req.body ?? {}, res); if (!body) return;
  const user = await store.findUserByInviteTokenHash(hashOneTimeToken(body.token));
  if (!user) return res.status(404).json({ detail: "This invitation is invalid or has expired" });
  const tenant = await store.getTenant(user.tenant_id);
  return res.json({ email: user.email, role: user.role, tenant_name: tenant?.name || null });
});

// --- Alerts ------------------------------------------------------------------

app.get("/alerts/stats", auth, async (req: AuthedRequest, res) => {
  res.json(await store.alertStats(req.user!.tenant_id));
});

app.get("/alerts", auth, async (req: AuthedRequest, res) => {
  const alerts = await store.listAlerts(req.user!.tenant_id, {
    severity: req.query.severity ? String(req.query.severity) : undefined,
    status: req.query.status ? String(req.query.status) : undefined,
    q: req.query.q ? String(req.query.q) : undefined,
    limit: req.query.limit ? Number(req.query.limit) : undefined,
    offset: req.query.offset ? Number(req.query.offset) : undefined,
  });
  res.json(alerts.map(outputAlert));
});

// --- Alert feed & sync (realtime recovery) -------------------------------------
// PostgreSQL is the source of truth; the WebSocket only says "something changed".
// A client that has been away — or missed a frame for any reason — asks these.
//   GET /alerts/feed   the list AND the cursor it corresponds to (one snapshot)
//   GET /alerts/sync   everything that changed after a cursor, oldest first
// Neither is ever cached: a cached answer here is a missed alert.

app.get("/alerts/feed", auth, async (req: AuthedRequest, res) => {
  res.setHeader("Cache-Control", "no-store");
  const { alerts, cursor } = await store.listAlertsWithCursor(req.user!.tenant_id, {
    severity: req.query.severity ? String(req.query.severity) : undefined,
    status: req.query.status ? String(req.query.status) : undefined,
    q: req.query.q ? String(req.query.q) : undefined,
    limit: req.query.limit ? Number(req.query.limit) : undefined,
    offset: req.query.offset ? Number(req.query.offset) : undefined,
  });
  res.json({ alerts: alerts.map(outputAlert), cursor });
});

app.get("/alerts/sync", auth, async (req: AuthedRequest, res) => {
  res.setHeader("Cache-Control", "no-store");
  const q = parse(z.object({
    after: z.coerce.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
    limit: z.coerce.number().int().min(1).max(500).default(200),
  }), req.query, res); if (!q) return;
  const result = await store.syncAlerts(req.user!.tenant_id, q.after, q.limit);
  res.json({ ...result, alerts: result.alerts.map(outputAlert) });
});

app.post("/alerts", requireRole("analyst"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({ id: z.string().max(100).optional(), title: z.string().min(1).max(300), severity: z.enum(["critical", "high", "medium", "low"]), agent: z.enum(["Sentinel", "Hunter", "Guardian", "Oracle", "Executor"]), summary: z.string().min(1).max(4000), confidence: z.number().min(0).max(100).default(0), source_ip: z.string().nullable().optional(), target: z.string().nullable().optional(), mitre_technique: z.string().nullable().optional() }), req.body, res); if (!body) return;
  const id = body.id || `LGN-${randomBytes(8).toString("hex").toUpperCase()}`;
  const alert = await outbox.insertAlertAndNotify({
    ...body, id, tenant_id: req.user!.tenant_id, status: "open",
    ai_explanation: null, explained_at: null,
    source_ip: body.source_ip || null, target: body.target || null,
    mitre_technique: body.mitre_technique || null, source: "manual",
  }, {
    asset: body.target ? { name: body.target, ip: body.source_ip || null, os: null } : null,
    realtime: newAlertFrame,
  });
  // Null means the (tenant, id) pair already exists. Scoped to the tenant, so
  // a caller can no longer probe for IDs belonging to another workspace.
  if (!alert) return res.status(400).json({ detail: "Alert ID already exists" });

  await log(req, "alert.created", "alert", id);
  return res.status(201).json(outputAlert(alert));
});

app.get("/alerts/:id", auth, async (req: AuthedRequest, res) => {
  const alert = await store.getAlert(req.user!.tenant_id, String(req.params.id));
  return alert ? res.json(outputAlert(alert)) : res.status(404).json({ detail: "Alert not found" });
});

app.patch("/alerts/:id/status", requireRole("analyst"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({ status: z.enum(["open", "investigating", "resolved"]) }), req.body, res); if (!body) return;
  const alert = await store.updateAlertStatus(req.user!.tenant_id, String(req.params.id), body.status);
  if (!alert) return res.status(404).json({ detail: "Alert not found" });
  await log(req, "alert.status_updated", "alert", alert.id, body.status);
  broadcast(alert.tenant_id, { type: "alert.status_updated", alert: outputAlert(alert) });
  return res.json(outputAlert(alert));
});

app.post("/alerts/:id/explain", requireRole("analyst"), async (req: AuthedRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const alert = await store.getAlert(tenantId, String(req.params.id));
  if (!alert) return res.status(404).json({ detail: "Alert not found" });
  const locale = localeOf(res);
  const policy = await aiPolicy(tenantId);
  // A stored explanation is reused only in the language it was written in
  // (explanations from before languages existed are English), and a stored
  // local fallback does not stop a later attempt at the real thing.
  if (
    alert.ai_explanation && (alert.ai_explanation_locale ?? "en") === locale && req.query.force !== "true" &&
    (alert.ai_explanation_source !== "local" || !policy.allowed)
  ) {
    return res.json(outputAlert(alert));
  }

  // Advisory only: the model's text is stored as an explanation. Nothing it
  // says is parsed, and nothing here can act on it.
  let text: string | null = null;
  let why: AiWhy = policy.reason;
  let meta;
  if (policy.allowed) {
    if (!consumeAiQuota(tenantId).ok) why = "rate_limited";
    else {
      const r = await explainAlertSafe(alert, locale, policy.dataMode);
      meta = r.meta;
      if (r.ok) { text = r.text; why = "ok"; } else why = r.reason;
    }
  }
  const explanation = text ?? localExplanation(alert, locale);
  const updated = await store.setAlertExplanation(tenantId, alert.id, explanation, locale, text ? "ai" : "local");
  await log(req, "alert.explained", "alert", alert.id, aiAuditDetail({ outcome: text ? "ai" : "local", why, meta, mode: policy.dataMode }));
  return res.json(outputAlert(updated || alert));
});

app.get("/assets", auth, async (req: AuthedRequest, res) => {
  res.json(await store.listAssets(req.user!.tenant_id, {
    risk: req.query.risk ? String(req.query.risk) : undefined,
    online: req.query.online === undefined ? undefined : req.query.online === "true",
    q: req.query.q ? String(req.query.q) : undefined,
  }));
});

app.post("/copilot/chat", requireRole("analyst"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({ message: z.string().min(1).max(4000), history: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string().min(1).max(4000) })).max(20).default([]) }), req.body, res); if (!body) return;

  const tenantId = req.user!.tenant_id;
  const alerts = await store.recentAlerts(tenantId, 30);
  const open = alerts.filter((a) => a.status !== "resolved");

  // The model answers the actual question when the organisation allows it and
  // a provider answers; the deterministic summary below is the fallback, not
  // the product. Either way the reply is advice for a person: nothing in it is
  // acted on.
  const locale = localeOf(res);
  const policy = await aiPolicy(tenantId);
  let answer: string | null = null;
  let why: AiWhy = policy.reason;
  let meta;
  if (policy.allowed) {
    if (!consumeAiQuota(tenantId).ok) why = "rate_limited";
    else {
      const r = await copilotAnswerSafe(body.message, body.history, alerts, locale, policy.dataMode);
      meta = r.meta;
      if (r.ok) { answer = r.text; why = "ok"; } else why = r.reason;
    }
  }
  const urgent = open.find((a) => a.severity === "critical") || open.find((a) => a.severity === "high") || open[0];
  const reply = answer || copilotFallback(open, urgent, locale);

  await log(req, "copilot.chat", null, null, aiAuditDetail({ outcome: answer ? "ai" : "local", why, meta, mode: policy.dataMode, extra: `history=${body.history.length}` }));
  res.json({ reply, source: answer ? "ai" : "local", ai_generated: Boolean(answer), advisory: true, ai_status: why });
});

// --- AI settings --------------------------------------------------------------
// The organisation's own control over whether its alert text may be sent to an
// AI provider, and how much of it. Reading is for everyone signed in (the
// dashboard needs to know whether to offer AI); changing it is for administrators.

async function aiSettingsView(tenantId: string) {
  const policy = await aiPolicy(tenantId);
  return {
    enabled: policy.allowed,
    tenant_setting: policy.tenantSetting,
    default_enabled: policy.defaultEnabled,
    provider_configured: policy.provider !== null,
    // Names the third party that would receive alert text.
    provider: policy.provider,
    data_mode: policy.dataMode,
    reason: policy.reason,
    circuit: aiCircuit().state,
    advisory: true,
    limits: { max_input_chars: config.aiMaxInputChars, max_output_chars: config.aiMaxOutputChars, timeout_ms: config.aiTimeoutMs, requests_per_minute: config.aiRateLimitPerMinute },
  };
}

app.get("/ai/settings", auth, async (req: AuthedRequest, res) => {
  res.json(await aiSettingsView(req.user!.tenant_id));
});

app.patch("/ai/settings", requireRole("admin"), async (req: AuthedRequest, res) => {
  const body = parse(z.strictObject({
    enabled: z.boolean().nullable().optional(),
    data_mode: z.enum(["standard", "strict"]).optional(),
  }).refine((b) => b.enabled !== undefined || b.data_mode !== undefined, { message: "Invalid request" }), req.body ?? {}, res); if (!body) return;
  await store.updateTenantAiSettings(req.user!.tenant_id, { enabled: body.enabled, data_mode: body.data_mode });
  await log(req, "ai.settings_changed", "tenant", req.user!.tenant_id,
    [body.enabled !== undefined ? `enabled=${body.enabled === null ? "default" : body.enabled}` : "", body.data_mode ? `data_mode=${body.data_mode}` : ""].filter(Boolean).join(" "));
  res.json(await aiSettingsView(req.user!.tenant_id));
});

// --- Team management ---------------------------------------------------------

app.get("/users", requireRole("admin"), async (req: AuthedRequest, res) => {
  const users = await store.listUsers(req.user!.tenant_id);
  res.json(users.map(publicUser));
});

app.post("/users/invite", requireRole("admin"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({
    email: z.string().email().max(254).transform((v) => v.toLowerCase()),
    role: z.enum(["admin", "analyst", "viewer"]),
  }), req.body, res); if (!body) return;

  // Invitations are platform email to an address the tenant chooses: capped per tenant.
  const invitesThisHour = (await store.recentAuditCount(req.user!.tenant_id, "user.invited")) + (await store.recentAuditCount(req.user!.tenant_id, "user.invite_resent"));
  if (invitesThisHour >= config.inviteHourlyCap) return res.status(429).json({ detail: "Too many invitations. Try again later." });
  const { token: inviteToken, hash: inviteHash } = newOneTimeToken();
  let user: User;
  try {
    user = await store.insertUser({
      email: body.email, password_hash: "", tenant_id: req.user!.tenant_id,
      role: body.role, status: "invited", invite_token_hash: inviteHash,
      invite_expires: new Date(Date.now() + config.inviteDays * 86_400_000).toISOString(),
      invited_by: req.user!.id,
    });
  } catch (error) {
    // Email is the login identifier, so it has to be unique across all tenants.
    if (store.isUniqueViolation(error)) {
      return res.status(400).json({ detail: "That email address is already in use" });
    }
    throw error;
  }

  await log(req, "user.invited", "user", user.id, `${user.email} as ${user.role}`);
  const tenant = await store.getTenant(user.tenant_id);
  const inviteUrl = `${config.frontendUrl}/accept-invite?token=${inviteToken}`;
  const mail = await sendMail({
    to: user.email,
    ...inviteEmail({
      inviteUrl, tenantName: tenant?.name || "Legion",
      invitedBy: req.user!.email, role: user.role, expiresDays: config.inviteDays,
      locale: requestLocale(req),
    }),
  });
  if (!mail.sent) logUnsentLink("invitation", inviteUrl, mail.reason);

  // No-store: in development without SMTP the response carries the link.
  res.setHeader("Cache-Control", "no-store");
  return res.status(201).json({
    ...publicUser(user),
    email_sent: mail.sent,
    // Surfacing the raw link without SMTP keeps local setup usable; production
    // refuses to boot without SMTP_HOST, so this can never leak from a live server.
    invite_url: mail.sent || config.isProduction ? undefined : inviteUrl,
  });
});

app.post("/users/:id/resend-invite", requireRole("admin"), async (req: AuthedRequest, res) => {
  const user = await store.findUserInTenant(req.user!.tenant_id, String(req.params.id));
  if (!user) return res.status(404).json({ detail: "User not found" });
  if (user.status !== "invited") return res.status(400).json({ detail: "That user has already accepted their invitation" });
  const invitesThisHour = (await store.recentAuditCount(req.user!.tenant_id, "user.invited")) + (await store.recentAuditCount(req.user!.tenant_id, "user.invite_resent"));
  if (invitesThisHour >= config.inviteHourlyCap) return res.status(429).json({ detail: "Too many invitations. Try again later." });

  // Fresh token: the previous link stops working, which is what you want if
  // the first one went to the wrong inbox.
  const { token: inviteToken, hash: inviteHash } = newOneTimeToken();
  await store.updateUser(user.id, {
    invite_token_hash: inviteHash,
    invite_expires: new Date(Date.now() + config.inviteDays * 86_400_000).toISOString(),
  });
  await log(req, "user.invite_resent", "user", user.id, user.email);

  const tenant = await store.getTenant(user.tenant_id);
  const inviteUrl = `${config.frontendUrl}/accept-invite?token=${inviteToken}`;
  const mail = await sendMail({
    to: user.email,
    ...inviteEmail({ inviteUrl, tenantName: tenant?.name || "Legion", invitedBy: req.user!.email, role: user.role, expiresDays: config.inviteDays, locale: requestLocale(req) }),
  });
  if (!mail.sent) logUnsentLink("invitation", inviteUrl, mail.reason);
  res.setHeader("Cache-Control", "no-store");
  return res.json({ email_sent: mail.sent, invite_url: mail.sent || config.isProduction ? undefined : inviteUrl });
});

app.patch("/users/:id/role", requireRole("admin"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({ role: z.enum(["admin", "analyst", "viewer"]) }), req.body, res); if (!body) return;
  const user = await store.findUserInTenant(req.user!.tenant_id, String(req.params.id));
  if (!user) return res.status(404).json({ detail: "User not found" });
  if (user.role === "admin" && body.role !== "admin" && (await store.countOtherActiveAdmins(user.tenant_id, user.id)) === 0) {
    return res.status(400).json({ detail: "A tenant must keep at least one admin" });
  }
  const updated = await store.updateUser(user.id, { role: body.role, bump_token_version: true });
  // Otherwise the user keeps their old permissions until the refresh token
  // expires, which for a demotion is exactly the wrong way round.
  await revokeUserEverywhere(user.id);
  await log(req, "user.role_updated", "user", user.id, body.role);
  return res.json(publicUser(updated!));
});

/** Deactivation, not deletion: audit rows reference this user and must keep
 *  resolving to a real identity. Bumping token_version kills live sessions. */
app.delete("/users/:id", requireRole("admin"), async (req: AuthedRequest, res) => {
  const user = await store.findUserInTenant(req.user!.tenant_id, String(req.params.id));
  if (!user) return res.status(404).json({ detail: "User not found" });
  if (user.id === req.user!.id) return res.status(400).json({ detail: "You cannot deactivate your own account" });
  if (user.role === "admin" && (await store.countOtherActiveAdmins(user.tenant_id, user.id)) === 0) {
    return res.status(400).json({ detail: "A tenant must keep at least one admin" });
  }
  const updated = await store.updateUser(user.id, {
    status: "disabled", invite_token_hash: null, invite_expires: null, reset_token_hash: null, reset_expires: null, bump_token_version: true,
  });
  await revokeUserEverywhere(user.id);
  await log(req, "user.deactivated", "user", user.id, user.email);
  return res.json(publicUser(updated!));
});

app.get("/audit", requireRole("admin"), async (req: AuthedRequest, res) => {
  res.json(await store.listAudit(req.user!.tenant_id, {
    action: req.query.action ? String(req.query.action) : undefined,
    resource_id: req.query.resource_id ? String(req.query.resource_id) : undefined,
    limit: req.query.limit ? Number(req.query.limit) : undefined,
  }));
});

/** Delivery state of this organisation's notifications — including the ones
 *  that failed for good ('dead'), which would otherwise go unnoticed. */
app.get("/notifications/deliveries", requireRole("admin"), async (req: AuthedRequest, res) => {
  res.json({ deliveries: await outbox.listDeliveries(req.user!.tenant_id) });
});

/** Queue health for this organisation: backlog, retries, dead letters and
 *  how long the oldest undelivered notification has been waiting. */
app.get("/notifications/health", requireRole("admin"), async (req: AuthedRequest, res) => {
  res.json(await outbox.queueMetrics(req.user!.tenant_id));
});

app.get("/notifications/settings", requireRole("admin"), async (req: AuthedRequest, res) => {
  const tenant = await store.getTenant(req.user!.tenant_id);
  res.json({
    notification_email: tenant?.notification_email ?? null,
    pending_notification_email: tenant?.notification_email_pending ?? null,
    notification_locale: tenant?.notification_locale ?? "en",
  });
});

const NOTIFY_CONFIRM_HOURS = 48;

/**
 * Where alert emails go. A NEW address receives nothing until its owner
 * confirms it: otherwise any administrator — in hosted mode, anyone who signs
 * up — could have this platform deliver sensor-written text to any inbox, from
 * the platform's own domain. The address in effect stays in effect meanwhile.
 */
app.patch("/notifications/settings", requireRole("admin"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({
    notification_email: z.string().max(254).email().nullable(),
    // Optional so older dashboards that only send the address keep working.
    notification_locale: z.enum(["en", "ru", "uz"]).optional(),
  }), req.body, res); if (!body) return;
  const tenantId = req.user!.tenant_id;
  const before = await store.getTenant(tenantId);
  const requested = body.notification_email?.toLowerCase() ?? null;
  let confirmationSent = false;

  if (body.notification_locale) await store.setNotificationLocale(tenantId, body.notification_locale);
  if (requested === null) {
    // Stopping email needs no confirmation.
    await store.setNotificationEmail(tenantId, null);
    await store.clearPendingNotificationEmail(tenantId);
  } else if (requested === before?.notification_email?.toLowerCase()) {
    await store.clearPendingNotificationEmail(tenantId);
  } else {
    // A new address, or the same pending one saved again (resends the link).
    if ((await store.recentAuditCount(tenantId, "notifications.confirmation_sent")) >= config.notificationConfirmHourlyCap) {
      return res.status(429).json({ detail: "Too many confirmation emails. Try again later." });
    }
    const { token, hash } = newOneTimeToken();
    await store.requestNotificationEmail(tenantId, requested, hash, new Date(Date.now() + NOTIFY_CONFIRM_HOURS * 3_600_000));
    const url = `${config.frontendUrl}/confirm-notification-email?token=${token}`;
    const mail = await sendMail({
      to: requested,
      ...notificationConfirmEmail({ url, tenantName: before?.name ?? "Legion", requestedBy: req.user!.email, hours: NOTIFY_CONFIRM_HOURS, locale: before?.notification_locale ?? "en" }),
    });
    if (!mail.sent) logUnsentLink("notification address confirmation", url, mail.reason);
    confirmationSent = mail.sent;
    await log(req, "notifications.confirmation_sent", "tenant", tenantId, requested);
  }
  await log(req, "notifications.settings_updated");
  const tenant = await store.getTenant(tenantId);
  res.json({
    notification_email: tenant?.notification_email ?? null,
    pending_notification_email: tenant?.notification_email_pending ?? null,
    confirmation_sent: confirmationSent,
    notification_locale: tenant?.notification_locale ?? "en",
  });
});

/** The owner of a requested address confirms it (link from the confirmation email). */
app.post("/notifications/confirm", authLimiter, async (req, res) => {
  const body = parse(z.object({ token: z.string().min(20).max(200) }), req.body, res); if (!body) return;
  const confirmed = await store.confirmNotificationEmail(hashOneTimeToken(body.token));
  if (!confirmed) return res.status(400).json({ detail: "This confirmation link is invalid or has expired." });
  await store.audit({ tenant_id: confirmed.id, user_id: null, user_email: confirmed.notification_email, action: "notifications.email_confirmed", resource_type: "tenant", resource_id: confirmed.id, detail: confirmed.notification_email, ip_address: req.ip || null });
  return res.json({ message: "Address confirmed. Security alerts will be sent here." });
});

app.post("/notifications/test", requireRole("admin"), async (req: AuthedRequest, res) => {
  const tenantId = req.user!.tenant_id;
  if ((await store.recentAuditCount(tenantId, "notifications.test")) >= config.notificationTestHourlyCap) {
    return res.status(429).json({ detail: "Too many test emails. Try again later." });
  }
  await log(req, "notifications.test");
  const tenant = await store.getTenant(tenantId);
  const to = tenant?.notification_email;
  if (!to) return res.status(400).json({ detail: "Set a notification email address first" });
  if (!mailEnabled()) return res.json({ status: "skipped: SMTP is not configured (set SMTP_HOST)", message: "SMTP is not configured (set SMTP_HOST)" });
  // SMTP errors name the mail host, relay and account. They go to the server
  // log (sanitised), not to a tenant administrator.
  const check = await verifyMail();
  if (!check.sent) {
    console.error(`Legion: SMTP check failed: ${outbox.sanitizeError(String(check.detail || check.reason))}`);
    return res.status(502).json({ detail: "The mail server could not be reached. Your administrator can see the details in the server log." });
  }
  // In the language alert emails will use, so the test shows what arrives.
  const result = await sendMail({ to, ...testNotificationEmail(tenant?.notification_locale ?? "en") });
  if (!result.sent) console.error(`Legion: test email failed: ${outbox.sanitizeError(String(result.detail || result.reason))}`);
  return result.sent
    ? res.json({ status: `sent to ${to}`, message: `Test email sent to ${to}` })
    : res.status(502).json({ detail: "The test email could not be sent. Your administrator can see the details in the server log." });
});

// --- Billing -----------------------------------------------------------------

// Billing belongs to the hosted service. A self-hosted customer bought the
// software; there is nothing here for them, and leaving the routes live would
// invite them to configure a Paddle account they do not need.
app.use("/billing", (_req, res, next) => {
  if (isSelfHosted()) {
    return res.status(404).json({ detail: "Billing is not available on a self-hosted installation" });
  }
  next();
});

app.get("/billing/subscription", auth, async (req: AuthedRequest, res) => {
  const tenantId = req.user!.tenant_id;
  const [sub, tenant, state] = await Promise.all([
    store.getSubscription(tenantId), store.getTenant(tenantId), accessState(tenantId),
  ]);
  if (!sub) {
    return res.status(404).json({
      detail: "No subscription on file for this tenant yet",
      trial_ends_at: tenant?.trial_ends_at || null,
      access_state: state,
    });
  }
  return res.json({ ...sub, access_state: state, trial_ends_at: tenant?.trial_ends_at || null });
});

app.post("/billing/checkout-context", requireRole("admin"), (req: AuthedRequest, res) => res.json({ checkout_token: jwt.sign({ purpose: "paddle_checkout", tenant_id: req.user!.tenant_id }, config.jwtSecret, { algorithm: "HS256", expiresIn: "1h" }) }));

app.post("/billing/portal", requireRole("admin"), async (req: AuthedRequest, res) => {
  if (!paddleConfigured()) return res.status(503).json({ detail: "Paddle is not configured" });
  const sub = await store.getSubscription(req.user!.tenant_id);
  if (!sub?.paddle_customer_id) {
    return res.status(404).json({ detail: "No Paddle customer on file for this tenant yet" });
  }
  const session = await createPortalSession(
    sub.paddle_customer_id,
    sub.paddle_subscription_id ? [sub.paddle_subscription_id] : []
  );
  if (!session.ok) return res.status(session.status).json({ detail: session.detail });
  await log(req, "billing.portal_opened");
  return res.json({ url: session.url });
});

// --- Paddle Billing webhook -------------------------------------------------
// Subscriptions only ever become active through this endpoint. The tenant is
// identified by the checkout_token minted by POST /billing/checkout-context,
// so a browser can never claim a subscription for someone else's tenant.
interface PaddleSubscriptionData {
  id?: string;
  status?: string;
  customer_id?: string;
  current_billing_period?: { ends_at?: string } | null;
  scheduled_change?: { action?: string } | null;
  items?: Array<{ price?: { id?: string } }>;
  custom_data?: Record<string, unknown> | null;
}

const subscriptionStatuses = new Set<Subscription["status"]>([
  "trialing", "active", "past_due", "paused", "canceled",
]);

function tenantFromCustomData(customData: Record<string, unknown> | null | undefined): string | null {
  const raw = customData?.["checkout_token"];
  if (typeof raw !== "string") return null;
  try {
    // Expiry is deliberately ignored here. The token only has to prove which
    // tenant opened the checkout (our signature, our purpose); the event itself
    // is proven genuine by Paddle's signature. If Legion was down when the
    // customer paid, Paddle retries for hours — an expired token must not
    // turn a real payment into an unassigned one.
    const claims = jwt.verify(raw, config.jwtSecret, { algorithms: ["HS256"], ignoreExpiration: true }) as Token;
    if (claims.purpose !== "paddle_checkout") return null;
    return claims.tenant_id || null;
  } catch {
    return null;
  }
}

app.post("/billing/webhook", async (req, res) => {
  const check = verifyPaddleSignature(
    req.header("paddle-signature"),
    (req as Request & { rawBody?: Buffer }).rawBody,
    config.paddleWebhookSecret
  );
  if (!check.ok) {
    const status = check.reason.includes("not configured") ? 503 : 401;
    return res.status(status).json({ detail: check.reason });
  }

  const eventType = String(req.body?.event_type || "");
  const occurredAt = String(req.body?.occurred_at || now());
  if (!eventType.startsWith("subscription.")) {
    return res.status(202).json({ status: "ignored", event_type: eventType });
  }

  const payload = (req.body?.data || {}) as PaddleSubscriptionData;
  if (!payload.id) return res.status(202).json({ status: "skipped", reason: "no subscription id" });

  const existing = await store.getSubscriptionByPaddleId(payload.id);
  let tenantId = existing?.tenant_id;
  if (!tenantId) {
    // First event for this subscription: bind it to a tenant via the token.
    tenantId = tenantFromCustomData(payload.custom_data) || undefined;
    if (!tenantId) {
      // A paid subscription Legion cannot attribute is money without access.
      // Say so loudly; the operator can match it in the Paddle dashboard.
      console.error(`Paddle ${eventType} for subscription ${payload.id} (customer ${payload.customer_id ?? "?"}) has no valid checkout_token — not assigned to any workspace.`);
      return res.status(202).json({ status: "skipped", reason: "no valid checkout_token in custom_data" });
    }
    if (!(await store.tenantExists(tenantId))) {
      return res.status(400).json({ detail: "Unknown tenant" });
    }
  }

  const status = payload.status as Subscription["status"] | undefined;
  const resolved: Subscription["status"] =
    eventType === "subscription.canceled" ? "canceled"
      : status && subscriptionStatuses.has(status) ? status
        : existing?.status || "trialing";

  // Ordering is enforced inside the statement — Paddle does not guarantee
  // delivery order, and a stale retry must not overwrite newer state.
  const record = await store.applySubscriptionEvent({
    tenant_id: tenantId,
    status: resolved,
    paddle_customer_id: payload.customer_id || existing?.paddle_customer_id || "",
    paddle_subscription_id: payload.id,
    paddle_price_id: payload.items?.[0]?.price?.id || existing?.paddle_price_id || null,
    current_period_end: payload.current_billing_period?.ends_at || null,
    cancel_at_period_end: payload.scheduled_change?.action === "cancel",
    last_event_at: occurredAt,
  });

  if (!record) return res.status(202).json({ status: "skipped", reason: "stale event" });

  await store.audit({
    tenant_id: record.tenant_id, user_id: null, user_email: null,
    action: `billing.${eventType}`, resource_type: "subscription",
    resource_id: payload.id, detail: record.status, ip_address: req.ip || null,
  });
  return res.status(202).json({ status: "processed", subscription_status: record.status });
});

// --- Security event ingestion ------------------------------------------------

app.get("/security-events/providers", requireRole("admin"), async (req: AuthedRequest, res) => {
  const configured = await webhookCredentials.hasUsableCredential(req.user!.tenant_id);
  res.json({ providers: ["mock", "webhook"], active: configured ? "webhook" : "mock", webhook_configured: configured });
});

// --- Webhook credentials (administrators) --------------------------------------
// Each organisation holds its own random credentials; see webhook-credentials.ts.
// The secret is shown once, in the response that creates it, and never again.

const noStore = (res: Response) => res.setHeader("Cache-Control", "no-store");

function credentialFailure(res: Response, error: unknown): Response {
  if (error instanceof webhookCredentials.CredentialError) {
    return res.status(error.code === "not_found" ? 404 : 409).json({ detail: error.message });
  }
  throw error;
}

app.get("/security-events/credentials", requireRole("admin"), async (req: AuthedRequest, res) => {
  res.json({ credentials: await webhookCredentials.listCredentials(req.user!.tenant_id) });
});

app.post("/security-events/credentials", requireRole("admin"), async (req: AuthedRequest, res) => {
  const body = parse(z.object({ label: z.string().trim().max(100).optional() }), req.body ?? {}, res); if (!body) return;
  try {
    const issued = await webhookCredentials.createCredential(req.user!.tenant_id, { label: body.label, createdBy: req.user!.id });
    await log(req, "webhook.credential_created", "webhook_credential", issued.id);
    noStore(res);
    return res.status(201).json(issued);
  } catch (error) { return credentialFailure(res, error); }
});

app.post("/security-events/credentials/:id/rotate", requireRole("admin"), async (req: AuthedRequest, res) => {
  const keyId = String(req.params.id);
  if (!isKeyId(keyId)) return res.status(404).json({ detail: "Webhook credential not found" });
  const body = parse(z.object({ overlap_hours: z.number().min(0).max(168).optional() }), req.body ?? {}, res); if (!body) return;
  try {
    const { issued, previous } = await webhookCredentials.rotateCredential(req.user!.tenant_id, keyId, { overlapHours: body.overlap_hours, createdBy: req.user!.id });
    await log(req, "webhook.credential_rotated", "webhook_credential", keyId, `replaced by ${issued.id}`);
    noStore(res);
    return res.status(201).json({ ...issued, previous });
  } catch (error) { return credentialFailure(res, error); }
});

app.delete("/security-events/credentials/:id", requireRole("admin"), async (req: AuthedRequest, res) => {
  const keyId = String(req.params.id);
  if (!isKeyId(keyId)) return res.status(404).json({ detail: "Webhook credential not found" });
  try {
    await webhookCredentials.revokeCredential(req.user!.tenant_id, keyId);
    await log(req, "webhook.credential_revoked", "webhook_credential", keyId);
    return res.json({ status: "revoked", id: keyId });
  } catch (error) { return credentialFailure(res, error); }
});

app.post("/security-events/sync", requireRole("admin"), async (req: AuthedRequest, res) => {
  const id = `SEC-${randomBytes(8).toString("hex").toUpperCase()}`;
  const alert = await outbox.insertAlertAndNotify({
    id, tenant_id: req.user!.tenant_id, title: "Mock provider: suspicious authentication burst",
    severity: "high", agent: "Hunter", status: "open",
    summary: "Multiple failed sign-in events were observed by the local Node provider.",
    confidence: 86, ai_explanation: null, explained_at: null,
    source_ip: "198.51.100.24", target: "identity-gateway", mitre_technique: "T1110", source: "mock",
  }, {
    asset: { name: "identity-gateway", ip: "198.51.100.24", os: null },
    realtime: newAlertFrame,
  });
  if (!alert) return res.json({ fetched: 1, ingested: 0, skipped: 1 });
  await log(req, "security_events.sync", "alert", id);
  res.json({ fetched: 1, ingested: 1, skipped: 0 });
});

/**
 * Sensor ingestion (Wazuh and anything that speaks the same shape).
 *
 * Deliberately NOT subject to the subscription gate: dropping a customer's
 * telemetry because an invoice is late would leave a hole in their security
 * history that can never be backfilled. Billing state limits the UI, not the
 * recording of events.
 */
app.post(WEBHOOK_PATH,
  // Refuses an address that keeps failing BEFORE its body is read.
  webhookFailureGate,
  // Raw bytes only, JSON content types only; nothing is parsed yet.
  express.raw({ type: "application/json", limit: config.webhookMaxBodyBytes }),
  async (req, res) => {
  // The organisation is whatever the credential belongs to. Nothing the sender
  // types — including the old x-tenant-id header, which is only cross-checked —
  // can choose it. See webhook-auth.ts for the scheme.
  const rawBody = Buffer.isBuffer(req.body) ? req.body : undefined;
  const auth = await webhookCredentials.authenticateWebhook({
    header: (name) => req.header(name),
    rawBody,
    claimedTenantId: req.header("x-tenant-id"),
  });
  if (!auth.ok) {
    // What is logged is fixed vocabulary plus a key id that already passed a
    // strict format check — never a header value, a signature or a secret.
    console.warn(`Legion: rejected webhook (${auth.cause}) key=${auth.keyId ? auth.keyId.slice(0, 8) : "-"} ip=${req.ip || "unknown"}`);
    return res.status(401).json({ detail: WEBHOOK_REJECTION_DETAIL[auth.reason] });
  }
  const tenantId = auth.tenantId;

  // Only now — the bytes are proven to come from the credential's holder — is
  // the body parsed. A signed document that is not valid JSON is the sender's
  // bug: 400, no stack trace.
  let body: { event?: unknown; provider?: unknown } & Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(rawBody!.toString("utf8"));
    body = parsed !== null && typeof parsed === "object" ? parsed as typeof body : {};
  } catch {
    return res.status(400).json({ detail: "Invalid request" });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const event: any = body.event || body;
  const description = String(event?.rule?.description || "");
  if (!description) return res.status(202).json({ status: "skipped" });

  const source = String(body.provider || "webhook");
  const rawId = String(event.id || JSON.stringify(event));
  const id = `SEC-${createHmac("sha256", config.webhookSecret || "legion-webhook-event-id").update(`${tenantId}:${source}:${rawId}`).digest("hex").slice(0, 16).toUpperCase()}`;

  const level = Number(event.rule?.level || 0);
  // Whatever the sensor sends is bounded and shaped before it is stored: these
  // fields feed prompts and analyst-facing suggestions, and are attacker-
  // influenced. (The original text remains in the summary/full_log.)
  const srcip = typeof event.data?.srcip === "string" && isIp(event.data.srcip) ? event.data.srcip : null;
  const severity: Severity = level >= 12 ? "critical" : level >= 9 ? "high" : level >= 5 ? "medium" : "low";
  const agentName = event.agent?.name ? clip(String(event.agent.name), 255) : null;

  // One transaction: the alert, the asset it came from, its email and its
  // dashboard frame. 202 is only sent after that commit, and nothing here
  // waits on SMTP or Redis — the outbox worker does that, with retries. If the
  // commit fails the request fails (5xx) and the sensor retries; nothing was
  // stored, so the retry is not a duplicate.
  const alert = await outbox.insertAlertAndNotify({
    id, tenant_id: tenantId, title: clip(description, 300), severity, agent: "Sentinel", status: "open",
    summary: String(event.full_log || description).slice(0, 4000),
    confidence: Math.min(100, level * 7), ai_explanation: null, explained_at: null,
    source_ip: srcip, target: agentName,
    mitre_technique: Array.isArray(event.rule?.mitre?.id) ? clip(event.rule.mitre.id.map(String).join(", "), 200) || null : null, source,
  }, {
    // Turns the asset inventory into live data from the sensors instead of a
    // static seed list.
    asset: agentName ? {
      name: agentName,
      ip: event.agent?.ip ? String(event.agent.ip) : null,
      os: event.agent?.os?.name ? String(event.agent.os.name) : null,
    } : null,
    realtime: newAlertFrame,
  });
  // Idempotent by construction: retries from the sensor collapse onto the same
  // primary key instead of creating duplicates.
  if (!alert) return res.status(202).json({ status: "skipped", reason: "duplicate", alert_id: id });
  return res.status(202).json({ status: "ingested", alert_id: id });
  });

app.use((_req, res) => res.status(404).json({ detail: "Not found" }));
app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  // Not the whole error object: a Postgres error's `detail` carries the
  // failing row ("Failing row contains (…)") — alert text, addresses, tokens.
  const e = error as { name?: string; code?: string; message?: string; status?: number; expose?: boolean };
  // A body the parser refused (malformed JSON, too large) is the sender's
  // mistake, not ours: 4xx, and nothing worth logging as an error.
  if (typeof e?.status === "number" && e.status >= 400 && e.status < 500 && e.expose) {
    return res.status(e.status).json({ detail: "Invalid request" });
  }
  console.error(`Unhandled error: ${e?.name ?? "Error"}${e?.code ? ` [${e.code}]` : ""}: ${e?.message ?? "unknown"}`);
  res.status(500).json({ detail: "Internal server error" });
});

// --- Realtime ----------------------------------------------------------------

// Clients only receive; nothing legitimate sends more than a ping.
const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024 });
httpServer.on("upgrade", (request, socket, head) => {
  void (async () => {
    if (request.url?.split("?")[0] !== "/ws/alerts") return socket.destroy();
    const refuse = (status: string) => { socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); socket.destroy(); };
    // Cross-site WebSocket hijacking: the browser attaches the session cookie to
    // a handshake started by ANY page, so the Origin must be one of ours.
    // Checked before anything touches the database.
    if (checkWebSocketOrigin(request.headers.origin) !== "ok") return refuse("403 Forbidden");
    if (upgradeRateLimited(clientAddress(app, request))) return refuse("429 Too Many Requests");
    // Cookie only. A `?token=` fallback would put the JWT into proxy logs,
    // access logs and browser history for every realtime connection.
    const cookieToken = request.headers.cookie?.split(";").map((x) => x.trim()).find((x) => x.startsWith("legion_token="))?.split("=").slice(1).join("=");
    const payload = verifyToken(cookieToken);
    // A purpose-scoped token (the MFA challenge) is not a session.
    const user = payload && !payload.purpose ? await store.findUserById(payload.sub) : null;

    const valid = user
      && payload!.tenant_id === user.tenant_id
      && payload!.token_version === user.token_version
      && user.status === "active"
      && (await accessState(user.tenant_id)) !== "blocked";

    if (!valid) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      return socket.destroy();
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
      (ws as WebSocket & { tenantId?: string; grant?: realtime.SocketGrant }).tenantId = user!.tenant_id;
      // The tenant comes from the user record, never from the request; the
      // grant is what lets the socket be re-authorized later.
      (ws as WebSocket & { grant?: realtime.SocketGrant }).grant = {
        userId: user!.id, tokenVersion: user!.token_version,
        // The socket lives no longer than the access token that opened it.
        expiresAt: typeof payload!.exp === "number" ? payload!.exp * 1000 : Date.now() + config.accessTokenMinutes * 60_000,
        tokenHash: createHash("sha256").update(cookieToken!).digest("hex"),
      };
      wss.emit("connection", ws, request);
    });
  })().catch((error) => {
    console.error("WebSocket upgrade failed:", error);
    socket.destroy();
  });
});

wss.on("connection", (ws: WebSocket & { tenantId?: string; grant?: realtime.SocketGrant }) => {
  const tenantId = ws.tenantId!;
  realtime.register(tenantId, ws, ws.grant);
  ws.on("close", () => realtime.unregister(tenantId, ws));
  // A socket error must not take the process down; onclose owns the cleanup.
  ws.on("error", () => {});
  // The client's cue to fetch whatever it missed while it was not connected.
  // Read from Postgres, like every cursor.
  store.alertCursor(tenantId)
    .then((cursor) => { if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ type: "hello", cursor })); })
    .catch(() => { /* the client's own reconciliation covers it */ });
});

// --- Boot --------------------------------------------------------------------

// Importing this module from a test must not bind a port or run migrations —
// the suite owns that lifecycle itself.
if (process.env.NODE_ENV !== "test") {
  // The API must not hold the database superuser (db/provision.ts). Refused
  // in production; said out loud everywhere else.
  const roleDecision = databaseRoleDecision(await currentRoleAttributes(), {
    production: config.isProduction, allowPrivileged: config.dbAllowPrivilegedRole,
  });
  if (roleDecision.action === "refuse") throw new Error(`Refusing to start: ${roleDecision.message}`);
  if (roleDecision.action === "warn") console.warn(`Legion: WARNING — ${roleDecision.message}`);
  await migrate();
  // Encrypts any TOTP seed still in plaintext and moves every sealed secret to
  // the active key. Never fatal and never destructive: an unreadable secret is
  // left as it is and reported (see secrets-migration.ts).
  try {
    const report = await migrateSecretsAtRest();
    const changed = report.mfa.converted + report.mfa.rotated + report.webhook.converted + report.webhook.rotated;
    if (changed || report.mfa.unreadable || report.webhook.unreadable) console.info(describeReport(report));
    if (report.mfa.unreadable || report.webhook.unreadable) {
      console.error("Legion: WARNING — some stored secrets cannot be decrypted with LEGION_ENCRYPTION_KEYS. Those users' two-factor sign-in (and those webhook credentials) are refused until the missing key is restored. Run: npm run secrets -w server -- status");
    }
  } catch (error) {
    console.error("Legion: secrets-at-rest migration failed:", error instanceof Error ? error.message : "unknown error");
  }
  if (keyringStatus().source === "dev") {
    console.warn("Legion: LEGION_ENCRYPTION_KEYS is not set — two-factor and webhook secrets are encrypted with a development key derived from JWT_SECRET. Development only.");
  }
  await seedDemoIfEmpty();

  // Self-hosted and not set up yet: nobody can use this install until the
  // person at the console creates the first administrator with this token.
  if (isSelfHosted()) {
    const banner = setupBanner(await ensureSetupToken(), config.frontendUrl);
    if (banner) console.info(banner);
  }

  // Not fatal: AI is optional and every caller falls back to local analysis.
  // But a silently-off provider is the kind of thing an operator discovers
  // weeks later, so it is said out loud once at boot.
  for (const warning of aiConfigWarnings(config)) console.warn(`Legion: ${warning}`);
  const provider = aiProviderName();
  console.info(
    provider
      ? `Legion: AI analysis via ${provider} — alert text will be sent there.`
      : "Legion: AI analysis off — no alert data leaves this server."
  );
  // Bounded: never blocks boot, even when Redis is unreachable.
  await initRateLimitStore();
  await realtime.initRealtime();
  // Sends each connected tenant its current cursor, from Postgres, so a client
  // that missed a frame notices without waiting for anything to be published.
  realtime.startHeartbeat(store.listTenantCursors, config.wsHeartbeatSeconds * 1000);
  // Live sockets are re-authorized on the same cadence: a user deactivated or a
  // tenant blocked on ANY instance stops receiving events within one interval.
  realtime.startRevalidation(socketGrantsStillValid, config.wsHeartbeatSeconds * 1000);

  // Delivers queued alert emails and retries failed ones (outbox.ts).
  outbox.startOutboxWorker();
  // Retries failed agent-suspension notices and purges expired agent tokens.
  const stopAgentJobs = agentLayer.identity.startBackgroundJobs();

  // Refresh tokens accumulate one row per rotation — every active user adds
  // one every few minutes — so dead rows have to be swept.
  const prune = async () => {
    try {
      const removed = await sessions.pruneExpired();
      if (removed > 0) console.info(`Pruned ${removed} expired session token(s).`);
    } catch (error) {
      console.error("Session prune failed:", error instanceof Error ? error.message : error);
    }
  };
  void prune();
  // unref() so this timer never holds the process open during a shutdown.
  setInterval(prune, 6 * 60 * 60 * 1000).unref();
  for (const warning of saasWarnings(config)) console.warn(`Legion (hosted): ${warning}`);
  if (config.isProduction && !config.backupStatusFile) {
    console.warn("Legion: WARNING — BACKUP_STATUS_FILE is not set, so /health/backup cannot report on backups. Run ops/check-backup.sh from a timer (RECOVERY.md).");
  }
  console.info(`Legion: trusting proxies — ${trustedProxies.description}.`);
  if (trustedProxies.byHopCount && config.bindAddress !== "127.0.0.1" && config.bindAddress !== "::1") {
    console.warn(
      "Legion: WARNING — TRUSTED_PROXIES trusts hops by position and the API listens on " +
      `${config.bindAddress}. Anything that can reach this port directly can forge its client address; ` +
      "firewall the port to the proxy, or list the proxy's address instead of a hop count."
    );
  }
  if (config.isProduction && config.wsAllowMissingOrigin) {
    console.warn("Legion: WARNING — WS_ALLOW_MISSING_ORIGIN=true lets non-browser WebSocket clients connect without an Origin.");
  }
  // Slow-loris bounds. Generous for a 256 KB body limit; response streaming is unaffected.
  httpServer.headersTimeout = 30_000;
  httpServer.requestTimeout = 60_000;
  httpServer.listen(config.port, config.bindAddress, () =>
    console.info(`Legion Node API: http://localhost:${config.port} (listening on ${config.bindAddress})`)
  );

  let shuttingDown = false;
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.on(signal, () => {
      if (shuttingDown) return;
      shuttingDown = true;
      console.info(`${signal} received — draining connections.`);
      outbox.stopOutboxWorker(); // undelivered rows stay queued for the next start
      realtime.stopHeartbeat();
      realtime.stopRevalidation();
      stopAgentJobs();
      httpServer.close(() => {
        Promise.allSettled([closePool(), closeRateLimitStore(), realtime.closeRealtime()])
          .then((results) => {
            for (const result of results) {
              if (result.status === "rejected") console.error("Shutdown step failed:", result.reason);
            }
          })
          .finally(() => process.exit(0));
      });
      // Don't let a hung connection hold the deploy open forever.
      setTimeout(() => process.exit(0), 10_000).unref();
    });
  }
}
