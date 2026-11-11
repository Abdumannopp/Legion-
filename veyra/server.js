require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {
  httpError,
  readPositiveInteger,
  parsePositiveNumber,
  parseMoney: parseMoneyUpTo,
  parseIsoDate,
  parseShipmentId,
  normalizePlate,
  readOptionalText,
  readOptionalPhone,
  parseEta
} = require('./lib/validation');
const {
  BCRYPT_COST,
  DEFAULT_TENANT_ID,
  ALLOWED_ROLES,
  CARRIER_MODES,
  CARRIER_MANUAL_STATUSES,
  initialize,
  getTenant,
  listTenants,
  createTenantWithAdmin,
  setTenantGpsTokenHash,
  findTenantByGpsTokenHash,
  setTenantInboxTokenHash,
  findTenantByInboxTokenHash,
  setTenantInboxAllowedSenders,
  setTenantMessagingSettings,
  createInboxItem,
  addInboxAttachment,
  getInboxAttachmentFile,
  deleteInboxAttachments,
  moveInboxAttachmentsToShipment,
  findShipmentIdsByReference,
  findMessageByCallbackTokenHash,
  recordMessageDelivery,
  getRouteData,
  getPulseData,
  listSentinelLoads,
  getInboxItem,
  listInboxItems,
  countInboxItemsToday,
  updateInboxItem,
  listTasks,
  getTask,
  resolveTask,
  resolveTasksByKey,
  addDocument,
  getDocument,
  listDocuments,
  getDocumentFile,
  updateDocumentExtraction,
  deleteDocument,
  findUserByEmail,
  findUserById,
  updateUser,
  createUser,
  listUsers,
  createAuthSession,
  isAuthSessionActive,
  revokeAuthSession,
  getRateLimitStatus,
  consumeRateLimit,
  recordRateLimitAttempts,
  clearRateLimitAttempts,
  listShipments,
  searchShipments,
  getShipment,
  updateShipmentStatus,
  createShipment,
  dispatchShipment,
  addTrackingUpdate,
  recordGpsPositions,
  listTrackingUpdates,
  listShipmentEvents,
  createMessage,
  listMessages,
  recordAgentTask,
  getAgentUsage,
  listCarriersWithStats,
  getScoutData,
  createCarrier,
  updateCarrierStatus,
  getAnalyticsReport,
  getDashboardPayload,
  getAlerts
} = require('./database');
const aiGateway = require('./ai/gateway');
const flowAgent = require('./agents/flow');
const scoutAgent = require('./agents/scout');
const relayAgent = require('./agents/relay');
const vaultAgent = require('./agents/vault');
const routeAgent = require('./agents/route');
const pulseAgent = require('./agents/pulse');
const sentinelAgent = require('./agents/sentinel');
const nexus = require('./agents/nexus');
const { parseInbound, senderAllowed, mentionedShipmentIds, guessDocumentType } = require('./lib/inbound-email');
const messaging = require('./integrations/messaging');

const REGISTRATION_INVITE_CODE = process.env.REGISTRATION_INVITE_CODE || '';
const MAX_LEN = {
  carrierName: 120, name: 120, email: 254, customer: 120, reference: 80, origin: 160, destination: 160, trackingNumber: 80, note: 500,
  phone: 40, contactName: 120, driverName: 120, driverPhone: 40, truckPlate: 20, location: 160, companyName: 120, message: 1000
};
// bcrypt only uses the first 72 bytes of a password; longer input would be silently cut.
const MAX_PASSWORD_BYTES = 72;

// Same hash cost as real accounts, so a login for an unknown email takes as long as a real one.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_COST);

const ROLE_PERMISSIONS = {
  admin: ['*'],
  operations: ['analytics:read', 'dashboard:read', 'carriers:read', 'carriers:write', 'shipments:read', 'shipments:create', 'shipments:status', 'shipments:dispatch', 'shipments:track', 'shipments:message', 'shipments:document', 'users:read'],
  // Dispatchers log where the truck is ("check calls") and message drivers, but cannot book or change status.
  operator: ['dashboard:read', 'carriers:read', 'shipments:read', 'shipments:create', 'shipments:track', 'shipments:message', 'shipments:document']
};

const app = express();
// Production is the default; development must be requested explicitly (NODE_ENV=development).
const isProduction = process.env.NODE_ENV !== 'development';
const PORT = process.env.PORT || 3000;
// Development mode has demo accounts with published passwords, so by default it only listens on this machine.
const HOST = process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1');
const JWT_SECRET = process.env.JWT_SECRET || (isProduction ? null : 'veyra-dev-secret');

// Region settings: one product, configured per deployment (kg or lb, local currency, message language).
const WEIGHT_UNIT = ['kg', 'lb'].includes(String(process.env.WEIGHT_UNIT).toLowerCase()) ? String(process.env.WEIGHT_UNIT).toLowerCase() : 'kg';
const CURRENCY = /^[A-Z]{3}$/.test(String(process.env.CURRENCY || '')) ? process.env.CURRENCY : 'USD';
const MESSAGE_LANGUAGE = relayAgent.LANGUAGES.includes(String(process.env.MESSAGE_LANGUAGE || '').toLowerCase()) ? String(process.env.MESSAGE_LANGUAGE).toLowerCase() : 'en';
const EQUIPMENT = ['Dry Van', 'Tent / Curtainsider', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
const MAX_WEIGHT = 1000000;
// Sanity bound for money fields. Raise MAX_RATE for currencies with large numbers (e.g. UZS).
const MAX_RATE = readPositiveInteger(process.env.MAX_RATE, 10000000);
// A booked truck nobody has checked on for this long is flagged.
const STALE_TRACKING_HOURS = readPositiveInteger(process.env.STALE_TRACKING_HOURS, 12);
const GPS_MIN_INTERVAL_MINUTES = readPositiveInteger(process.env.GPS_MIN_INTERVAL_MINUTES, 15);
const GPS_WEBHOOK_PATH = '/api/integrations/gps';
const INBOX_WEBHOOK_PREFIX = '/api/integrations/inbox/';
const INBOX_DAILY_LIMIT = readPositiveInteger(process.env.INBOX_DAILY_LIMIT, 200);
// Automatic AI work (reading emails and documents) stops at this many AI calls per company per day.
const AI_DAILY_LIMIT_PER_TENANT = readPositiveInteger(process.env.AI_DAILY_LIMIT_PER_TENANT, 300);
const DOC_MAX_BYTES = readPositiveInteger(process.env.DOC_MAX_MB, 8) * 1024 * 1024;
const DOC_MAX_PER_SHIPMENT = readPositiveInteger(process.env.DOC_MAX_PER_SHIPMENT, 20);
const DOC_MIME_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];
// Emails with files: the whole email may be this large, and at most this many files are kept.
const INBOX_MAX_BYTES = readPositiveInteger(process.env.INBOX_MAX_MB, 15) * 1024 * 1024;
const INBOX_MAX_ATTACHMENTS = readPositiveInteger(process.env.INBOX_MAX_ATTACHMENTS, 5);
// Small pictures in an email are almost always signature logos, not documents.
const INBOX_MIN_IMAGE_BYTES = 10 * 1024;
const TWILIO_STATUS_PREFIX = '/api/integrations/twilio/status/';
// The public https address of this server. Twilio reports "delivered / read / failed" to it.
// Render and Railway tell the app its address; elsewhere set PUBLIC_URL. Without it, delivery reports are off.
const PUBLIC_URL = (() => {
  const raw = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL
    || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : '');
  try {
    const url = new URL(raw);
    return url.protocol === 'https:' ? url.origin : null;
  } catch (_) {
    return null;
  }
})();
// Open self-sign-up is a demo convenience. In production nobody can create an account
// unless an invite code is configured or open registration is switched on explicitly.
const REGISTRATION_MODE = REGISTRATION_INVITE_CODE
  ? 'invite'
  : (!isProduction || process.env.ALLOW_OPEN_REGISTRATION === 'true' ? 'open' : 'closed');
const SESSION_COOKIE = 'veyraSession';
const SESSION_DURATION_SECONDS = 8 * 60 * 60;
const AUTH_RATE_LIMIT_CONFIG = {
  normalApi: {
    windowMs: readPositiveInteger(process.env.API_RATE_LIMIT_WINDOW_MS, 60 * 1000),
    max: readPositiveInteger(process.env.API_RATE_LIMIT_MAX, 120)
  },
  register: {
    windowMs: readPositiveInteger(process.env.REGISTER_RATE_LIMIT_WINDOW_MS, 60 * 60 * 1000),
    max: readPositiveInteger(process.env.REGISTER_RATE_LIMIT_MAX, 5),
    message: 'Too many registration attempts from this IP. Please try again later.'
  },
  login: {
    windowMs: readPositiveInteger(process.env.LOGIN_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
    max: readPositiveInteger(process.env.LOGIN_RATE_LIMIT_MAX, 8),
    ipMax: readPositiveInteger(process.env.LOGIN_RATE_LIMIT_IP_MAX, 30),
    // Failures for one account from ALL addresses together; stops password guessing spread over many IPs.
    accountMax: readPositiveInteger(process.env.LOGIN_RATE_LIMIT_ACCOUNT_MAX, 30),
    message: 'Too many login attempts. Please try again in 15 minutes.',
    logThreshold: readPositiveInteger(process.env.LOGIN_FAILURE_LOG_THRESHOLD, 4)
  }
};
const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: 'lax',
  path: '/',
  maxAge: SESSION_DURATION_SECONDS * 1000
};

if (isProduction && !process.env.JWT_SECRET) {
  console.error('JWT_SECRET is required in production. Set it in your environment or .env file.');
  process.exit(1);
}

const parseMoney = (value) => parseMoneyUpTo(value, MAX_RATE);

nexus.configure({
  flow: { weightUnit: WEIGHT_UNIT, currency: CURRENCY, equipment: EQUIPMENT, maxRate: MAX_RATE, maxWeight: MAX_WEIGHT },
  language: MESSAGE_LANGUAGE,
  staleHours: STALE_TRACKING_HOURS,
  aiDailyLimit: AI_DAILY_LIMIT_PER_TENANT,
  formatMoney: (value) => {
    try {
      return Number(value).toLocaleString('en-US', { style: 'currency', currency: CURRENCY, maximumFractionDigits: 2 });
    } catch (_) {
      return `${Number(value).toFixed(2)} ${CURRENCY}`;
    }
  }
});

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  // Defence in depth against XSS: only same-origin scripts, no inline <script>, no framing.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' https://fonts.googleapis.com",
    "style-src-attr 'unsafe-inline'",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; '));
  if (isProduction) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});
app.use(cors({
  origin: isProduction ? process.env.ALLOWED_ORIGIN || false : true,
  credentials: true
}));
// GPS providers send batches of positions, so their endpoint accepts larger bodies.
const smallJson = express.json({ limit: '50kb' });
const gpsJson = express.json({ limit: '1mb' });
// Email providers post JSON, a form, or a multipart form with files. These bodies can be large, so they are
// read only inside the inbox route, after the address was checked (see parseInboxBody).
const inboxMultipart = express.raw({ limit: INBOX_MAX_BYTES, type: (req) => /^multipart\/form-data/i.test(String(req.headers['content-type'] || '')) });
const inboxJson = express.json({ limit: INBOX_MAX_BYTES });
const inboxForm = express.urlencoded({ extended: false, limit: '1mb' });
const parseInboxBody = (req, res, next) => inboxMultipart(req, res, (multipartError) => (multipartError ? next(multipartError)
  : inboxJson(req, res, (jsonError) => (jsonError ? next(jsonError) : inboxForm(req, res, next)))));
app.use((req, res, next) => {
  if (req.path === GPS_WEBHOOK_PATH) return gpsJson(req, res, next);
  if (req.path.startsWith(INBOX_WEBHOOK_PREFIX) || req.path.startsWith(TWILIO_STATUS_PREFIX)) return next();
  return smallJson(req, res, next);
});
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

function readPaging(req) {
  const limit = Math.min(readPositiveInteger(req.query.limit, 100), 200);
  const page = readPositiveInteger(req.query.page, 1);
  return { limit, offset: (page - 1) * limit, page };
}

const SHIPMENT_STATUSES = ['New', 'Sourcing', 'Pending Approval', 'Dispatched', 'In Transit', 'Exception', 'Delivered', 'Cancelled'];

function passwordTooLong(password) {
  return Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES;
}

function validateNewPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || passwordTooLong(password) || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    return `Password must be at least 8 characters (at most ${MAX_PASSWORD_BYTES} bytes) and include a letter and a number.`;
  }
  return null;
}

function validateNameAndEmail(name, email) {
  if (typeof name !== 'string' || typeof email !== 'string' || !name.trim() || !email.trim()) {
    return 'Name and email are required.';
  }
  if (name.length > MAX_LEN.name || email.length > MAX_LEN.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return 'Name or email is invalid.';
  }
  return null;
}

function formatMoney(value) {
  try {
    return Number(value).toLocaleString('en-US', { style: 'currency', currency: CURRENCY, maximumFractionDigits: 2 });
  } catch (_) {
    return `${Number(value).toFixed(2)} ${CURRENCY}`;
  }
}

function serializeShipment(shipment) {
  const hasMargin = shipment.rate !== null && shipment.rate !== undefined && shipment.customer_rate !== null && shipment.customer_rate !== undefined;
  return {
    id: `SHP-${shipment.id}`,
    customer: shipment.customer,
    customerPhone: shipment.customer_phone || null,
    origin: shipment.origin,
    destination: shipment.destination,
    pickup: shipment.pickup || 'Today',
    delivery: shipment.delivery || 'Next Day',
    status: shipment.status || 'Pending Approval',
    reference: shipment.reference,
    carrier: shipment.carrier_id,
    carrierId: shipment.carrier_id,
    rate: shipment.rate,
    customerRate: shipment.customer_rate ?? null,
    margin: hasMargin ? Math.round((shipment.customer_rate - shipment.rate) * 100) / 100 : null,
    weight: shipment.weight,
    equipment: shipment.equipment,
    carrierName: shipment.carrierName,
    carrierPhone: shipment.carrierPhone || null,
    driverName: shipment.driver_name || null,
    driverPhone: shipment.driver_phone || null,
    truckPlate: shipment.truck_plate || null,
    lastLocation: shipment.last_location || null,
    eta: shipment.eta || null,
    lastTrackedAt: shipment.last_tracked_at || null,
    trackingNumber: shipment.tracking_number
  };
}

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function getNormalizedEmail(req) {
  const email = req.body?.email || '';
  return String(email).trim().toLowerCase();
}

function createRateLimiter({ windowMs, max, keyGenerator, message, onLimitReached, store = new Map() }) {
  setInterval(() => {
    const cutoff = Date.now() - windowMs;
    for (const [key, attempts] of store) {
      const recentAttempts = attempts.filter((timestamp) => timestamp > cutoff);
      if (recentAttempts.length) store.set(key, recentAttempts);
      else store.delete(key);
    }
  }, windowMs).unref();

  return function rateLimiter(req, res, next) {
    const key = keyGenerator(req);
    const now = Date.now();
    const cutoff = now - windowMs;
    const recentRequests = (store.get(key) || []).filter((timestamp) => timestamp > cutoff);

    if (recentRequests.length >= max) {
      const retryAfterSeconds = Math.max(1, Math.ceil((recentRequests[0] + windowMs - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      res.setHeader('RateLimit-Limit', String(max));
      res.setHeader('RateLimit-Remaining', '0');
      res.setHeader('RateLimit-Reset', String(Math.ceil((recentRequests[0] + windowMs) / 1000)));
      if (onLimitReached) {
        onLimitReached(req, res, key, recentRequests.length);
      }
      if (res.headersSent) {
        return;
      }
      return res.status(429).json({
        success: false,
        message: message || 'Too many requests. Please try again later.'
      });
    }

    recentRequests.push(now);
    store.set(key, recentRequests);
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(Math.max(0, max - recentRequests.length)));
    res.setHeader('RateLimit-Reset', String(Math.ceil((recentRequests[0] + windowMs) / 1000)));
    return next();
  };
}

function rateLimitKey(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

async function trackFailedLoginAttempt(req, email) {
  const ip = getClientIp(req);
  const normalizedEmail = (email || '').trim().toLowerCase();
  const accountId = rateLimitKey(normalizedEmail || 'unknown').slice(0, 12);
  const ipAttempts = await recordRateLimitAttempts(
    [
      rateLimitKey(`login-ip:${ip}`),
      rateLimitKey(`login-account:${ip}:${normalizedEmail || 'unknown'}`),
      rateLimitKey(`login-account-any:${normalizedEmail || 'unknown'}`)
    ],
    AUTH_RATE_LIMIT_CONFIG.login.windowMs
  );

  if (ipAttempts === AUTH_RATE_LIMIT_CONFIG.login.logThreshold || ipAttempts === AUTH_RATE_LIMIT_CONFIG.login.ipMax) {
    console.warn(`[AUTH SECURITY] repeated failed login attempts for account=${accountId} from ${ip} (count=${ipAttempts})`);
  }
}

async function clearFailedLoginAttempt(req, email) {
  const ip = getClientIp(req);
  const normalizedEmail = (email || '').trim().toLowerCase();
  await clearRateLimitAttempts(rateLimitKey(`login-account:${ip}:${normalizedEmail || 'unknown'}`));
  await clearRateLimitAttempts(rateLimitKey(`login-account-any:${normalizedEmail || 'unknown'}`));
}

const normalApiLimiter = createRateLimiter({
  windowMs: AUTH_RATE_LIMIT_CONFIG.normalApi.windowMs,
  max: AUTH_RATE_LIMIT_CONFIG.normalApi.max,
  keyGenerator: (req) => getClientIp(req),
  message: 'Too many API requests. Please try again later.'
});

// AI calls cost money: each person gets a fair hourly budget.
const aiLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: readPositiveInteger(process.env.AI_RATE_LIMIT_PER_HOUR, 60),
  keyGenerator: (req) => `ai:${req.user?.id}`,
  message: 'AI hourly limit reached. Please fill the form by hand or try again later.'
});

// Text messages cost money and can annoy drivers: an hourly cap per person.
const messageLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: readPositiveInteger(process.env.MESSAGE_RATE_LIMIT_PER_HOUR, 60),
  keyGenerator: (req) => `msg:${req.user?.id}`,
  message: 'Message limit reached for this hour.'
});

const gpsLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: readPositiveInteger(process.env.GPS_RATE_LIMIT_PER_MINUTE, 600),
  keyGenerator: (req) => `gps:${req.gpsTokenHash || getClientIp(req)}`,
  message: 'Too many GPS requests.'
});

const inboxLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: readPositiveInteger(process.env.INBOX_RATE_LIMIT_PER_MINUTE, 60),
  keyGenerator: (req) => `inbox:${req.inboxTokenHash || getClientIp(req)}`,
  message: 'Too many messages.'
});

// The inbox address is a secret in the URL: also limit by sender address, so guessing addresses is not free.
const inboxIpLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: readPositiveInteger(process.env.INBOX_IP_RATE_LIMIT_PER_MINUTE, 600),
  keyGenerator: (req) => `inbox-ip:${getClientIp(req)}`,
  message: 'Too many requests.'
});

// Twilio sends several reports per message, all from its own addresses.
const twilioStatusLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: readPositiveInteger(process.env.TWILIO_STATUS_RATE_LIMIT_PER_MINUTE, 1200),
  keyGenerator: (req) => `twilio-status:${getClientIp(req)}`,
  message: 'Too many requests.'
});

const documentLimiter = createRateLimiter({
  windowMs: 60 * 60 * 1000,
  max: readPositiveInteger(process.env.DOC_RATE_LIMIT_PER_HOUR, 60),
  keyGenerator: (req) => `doc:${req.user?.id}`,
  message: 'Upload limit reached for this hour.'
});

const loginLimiter = async (req, res, next) => {
  const ip = getClientIp(req);
  const email = getNormalizedEmail(req);
  try {
    const { windowMs, ipMax, max, accountMax } = AUTH_RATE_LIMIT_CONFIG.login;
    const [ipStatus, accountStatus, anyIpStatus] = await Promise.all([
      getRateLimitStatus(rateLimitKey(`login-ip:${ip}`), windowMs, ipMax),
      getRateLimitStatus(rateLimitKey(`login-account:${ip}:${email || 'unknown'}`), windowMs, max),
      getRateLimitStatus(rateLimitKey(`login-account-any:${email || 'unknown'}`), windowMs, accountMax)
    ]);

    if (ipStatus.limited || accountStatus.limited || anyIpStatus.limited) {
      const emailId = rateLimitKey(email || 'unknown').slice(0, 12);
      console.warn(`[AUTH SECURITY] login rate limit exceeded for account=${emailId} from ${ip}`);
      const retryAfterMs = Math.max(ipStatus.retryAfterMs, accountStatus.retryAfterMs, anyIpStatus.retryAfterMs);
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
      return res.status(429).json({ success: false, message: AUTH_RATE_LIMIT_CONFIG.login.message });
    }
    return next();
  } catch (error) {
    console.error('[AUTH SECURITY] login rate limiter unavailable:', error.message);
    return res.status(503).json({ success: false, message: 'Authentication is temporarily unavailable.' });
  }
};

const registerLimiter = async (req, res, next) => {
  const ip = getClientIp(req);
  try {
    const result = await consumeRateLimit(
      rateLimitKey(`register:${ip}`),
      AUTH_RATE_LIMIT_CONFIG.register.windowMs,
      AUTH_RATE_LIMIT_CONFIG.register.max
    );
    if (result.limited) {
      console.warn(`[AUTH SECURITY] registration rate limit exceeded from ${ip}`);
      res.setHeader('Retry-After', String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
      return res.status(429).json({ success: false, message: AUTH_RATE_LIMIT_CONFIG.register.message });
    }
    return next();
  } catch (error) {
    console.error('[AUTH SECURITY] registration rate limiter unavailable:', error.message);
    return res.status(503).json({ success: false, message: 'Registration is temporarily unavailable.' });
  }
};

// The GPS webhook has its own token and limiter (providers send many requests from one address).
app.use('/api', (req, res, next) => (req.path === '/integrations/gps' || req.path.startsWith('/integrations/inbox/') || req.path.startsWith('/integrations/twilio/')
  ? next() : normalApiLimiter(req, res, next)));

const authRateLimiters = { login: loginLimiter, register: registerLimiter };

function makeToken(user) {
  const jti = crypto.randomUUID();
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_DURATION_SECONDS;
  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      jti
    },
    JWT_SECRET,
    { expiresIn: SESSION_DURATION_SECONDS }
  );
  return { token, jti, expiresAt };
}

function readSessionCookie(req) {
  const cookieHeader = req.headers.cookie || '';
  const cookie = cookieHeader.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (!cookie) return null;
  try {
    return decodeURIComponent(cookie.slice(SESSION_COOKIE.length + 1));
  } catch (error) {
    return null;
  }
}

async function issueSessionCookie(user, res) {
  const session = makeToken(user);
  await createAuthSession(session.jti, session.expiresAt, user.id);
  res.cookie(SESSION_COOKIE, session.token, SESSION_COOKIE_OPTIONS);
}

async function authMiddleware(req, res, next) {
  const token = readSessionCookie(req);
  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required.'
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!(await isAuthSessionActive(payload.jti))) {
      return res.status(401).json({
        success: false,
        message: 'Session expired or revoked.'
      });
    }
    // Role, company and access come from the database on every request, not from the token,
    // so an admin's change (new role, account disabled) applies immediately.
    const user = await findUserById(payload.id);
    if (!user || user.disabledAt) {
      return res.status(401).json({ success: false, message: 'Session expired or revoked.' });
    }
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      jti: payload.jti,
      tenantId: user.tenantId,
      tenantName: user.tenantName,
      isPlatformAdmin: Boolean(user.isPlatformAdmin)
    };
    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token.'
    });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    const permissions = ROLE_PERMISSIONS[req.user?.role] || [];
    if (!permissions.includes('*') && !permissions.includes(permission)) {
      return res.status(403).json({
        success: false,
        message: `Forbidden: missing ${permission} permission.`
      });
    }
    return next();
  };
}

// The platform owner adds customer companies; a company's own admin cannot.
function requirePlatformAdmin(req, res, next) {
  if (!req.user?.isPlatformAdmin) {
    return res.status(403).json({ success: false, message: 'Forbidden: platform administrators only.' });
  }
  return next();
}

function hasPermission(user, permission) {
  const permissions = ROLE_PERMISSIONS[user?.role] || [];
  return permissions.includes('*') || permissions.includes(permission);
}

function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    permissions: ROLE_PERMISSIONS[user.role] || [],
    isPlatformAdmin: Boolean(user.is_platform_admin ?? user.isPlatformAdmin)
  };
}

// Writes an agent_tasks row for every AI call (success or failure).
function agentLogger(req, shipmentId = null) {
  return (task) => recordAgentTask(req.user.tenantId, { ...task, shipmentId, actorId: req.user.id })
    .catch((error) => console.error('[agent log] failed:', error.message));
}

function sendError(res, error, fallbackMessage, logLabel) {
  if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
  console.error(`[${logLabel}] failed:`, error.message);
  return res.status(500).json({ success: false, message: fallbackMessage });
}

/* =========================================================
   PUBLIC
   ========================================================= */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VEYRA Logistics API',
    timestamp: new Date().toISOString()
  });
});

// Public settings the UI needs before sign-in (units, currency, whether sign-up is possible, features on).
app.get('/api/config', (req, res) => {
  res.json({
    weightUnit: WEIGHT_UNIT,
    currency: CURRENCY,
    equipment: EQUIPMENT,
    registration: REGISTRATION_MODE,
    maxRate: MAX_RATE,
    staleTrackingHours: STALE_TRACKING_HOURS,
    ai: { enabled: aiGateway.isEnabled() },
    // Which channels can send depends on the company: see GET /api/messaging/status (after sign-in).
    messaging: { language: MESSAGE_LANGUAGE, languages: relayAgent.LANGUAGES },
    documents: { maxMb: DOC_MAX_BYTES / (1024 * 1024), types: DOC_MIME_TYPES },
    nexus: { enabled: process.env.NEXUS_ENABLED !== 'false' }
  });
});

app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { name, email, password, inviteCode } = req.body || {};

    if (REGISTRATION_MODE === 'closed') {
      return res.status(403).json({ success: false, message: 'Sign-up is closed. Ask your administrator to create an account for you.' });
    }
    if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string' || !name.trim() || !email.trim() || !password) {
      return res.status(400).json({
        success: false,
        message: 'Name, email and password are required.'
      });
    }
    const identityError = validateNameAndEmail(name, email);
    if (identityError) return res.status(400).json({ success: false, message: identityError });
    const passwordError = validateNewPassword(password);
    if (passwordError) return res.status(400).json({ success: false, message: passwordError });
    if (REGISTRATION_INVITE_CODE) {
      const provided = Buffer.from(String(inviteCode || ''));
      const expected = Buffer.from(REGISTRATION_INVITE_CODE);
      if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
        return res.status(403).json({ success: false, message: 'A valid invite code is required.' });
      }
    }

    const normalizedEmail = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, BCRYPT_COST);
    const existingUser = await findUserByEmail(normalizedEmail);
    if (existingUser) {
      // Generic message: do not reveal whether the email is registered.
      return res.status(409).json({
        success: false,
        message: 'Registration could not be completed. Try signing in or use a different email.'
      });
    }

    let user;
    try {
      // Self-registered people join the default company as operators.
      user = await createUser({
        name: name.trim(),
        email: normalizedEmail,
        password: hashedPassword,
        role: 'operator',
        tenantId: DEFAULT_TENANT_ID
      });
    } catch (error) {
      if (String(error.code) === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({ success: false, message: 'Registration could not be completed. Try signing in or use a different email.' });
      }
      throw error;
    }
    await issueSessionCookie(user, res);

    return res.status(201).json({
      success: true,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('[register] failed:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Registration failed'
    });
  }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string' || !email.trim() || !password
      || email.length > MAX_LEN.email || passwordTooLong(password)) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    const normalizedEmail = email.trim().toLowerCase();

    const user = await findUserByEmail(normalizedEmail);
    // A disabled account is treated exactly like an unknown one (same message, same timing).
    if (!user || user.disabled_at) {
      // Equalise timing with the real-user path so response time does not reveal valid emails.
      await bcrypt.compare(String(password || ''), DUMMY_HASH);
      await trackFailedLoginAttempt(req, normalizedEmail);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    const isValid = await bcrypt.compare(String(password || ''), user.password);
    if (!isValid) {
      await trackFailedLoginAttempt(req, normalizedEmail);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password.'
      });
    }

    await clearFailedLoginAttempt(req, normalizedEmail);
    await issueSessionCookie(user, res);
    return res.json({
      success: true,
      user: sanitizeUser(user)
    });
  } catch (error) {
    console.error('[login] failed:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
});

app.post('/api/logout', async (req, res) => {
  const token = readSessionCookie(req);
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      await revokeAuthSession(payload.jti);
    } catch (error) {
      // Expired or malformed cookies are still cleared below.
    }
  }

  res.clearCookie(SESSION_COOKIE, {
    httpOnly: SESSION_COOKIE_OPTIONS.httpOnly,
    secure: SESSION_COOKIE_OPTIONS.secure,
    sameSite: SESSION_COOKIE_OPTIONS.sameSite,
    path: SESSION_COOKIE_OPTIONS.path
  });
  return res.json({ success: true });
});

/* =========================================================
   DASHBOARD, ANALYTICS, ALERTS
   ========================================================= */
app.get('/api/dashboard', authMiddleware, requirePermission('dashboard:read'), async (req, res) => {
  try {
    const payload = await getDashboardPayload(req.user.tenantId, { days: req.query.days });
    if (!hasPermission(req.user, 'analytics:read')) {
      delete payload.stats;
      delete payload.statuses;
      delete payload.weeklyVolume;
    }
    res.json(payload);
  } catch (error) {
    console.error('[dashboard] failed:', error.message);
    res.status(500).json({
      success: false,
      message: 'Dashboard unavailable'
    });
  }
});

app.get('/api/analytics', authMiddleware, requirePermission('analytics:read'), async (req, res) => {
  try {
    const report = await getAnalyticsReport(req.user.tenantId, { days: req.query.days });
    report.agents = await getAgentUsage(req.user.tenantId, report.rangeDays);
    res.json(report);
  } catch (error) {
    console.error('[analytics] failed:', error.message);
    res.status(500).json({ success: false, message: 'Analytics unavailable.' });
  }
});

// What needs attention right now (notification bell).
app.get('/api/alerts', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    res.json({ success: true, alerts: await getAlerts(req.user.tenantId, { staleHours: STALE_TRACKING_HOURS }) });
  } catch (error) {
    console.error('[alerts] failed:', error.message);
    res.status(500).json({ success: false, message: 'Alerts unavailable.' });
  }
});

/* =========================================================
   SHIPMENTS
   ========================================================= */
app.get('/api/shipments', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipments = await listShipments(req.user.tenantId, readPaging(req));
    res.json(shipments.map(serializeShipment));
  } catch (error) {
    console.error('[shipments] failed:', error.message);
    res.status(500).json({ success: false, message: 'Shipments unavailable' });
  }
});

// Paged, filtered list for the Shipments page and CSV export. Registered before /:id.
app.get('/api/shipments/search', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const { limit, offset, page } = readPaging(req);
  const status = SHIPMENT_STATUSES.includes(req.query.status) ? req.query.status : null;
  const equipment = EQUIPMENT.includes(req.query.equipment) ? req.query.equipment : null;
  const q = typeof req.query.q === 'string' ? req.query.q.slice(0, 120) : '';
  const sort = typeof req.query.sort === 'string' ? req.query.sort : 'newest';
  try {
    const result = await searchShipments(req.user.tenantId, { status, equipment, q, sort, limit, offset });
    res.json({
      success: true,
      items: result.items.map(serializeShipment),
      total: result.total,
      allCount: result.allCount,
      statusCounts: result.statusCounts,
      page,
      pageSize: limit,
      pages: Math.max(1, Math.ceil(result.total / limit))
    });
  } catch (error) {
    console.error('[shipment search] failed:', error.message);
    res.status(500).json({ success: false, message: 'Shipments unavailable' });
  }
});

app.get('/api/shipments/:id', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) {
    return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  }
  try {
    const shipment = await getShipment(req.user.tenantId, shipmentId);
    if (!shipment) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    return res.json(serializeShipment(shipment));
  } catch (error) {
    console.error('[shipment] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Shipment unavailable' });
  }
});

app.post('/api/shipments', authMiddleware, requirePermission('shipments:create'), async (req, res) => {
  try {
    const { customer, reference, origin, destination, pickup, delivery, weight, equipment, trackingNumber } = req.body || {};
    const pickupDate = parseIsoDate(pickup);
    const deliveryDate = parseIsoDate(delivery);
    const weightValue = parsePositiveNumber(weight, MAX_WEIGHT);
    const hasCustomerRate = req.body?.customerRate !== undefined && req.body?.customerRate !== null && req.body?.customerRate !== '';
    const customerRate = hasCustomerRate ? parseMoney(req.body.customerRate) : null;
    if (hasCustomerRate && customerRate === null) {
      return res.status(400).json({ success: false, message: `Customer price must be between 0.01 and ${MAX_RATE.toLocaleString('en-US')}.` });
    }
    const customerPhone = readOptionalPhone(req.body, 'customerPhone');
    if (customerPhone.error) return res.status(400).json({ success: false, message: customerPhone.error });
    // Optional: the email this load was made from (closes its task and marks it converted).
    const inboxId = req.body?.inboxId === undefined || req.body?.inboxId === null || req.body?.inboxId === '' ? null : Number(req.body.inboxId);
    if (inboxId !== null) {
      const item = Number.isInteger(inboxId) && inboxId > 0 ? await getInboxItem(req.user.tenantId, inboxId) : null;
      if (!item || ['converted', 'dismissed'].includes(item.status)) {
        return res.status(400).json({ success: false, message: 'That incoming message no longer exists or was already handled.' });
      }
    }

    const textFields = { customer, origin, destination };
    for (const [field, value] of Object.entries(textFields)) {
      if (typeof value !== 'string' || value.trim().length > MAX_LEN[field]) {
        return res.status(400).json({ success: false, message: `${field} is required and must be at most ${MAX_LEN[field]} characters.` });
      }
    }
    for (const field of ['reference', 'trackingNumber']) {
      const value = req.body?.[field];
      if (value !== undefined && value !== null && (typeof value !== 'string' || value.trim().length > MAX_LEN[field])) {
        return res.status(400).json({ success: false, message: `${field} must be text of at most ${MAX_LEN[field]} characters.` });
      }
    }
    if (!customer?.trim() || !origin?.trim() || !destination?.trim() || weightValue === null || !EQUIPMENT.includes(equipment)) {
      return res.status(400).json({ success: false, message: `Customer, route, a weight up to ${MAX_WEIGHT.toLocaleString('en-US')} ${WEIGHT_UNIT}, and valid equipment are required.` });
    }
    if (!pickupDate || !deliveryDate) {
      return res.status(400).json({ success: false, message: 'Pickup and delivery must be valid dates (YYYY-MM-DD).' });
    }
    if (deliveryDate < pickupDate) {
      return res.status(400).json({ success: false, message: 'Delivery date must be on or after pickup date.' });
    }

    const shipment = await createShipment({
      customer: customer.trim(),
      origin: origin.trim(),
      destination: destination.trim(),
      pickup,
      delivery,
      status: 'New',
      weight: `${weightValue} ${WEIGHT_UNIT}`,
      equipment,
      reference: reference?.trim(),
      trackingNumber: trackingNumber?.trim(),
      customerRate,
      customerPhone: customerPhone.value,
      actorId: req.user.id,
      tenantId: req.user.tenantId
    });

    let documentsAttached = 0;
    if (inboxId !== null) {
      const newId = parseShipmentId(shipment.id);
      await updateInboxItem(req.user.tenantId, inboxId, { status: 'converted', shipmentId: newId });
      await resolveTasksByKey(req.user.tenantId, `inbox:${inboxId}`, { userId: req.user.id });
      // Files that came with the email go with the load.
      const moved = await moveInboxAttachmentsToShipment(req.user.tenantId, inboxId, newId, {
        uploadedBy: req.user.id, typeFor: (filename) => guessDocumentType(filename) || 'other', maxPerShipment: DOC_MAX_PER_SHIPMENT
      });
      documentsAttached = moved.documentIds.length;
      moved.documentIds.forEach((documentId) => nexus.emit('document.uploaded', { tenantId: req.user.tenantId, shipmentId: newId, documentId }));
    }

    return res.status(201).json({
      success: true,
      shipment,
      documentsAttached
    });
  } catch (error) {
    console.error('[create shipment] failed:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Shipment creation failed'
    });
  }
});

app.get('/api/shipments/:id/events', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipmentId = parseShipmentId(req.params.id);
    if (!shipmentId) {
      return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
    }
    return res.json({ success: true, events: await listShipmentEvents(req.user.tenantId, shipmentId) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Shipment history unavailable.' });
  }
});

// Where is the truck? Location updates (typed check calls and GPS), newest first.
app.get('/api/shipments/:id/tracking', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  try {
    if (!(await getShipment(req.user.tenantId, shipmentId))) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    return res.json({ success: true, updates: await listTrackingUpdates(req.user.tenantId, shipmentId) });
  } catch (error) {
    console.error('[tracking list] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Tracking history unavailable.' });
  }
});

app.post('/api/shipments/:id/tracking', authMiddleware, requirePermission('shipments:track'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const location = req.body?.location;
  if (!shipmentId || typeof location !== 'string' || !location.trim() || location.trim().length > MAX_LEN.location) {
    return res.status(400).json({ success: false, message: `A current location (at most ${MAX_LEN.location} characters) is required.` });
  }
  const eta = parseEta(req.body?.eta);
  const note = readOptionalText(req.body, 'note', MAX_LEN.note);
  const invalid = eta.error || note.error;
  if (invalid) return res.status(400).json({ success: false, message: invalid });
  try {
    const update = await addTrackingUpdate(req.user.tenantId, shipmentId, { location: location.trim(), eta: eta.value, note: note.value }, req.user.id);
    return res.status(201).json({ success: true, update });
  } catch (error) {
    return sendError(res, error, 'Location update failed.', 'tracking add');
  }
});

/* ---------- RELAY: messages to driver / carrier / customer ---------- */
const MESSAGE_RECIPIENTS = Object.keys(relayAgent.PURPOSES);
const MESSAGE_CHANNELS = ['sms', 'whatsapp'];

app.get('/api/shipments/:id/messages', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  try {
    if (!(await getShipment(req.user.tenantId, shipmentId))) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    return res.json({ success: true, messages: await listMessages(req.user.tenantId, shipmentId) });
  } catch (error) {
    return sendError(res, error, 'Messages unavailable.', 'messages list');
  }
});

app.post('/api/shipments/:id/messages/draft', authMiddleware, requirePermission('shipments:message'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const { recipient, purpose, language } = req.body || {};
  if (!shipmentId || !MESSAGE_RECIPIENTS.includes(recipient)) {
    return res.status(400).json({ success: false, message: `Choose who the message is for: ${MESSAGE_RECIPIENTS.join(', ')}.` });
  }
  try {
    const shipment = await getShipment(req.user.tenantId, shipmentId);
    if (!shipment) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    const draft = relayAgent.draftMessage({
      shipment,
      recipient,
      purpose,
      language: typeof language === 'string' ? language : MESSAGE_LANGUAGE,
      company: req.user.tenantName,
      formatMoney
    });
    const tenant = await getTenant(req.user.tenantId);
    return res.json({ success: true, draft: { ...draft, recipient, channels: messaging.publicStatus(tenant, DEFAULT_TENANT_ID).channels } });
  } catch (error) {
    return sendError(res, error, 'Draft failed.', 'message draft');
  }
});

app.post('/api/shipments/:id/messages', authMiddleware, requirePermission('shipments:message'), messageLimiter, async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const { recipient, channel, body } = req.body || {};
  if (!shipmentId || !MESSAGE_RECIPIENTS.includes(recipient) || !MESSAGE_CHANNELS.includes(channel)
    || typeof body !== 'string' || !body.trim() || body.length > MAX_LEN.message) {
    return res.status(400).json({ success: false, message: `A recipient, a channel (sms or whatsapp) and a message of at most ${MAX_LEN.message} characters are required.` });
  }
  try {
    const shipment = await getShipment(req.user.tenantId, shipmentId);
    if (!shipment) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    const delivered = await deliverMessage(req, shipment, { recipient, channel, body: body.trim() });
    if (delivered.result.status !== 'sent') {
      return res.status(502).json({ success: false, message: `The message was not delivered: ${delivered.result.error}`, messageId: delivered.saved.id });
    }
    return res.status(201).json({ success: true, message: { id: delivered.saved.id, status: delivered.result.status, to: delivered.to } });
  } catch (error) {
    return sendError(res, error, 'Message could not be sent.', 'message send');
  }
});

// Sends one message with the signed-in company's Twilio account and records the result.
// The number always comes from the load record, never from the browser.
async function deliverMessage(req, shipment, { recipient, channel, body }) {
  const to = relayAgent.recipientPhone(shipment, recipient);
  if (!to) throw httpError(400, `There is no ${recipient} phone number on this load.`);
  const tenant = await getTenant(req.user.tenantId);
  const { config } = messaging.resolveConfig(tenant, DEFAULT_TENANT_ID);
  // A one-time secret in the report address ties Twilio's delivery report to this message.
  const callbackToken = PUBLIC_URL ? crypto.randomBytes(24).toString('hex') : null;
  const result = await messaging.send(config, {
    channel, to, body, statusCallback: callbackToken ? `${PUBLIC_URL}${TWILIO_STATUS_PREFIX}${callbackToken}` : null
  });
  const saved = await createMessage(req.user.tenantId, {
    callbackTokenHash: callbackToken && result.status === 'sent' ? rateLimitKey(callbackToken) : null,
    shipmentId: shipment.id,
    channel,
    recipientType: recipient,
    toPhone: to,
    body,
    status: result.status,
    provider: result.provider,
    providerMessageId: result.providerMessageId,
    error: result.error,
    createdBy: req.user.id
  });
  return { result, saved, to };
}

/* =========================================================
   NEXUS TASKS: what the agents prepared for a person
   ========================================================= */
app.get('/api/tasks', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    res.json({ success: true, tasks: await listTasks(req.user.tenantId, { status: 'open' }) });
  } catch (error) {
    return sendError(res, error, 'Tasks unavailable.', 'tasks');
  }
});

app.post('/api/tasks/:id/dismiss', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const taskId = Number(req.params.id);
  if (!Number.isInteger(taskId) || taskId <= 0) return res.status(400).json({ success: false, message: 'Valid task ID is required.' });
  try {
    if (!(await getTask(req.user.tenantId, taskId))) return res.status(404).json({ success: false, message: 'Task not found.' });
    await resolveTask(req.user.tenantId, taskId, { status: 'dismissed', userId: req.user.id });
    return res.json({ success: true });
  } catch (error) {
    return sendError(res, error, 'Task could not be updated.', 'task dismiss');
  }
});

// A person approves a drafted message: it is sent now (optionally edited), and the task is closed.
app.post('/api/tasks/:id/approve', authMiddleware, requirePermission('shipments:message'), messageLimiter, async (req, res) => {
  const taskId = Number(req.params.id);
  const channel = req.body?.channel;
  const edited = req.body?.body;
  if (!Number.isInteger(taskId) || taskId <= 0 || !MESSAGE_CHANNELS.includes(channel)
    || (edited !== undefined && (typeof edited !== 'string' || !edited.trim() || edited.length > MAX_LEN.message))) {
    return res.status(400).json({ success: false, message: `A task, a channel (sms or whatsapp) and, if you edit it, a message of at most ${MAX_LEN.message} characters are required.` });
  }
  try {
    const task = await getTask(req.user.tenantId, taskId);
    if (!task) return res.status(404).json({ success: false, message: 'Task not found.' });
    if (task.status !== 'open') return res.status(409).json({ success: false, message: 'This task was already handled.' });
    if (task.kind !== 'message' || !task.shipmentId || !MESSAGE_RECIPIENTS.includes(task.payload?.recipient)) {
      return res.status(400).json({ success: false, message: 'Only message tasks can be approved.' });
    }
    const shipment = await getShipment(req.user.tenantId, parseShipmentId(task.shipmentId));
    if (!shipment) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    const body = (edited ?? task.payload.body).trim();
    const delivered = await deliverMessage(req, shipment, { recipient: task.payload.recipient, channel, body });
    if (delivered.result.status !== 'sent') {
      return res.status(502).json({ success: false, message: `The message was not delivered: ${delivered.result.error}`, messageId: delivered.saved.id });
    }
    await resolveTask(req.user.tenantId, taskId, { status: 'done', userId: req.user.id });
    return res.status(201).json({ success: true, message: { id: delivered.saved.id, status: 'sent', to: delivered.to } });
  } catch (error) {
    return sendError(res, error, 'Message could not be sent.', 'task approve');
  }
});

/* =========================================================
   INBOX: orders that arrive by email
   ========================================================= */
app.get('/api/inbox', authMiddleware, requirePermission('shipments:create'), async (req, res) => {
  try {
    res.json({ success: true, items: await listInboxItems(req.user.tenantId) });
  } catch (error) {
    return sendError(res, error, 'Inbox unavailable.', 'inbox');
  }
});

app.post('/api/inbox/:id/dismiss', authMiddleware, requirePermission('shipments:create'), async (req, res) => {
  const itemId = Number(req.params.id);
  if (!Number.isInteger(itemId) || itemId <= 0) return res.status(400).json({ success: false, message: 'Valid inbox ID is required.' });
  try {
    if (!(await updateInboxItem(req.user.tenantId, itemId, { status: 'dismissed' }))) return res.status(404).json({ success: false, message: 'Message not found.' });
    await resolveTasksByKey(req.user.tenantId, `inbox:${itemId}`, { status: 'dismissed', userId: req.user.id });
    await deleteInboxAttachments(req.user.tenantId, itemId);
    return res.json({ success: true });
  } catch (error) {
    return sendError(res, error, 'Message could not be dismissed.', 'inbox dismiss');
  }
});

// Read a stored email with FLOW on demand (when it was not read automatically).
app.post('/api/inbox/:id/parse', authMiddleware, requirePermission('shipments:create'), aiLimiter, async (req, res) => {
  const itemId = Number(req.params.id);
  if (!Number.isInteger(itemId) || itemId <= 0) return res.status(400).json({ success: false, message: 'Valid inbox ID is required.' });
  try {
    const item = await getInboxItem(req.user.tenantId, itemId);
    if (!item) return res.status(404).json({ success: false, message: 'Message not found.' });
    if (['converted', 'dismissed'].includes(item.status)) return res.status(409).json({ success: false, message: 'This message was already handled.' });
    const parsed = await flowAgent.parseOrder(`Subject: ${item.subject || ''}\n\n${item.body}`, flowSettings(), agentLogger(req));
    await updateInboxItem(req.user.tenantId, itemId, { status: 'parsed', parsed, error: null });
    return res.json({ success: true, ...parsed });
  } catch (error) {
    return sendError(res, error, 'The AI assistant is unavailable.', 'inbox parse');
  }
});

function flowSettings() {
  return { weightUnit: WEIGHT_UNIT, currency: CURRENCY, equipment: EQUIPMENT, maxRate: MAX_RATE, maxWeight: MAX_WEIGHT };
}

// Which load is an email about? Its number (SHP-12) or, failing that, the load's own reference in the text.
// Only an unambiguous match counts.
async function matchShipmentForEmail(tenantId, message) {
  const text = `${message.subject}\n${message.text}`;
  const found = [];
  for (const id of mentionedShipmentIds(text)) {
    if (await getShipment(tenantId, id)) found.push(id);
  }
  if (found.length === 1) return found[0];
  if (found.length > 1) return null;
  const words = (text.slice(0, 2000).match(/[A-Za-z0-9][A-Za-z0-9\-_/]{3,39}/g) || []).filter((word) => /\d/.test(word));
  const byReference = await findShipmentIdsByReference(tenantId, words);
  return byReference.length === 1 ? byReference[0] : null;
}

// Moves an email's files to a load. A file whose name or email does not say what it is counts as a CMR
// (proof of delivery once the load is delivered), because that is what people send about a running load.
async function attachEmailFilesToShipment(tenantId, inboxId, shipment, { context = '', uploadedBy = null } = {}) {
  const fallback = shipment.status === 'Delivered' ? 'pod' : 'cmr';
  return moveInboxAttachmentsToShipment(tenantId, inboxId, shipment.id, {
    uploadedBy, typeFor: (filename) => guessDocumentType(filename, context) || fallback, maxPerShipment: DOC_MAX_PER_SHIPMENT
  });
}

app.post(`${INBOX_WEBHOOK_PREFIX}:token`, (req, res, next) => {
  req.inboxTokenHash = rateLimitKey(String(req.params.token));
  return inboxIpLimiter(req, res, (error) => (error ? next(error) : inboxLimiter(req, res, next)));
}, async (req, res, next) => {
  // The address is checked before the (possibly large) body is read.
  try {
    req.inboxTenant = await findTenantByInboxTokenHash(req.inboxTokenHash);
    if (!req.inboxTenant) return res.status(404).json({ success: false, message: 'Unknown inbox address.' });
    return next();
  } catch (error) {
    return sendError(res, error, 'Message could not be stored.', 'inbox webhook');
  }
}, parseInboxBody, async (req, res) => {
  try {
    const tenant = req.inboxTenant;
    let message;
    try {
      message = parseInbound(req.body, req.headers['content-type'], DOC_MAX_BYTES);
    } catch (_) {
      // Providers retry on errors, so an unusable message is acknowledged, not rejected.
      return res.json({ success: true, ignored: 'unreadable' });
    }
    // Keep real documents only: the type comes from the file's first bytes, never from its name.
    const files = [];
    let filesSkipped = 0;
    for (const attachment of message.attachments) {
      const mime = attachment.content.length <= DOC_MAX_BYTES ? detectMime(attachment.content) : null;
      const logo = mime && mime !== 'application/pdf' && attachment.content.length < INBOX_MIN_IMAGE_BYTES;
      if (logo) continue;
      if (!mime || files.length >= INBOX_MAX_ATTACHMENTS) {
        filesSkipped += 1;
        continue;
      }
      files.push({ filename: safeFilename(attachment.filename, mime), mime, content: attachment.content });
    }
    if (!message.text && !files.length) return res.json({ success: true, ignored: 'empty' });
    if ((await countInboxItemsToday(tenant.id)) >= INBOX_DAILY_LIMIT) {
      return res.status(429).json({ success: false, message: 'Daily limit of incoming messages reached.' });
    }
    const settings = await getTenant(tenant.id);
    const allowed = senderAllowed(message.from, settings.allowedSenders);
    const { item, duplicate } = await createInboxItem(tenant.id, {
      externalId: message.messageId || null,
      from: message.from,
      subject: message.subject,
      body: message.text,
      status: allowed ? 'new' : 'blocked'
    });
    if (duplicate) return res.json({ success: true, duplicate: true });
    // Files from senders who are not allowed are not kept at all.
    if (!allowed) return res.status(201).json({ success: true, id: item.id, accepted: false });
    for (const file of files) await addInboxAttachment(tenant.id, item.id, file);

    // An email with files that names one of this company's loads: the files go straight to that load.
    const shipmentId = files.length ? await matchShipmentForEmail(tenant.id, message) : null;
    if (shipmentId) {
      const shipment = await getShipment(tenant.id, shipmentId);
      const moved = await attachEmailFilesToShipment(tenant.id, item.id, shipment, { context: `${message.subject} ${message.text}` });
      if (moved.documentIds.length || !moved.skipped) {
        await updateInboxItem(tenant.id, item.id, { status: 'attached', shipmentId });
        nexus.emit('inbox.attached', { tenantId: tenant.id, inboxId: item.id, shipmentId, documentIds: moved.documentIds, skipped: moved.skipped, from: message.from });
        return res.status(201).json({ success: true, id: item.id, accepted: true, attachedTo: `SHP-${shipmentId}`, documents: moved.documentIds.length, filesSkipped });
      }
    }
    nexus.emit('inbox.received', { tenantId: tenant.id, inboxId: item.id });
    return res.status(201).json({ success: true, id: item.id, accepted: true, files: files.length, filesSkipped });
  } catch (error) {
    return sendError(res, error, 'Message could not be stored.', 'inbox webhook');
  }
});

// A file that came with an email (before it is on a load). Always a download.
app.get('/api/inbox/:id/attachments/:fileId/file', authMiddleware, requirePermission('shipments:create'), async (req, res) => {
  const itemId = Number(req.params.id);
  const fileId = Number(req.params.fileId);
  if (!Number.isInteger(itemId) || itemId <= 0 || !Number.isInteger(fileId) || fileId <= 0) return res.status(400).json({ success: false, message: 'Valid IDs are required.' });
  try {
    const file = await getInboxAttachmentFile(req.user.tenantId, itemId, fileId);
    if (!file) return res.status(404).json({ success: false, message: 'File not found.' });
    res.attachment(file.filename);
    res.type(file.mime);
    return res.send(file.content);
  } catch (error) {
    return sendError(res, error, 'File unavailable.', 'inbox file');
  }
});

// A person says which load an email's files belong to.
app.post('/api/inbox/:id/attach', authMiddleware, requirePermission('shipments:document'), async (req, res) => {
  const itemId = Number(req.params.id);
  const shipmentId = parseShipmentId(req.body?.shipmentId);
  if (!Number.isInteger(itemId) || itemId <= 0 || !shipmentId) return res.status(400).json({ success: false, message: 'An email and a load number (for example SHP-12) are required.' });
  try {
    const item = await getInboxItem(req.user.tenantId, itemId);
    if (!item || item.status === 'blocked') return res.status(404).json({ success: false, message: 'Message not found.' });
    if (!item.attachments.length) return res.status(400).json({ success: false, message: 'This email has no files.' });
    const shipment = await getShipment(req.user.tenantId, shipmentId);
    if (!shipment) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    const moved = await attachEmailFilesToShipment(req.user.tenantId, itemId, shipment, { context: `${item.subject || ''} ${item.body}`, uploadedBy: req.user.id });
    if (!moved.documentIds.length && moved.skipped) {
      return res.status(409).json({ success: false, message: `A load can have at most ${DOC_MAX_PER_SHIPMENT} documents.` });
    }
    await updateInboxItem(req.user.tenantId, itemId, { status: 'attached', shipmentId });
    await resolveTasksByKey(req.user.tenantId, `inbox:${itemId}`, { userId: req.user.id });
    moved.documentIds.forEach((documentId) => nexus.emit('document.uploaded', { tenantId: req.user.tenantId, shipmentId, documentId }));
    return res.json({ success: true, shipmentId: `SHP-${shipmentId}`, documents: moved.documentIds.length, skipped: moved.skipped });
  } catch (error) {
    return sendError(res, error, 'Files could not be attached.', 'inbox attach');
  }
});

/* =========================================================
   DELIVERY REPORTS: Twilio tells us what happened to a sent message
   ========================================================= */
// The address holds a one-time secret for one message, and the request must carry a valid signature
// made with that company's Twilio auth token. Both must be right.
app.post(`${TWILIO_STATUS_PREFIX}:token`, twilioStatusLimiter, express.urlencoded({ extended: false, limit: '20kb' }), async (req, res) => {
  try {
    const token = String(req.params.token);
    if (!PUBLIC_URL || !/^[a-f0-9]{48}$/.test(token)) return res.status(404).json({ success: false, message: 'Not found.' });
    const message = await findMessageByCallbackTokenHash(rateLimitKey(token));
    if (!message) return res.status(404).json({ success: false, message: 'Not found.' });
    const { config } = messaging.resolveConfig(await getTenant(message.tenantId), DEFAULT_TENANT_ID);
    const fields = req.body && typeof req.body === 'object' ? req.body : {};
    if (!config || !messaging.validSignature(config.token, `${PUBLIC_URL}${TWILIO_STATUS_PREFIX}${token}`, fields, req.get('x-twilio-signature'))) {
      return res.status(403).json({ success: false, message: 'Invalid signature.' });
    }
    const sid = fields.MessageSid || fields.SmsSid;
    if (message.providerMessageId && sid && sid !== message.providerMessageId) {
      return res.status(400).json({ success: false, message: 'Report does not match the message.' });
    }
    const outcome = await recordMessageDelivery(message.tenantId, message.id, { status: fields.MessageStatus || fields.SmsStatus, errorCode: fields.ErrorCode });
    if (outcome.failedNow) {
      nexus.emit('message.failed', {
        tenantId: message.tenantId, messageId: message.id, shipmentId: message.shipmentId,
        recipient: message.recipientType, to: message.toPhone, errorCode: /^\d{1,6}$/.test(String(fields.ErrorCode || '')) ? String(fields.ErrorCode) : null
      });
    }
    return res.status(204).end();
  } catch (error) {
    return sendError(res, error, 'Report could not be stored.', 'twilio status');
  }
});

/* =========================================================
   DOCUMENTS (VAULT): CMR, proof of delivery, other files
   ========================================================= */
// The real file type comes from the first bytes, not from the name or the browser's claim.
function detectMime(buffer) {
  if (buffer.length >= 5 && buffer.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buffer.length >= 12 && buffer.subarray(0, 4).toString('latin1') === 'RIFF' && buffer.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  return null;
}

function safeFilename(raw, mime) {
  const base = String(raw || '').split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f"<>:*?|]/g, '').trim().slice(0, 120);
  const extension = { 'application/pdf': '.pdf', 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' }[mime];
  return base || `document${extension}`;
}

const rawDocument = express.raw({
  limit: DOC_MAX_BYTES,
  type: (req) => DOC_MIME_TYPES.includes(String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase())
});

app.get('/api/shipments/:id/documents', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  try {
    if (!(await getShipment(req.user.tenantId, shipmentId))) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    return res.json({ success: true, documents: await listDocuments(req.user.tenantId, shipmentId), readsDocuments: aiGateway.isEnabled() });
  } catch (error) {
    return sendError(res, error, 'Documents unavailable.', 'documents list');
  }
});

app.post('/api/shipments/:id/documents', authMiddleware, requirePermission('shipments:document'), documentLimiter, rawDocument, async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const type = String(req.query.type || 'other');
  if (!shipmentId || !vaultAgent.DOC_TYPES.includes(type)) {
    return res.status(400).json({ success: false, message: `A valid shipment and a document type (${vaultAgent.DOC_TYPES.join(', ')}) are required.` });
  }
  if (!Buffer.isBuffer(req.body) || !req.body.length) {
    return res.status(415).json({ success: false, message: 'Send a PDF, JPEG, PNG or WebP file as the request body.' });
  }
  const mime = detectMime(req.body);
  const claimed = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (!mime || mime !== claimed) {
    return res.status(415).json({ success: false, message: 'The file is not a real PDF, JPEG, PNG or WebP.' });
  }
  try {
    const existing = await listDocuments(req.user.tenantId, shipmentId);
    if (existing.length >= DOC_MAX_PER_SHIPMENT) {
      return res.status(409).json({ success: false, message: `A load can have at most ${DOC_MAX_PER_SHIPMENT} documents.` });
    }
    const { document, duplicate } = await addDocument(req.user.tenantId, shipmentId, {
      type, filename: safeFilename(req.query.filename, mime), mime, content: req.body, uploadedBy: req.user.id
    });
    if (duplicate) return res.json({ success: true, duplicate: true, document });
    nexus.emit('document.uploaded', { tenantId: req.user.tenantId, shipmentId, documentId: document.id });
    return res.status(201).json({ success: true, document });
  } catch (error) {
    return sendError(res, error, 'Document could not be saved.', 'document upload');
  }
});

// Downloads are always an attachment, never shown inside the app's own page.
app.get('/api/shipments/:id/documents/:docId/file', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const docId = Number(req.params.docId);
  if (!shipmentId || !Number.isInteger(docId) || docId <= 0) return res.status(400).json({ success: false, message: 'Valid IDs are required.' });
  try {
    const file = await getDocumentFile(req.user.tenantId, shipmentId, docId);
    if (!file) return res.status(404).json({ success: false, message: 'Document not found.' });
    res.attachment(file.filename);
    res.type(file.mime);
    return res.send(file.content);
  } catch (error) {
    return sendError(res, error, 'Document unavailable.', 'document download');
  }
});

// Read (or re-read) a document with VAULT. Runs in the background; the list shows the result.
app.post('/api/shipments/:id/documents/:docId/extract', authMiddleware, requirePermission('shipments:document'), aiLimiter, async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const docId = Number(req.params.docId);
  if (!shipmentId || !Number.isInteger(docId) || docId <= 0) return res.status(400).json({ success: false, message: 'Valid IDs are required.' });
  try {
    const document = await getDocument(req.user.tenantId, shipmentId, docId);
    if (!document) return res.status(404).json({ success: false, message: 'Document not found.' });
    if (!aiGateway.isEnabled()) return res.status(503).json({ success: false, message: 'AI is not configured. Add OPENROUTER_API_KEY to the server settings.' });
    await updateDocumentExtraction(req.user.tenantId, docId, { status: 'pending' });
    nexus.emit('document.uploaded', { tenantId: req.user.tenantId, shipmentId, documentId: docId });
    return res.status(202).json({ success: true, status: 'pending' });
  } catch (error) {
    return sendError(res, error, 'Document could not be read.', 'document extract');
  }
});

app.delete('/api/shipments/:id/documents/:docId', authMiddleware, requirePermission('shipments:status'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  const docId = Number(req.params.docId);
  if (!shipmentId || !Number.isInteger(docId) || docId <= 0) return res.status(400).json({ success: false, message: 'Valid IDs are required.' });
  try {
    if (!(await deleteDocument(req.user.tenantId, shipmentId, docId))) return res.status(404).json({ success: false, message: 'Document not found.' });
    await resolveTasksByKey(req.user.tenantId, `doc:${docId}`, { status: 'dismissed', userId: req.user.id });
    return res.json({ success: true });
  } catch (error) {
    return sendError(res, error, 'Document could not be deleted.', 'document delete');
  }
});

/* =========================================================
   AI AGENTS
   ========================================================= */
// FLOW: order text -> shipment draft for a person to review. Nothing is saved here.
app.post('/api/agents/flow/parse', authMiddleware, requirePermission('shipments:create'), aiLimiter, async (req, res) => {
  const text = req.body?.text;
  if (typeof text !== 'string' || !text.trim() || text.length > flowAgent.MAX_INPUT_CHARS) {
    return res.status(400).json({ success: false, message: `Paste the order text (at most ${flowAgent.MAX_INPUT_CHARS} characters).` });
  }
  try {
    const result = await flowAgent.parseOrder(text, {
      weightUnit: WEIGHT_UNIT,
      currency: CURRENCY,
      equipment: EQUIPMENT,
      maxRate: MAX_RATE,
      maxWeight: MAX_WEIGHT
    }, agentLogger(req));
    return res.json({ success: true, ...result });
  } catch (error) {
    return sendError(res, error, 'The AI assistant is unavailable.', 'flow');
  }
});

// SCOUT: ranked carrier suggestions for one load (rules, no language model).
app.get('/api/agents/scout/:id', authMiddleware, requirePermission('shipments:dispatch'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  try {
    const data = await getScoutData(req.user.tenantId, shipmentId);
    return res.json({
      success: true,
      recommendations: scoutAgent.rankCarriers(data),
      laneAverageRate: data.laneAverageRate,
      laneLoads: data.laneLoads
    });
  } catch (error) {
    return sendError(res, error, 'Carrier suggestions unavailable.', 'scout');
  }
});

// ROUTE: is the schedule realistic, when will the truck probably arrive, which trucks end up near the pickup.
app.get('/api/agents/route/:id', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  try {
    return res.json({ success: true, ...routeAgent.planRoute(await getRouteData(req.user.tenantId, shipmentId)) });
  } catch (error) {
    return sendError(res, error, 'Route advice unavailable.', 'route');
  }
});

// PULSE: what this lane usually costs, a suggested customer price, and whether the given prices are unusual.
app.get('/api/agents/pulse/:id', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  const optionalMoney = (value) => (value === undefined || value === '' ? null : parseMoney(value));
  const rate = optionalMoney(req.query.rate);
  const customerRate = optionalMoney(req.query.customerRate);
  if ((req.query.rate && rate === null) || (req.query.customerRate && customerRate === null)) {
    return res.status(400).json({ success: false, message: 'Prices must be positive numbers.' });
  }
  try {
    return res.json({ success: true, ...pulseAgent.analyzePrices(await getPulseData(req.user.tenantId, shipmentId), { rate, customerRate, formatMoney }) });
  } catch (error) {
    return sendError(res, error, 'Price advice unavailable.', 'pulse');
  }
});

// SENTINEL: every open load of this company that is at risk right now, worst first.
app.get('/api/agents/sentinel', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const risks = sentinelAgent.assess(await listSentinelLoads(req.user.tenantId), { staleHours: STALE_TRACKING_HOURS });
    return res.json({ success: true, risks: risks.slice(0, 200), total: risks.length });
  } catch (error) {
    return sendError(res, error, 'Risk check unavailable.', 'sentinel');
  }
});

/* =========================================================
   CARRIERS
   ========================================================= */
app.get('/api/carriers', authMiddleware, requirePermission('carriers:read'), async (req, res) => {
  try {
    const carriers = await listCarriersWithStats(req.user.tenantId);
    res.json(carriers);
  } catch (error) {
    console.error('[carriers] failed:', error.message);
    res.status(500).json({
      success: false,
      message: 'Carriers unavailable'
    });
  }
});

app.post('/api/carriers', authMiddleware, requirePermission('carriers:write'), async (req, res) => {
  const { name, mode } = req.body || {};
  if (typeof name !== 'string' || !name.trim() || name.trim().length > MAX_LEN.carrierName || !CARRIER_MODES.includes(mode)) {
    return res.status(400).json({ success: false, message: `Carrier name (max ${MAX_LEN.carrierName} characters) and a valid mode are required.` });
  }
  const phone = readOptionalPhone(req.body, 'phone');
  const contactName = readOptionalText(req.body, 'contactName', MAX_LEN.contactName);
  const invalid = phone.error || contactName.error;
  if (invalid) return res.status(400).json({ success: false, message: invalid });
  try {
    const carrier = await createCarrier({ name: name.trim(), mode, phone: phone.value, contactName: contactName.value, tenantId: req.user.tenantId });
    return res.status(201).json({ success: true, carrier });
  } catch (error) {
    return sendError(res, error, 'Carrier creation failed', 'create carrier');
  }
});

app.patch('/api/carriers/:id/status', authMiddleware, requirePermission('carriers:write'), async (req, res) => {
  const carrierId = Number(req.params.id);
  const status = req.body?.status;
  if (!Number.isInteger(carrierId) || carrierId <= 0 || !CARRIER_MANUAL_STATUSES.includes(status)) {
    return res.status(400).json({ success: false, message: `A valid carrier ID and status (${CARRIER_MANUAL_STATUSES.join(' or ')}) are required.` });
  }
  try {
    const carrier = await updateCarrierStatus(req.user.tenantId, carrierId, status);
    return res.json({ success: true, carrier });
  } catch (error) {
    return sendError(res, error, 'Carrier update failed', 'carrier status');
  }
});

/* =========================================================
   ACCOUNT AND TEAM
   ========================================================= */
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      role: req.user.role,
      permissions: ROLE_PERMISSIONS[req.user.role] || [],
      tenantId: req.user.tenantId,
      tenantName: req.user.tenantName,
      isPlatformAdmin: req.user.isPlatformAdmin
    }
  });
});

app.get('/api/admin/users', authMiddleware, requirePermission('users:read'), async (req, res) => {
  try {
    const users = await listUsers(req.user.tenantId);
    res.json({
      success: true,
      users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'User list unavailable'
    });
  }
});

// Admin adds a team member to their own company with a starting password.
app.post('/api/admin/users', authMiddleware, requirePermission('users:write'), async (req, res) => {
  const { name, email, password, role } = req.body || {};
  const identityError = validateNameAndEmail(name, email);
  if (identityError) return res.status(400).json({ success: false, message: identityError });
  if (!ALLOWED_ROLES.includes(role)) {
    return res.status(400).json({ success: false, message: `Role must be one of: ${ALLOWED_ROLES.join(', ')}.` });
  }
  const passwordError = validateNewPassword(password);
  if (passwordError) return res.status(400).json({ success: false, message: passwordError });
  try {
    const normalizedEmail = email.trim().toLowerCase();
    if (await findUserByEmail(normalizedEmail)) {
      return res.status(409).json({ success: false, message: 'A user with this email already exists.' });
    }
    const user = await createUser({
      name: name.trim(),
      email: normalizedEmail,
      password: await bcrypt.hash(password, BCRYPT_COST),
      role,
      tenantId: req.user.tenantId
    });
    return res.status(201).json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, active: true } });
  } catch (error) {
    if (String(error.code) === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ success: false, message: 'A user with this email already exists.' });
    }
    console.error('[create user] failed:', error.message);
    return res.status(500).json({ success: false, message: 'User could not be created.' });
  }
});

// Change role and/or enable/disable an account in the same company. Takes effect at once.
app.patch('/api/admin/users/:id', authMiddleware, requirePermission('users:write'), async (req, res) => {
  const userId = Number(req.params.id);
  const { role, active } = req.body || {};
  if (!Number.isInteger(userId) || userId <= 0
    || (role === undefined && active === undefined)
    || (role !== undefined && !ALLOWED_ROLES.includes(role))
    || (active !== undefined && typeof active !== 'boolean')) {
    return res.status(400).json({ success: false, message: `Send a role (${ALLOWED_ROLES.join(', ')}) and/or active (true or false).` });
  }
  try {
    const user = await updateUser(req.user.tenantId, userId, { role, active }, req.user.id);
    return res.json({ success: true, user });
  } catch (error) {
    return sendError(res, error, 'User could not be updated.', 'update user');
  }
});

app.get('/api/admin/shipments', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipments = await listShipments(req.user.tenantId, readPaging(req));
    res.json({
      success: true,
      shipments: shipments.map(serializeShipment)
    });
  } catch (error) {
    console.error('[admin shipments] failed:', error.message);
    res.status(500).json({ success: false, message: 'Admin shipment list unavailable' });
  }
});

app.patch('/api/admin/shipments/:id/status', authMiddleware, requirePermission('shipments:status'), async (req, res) => {
  try {
    const shipmentId = parseShipmentId(req.params.id);
    const { status, note } = req.body || {};

    if (!shipmentId || !SHIPMENT_STATUSES.includes(status) || (note !== undefined && note !== null && (typeof note !== 'string' || note.length > MAX_LEN.note))) {
      return res.status(400).json({
        success: false,
        message: `A valid shipment ID and a status (${SHIPMENT_STATUSES.join(', ')}) are required.`
      });
    }

    const result = await updateShipmentStatus(req.user.tenantId, shipmentId, status, req.user.id, note);
    nexus.emit('shipment.status', { tenantId: req.user.tenantId, shipmentId, status });
    return res.json({
      success: true,
      shipment: {
        id: `SHP-${result.id}`,
        status: result.status,
        updated: result.changes > 0
      }
    });
  } catch (error) {
    return sendError(res, error, 'Shipment status update failed', 'status');
  }
});

app.post('/api/admin/shipments/:id/dispatch', authMiddleware, requirePermission('shipments:dispatch'), async (req, res) => {
  try {
    const shipmentId = parseShipmentId(req.params.id);
    const carrierId = typeof req.body?.carrierId === 'number' ? req.body.carrierId : NaN;
    const rate = parseMoney(req.body?.rate);
    if (!Number.isInteger(shipmentId) || shipmentId <= 0 || !Number.isInteger(carrierId) || carrierId <= 0 || rate === null) {
      return res.status(400).json({ success: false, message: `A valid carrier and a rate between 0.01 and ${MAX_RATE.toLocaleString('en-US')} are required.` });
    }
    const hasCustomerRate = req.body?.customerRate !== undefined && req.body?.customerRate !== null && req.body?.customerRate !== '';
    const customerRate = hasCustomerRate ? parseMoney(req.body.customerRate) : null;
    if (hasCustomerRate && customerRate === null) {
      return res.status(400).json({ success: false, message: `Customer price must be between 0.01 and ${MAX_RATE.toLocaleString('en-US')}.` });
    }
    const driverName = readOptionalText(req.body, 'driverName', MAX_LEN.driverName);
    const driverPhone = readOptionalPhone(req.body, 'driverPhone');
    const truckPlate = readOptionalText(req.body, 'truckPlate', MAX_LEN.truckPlate);
    const invalid = driverName.error || driverPhone.error || truckPlate.error;
    if (invalid) return res.status(400).json({ success: false, message: invalid });

    const shipment = await dispatchShipment(req.user.tenantId, shipmentId, carrierId, rate, req.user.id, {
      customerRate,
      driverName: driverName.value,
      driverPhone: driverPhone.value,
      truckPlate: truckPlate.value
    });
    nexus.emit('shipment.dispatched', { tenantId: req.user.tenantId, shipmentId });
    return res.json({ success: true, shipment: { ...shipment, id: `SHP-${shipment.id}` } });
  } catch (error) {
    return sendError(res, error, 'Dispatch failed', 'dispatch');
  }
});

/* =========================================================
   INTEGRATIONS (GPS, messaging, AI status)
   ========================================================= */
app.get('/api/integrations/status', authMiddleware, requirePermission('users:read'), async (req, res) => {
  try {
    const tenant = await getTenant(req.user.tenantId);
    res.json({
      success: true,
      ai: { enabled: aiGateway.isEnabled(), model: process.env.OPENROUTER_MODEL || null },
      messaging: { ...messaging.publicStatus(tenant, DEFAULT_TENANT_ID), deliveryReports: Boolean(PUBLIC_URL) },
      gps: { configured: Boolean(tenant?.gpsTokenHash), webhookPath: GPS_WEBHOOK_PATH, minIntervalMinutes: GPS_MIN_INTERVAL_MINUTES },
      inbox: { configured: Boolean(tenant?.inboxTokenHash), pathPrefix: INBOX_WEBHOOK_PREFIX, allowedSenders: tenant?.allowedSenders || [], dailyLimit: INBOX_DAILY_LIMIT,
        maxMb: INBOX_MAX_BYTES / (1024 * 1024), maxFiles: INBOX_MAX_ATTACHMENTS },
      documents: { reads: aiGateway.isEnabled(), maxMb: DOC_MAX_BYTES / (1024 * 1024) },
      nexus: { enabled: process.env.NEXUS_ENABLED !== 'false', staleHours: STALE_TRACKING_HOURS, aiDailyLimit: AI_DAILY_LIMIT_PER_TENANT }
    });
  } catch (error) {
    return sendError(res, error, 'Integration status unavailable.', 'integrations');
  }
});

// Which channels (SMS / WhatsApp) this company can send with. Open to every signed-in user: the
// message form needs it. It contains no credentials.
app.get('/api/messaging/status', authMiddleware, async (req, res) => {
  try {
    res.json({ success: true, ...messaging.publicStatus(await getTenant(req.user.tenantId), DEFAULT_TENANT_ID) });
  } catch (error) {
    return sendError(res, error, 'Messaging status unavailable.', 'messaging status');
  }
});

// This company's own Twilio account. Checked with Twilio before saving, stored encrypted,
// never returned. Leave the token empty to keep the saved one when only the numbers change.
app.put('/api/settings/messaging', authMiddleware, requirePermission('settings:write'), async (req, res) => {
  const { accountSid, authToken, smsFrom, whatsappFrom } = req.body || {};
  const sid = typeof accountSid === 'string' ? accountSid.trim() : '';
  if (!/^AC[0-9a-fA-F]{32}$/.test(sid)) {
    return res.status(400).json({ success: false, message: 'Account SID looks like AC followed by 32 letters and digits (find it on the Twilio console home page).' });
  }
  const readNumber = (value) => {
    if (value === undefined || value === null || String(value).trim() === '') return { value: '' };
    const number = messaging.toE164(String(value).trim().replace(/^whatsapp:/i, ''));
    return number ? { value: number } : { error: true };
  };
  const sms = readNumber(smsFrom);
  const whatsapp = readNumber(whatsappFrom);
  if (sms.error || whatsapp.error) {
    return res.status(400).json({ success: false, message: 'Sender numbers must be in international format, e.g. +15551234567.' });
  }
  if (!sms.value && !whatsapp.value) {
    return res.status(400).json({ success: false, message: 'Enter at least one sender number (SMS or WhatsApp).' });
  }
  try {
    const tenant = await getTenant(req.user.tenantId);
    let token = typeof authToken === 'string' ? authToken.trim() : '';
    if (!token && tenant.messagingSettings?.sid === sid) token = tenant.messagingSettings.token;
    if (!/^[0-9a-zA-Z]{16,64}$/.test(token)) {
      return res.status(400).json({ success: false, message: 'Enter the Auth Token from the Twilio console.' });
    }
    const settings = { sid, token, smsFrom: sms.value, whatsappFrom: whatsapp.value };
    const check = await messaging.verifyCredentials(settings);
    if (!check.ok) return res.status(400).json({ success: false, message: check.reason });
    await setTenantMessagingSettings(req.user.tenantId, settings);
    return res.json({ success: true, messaging: messaging.publicStatus({ id: req.user.tenantId, messagingSettings: settings }, DEFAULT_TENANT_ID) });
  } catch (error) {
    return sendError(res, error, 'Settings could not be saved.', 'messaging settings');
  }
});

app.delete('/api/settings/messaging', authMiddleware, requirePermission('settings:write'), async (req, res) => {
  try {
    await setTenantMessagingSettings(req.user.tenantId, null);
    return res.json({ success: true, messaging: messaging.publicStatus(await getTenant(req.user.tenantId), DEFAULT_TENANT_ID) });
  } catch (error) {
    return sendError(res, error, 'Settings could not be removed.', 'messaging settings delete');
  }
});

// The company's email inbox address. The token is shown once; only its hash is stored.
app.post('/api/settings/inbox/token', authMiddleware, requirePermission('settings:write'), async (req, res) => {
  try {
    const token = `inbox_${crypto.randomBytes(24).toString('hex')}`;
    await setTenantInboxTokenHash(req.user.tenantId, rateLimitKey(token));
    res.status(201).json({ success: true, token, webhookPath: `${INBOX_WEBHOOK_PREFIX}${token}` });
  } catch (error) {
    return sendError(res, error, 'Token could not be created.', 'inbox token');
  }
});

// Who may send orders in. Empty = anyone who knows the address. Entries: an address or a domain.
app.put('/api/settings/inbox', authMiddleware, requirePermission('settings:write'), async (req, res) => {
  const list = req.body?.allowedSenders;
  if (!Array.isArray(list) || list.length > 50 || list.some((entry) => typeof entry !== 'string' || !/^@?[a-z0-9._+-]+(@[a-z0-9.-]+)?$/i.test(entry.trim()) || entry.length > 254)) {
    return res.status(400).json({ success: false, message: 'Send up to 50 email addresses or domains, e.g. ["customer.com", "boss@partner.com"].' });
  }
  try {
    const cleaned = [...new Set(list.map((entry) => entry.trim().toLowerCase()))];
    await setTenantInboxAllowedSenders(req.user.tenantId, cleaned);
    return res.json({ success: true, allowedSenders: cleaned });
  } catch (error) {
    return sendError(res, error, 'Settings could not be saved.', 'inbox settings');
  }
});

// Creates (or replaces) this company's GPS token. Shown once; only its hash is stored.
app.post('/api/integrations/gps/token', authMiddleware, requirePermission('settings:write'), async (req, res) => {
  try {
    const token = `gps_${crypto.randomBytes(24).toString('hex')}`;
    await setTenantGpsTokenHash(req.user.tenantId, rateLimitKey(token));
    res.status(201).json({ success: true, token, webhookPath: GPS_WEBHOOK_PATH });
  } catch (error) {
    return sendError(res, error, 'Token could not be created.', 'gps token');
  }
});

function readGpsToken(req) {
  const header = String(req.headers.authorization || '');
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  if (req.headers['x-veyra-token']) return String(req.headers['x-veyra-token']).trim();
  // Some trackers can only call a plain URL, so ?token= is accepted too.
  return typeof req.query.token === 'string' ? req.query.token.trim() : '';
}

function parseGpsPosition(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const lat = Number(raw.lat ?? raw.latitude);
  const lng = Number(raw.lng ?? raw.lon ?? raw.longitude);
  if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) return null;
  const shipmentId = raw.shipmentId !== undefined ? parseShipmentId(raw.shipmentId) : null;
  const plate = typeof raw.truckPlate === 'string' && raw.truckPlate.length <= MAX_LEN.truckPlate ? normalizePlate(raw.truckPlate) : '';
  if (!shipmentId && !plate) return null;
  const speedNumber = raw.speed === undefined || raw.speed === null ? null : Number(raw.speed);
  const address = typeof raw.address === 'string' && raw.address.trim() && raw.address.trim().length <= MAX_LEN.location ? raw.address.trim() : null;
  return {
    lat,
    lng,
    shipmentId,
    truckPlate: plate,
    speed: Number.isFinite(speedNumber) && speedNumber >= 0 && speedNumber <= 300 ? speedNumber : null,
    address
  };
}

// GPS provider webhook: positions for trucks on active loads. Authenticated by the company's GPS token.
app.post(GPS_WEBHOOK_PATH, async (req, res, next) => {
  const token = readGpsToken(req);
  if (!token) return res.status(401).json({ success: false, message: 'GPS token required.' });
  req.gpsTokenHash = rateLimitKey(token);
  return gpsLimiter(req, res, next);
}, async (req, res) => {
  try {
    const tenant = await findTenantByGpsTokenHash(req.gpsTokenHash);
    if (!tenant) return res.status(401).json({ success: false, message: 'Invalid GPS token.' });
    const body = req.body;
    const list = Array.isArray(body) ? body : (Array.isArray(body?.positions) ? body.positions : [body]);
    if (!list.length || list.length > 500) {
      return res.status(400).json({ success: false, message: 'Send between 1 and 500 positions.' });
    }
    const positions = list.map(parseGpsPosition);
    const valid = positions.filter(Boolean);
    const summary = valid.length
      ? await recordGpsPositions(tenant.id, valid, { minIntervalMinutes: GPS_MIN_INTERVAL_MINUTES })
      : { accepted: 0, skipped: 0, unmatched: 0 };
    return res.json({ success: true, ...summary, invalid: positions.length - valid.length });
  } catch (error) {
    return sendError(res, error, 'GPS positions could not be saved.', 'gps webhook');
  }
});

/* =========================================================
   PLATFORM: customer companies (multi-tenant)
   ========================================================= */
app.get('/api/platform/tenants', authMiddleware, requirePlatformAdmin, async (req, res) => {
  try {
    res.json({ success: true, tenants: await listTenants() });
  } catch (error) {
    return sendError(res, error, 'Companies unavailable.', 'tenants');
  }
});

// A new customer company with its first administrator. Each company sees only its own data.
app.post('/api/platform/tenants', authMiddleware, requirePlatformAdmin, async (req, res) => {
  const { companyName, adminName, adminEmail, adminPassword } = req.body || {};
  if (typeof companyName !== 'string' || !companyName.trim() || companyName.trim().length > MAX_LEN.companyName) {
    return res.status(400).json({ success: false, message: `Company name is required (at most ${MAX_LEN.companyName} characters).` });
  }
  const identityError = validateNameAndEmail(adminName, adminEmail);
  if (identityError) return res.status(400).json({ success: false, message: identityError });
  const passwordError = validateNewPassword(adminPassword);
  if (passwordError) return res.status(400).json({ success: false, message: passwordError });
  try {
    const result = await createTenantWithAdmin({
      name: companyName.trim(),
      adminName: adminName.trim(),
      adminEmail: adminEmail.trim().toLowerCase(),
      passwordHash: await bcrypt.hash(adminPassword, BCRYPT_COST)
    });
    return res.status(201).json({ success: true, ...result });
  } catch (error) {
    if (String(error.code) === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ success: false, message: 'A user with this email already exists.' });
    }
    return sendError(res, error, 'Company could not be created.', 'create tenant');
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ success: false, message: 'Not found.' });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// Final safety net: never leak internals (stack traces, SQL, paths) to clients.
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error?.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, message: 'Request body must be valid JSON.' });
  }
  if (error?.type === 'entity.too.large') {
    return res.status(413).json({ success: false, message: 'Request body is too large.' });
  }
  if (Number.isInteger(error?.status) && error.status >= 400 && error.status < 500) {
    return res.status(error.status).json({ success: false, message: 'Request could not be processed.' });
  }
  console.error('[unhandled] failed:', error?.message || error);
  return res.status(500).json({ success: false, message: 'Something went wrong. Please try again.' });
});

function startServer() {
  return initialize()
    .then(() => new Promise((resolve) => {
      const server = app.listen(PORT, HOST, () => {
        console.log(`VEYRA API running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT} (${isProduction ? 'production' : 'development'}, ${WEIGHT_UNIT}, ${CURRENCY}, sign-up: ${REGISTRATION_MODE}, AI: ${aiGateway.isEnabled() ? 'on' : 'off'}, messaging: ${messaging.channelsOf(messaging.envConfig()).join('+') || 'per company only'}, NEXUS: ${process.env.NEXUS_ENABLED === 'false' ? 'off' : 'on'})`);
        nexus.startSweeper();
        if (!isProduction) {
          console.warn('[VEYRA] Development mode: demo accounts with public passwords exist. Never expose this server to the internet.');
        }
        resolve(server);
      });
    }))
    .catch((error) => {
      console.error('Database initialization failed:', error);
      process.exit(1);
    });
}

module.exports = {
  app,
  initialize,
  startServer,
  authRateLimiters
};

if (require.main === module) {
  startServer();
}
