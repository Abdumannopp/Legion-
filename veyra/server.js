require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const REGISTRATION_INVITE_CODE = process.env.REGISTRATION_INVITE_CODE || '';
const MAX_LEN = {
  carrierName: 120, name: 120, email: 254, customer: 120, reference: 80, origin: 160, destination: 160, trackingNumber: 80, note: 500,
  phone: 40, contactName: 120, driverName: 120, driverPhone: 40, truckPlate: 20, location: 160
};
// bcrypt only uses the first 72 bytes of a password; longer input would be silently cut.
const MAX_PASSWORD_BYTES = 72;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {
  BCRYPT_COST,
  ALLOWED_ROLES,
  TRACKABLE_STATUSES,
  initialize,
  findUserByEmail,
  findUserById,
  updateUser,
  addTrackingUpdate,
  listTrackingUpdates,
  createAuthSession,
  isAuthSessionActive,
  revokeAuthSession,
  getRateLimitStatus,
  consumeRateLimit,
  recordRateLimitAttempts,
  clearRateLimitAttempts,
  createUser,
  listUsers,
  listShipments,
  getShipment,
  updateShipmentStatus,
  createShipment,
  dispatchShipment,
  listShipmentEvents,
  listCarriers,
  getAnalyticsPayload,
  getDashboardPayload,
  listCarriersWithStats,
  createCarrier,
  updateCarrierStatus,
  CARRIER_MODES,
  CARRIER_MANUAL_STATUSES,
  getAnalyticsReport,
} = require('./database');

function readPositiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

// Same hash cost as real accounts, so a login for an unknown email takes as long as a real one.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_COST);

const ROLE_PERMISSIONS = {
  admin: ['*'],
  operations: ['analytics:read', 'dashboard:read', 'carriers:read', 'carriers:write', 'shipments:read', 'shipments:create', 'shipments:status', 'shipments:dispatch', 'shipments:track', 'users:read'],
  // Dispatchers log where the truck is ("check calls"), but cannot book or change status.
  operator: ['dashboard:read', 'carriers:read', 'shipments:read', 'shipments:create', 'shipments:track']
};

const app = express();
// Production is the default; development must be requested explicitly (NODE_ENV=development).
const isProduction = process.env.NODE_ENV !== 'development';
const PORT = process.env.PORT || 3000;
// Development mode has demo accounts with published passwords, so by default it only listens on this machine.
const HOST = process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1');
const JWT_SECRET = process.env.JWT_SECRET || (isProduction ? null : 'veyra-dev-secret');

// Region settings: one product, configured per deployment (kg or lb, local currency).
const WEIGHT_UNIT = ['kg', 'lb'].includes(String(process.env.WEIGHT_UNIT).toLowerCase()) ? String(process.env.WEIGHT_UNIT).toLowerCase() : 'kg';
const CURRENCY = /^[A-Z]{3}$/.test(String(process.env.CURRENCY || '')) ? process.env.CURRENCY : 'USD';
const EQUIPMENT = ['Dry Van', 'Tent / Curtainsider', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
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
app.use(express.json({ limit: '50kb' }));
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR));

function readPaging(req) {
  const limit = Math.min(readPositiveInteger(req.query.limit, 100), 200);
  const page = readPositiveInteger(req.query.page, 1);
  return { limit, offset: (page - 1) * limit };
}

const SHIPMENT_STATUSES = ['New', 'Sourcing', 'Pending Approval', 'Dispatched', 'In Transit', 'Exception', 'Delivered', 'Cancelled'];

function parseShipmentId(raw) {
  const match = /^(?:SHP-)?([1-9]\d{0,9})$/.exec(String(raw));
  return match ? Number(match[1]) : null;
}

function parsePositiveNumber(value, max) {
  const isNumeric = typeof value === 'number' || (typeof value === 'string' && /^\d+(\.\d{1,2})?$/.test(value.trim()));
  const number = isNumeric ? Number(value) : NaN;
  return Number.isFinite(number) && number > 0 && number <= max ? number : null;
}

const MAX_WEIGHT = 1000000;
// Sanity bound for money fields. Raise MAX_RATE for currencies with large numbers (e.g. UZS).
const MAX_RATE = readPositiveInteger(process.env.MAX_RATE, 10000000);

function parseMoney(value) {
  const amount = parsePositiveNumber(value, MAX_RATE);
  return amount === null ? null : Math.round(amount * 100) / 100;
}

// Optional free-text field: undefined/null/'' mean "not given". Returns { value } or { error }.
function readOptionalText(body, field, maxLength) {
  const value = body?.[field];
  if (value === undefined || value === null || value === '') return { value: null };
  if (typeof value !== 'string' || value.trim().length > maxLength) return { error: `${field} must be text of at most ${maxLength} characters.` };
  return { value: value.trim() || null };
}

function readOptionalPhone(body, field) {
  const result = readOptionalText(body, field, MAX_LEN[field] || 40);
  if (result.error || !result.value) return result;
  return /^[+\d][\d\s()-]{4,}$/.test(result.value) ? result : { error: `${field} must be a phone number (digits, spaces, + ( ) -).` };
}

// ETA: a date (YYYY-MM-DD) or a date and time (YYYY-MM-DDTHH:MM), as entered by the dispatcher.
function parseEta(value) {
  if (value === undefined || value === null || value === '') return { value: null };
  if (typeof value !== 'string') return { error: 'ETA must be a date (YYYY-MM-DD) or date and time (YYYY-MM-DDTHH:MM).' };
  const match = /^(\d{4}-\d{2}-\d{2})(?:T([01]\d|2[0-3]):([0-5]\d))?$/.exec(value.trim());
  if (!match || !parseIsoDate(match[1])) return { error: 'ETA must be a date (YYYY-MM-DD) or date and time (YYYY-MM-DDTHH:MM).' };
  return { value: value.trim() };
}

function passwordTooLong(password) {
  return Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES;
}

function validateNewPassword(password) {
  if (typeof password !== 'string' || password.length < 8 || passwordTooLong(password) || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    return `Password must be at least 8 characters (at most ${MAX_PASSWORD_BYTES} bytes) and include a letter and a number.`;
  }
  return null;
}

function parseIsoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? null : date;
}

function serializeShipment(shipment) {
  const hasMargin = shipment.rate !== null && shipment.rate !== undefined && shipment.customer_rate !== null && shipment.customer_rate !== undefined;
  return {
    id: `SHP-${shipment.id}`,
    customer: shipment.customer,
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

app.use('/api', normalApiLimiter);

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
    // Role and access come from the database on every request, not from the token,
    // so an admin's change (new role, account disabled) applies immediately.
    const user = await findUserById(payload.id);
    if (!user || user.disabledAt) {
      return res.status(401).json({ success: false, message: 'Session expired or revoked.' });
    }
    req.user = { id: user.id, email: user.email, name: user.name, role: user.role, jti: payload.jti };
    return next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token.'
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Forbidden: insufficient role permissions.'
      });
    }

    return next();
  };
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

function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    permissions: ROLE_PERMISSIONS[user.role] || []
  };
}

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'VEYRA Logistics API',
    timestamp: new Date().toISOString()
  });
});

// Public settings the UI needs before sign-in (units, currency, whether sign-up is possible).
app.get('/api/config', (req, res) => {
  res.json({
    weightUnit: WEIGHT_UNIT,
    currency: CURRENCY,
    equipment: EQUIPMENT,
    registration: REGISTRATION_MODE,
    maxRate: MAX_RATE
  });
});

function validateNameAndEmail(name, email) {
  if (typeof name !== 'string' || typeof email !== 'string' || !name.trim() || !email.trim()) {
    return 'Name and email are required.';
  }
  if (name.length > MAX_LEN.name || email.length > MAX_LEN.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return 'Name or email is invalid.';
  }
  return null;
}

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
      user = await createUser({
        name: name.trim(),
        email: normalizedEmail,
        password: hashedPassword,
        role: 'operator'
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

app.get('/api/dashboard', authMiddleware, requirePermission('dashboard:read'), async (req, res) => {
  try {
    const payload = await getDashboardPayload({ days: req.query.days });
    const permissions = ROLE_PERMISSIONS[req.user.role] || [];
    if (!permissions.includes('*') && !permissions.includes('analytics:read')) {
      delete payload.stats;
      delete payload.statuses;
      delete payload.weeklyVolume;
    }
    res.json(payload);
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Dashboard unavailable'
    });
  }
});

app.get('/api/analytics', authMiddleware, requirePermission('analytics:read'), async (req, res) => {
  try {
    res.json(await getAnalyticsReport({ days: req.query.days }));
  } catch (error) {
    res.status(500).json({ success: false, message: 'Analytics unavailable.' });
  }
});

app.get('/api/shipments', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipments = await listShipments(readPaging(req));
    res.json(shipments.map(serializeShipment));
  } catch (error) {
    console.error('[shipments] failed:', error.message);
    res.status(500).json({ success: false, message: 'Shipments unavailable' });
  }
});

app.get('/api/shipments/:id', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) {
    return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  }
  try {
    const shipment = await getShipment(shipmentId);
    if (!shipment) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    return res.json(serializeShipment(shipment));
  } catch (error) {
    console.error('[shipment] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Shipment unavailable' });
  }
});

app.get('/api/carriers', authMiddleware, requirePermission('carriers:read'), async (req, res) => {
  try {
    const carriers = await listCarriersWithStats();
    res.json(carriers);
  } catch (error) {
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
    const carrier = await createCarrier({ name: name.trim(), mode, phone: phone.value, contactName: contactName.value });
    return res.status(201).json({ success: true, carrier });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
    console.error('[create carrier] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Carrier creation failed' });
  }
});

app.patch('/api/carriers/:id/status', authMiddleware, requirePermission('carriers:write'), async (req, res) => {
  const carrierId = Number(req.params.id);
  const status = req.body?.status;
  if (!Number.isInteger(carrierId) || carrierId <= 0 || !CARRIER_MANUAL_STATUSES.includes(status)) {
    return res.status(400).json({ success: false, message: `A valid carrier ID and status (${CARRIER_MANUAL_STATUSES.join(' or ')}) are required.` });
  }
  try {
    const carrier = await updateCarrierStatus(carrierId, status);
    return res.json({ success: true, carrier });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
    console.error('[carrier status] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Carrier update failed' });
  }
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      role: req.user.role,
      permissions: ROLE_PERMISSIONS[req.user.role] || []
    }
  });
});

app.get('/api/admin/users', authMiddleware, requirePermission('users:read'), async (req, res) => {
  try {
    const users = await listUsers();
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

// Admin adds a team member with a starting password (sign-up is closed in production).
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
    const user = await createUser({ name: name.trim(), email: normalizedEmail, password: await bcrypt.hash(password, BCRYPT_COST), role });
    return res.status(201).json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, active: true } });
  } catch (error) {
    if (String(error.code) === 'SQLITE_CONSTRAINT') {
      return res.status(409).json({ success: false, message: 'A user with this email already exists.' });
    }
    console.error('[create user] failed:', error.message);
    return res.status(500).json({ success: false, message: 'User could not be created.' });
  }
});

// Change role and/or enable/disable an account. Takes effect at once (sessions are revoked).
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
    const user = await updateUser(userId, { role, active }, req.user.id);
    return res.json({ success: true, user });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
    console.error('[update user] failed:', error.message);
    return res.status(500).json({ success: false, message: 'User could not be updated.' });
  }
});

app.get('/api/admin/shipments', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipments = await listShipments(readPaging(req));
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

    const result = await updateShipmentStatus(shipmentId, status, req.user.id, note);
    return res.json({
      success: true,
      shipment: {
        id: `SHP-${result.id}`,
        status: result.status,
        updated: result.changes > 0
      }
    });
  } catch (error) {
    if (error.statusCode) {
      return res.status(error.statusCode).json({ success: false, message: error.message });
    }
    console.error('[status] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Shipment status update failed' });
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

    const shipment = await dispatchShipment(shipmentId, carrierId, rate, req.user.id, {
      customerRate,
      driverName: driverName.value,
      driverPhone: driverPhone.value,
      truckPlate: truckPlate.value
    });
    return res.json({ success: true, shipment: { ...shipment, id: `SHP-${shipment.id}` } });
  } catch (error) {
    if (error.statusCode) {
      return res.status(error.statusCode).json({ success: false, message: error.message });
    }
    console.error('[dispatch] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Dispatch failed' });
  }
});

app.get('/api/shipments/:id/events', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipmentId = parseShipmentId(req.params.id);
    if (!shipmentId) {
      return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
    }
    return res.json({ success: true, events: await listShipmentEvents(shipmentId) });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Shipment history unavailable.' });
  }
});

// Where is the truck? Location updates ("check calls") for a booked load, newest first.
app.get('/api/shipments/:id/tracking', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  const shipmentId = parseShipmentId(req.params.id);
  if (!shipmentId) return res.status(400).json({ success: false, message: 'Valid shipment ID is required.' });
  try {
    if (!(await getShipment(shipmentId))) return res.status(404).json({ success: false, message: 'Shipment not found.' });
    return res.json({ success: true, updates: await listTrackingUpdates(shipmentId) });
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
    const update = await addTrackingUpdate(shipmentId, { location: location.trim(), eta: eta.value, note: note.value }, req.user.id);
    return res.status(201).json({ success: true, update });
  } catch (error) {
    if (error.statusCode) return res.status(error.statusCode).json({ success: false, message: error.message });
    console.error('[tracking add] failed:', error.message);
    return res.status(500).json({ success: false, message: 'Location update failed.' });
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
      actorId: req.user.id
    });

    return res.status(201).json({
      success: true,
      shipment
    });
  } catch (error) {
    console.error('[create shipment] failed:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Shipment creation failed'
    });
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
        console.log(`VEYRA API running at http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT} (${isProduction ? 'production' : 'development'}, ${WEIGHT_UNIT}, ${CURRENCY}, sign-up: ${REGISTRATION_MODE})`);
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
