require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const REGISTRATION_INVITE_CODE = process.env.REGISTRATION_INVITE_CODE || '';
const DUMMY_HASH = '$2b$10$w4Kn/xbbbqc1P3LEUhFhjuvby9b95CZTCEfa.chsvQmNnSH/.a40G';
const MAX_LEN = { carrierName: 120, name: 120, email: 254, customer: 120, reference: 80, origin: 160, destination: 160, trackingNumber: 80, note: 500 };
const MAX_PASSWORD_LENGTH = 72;
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {
  initialize,
  findUserByEmail,
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

const ROLE_PERMISSIONS = {
  admin: ['*'],
  operations: ['analytics:read', 'dashboard:read', 'carriers:read', 'carriers:write', 'shipments:read', 'shipments:create', 'shipments:status', 'shipments:dispatch', 'users:read'],
  operator: ['dashboard:read', 'carriers:read', 'shipments:read', 'shipments:create']
};

const app = express();
// Production is the default; development must be requested explicitly (NODE_ENV=development).
const isProduction = process.env.NODE_ENV !== 'development';
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || (isProduction ? null : 'veyra-dev-secret');
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

const MAX_WEIGHT_LB = 1000000;
const MAX_RATE_USD = 10000000;

function parseIsoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? null : date;
}

function serializeShipment(shipment) {
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
    weight: shipment.weight,
    equipment: shipment.equipment,
    carrierName: shipment.carrierName,
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
    [rateLimitKey(`login-ip:${ip}`), rateLimitKey(`login-account:${ip}:${normalizedEmail || 'unknown'}`)],
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
    const [ipStatus, accountStatus] = await Promise.all([
      getRateLimitStatus(rateLimitKey(`login-ip:${ip}`), AUTH_RATE_LIMIT_CONFIG.login.windowMs, AUTH_RATE_LIMIT_CONFIG.login.ipMax),
      getRateLimitStatus(rateLimitKey(`login-account:${ip}:${email || 'unknown'}`), AUTH_RATE_LIMIT_CONFIG.login.windowMs, AUTH_RATE_LIMIT_CONFIG.login.max)
    ]);

    if (ipStatus.limited || accountStatus.limited) {
      const emailId = rateLimitKey(email || 'unknown').slice(0, 12);
      console.warn(`[AUTH SECURITY] login rate limit exceeded for account=${emailId} from ${ip}`);
      const retryAfterMs = Math.max(ipStatus.retryAfterMs, accountStatus.retryAfterMs);
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
  await createAuthSession(session.jti, session.expiresAt);
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
    req.user = payload;
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

app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    const { name, email, password, inviteCode } = req.body || {};

    if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string' || !name.trim() || !email.trim() || !password) {
      return res.status(400).json({
        success: false,
        message: 'Name, email and password are required.'
      });
    }
    if (name.length > MAX_LEN.name || email.length > MAX_LEN.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return res.status(400).json({ success: false, message: 'Name or email is invalid.' });
    }
    if (password.length < 8 || password.length > MAX_PASSWORD_LENGTH || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      return res.status(400).json({ success: false, message: `Password must be 8-${MAX_PASSWORD_LENGTH} characters and include a letter and a number.` });
    }
    if (REGISTRATION_INVITE_CODE) {
      const provided = Buffer.from(String(inviteCode || ''));
      const expected = Buffer.from(REGISTRATION_INVITE_CODE);
      if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
        return res.status(403).json({ success: false, message: 'A valid invite code is required.' });
      }
    }

    const normalizedEmail = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 10);
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
      || email.length > MAX_LEN.email || password.length > MAX_PASSWORD_LENGTH) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }
    const normalizedEmail = email.trim().toLowerCase();

    const user = await findUserByEmail(normalizedEmail);
    if (!user) {
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
  try {
    const carrier = await createCarrier({ name: name.trim(), mode });
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

app.get('/api/admin/shipments', authMiddleware, requirePermission('shipments:read'), async (req, res) => {
  try {
    const shipments = await listShipments(readPaging(req));
    res.json({
      success: true,
      shipments: shipments.map((shipment) => ({
        ...serializeShipment(shipment),
        weight: shipment.weight || '10,000 lb',
        equipment: shipment.equipment || 'Dry Van'
      }))
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
    const rate = parsePositiveNumber(req.body?.rate, MAX_RATE_USD);
    if (!Number.isInteger(shipmentId) || shipmentId <= 0 || !Number.isInteger(carrierId) || carrierId <= 0 || rate === null) {
      return res.status(400).json({ success: false, message: `A valid carrier and a rate between 0.01 and ${MAX_RATE_USD.toLocaleString('en-US')} are required.` });
    }

    const shipment = await dispatchShipment(shipmentId, carrierId, rate, req.user.id);
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

app.post('/api/shipments', authMiddleware, requirePermission('shipments:create'), async (req, res) => {
  try {
    const { customer, reference, origin, destination, pickup, delivery, weight, equipment, trackingNumber } = req.body || {};
    const validEquipment = ['Dry Van', 'Reefer', 'Flatbed', 'LTL', 'Expedited'];
    const pickupDate = parseIsoDate(pickup);
    const deliveryDate = parseIsoDate(delivery);
    const weightValue = parsePositiveNumber(weight, MAX_WEIGHT_LB);

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
    if (!customer?.trim() || !origin?.trim() || !destination?.trim() || weightValue === null || !validEquipment.includes(equipment)) {
      return res.status(400).json({ success: false, message: `Customer, route, a weight up to ${MAX_WEIGHT_LB.toLocaleString('en-US')} lb, and valid equipment are required.` });
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
      weight: `${weightValue} lb`,
      equipment,
      reference: reference?.trim(),
      trackingNumber: trackingNumber?.trim(),
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
      const server = app.listen(PORT, () => {
        console.log(`VEYRA API running at http://localhost:${PORT}`);
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
