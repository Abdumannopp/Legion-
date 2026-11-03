const bcrypt = require('bcryptjs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { httpError, normalizePlate } = require('./lib/validation');

const DB_PATH = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(__dirname, 'data', 'veyra.db');
const db = new sqlite3.Database(DB_PATH);
db.configure('busyTimeout', 10000);
db.run('PRAGMA foreign_keys = ON');
let hasLegacyEventStatusColumn = false;
let connectionQueue = Promise.resolve();

// One bcrypt cost for every hash (seeded, registered, admin-created and the login dummy),
// so response time cannot reveal which accounts exist.
const BCRYPT_COST = Math.min(Math.max(Number.parseInt(process.env.BCRYPT_COST, 10) || 12, 10), 14);

// Tenant 1 always exists: single-company installs and data from before multi-tenancy live there.
const DEFAULT_TENANT_ID = 1;

function runRaw(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function getRaw(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row || null);
    });
  });
}

function allRaw(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows || []);
    });
  });
}

function enqueueQuery(query) {
  const operation = connectionQueue.then(query);
  connectionQueue = operation.then(() => undefined, () => undefined);
  return operation;
}

function run(sql, params = []) {
  return enqueueQuery(() => runRaw(sql, params));
}

function get(sql, params = []) {
  return enqueueQuery(() => getRaw(sql, params));
}

function all(sql, params = []) {
  return enqueueQuery(() => allRaw(sql, params));
}

function withTransaction(work) {
  const transaction = connectionQueue.then(async () => {
    await runRaw('BEGIN IMMEDIATE');
    try {
      const result = await work({ run: runRaw, get: getRaw, all: allRaw });
      await runRaw('COMMIT');
      return result;
    } catch (error) {
      try {
        await runRaw('ROLLBACK');
      } catch (rollbackError) {
        error.rollbackError = rollbackError;
      }
      throw error;
    }
  });
  connectionQueue = transaction.then(() => undefined, () => undefined);
  return transaction;
}

// Every data function is scoped to one company. A missing tenant is a programming error,
// and failing closed here is what keeps one company's loads invisible to another.
function assertTenant(tenantId) {
  if (!Number.isInteger(tenantId) || tenantId <= 0) {
    throw new Error('A tenant is required for this operation.');
  }
  return tenantId;
}

async function ensureColumns(table, columns) {
  const existing = new Set((await all(`PRAGMA table_info(${table})`)).map((column) => column.name));
  for (const [column, type] of columns) {
    if (!existing.has(column)) {
      await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
  }
}

async function initialize() {
  const isProduction = process.env.NODE_ENV !== 'development';

  await run(`
    CREATE TABLE IF NOT EXISTS tenants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      gps_token_hash TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run('INSERT OR IGNORE INTO tenants (id, name) VALUES (?, ?)', [DEFAULT_TENANT_ID, (process.env.COMPANY_NAME || 'My company').slice(0, 120)]);

  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'operator'
    )
  `);
  // ALTER TABLE cannot add a REFERENCES column with a non-NULL default, so tenant links are
  // enforced by the application (every query filters on tenant_id).
  await ensureColumns('users', [
    ['disabled_at', 'INTEGER'],
    ['tenant_id', `INTEGER NOT NULL DEFAULT ${DEFAULT_TENANT_ID}`],
    ['is_platform_admin', 'INTEGER NOT NULL DEFAULT 0']
  ]);

  await run(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      jti TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER
    )
  `);
  await ensureColumns('auth_sessions', [['user_id', 'INTEGER']]);
  await run('DELETE FROM auth_sessions WHERE expires_at <= ?', [Math.floor(Date.now() / 1000)]);

  await run(`
    CREATE TABLE IF NOT EXISTS rate_limit_attempts (
      rate_key TEXT NOT NULL,
      attempted_at INTEGER NOT NULL
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_rate_limit_attempts_key_time ON rate_limit_attempts (rate_key, attempted_at)');
  await run('DELETE FROM rate_limit_attempts WHERE attempted_at <= ?', [Date.now() - 30 * 24 * 60 * 60 * 1000]);

  await run(`
    CREATE TABLE IF NOT EXISTS shipments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer TEXT NOT NULL,
      origin TEXT NOT NULL,
      destination TEXT NOT NULL,
      pickup TEXT,
      delivery TEXT,
      status TEXT NOT NULL,
      weight TEXT,
      equipment TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await ensureColumns('shipments', [
    ['reference', 'TEXT'],
    ['carrier_id', 'INTEGER REFERENCES carriers(id)'],
    ['rate', 'REAL'],
    ['tracking_number', 'TEXT'],
    // Truck workflow: what the customer pays, who drives which truck, and where it is now.
    ['customer_rate', 'REAL'],
    ['driver_name', 'TEXT'],
    ['driver_phone', 'TEXT'],
    ['truck_plate', 'TEXT'],
    ['last_location', 'TEXT'],
    ['eta', 'TEXT'],
    ['last_tracked_at', 'TEXT'],
    ['customer_phone', 'TEXT'],
    ['tenant_id', `INTEGER NOT NULL DEFAULT ${DEFAULT_TENANT_ID}`]
  ]);

  await run(`
    CREATE TABLE IF NOT EXISTS shipment_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shipment_id INTEGER NOT NULL,
      actor_id INTEGER,
      from_status TEXT,
      to_status TEXT NOT NULL,
      note TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (shipment_id) REFERENCES shipments(id),
      FOREIGN KEY (actor_id) REFERENCES users(id)
    )
  `);

  const eventColumns = await all('PRAGMA table_info(shipment_events)');
  const existingEventColumns = new Set(eventColumns.map((column) => column.name));
  hasLegacyEventStatusColumn = existingEventColumns.has('status');
  if (!existingEventColumns.has('from_status')) {
    await run('ALTER TABLE shipment_events ADD COLUMN from_status TEXT');
  }
  if (!existingEventColumns.has('to_status')) {
    await run('ALTER TABLE shipment_events ADD COLUMN to_status TEXT');
    if (existingEventColumns.has('status')) {
      await run('UPDATE shipment_events SET to_status = status WHERE to_status IS NULL');
    }
  }

  await run(`
    CREATE TABLE IF NOT EXISTS carriers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      mode TEXT NOT NULL,
      status TEXT NOT NULL
    )
  `);
  await ensureColumns('carriers', [
    ['phone', 'TEXT'],
    ['contact_name', 'TEXT'],
    ['tenant_id', `INTEGER NOT NULL DEFAULT ${DEFAULT_TENANT_ID}`]
  ]);

  // Location updates: typed by a dispatcher ("check call") or pushed by a GPS provider.
  await run(`
    CREATE TABLE IF NOT EXISTS tracking_updates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      shipment_id INTEGER NOT NULL,
      actor_id INTEGER,
      location TEXT NOT NULL,
      eta TEXT,
      note TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (shipment_id) REFERENCES shipments(id),
      FOREIGN KEY (actor_id) REFERENCES users(id)
    )
  `);
  await ensureColumns('tracking_updates', [
    ['source', "TEXT NOT NULL DEFAULT 'manual'"],
    ['lat', 'REAL'],
    ['lng', 'REAL']
  ]);

  // SMS / WhatsApp messages sent from a load (RELAY).
  await run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL REFERENCES tenants(id),
      shipment_id INTEGER NOT NULL REFERENCES shipments(id),
      channel TEXT NOT NULL,
      recipient_type TEXT NOT NULL,
      to_phone TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT NOT NULL,
      provider TEXT,
      provider_message_id TEXT,
      error TEXT,
      created_by INTEGER REFERENCES users(id),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // One row per AI call: which agent, which model, tokens, time, result. Cost and quality are measured from this.
  await run(`
    CREATE TABLE IF NOT EXISTS agent_tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL REFERENCES tenants(id),
      shipment_id INTEGER REFERENCES shipments(id),
      agent TEXT NOT NULL,
      status TEXT NOT NULL,
      model TEXT,
      input_tokens INTEGER,
      output_tokens INTEGER,
      latency_ms INTEGER,
      error TEXT,
      actor_id INTEGER REFERENCES users(id),
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const seedUsers = [
    { name: 'Alex Carter', email: 'admin@veyra.ai', password: 'admin123', role: 'admin', platform: 1 },
    { name: 'Emma Wilson', email: 'ops@veyra.ai', password: 'ops123', role: 'operations', platform: 0 },
    { name: 'Demo Operator', email: 'demo@veyra.ai', password: 'demo123', role: 'operator', platform: 0 }
  ];

  if (isProduction) {
    const userCount = await get('SELECT COUNT(*) AS total FROM users');
    if (Number(userCount?.total) === 0) {
      const { INITIAL_ADMIN_NAME, INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD } = process.env;
      if (!INITIAL_ADMIN_NAME || !INITIAL_ADMIN_EMAIL || !INITIAL_ADMIN_PASSWORD || INITIAL_ADMIN_PASSWORD.length < 12) {
        throw new Error('Set INITIAL_ADMIN_NAME, INITIAL_ADMIN_EMAIL, and an INITIAL_ADMIN_PASSWORD of at least 12 characters before first production startup.');
      }
      const hashedPassword = await bcrypt.hash(INITIAL_ADMIN_PASSWORD, BCRYPT_COST);
      // The first administrator also runs the platform: they can add other companies.
      await run(
        'INSERT INTO users (name, email, password, role, tenant_id, is_platform_admin) VALUES (?, ?, ?, ?, ?, 1)',
        [INITIAL_ADMIN_NAME.trim(), INITIAL_ADMIN_EMAIL.trim().toLowerCase(), hashedPassword, 'admin', DEFAULT_TENANT_ID]
      );
    }
  } else {
    for (const user of seedUsers) {
      const exists = await get('SELECT id FROM users WHERE email = ?', [user.email]);
      if (!exists) {
        const hashedPassword = await bcrypt.hash(user.password, BCRYPT_COST);
        await run(
          'INSERT INTO users (name, email, password, role, tenant_id, is_platform_admin) VALUES (?, ?, ?, ?, ?, ?)',
          [user.name, user.email, hashedPassword, user.role, DEFAULT_TENANT_ID, user.platform]
        );
      }
    }

    const carrierCount = await get('SELECT COUNT(*) AS total FROM carriers');
    if (!carrierCount || Number(carrierCount.total) === 0) {
      await run('INSERT INTO carriers (name, mode, status, phone, contact_name, tenant_id) VALUES (?, ?, ?, ?, ?, ?)', ['Atlas Freight', 'Truckload', 'Available', '+1 214 555 0100', 'Dana Brooks', DEFAULT_TENANT_ID]);
      await run('INSERT INTO carriers (name, mode, status, phone, contact_name, tenant_id) VALUES (?, ?, ?, ?, ?, ?)', ['North Wind Logistics', 'LTL', 'Available', '+1 312 555 0142', 'Sam Ortiz', DEFAULT_TENANT_ID]);
      // Available (not Busy): a carrier is only Busy while it has an active load.
      await run('INSERT INTO carriers (name, mode, status, phone, contact_name, tenant_id) VALUES (?, ?, ?, ?, ?, ?)', ['Blue Ridge Cargo', 'Expedited', 'Available', '+1 404 555 0178', 'Lee Grant', DEFAULT_TENANT_ID]);
    }

    const shipmentCount = await get('SELECT COUNT(*) AS total FROM shipments');
    if (!shipmentCount || Number(shipmentCount.total) === 0) {
      const seed = 'INSERT INTO shipments (customer, origin, destination, pickup, delivery, status, weight, equipment, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
      await run(seed, ['ABC Retail', 'Dallas, TX', 'Houston, TX', 'Oct 3', 'Oct 4', 'New', '4500 kg', 'Dry Van', DEFAULT_TENANT_ID]);
      await run(seed, ['Global Parts', 'Chicago, IL', 'Atlanta, GA', 'Oct 3', 'Oct 5', 'Pending Approval', '3850 kg', 'Reefer', DEFAULT_TENANT_ID]);
      await run(seed, ['Prime Goods', 'Los Angeles, CA', 'Phoenix, AZ', 'Oct 2', 'Oct 3', 'Sourcing', '5400 kg', 'Flatbed', DEFAULT_TENANT_ID]);
    }
  }

  // Upgrading an install from before multi-company support: its first active admin runs the platform.
  const platformAdmin = await get('SELECT id FROM users WHERE is_platform_admin = 1 LIMIT 1');
  if (!platformAdmin) {
    await run(
      "UPDATE users SET is_platform_admin = 1 WHERE id = (SELECT id FROM users WHERE role = 'admin' AND disabled_at IS NULL AND tenant_id = ? ORDER BY id LIMIT 1)",
      [DEFAULT_TENANT_ID]
    );
  }

  const eventBackfill = hasLegacyEventStatusColumn
    ? `INSERT INTO shipment_events (shipment_id, status, from_status, to_status, note)
       SELECT shipments.id, shipments.status, NULL, shipments.status, 'Current status imported'
       FROM shipments
       WHERE NOT EXISTS (SELECT 1 FROM shipment_events WHERE shipment_events.shipment_id = shipments.id)`
    : `INSERT INTO shipment_events (shipment_id, from_status, to_status, note)
       SELECT shipments.id, NULL, shipments.status, 'Current status imported'
       FROM shipments
       WHERE NOT EXISTS (SELECT 1 FROM shipment_events WHERE shipment_events.shipment_id = shipments.id)`;
  await run(eventBackfill);

  // Indexes for the columns the app filters, joins and sorts on.
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_shipments_status ON shipments (status)',
    'CREATE INDEX IF NOT EXISTS idx_shipments_carrier ON shipments (carrier_id)',
    'CREATE INDEX IF NOT EXISTS idx_shipments_created ON shipments (created_at, id)',
    'CREATE INDEX IF NOT EXISTS idx_shipments_tenant ON shipments (tenant_id, id)',
    'CREATE INDEX IF NOT EXISTS idx_shipments_tenant_status ON shipments (tenant_id, status)',
    'CREATE INDEX IF NOT EXISTS idx_shipment_events_shipment ON shipment_events (shipment_id, id)',
    'CREATE INDEX IF NOT EXISTS idx_carriers_status ON carriers (status)',
    'CREATE INDEX IF NOT EXISTS idx_carriers_tenant ON carriers (tenant_id, status)',
    'CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id)',
    'CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions (expires_at)',
    'CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions (user_id)',
    'CREATE INDEX IF NOT EXISTS idx_tracking_updates_shipment ON tracking_updates (shipment_id, id)',
    'CREATE INDEX IF NOT EXISTS idx_messages_shipment ON messages (shipment_id, id)',
    'CREATE INDEX IF NOT EXISTS idx_agent_tasks_tenant ON agent_tasks (tenant_id, id)'
  ];
  for (const statement of indexes) await run(statement);

  const health = await checkIntegrity();
  if (!health.ok) {
    console.warn('[database] integrity warning:', JSON.stringify(health));
  }
}

async function checkIntegrity() {
  const [integrity, violations] = await Promise.all([all('PRAGMA integrity_check'), all('PRAGMA foreign_key_check')]);
  const messages = integrity.map((row) => row.integrity_check);
  return {
    ok: messages.length === 1 && messages[0] === 'ok' && violations.length === 0,
    integrity: messages,
    foreignKeyViolations: violations.length
  };
}

/* ---------------- tenants (companies) ---------------- */

async function getTenant(tenantId) {
  return get('SELECT id, name, gps_token_hash AS gpsTokenHash, created_at AS createdAt FROM tenants WHERE id = ?', [assertTenant(tenantId)]);
}

async function listTenants() {
  const rows = await all(`
    SELECT tenants.id, tenants.name, tenants.created_at AS createdAt,
      (SELECT COUNT(*) FROM users WHERE users.tenant_id = tenants.id) AS users,
      (SELECT COUNT(*) FROM shipments WHERE shipments.tenant_id = tenants.id) AS shipments
    FROM tenants ORDER BY tenants.id
  `);
  return rows.map((row) => ({ ...row, users: Number(row.users) || 0, shipments: Number(row.shipments) || 0 }));
}

// A new customer company and its first administrator, created together or not at all.
async function createTenantWithAdmin({ name, adminName, adminEmail, passwordHash }) {
  return withTransaction(async (transaction) => {
    if (await transaction.get('SELECT id FROM users WHERE email = ?', [adminEmail])) {
      throw httpError(409, 'A user with this email already exists.');
    }
    if (await transaction.get('SELECT id FROM tenants WHERE lower(name) = lower(?)', [name])) {
      throw httpError(409, 'A company with this name already exists.');
    }
    const tenant = await transaction.run('INSERT INTO tenants (name) VALUES (?)', [name]);
    const user = await transaction.run(
      "INSERT INTO users (name, email, password, role, tenant_id) VALUES (?, ?, ?, 'admin', ?)",
      [adminName, adminEmail, passwordHash, tenant.id]
    );
    return { tenant: { id: tenant.id, name }, admin: { id: user.id, name: adminName, email: adminEmail, role: 'admin' } };
  });
}

async function setTenantGpsTokenHash(tenantId, tokenHash) {
  await run('UPDATE tenants SET gps_token_hash = ? WHERE id = ?', [tokenHash, assertTenant(tenantId)]);
}

async function findTenantByGpsTokenHash(tokenHash) {
  if (!tokenHash) return null;
  return get('SELECT id, name FROM tenants WHERE gps_token_hash = ?', [tokenHash]);
}

/* ---------------- users and sessions ---------------- */

async function findUserByEmail(email) {
  return get('SELECT * FROM users WHERE email = ?', [email]);
}

async function createAuthSession(jti, expiresAt, userId = null) {
  await run('INSERT INTO auth_sessions (jti, expires_at, user_id) VALUES (?, ?, ?)', [jti, expiresAt, userId]);
}

async function revokeUserSessions(userId, queryRun = run) {
  await queryRun(
    'UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL',
    [Math.floor(Date.now() / 1000), userId]
  );
}

async function isAuthSessionActive(jti) {
  if (!jti) return false;
  const session = await get(
    'SELECT jti FROM auth_sessions WHERE jti = ? AND revoked_at IS NULL AND expires_at > ?',
    [jti, Math.floor(Date.now() / 1000)]
  );
  return Boolean(session);
}

async function revokeAuthSession(jti) {
  if (!jti) return;
  await run(
    'UPDATE auth_sessions SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL',
    [Math.floor(Date.now() / 1000), jti]
  );
}

async function getRateLimitStatus(rateKey, windowMs, max) {
  const now = Date.now();
  const result = await get(
    'SELECT COUNT(*) AS attempts, MIN(attempted_at) AS oldest_attempt FROM rate_limit_attempts WHERE rate_key = ? AND attempted_at > ?',
    [rateKey, now - windowMs]
  );
  const attempts = Number(result?.attempts || 0);
  return {
    limited: attempts >= max,
    attempts,
    retryAfterMs: attempts >= max ? Math.max(1, Number(result.oldest_attempt) + windowMs - now) : 0
  };
}

async function consumeRateLimit(rateKey, windowMs, max) {
  return withTransaction(async (query) => {
    const now = Date.now();
    const cutoff = now - windowMs;
    await query.run('DELETE FROM rate_limit_attempts WHERE rate_key = ? AND attempted_at <= ?', [rateKey, cutoff]);
    const result = await query.get(
      'SELECT COUNT(*) AS attempts, MIN(attempted_at) AS oldest_attempt FROM rate_limit_attempts WHERE rate_key = ?',
      [rateKey]
    );
    const attempts = Number(result?.attempts || 0);
    if (attempts >= max) {
      return {
        limited: true,
        attempts,
        retryAfterMs: Math.max(1, Number(result.oldest_attempt) + windowMs - now)
      };
    }

    await query.run('INSERT INTO rate_limit_attempts (rate_key, attempted_at) VALUES (?, ?)', [rateKey, now]);
    return { limited: false, attempts: attempts + 1, retryAfterMs: 0 };
  });
}

async function recordRateLimitAttempts(rateKeys, windowMs) {
  return withTransaction(async (query) => {
    const now = Date.now();
    const cutoff = now - windowMs;
    for (const rateKey of rateKeys) {
      await query.run('DELETE FROM rate_limit_attempts WHERE rate_key = ? AND attempted_at <= ?', [rateKey, cutoff]);
      await query.run('INSERT INTO rate_limit_attempts (rate_key, attempted_at) VALUES (?, ?)', [rateKey, now]);
    }
    const ipResult = await query.get(
      'SELECT COUNT(*) AS attempts FROM rate_limit_attempts WHERE rate_key = ?',
      [rateKeys[0]]
    );
    return Number(ipResult?.attempts || 0);
  });
}

async function clearRateLimitAttempts(rateKey) {
  await run('DELETE FROM rate_limit_attempts WHERE rate_key = ?', [rateKey]);
}

async function findUserById(id) {
  if (!id || !Number.isInteger(Number(id))) return null;
  return get(
    `SELECT users.id, users.name, users.email, users.role, users.disabled_at AS disabledAt, users.tenant_id AS tenantId,
       users.is_platform_admin AS isPlatformAdmin, tenants.name AS tenantName
     FROM users JOIN tenants ON tenants.id = users.tenant_id WHERE users.id = ?`,
    [Number(id)]
  );
}

const ALLOWED_ROLES = ['admin', 'operations', 'operator'];

// Change a user's role and/or access. Any change revokes that user's sessions,
// so a demoted or disabled user loses access immediately, not when the token expires.
async function updateUser(tenantId, id, { role, active }, actorId) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const user = await transaction.get('SELECT id, name, email, role, disabled_at FROM users WHERE id = ? AND tenant_id = ?', [id, tenantId]);
    if (!user) throw httpError(404, 'User not found.');
    if (Number(actorId) === Number(id)) throw httpError(409, 'You cannot change your own role or access.');

    const nextRole = role === undefined ? user.role : role;
    const nextDisabled = active === undefined ? user.disabled_at : (active ? null : Math.floor(Date.now() / 1000));
    if (!ALLOWED_ROLES.includes(nextRole)) throw httpError(400, 'Unknown role.');

    const losesAdmin = user.role === 'admin' && !user.disabled_at && (nextRole !== 'admin' || nextDisabled);
    if (losesAdmin) {
      const others = await transaction.get(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin' AND disabled_at IS NULL AND id <> ? AND tenant_id = ?",
        [id, tenantId]
      );
      if (!Number(others?.total)) throw httpError(409, 'At least one active administrator must remain.');
    }

    await transaction.run('UPDATE users SET role = ?, disabled_at = ? WHERE id = ?', [nextRole, nextDisabled, id]);
    await revokeUserSessions(id, transaction.run);
    return { id: user.id, name: user.name, email: user.email, role: nextRole, active: !nextDisabled };
  });
}

async function createUser({ name, email, password, role = 'operator', tenantId }) {
  assertTenant(tenantId);
  const safeRole = ALLOWED_ROLES.includes(role) ? role : 'operator';
  const result = await run(
    'INSERT INTO users (name, email, password, role, tenant_id) VALUES (?, ?, ?, ?, ?)',
    [name, email, password, safeRole, tenantId]
  );

  return {
    id: result.id,
    name,
    email,
    role: safeRole,
    tenant_id: tenantId,
    is_platform_admin: 0
  };
}

async function listUsers(tenantId) {
  const rows = await all('SELECT id, name, email, role, disabled_at FROM users WHERE tenant_id = ? ORDER BY id', [assertTenant(tenantId)]);
  return rows.map((row) => ({ id: row.id, name: row.name, email: row.email, role: row.role, active: !row.disabled_at }));
}

/* ---------------- shipments ---------------- */

const SHIPMENT_SELECT = `SELECT shipments.*, carriers.name AS carrierName, carriers.phone AS carrierPhone
  FROM shipments LEFT JOIN carriers ON carriers.id = shipments.carrier_id`;

async function listShipments(tenantId, { limit = 50, offset = 0 } = {}) {
  assertTenant(tenantId);
  const safeLimit = Math.min(Math.max(Math.trunc(Number(limit)) || 50, 1), 200);
  const safeOffset = Math.max(Math.trunc(Number(offset)) || 0, 0);
  return all(
    `${SHIPMENT_SELECT} WHERE shipments.tenant_id = ? ORDER BY shipments.created_at DESC, shipments.id DESC LIMIT ? OFFSET ?`,
    [tenantId, safeLimit, safeOffset]
  );
}

const SEARCH_SORTS = {
  newest: 'shipments.id DESC',
  oldest: 'shipments.id ASC',
  customer: 'shipments.customer COLLATE NOCASE ASC, shipments.id DESC',
  rate: 'shipments.rate IS NULL, shipments.rate DESC, shipments.id DESC'
};

// Server-side filtering and paging, so the list works the same with 50 or 50,000 loads.
async function searchShipments(tenantId, { status, q, equipment, sort, limit = 50, offset = 0 } = {}) {
  assertTenant(tenantId);
  const where = ['shipments.tenant_id = ?'];
  const params = [tenantId];
  if (equipment) {
    where.push('shipments.equipment = ?');
    params.push(equipment);
  }
  const text = String(q || '').trim();
  if (text) {
    const like = `%${text.replace(/[\\%_]/g, '\\$&')}%`;
    const columns = ["'SHP-' || shipments.id", 'shipments.reference', 'shipments.customer', 'shipments.origin', 'shipments.destination',
      'carriers.name', 'shipments.tracking_number', 'shipments.status', 'shipments.driver_name', 'shipments.truck_plate', 'shipments.last_location'];
    where.push(`(${columns.map((column) => `${column} LIKE ? ESCAPE '\\'`).join(' OR ')})`);
    columns.forEach(() => params.push(like));
  }
  const baseFrom = 'FROM shipments LEFT JOIN carriers ON carriers.id = shipments.carrier_id';
  const countRows = await all(`SELECT shipments.status AS status, COUNT(*) AS total ${baseFrom} WHERE ${where.join(' AND ')} GROUP BY shipments.status`, params);
  const statusCounts = Object.fromEntries(countRows.map((row) => [row.status, Number(row.total)]));
  const allCount = countRows.reduce((sum, row) => sum + Number(row.total), 0);

  const listWhere = [...where];
  const listParams = [...params];
  if (status) {
    listWhere.push('shipments.status = ?');
    listParams.push(status);
  }
  const safeLimit = Math.min(Math.max(Math.trunc(Number(limit)) || 50, 1), 200);
  const safeOffset = Math.max(Math.trunc(Number(offset)) || 0, 0);
  const items = await all(
    `${SHIPMENT_SELECT} WHERE ${listWhere.join(' AND ')} ORDER BY ${SEARCH_SORTS[sort] || SEARCH_SORTS.newest} LIMIT ? OFFSET ?`,
    [...listParams, safeLimit, safeOffset]
  );
  return { items, total: status ? (statusCounts[status] || 0) : allCount, allCount, statusCounts };
}

async function getShipment(tenantId, id) {
  return get(`${SHIPMENT_SELECT} WHERE shipments.id = ? AND shipments.tenant_id = ?`, [id, assertTenant(tenantId)]);
}

const STATUS_TRANSITIONS = {
  New: ['Sourcing', 'Cancelled'],
  // 'Dispatched' is reachable only through dispatchShipment (needs carrier + rate).
  Sourcing: ['Pending Approval', 'Cancelled'],
  'Pending Approval': ['Sourcing', 'Cancelled'],
  // A booked truck can still be cancelled before pickup; the carrier is released.
  Dispatched: ['In Transit', 'Exception', 'Cancelled'],
  'In Transit': ['Delivered', 'Exception'],
  Exception: ['In Transit', 'Cancelled']
};

// Statuses where the truck is booked and moving (or stuck), so location updates make sense.
const TRACKABLE_STATUSES = ['Dispatched', 'In Transit', 'Exception'];

async function recordShipmentEvent(shipmentId, fromStatus, toStatus, note, actorId, queryRun = run) {
  if (hasLegacyEventStatusColumn) {
    await queryRun(
      'INSERT INTO shipment_events (shipment_id, status, from_status, to_status, note, actor_id) VALUES (?, ?, ?, ?, ?, ?)',
      [shipmentId, toStatus, fromStatus || null, toStatus, note || null, actorId || null]
    );
    return;
  }
  await queryRun(
    'INSERT INTO shipment_events (shipment_id, from_status, to_status, note, actor_id) VALUES (?, ?, ?, ?, ?)',
    [shipmentId, fromStatus || null, toStatus, note || null, actorId || null]
  );
}

async function updateShipmentStatus(tenantId, id, status, actorId, note) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const current = await transaction.get('SELECT id, status, carrier_id FROM shipments WHERE id = ? AND tenant_id = ?', [id, tenantId]);
    if (!current) throw httpError(404, 'Shipment not found.');

    if (!(STATUS_TRANSITIONS[current.status] || []).includes(status)) {
      throw httpError(409, `Cannot move shipment from ${current.status} to ${status}.`);
    }

    const result = await transaction.run(
      'UPDATE shipments SET status = ? WHERE id = ? AND status = ?',
      [status, id, current.status]
    );
    if (result.changes !== 1) throw httpError(409, 'Shipment state changed before the update could be applied.');

    if (['Delivered', 'Cancelled'].includes(status) && current.carrier_id) {
      const carrier = await transaction.get('SELECT id, status FROM carriers WHERE id = ?', [current.carrier_id]);
      if (!carrier) throw httpError(409, 'Assigned carrier no longer exists.');

      const otherActiveAssignment = await transaction.get(
        "SELECT id FROM shipments WHERE carrier_id = ? AND id <> ? AND status NOT IN ('Delivered', 'Cancelled') LIMIT 1",
        [current.carrier_id, id]
      );
      if (otherActiveAssignment) throw httpError(409, 'Assigned carrier is still attached to another active shipment.');

      if (carrier.status === 'Busy') {
        const released = await transaction.run(
          "UPDATE carriers SET status = 'Available' WHERE id = ? AND status = 'Busy'",
          [current.carrier_id]
        );
        if (released.changes !== 1) throw httpError(409, 'Carrier availability changed during shipment completion.');
      } else if (carrier.status !== 'Available') {
        throw httpError(409, 'Assigned carrier has an invalid availability state.');
      }
    }

    await recordShipmentEvent(id, current.status, status, note, actorId, transaction.run);
    return { changes: result.changes, id, status };
  });
}

async function createShipment({ customer, origin, destination, pickup, delivery, status, weight, equipment, reference, trackingNumber, customerRate, customerPhone, actorId, tenantId }) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const result = await transaction.run(
      `INSERT INTO shipments (customer, origin, destination, pickup, delivery, status, weight, equipment, reference, tracking_number, customer_rate, customer_phone, tenant_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [customer, origin, destination, pickup, delivery, status, weight, equipment, reference || null, trackingNumber || null, customerRate ?? null, customerPhone || null, tenantId]
    );
    await recordShipmentEvent(result.id, null, status, 'Shipment created', actorId, transaction.run);

    return {
      id: `SHP-${result.id}`,
      reference: reference || null,
      customer,
      origin,
      destination,
      pickup,
      delivery,
      status,
      weight,
      equipment,
      customerRate: customerRate ?? null,
      customerPhone: customerPhone || null
    };
  });
}

// details: optional { customerRate, driverName, driverPhone, truckPlate } agreed at booking.
async function dispatchShipment(tenantId, id, carrierId, rate, actorId, details = {}) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const shipment = await transaction.get('SELECT id, status, carrier_id FROM shipments WHERE id = ? AND tenant_id = ?', [id, tenantId]);
    if (!shipment) throw httpError(404, 'Shipment not found.');
    if (!['Sourcing', 'Pending Approval'].includes(shipment.status) || shipment.carrier_id) {
      throw httpError(409, 'Shipment must be unassigned and in sourcing or pending approval before dispatch.');
    }

    // A carrier from another company is treated as not existing.
    const carrier = await transaction.get('SELECT id, name, status FROM carriers WHERE id = ? AND tenant_id = ?', [carrierId, tenantId]);
    if (!carrier) throw httpError(404, 'Carrier not found.');
    if (carrier.status !== 'Available') throw httpError(409, 'Selected carrier is not available.');

    const activeAssignment = await transaction.get(
      "SELECT id FROM shipments WHERE carrier_id = ? AND status NOT IN ('Delivered', 'Cancelled') LIMIT 1",
      [carrierId]
    );
    if (activeAssignment) throw httpError(409, 'Selected carrier already has an active shipment.');

    const claimedCarrier = await transaction.run(
      "UPDATE carriers SET status = 'Busy' WHERE id = ? AND status = 'Available'",
      [carrierId]
    );
    if (claimedCarrier.changes !== 1) throw httpError(409, 'Selected carrier is no longer available.');

    const { customerRate, driverName, driverPhone, truckPlate } = details;
    const assignedShipment = await transaction.run(
      `UPDATE shipments SET carrier_id = ?, rate = ?, status = 'Dispatched',
         customer_rate = COALESCE(?, customer_rate), driver_name = ?, driver_phone = ?, truck_plate = ?
       WHERE id = ? AND status = ? AND carrier_id IS NULL`,
      [carrierId, rate, customerRate ?? null, driverName || null, driverPhone || null, truckPlate || null, id, shipment.status]
    );
    if (assignedShipment.changes !== 1) throw httpError(409, 'Shipment state changed before dispatch could be applied.');

    const truck = [truckPlate && `truck ${truckPlate}`, driverName && `driver ${driverName}`].filter(Boolean).join(', ');
    const note = `Assigned to ${carrier.name} at ${Number(rate).toFixed(2)}${truck ? ` (${truck})` : ''}`;
    await recordShipmentEvent(id, shipment.status, 'Dispatched', note, actorId, transaction.run);
    return { id, status: 'Dispatched', carrier: carrier.name, rate };
  });
}

/* ---------------- tracking (manual check calls and GPS) ---------------- */

async function addTrackingUpdate(tenantId, shipmentId, { location, eta, note }, actorId) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const shipment = await transaction.get('SELECT id, status FROM shipments WHERE id = ? AND tenant_id = ?', [shipmentId, tenantId]);
    if (!shipment) throw httpError(404, 'Shipment not found.');
    if (!TRACKABLE_STATUSES.includes(shipment.status)) {
      throw httpError(409, `Location updates are only possible while a load is ${TRACKABLE_STATUSES.join(', ')}.`);
    }
    const result = await transaction.run(
      "INSERT INTO tracking_updates (shipment_id, actor_id, location, eta, note, source) VALUES (?, ?, ?, ?, ?, 'manual')",
      [shipmentId, actorId || null, location, eta || null, note || null]
    );
    const created = await transaction.get('SELECT created_at FROM tracking_updates WHERE id = ?', [result.id]);
    // Keep the newest position and ETA on the shipment itself so lists can show it without a join.
    await transaction.run(
      'UPDATE shipments SET last_location = ?, eta = COALESCE(?, eta), last_tracked_at = ? WHERE id = ?',
      [location, eta || null, created.created_at, shipmentId]
    );
    return { id: result.id, shipmentId: `SHP-${shipmentId}`, location, eta: eta || null, note: note || null, source: 'manual', createdAt: created.created_at };
  });
}

// GPS positions for one company. Each is matched to that company's active load by truck plate
// (or load id). Positions closer together than minIntervalMinutes are skipped so a tracker that
// reports every few seconds does not flood the history.
async function recordGpsPositions(tenantId, positions, { minIntervalMinutes = 15 } = {}) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const summary = { accepted: 0, skipped: 0, unmatched: 0 };
    for (const position of positions) {
      const shipment = position.shipmentId
        ? await transaction.get(
          `SELECT id FROM shipments WHERE id = ? AND tenant_id = ? AND status IN (${TRACKABLE_STATUSES.map(() => '?').join(', ')})`,
          [position.shipmentId, tenantId, ...TRACKABLE_STATUSES]
        )
        : await transaction.get(
          `SELECT id FROM shipments WHERE tenant_id = ? AND truck_plate IS NOT NULL
             AND upper(replace(replace(replace(truck_plate, ' ', ''), '-', ''), '.', '')) = ?
             AND status IN (${TRACKABLE_STATUSES.map(() => '?').join(', ')})
           ORDER BY id DESC LIMIT 1`,
          [tenantId, normalizePlate(position.truckPlate), ...TRACKABLE_STATUSES]
        );
      if (!shipment) {
        summary.unmatched += 1;
        continue;
      }
      const recent = await transaction.get(
        "SELECT id FROM tracking_updates WHERE shipment_id = ? AND source = 'gps' AND created_at > datetime('now', ?) LIMIT 1",
        [shipment.id, `-${Number(minIntervalMinutes)} minutes`]
      );
      if (recent) {
        summary.skipped += 1;
        continue;
      }
      const location = position.address || `${position.lat.toFixed(5)}, ${position.lng.toFixed(5)}`;
      const note = position.speed !== null && position.speed !== undefined ? `GPS · ${Math.round(position.speed)} km/h` : 'GPS';
      const result = await transaction.run(
        "INSERT INTO tracking_updates (shipment_id, actor_id, location, note, source, lat, lng) VALUES (?, NULL, ?, ?, 'gps', ?, ?)",
        [shipment.id, location, note, position.lat, position.lng]
      );
      const created = await transaction.get('SELECT created_at FROM tracking_updates WHERE id = ?', [result.id]);
      await transaction.run('UPDATE shipments SET last_location = ?, last_tracked_at = ? WHERE id = ?', [location, created.created_at, shipment.id]);
      summary.accepted += 1;
    }
    return summary;
  });
}

async function listTrackingUpdates(tenantId, shipmentId) {
  assertTenant(tenantId);
  return all(
    `SELECT tracking_updates.id, tracking_updates.location, tracking_updates.eta, tracking_updates.note, tracking_updates.source,
       tracking_updates.lat, tracking_updates.lng, tracking_updates.created_at AS createdAt, users.name AS actorName
     FROM tracking_updates
     JOIN shipments ON shipments.id = tracking_updates.shipment_id
     LEFT JOIN users ON users.id = tracking_updates.actor_id
     WHERE tracking_updates.shipment_id = ? AND shipments.tenant_id = ? ORDER BY tracking_updates.id DESC`,
    [shipmentId, tenantId]
  );
}

async function listShipmentEvents(tenantId, id) {
  assertTenant(tenantId);
  return all(
    `SELECT shipment_events.id, shipment_events.shipment_id AS shipmentId, shipment_events.from_status AS fromStatus,
       shipment_events.to_status AS status, shipment_events.note, shipment_events.actor_id AS actorId, shipment_events.created_at AS createdAt
     FROM shipment_events JOIN shipments ON shipments.id = shipment_events.shipment_id
     WHERE shipment_events.shipment_id = ? AND shipments.tenant_id = ? ORDER BY shipment_events.id DESC`,
    [id, tenantId]
  );
}

/* ---------------- messages (RELAY) ---------------- */

async function createMessage(tenantId, { shipmentId, channel, recipientType, toPhone, body, status, provider, providerMessageId, error, createdBy }) {
  assertTenant(tenantId);
  const result = await run(
    `INSERT INTO messages (tenant_id, shipment_id, channel, recipient_type, to_phone, body, status, provider, provider_message_id, error, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [tenantId, shipmentId, channel, recipientType, toPhone, body, status, provider || null, providerMessageId || null, error || null, createdBy || null]
  );
  return { id: result.id };
}

async function listMessages(tenantId, shipmentId) {
  assertTenant(tenantId);
  return all(
    `SELECT messages.id, messages.channel, messages.recipient_type AS recipientType, messages.to_phone AS toPhone, messages.body,
       messages.status, messages.error, messages.created_at AS createdAt, users.name AS sentBy
     FROM messages LEFT JOIN users ON users.id = messages.created_by
     WHERE messages.shipment_id = ? AND messages.tenant_id = ? ORDER BY messages.id DESC`,
    [shipmentId, tenantId]
  );
}

/* ---------------- AI agent tasks ---------------- */

async function recordAgentTask(tenantId, { shipmentId, agent, status, model, inputTokens, outputTokens, latencyMs, error, actorId }) {
  assertTenant(tenantId);
  await run(
    `INSERT INTO agent_tasks (tenant_id, shipment_id, agent, status, model, input_tokens, output_tokens, latency_ms, error, actor_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [tenantId, shipmentId || null, agent, status, model || null, inputTokens ?? null, outputTokens ?? null, latencyMs ?? null, error ? String(error).slice(0, 300) : null, actorId || null]
  );
}

async function getAgentUsage(tenantId, days = 30) {
  assertTenant(tenantId);
  const rows = await all(
    `SELECT agent, COUNT(*) AS calls, SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded,
       COALESCE(SUM(input_tokens), 0) AS inputTokens, COALESCE(SUM(output_tokens), 0) AS outputTokens, AVG(latency_ms) AS avgLatencyMs
     FROM agent_tasks WHERE tenant_id = ? AND created_at >= datetime('now', ?) GROUP BY agent ORDER BY agent`,
    [tenantId, `-${Number(days)} days`]
  );
  return rows.map((row) => ({
    agent: row.agent,
    calls: Number(row.calls),
    succeeded: Number(row.succeeded),
    inputTokens: Number(row.inputTokens),
    outputTokens: Number(row.outputTokens),
    avgLatencyMs: row.avgLatencyMs === null ? null : Math.round(row.avgLatencyMs)
  }));
}

/* ---------------- carriers ---------------- */

async function listCarriers(tenantId) {
  return all('SELECT * FROM carriers WHERE tenant_id = ? ORDER BY id', [assertTenant(tenantId)]);
}

const CARRIER_MODES = ['Truckload', 'LTL', 'Expedited', 'Reefer', 'Flatbed', 'Intermodal'];
const CARRIER_MANUAL_STATUSES = ['Available', 'Inactive'];

async function listCarriersWithStats(tenantId) {
  assertTenant(tenantId);
  // Cancelled loads are counted as loads but never as booked money (same rule as bookedRevenue).
  const rows = await all(`
    SELECT carriers.id, carriers.name, carriers.mode, carriers.status, carriers.phone, carriers.contact_name AS contactName,
      COUNT(shipments.id) AS totalLoads,
      SUM(CASE WHEN shipments.status NOT IN ('Delivered', 'Cancelled') THEN 1 ELSE 0 END) AS activeLoads,
      SUM(CASE WHEN shipments.status = 'Delivered' THEN 1 ELSE 0 END) AS deliveredLoads,
      SUM(CASE WHEN shipments.status = 'Exception' THEN 1 ELSE 0 END) AS exceptionLoads,
      COALESCE(SUM(CASE WHEN shipments.status <> 'Cancelled' THEN shipments.rate END), 0) AS revenue,
      AVG(CASE WHEN shipments.status <> 'Cancelled' THEN shipments.rate END) AS averageRate,
      MAX(CASE WHEN shipments.status NOT IN ('Delivered', 'Cancelled') THEN shipments.id END) AS currentShipmentId
    FROM carriers
    LEFT JOIN shipments ON shipments.carrier_id = carriers.id
    WHERE carriers.tenant_id = ?
    GROUP BY carriers.id
    ORDER BY carriers.id
  `, [tenantId]);
  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    mode: row.mode,
    status: row.status,
    phone: row.phone || null,
    contactName: row.contactName || null,
    totalLoads: Number(row.totalLoads) || 0,
    activeLoads: Number(row.activeLoads) || 0,
    deliveredLoads: Number(row.deliveredLoads) || 0,
    exceptionLoads: Number(row.exceptionLoads) || 0,
    revenue: Number(row.revenue) || 0,
    averageRate: row.averageRate === null ? null : Number(row.averageRate),
    currentShipment: row.currentShipmentId ? `SHP-${row.currentShipmentId}` : null
  }));
}

// Everything SCOUT needs to rank carriers for one load: availability, history on this lane,
// delivered loads and how often their loads went into Exception.
async function getScoutData(tenantId, shipmentId) {
  assertTenant(tenantId);
  const shipment = await getShipment(tenantId, shipmentId);
  if (!shipment) throw httpError(404, 'Shipment not found.');
  const lane = [shipment.origin, shipment.destination];
  const carriers = await all(`
    SELECT carriers.id, carriers.name, carriers.mode, carriers.phone,
      SUM(CASE WHEN shipments.status = 'Delivered' THEN 1 ELSE 0 END) AS delivered,
      SUM(CASE WHEN shipments.status = 'Delivered' AND lower(shipments.origin) = lower(?) AND lower(shipments.destination) = lower(?) THEN 1 ELSE 0 END) AS laneDelivered,
      AVG(CASE WHEN shipments.status <> 'Cancelled' AND lower(shipments.origin) = lower(?) AND lower(shipments.destination) = lower(?) THEN shipments.rate END) AS laneAverageRate,
      (SELECT COUNT(DISTINCT shipment_events.shipment_id) FROM shipment_events
         JOIN shipments AS s2 ON s2.id = shipment_events.shipment_id
         WHERE s2.carrier_id = carriers.id AND shipment_events.to_status = 'Exception') AS exceptionLoads
    FROM carriers
    LEFT JOIN shipments ON shipments.carrier_id = carriers.id
    WHERE carriers.tenant_id = ? AND carriers.status = 'Available'
    GROUP BY carriers.id
  `, [...lane, ...lane, tenantId]);
  const market = await get(
    "SELECT AVG(rate) AS averageRate, COUNT(rate) AS loads FROM shipments WHERE tenant_id = ? AND status <> 'Cancelled' AND lower(origin) = lower(?) AND lower(destination) = lower(?)",
    [tenantId, ...lane]
  );
  return {
    shipment,
    carriers: carriers.map((row) => ({
      id: row.id,
      name: row.name,
      mode: row.mode,
      phone: row.phone || null,
      delivered: Number(row.delivered) || 0,
      laneDelivered: Number(row.laneDelivered) || 0,
      laneAverageRate: row.laneAverageRate === null ? null : Number(row.laneAverageRate),
      exceptionLoads: Number(row.exceptionLoads) || 0
    })),
    laneAverageRate: market?.averageRate === null || market?.averageRate === undefined ? null : Number(market.averageRate),
    laneLoads: Number(market?.loads) || 0
  };
}

async function createCarrier({ name, mode, phone, contactName, tenantId }) {
  assertTenant(tenantId);
  // Check and insert in one transaction so two people cannot add the same carrier twice.
  return withTransaction(async (transaction) => {
    const existing = await transaction.get('SELECT id FROM carriers WHERE lower(name) = lower(?) AND tenant_id = ?', [name, tenantId]);
    if (existing) throw httpError(409, 'A carrier with this name already exists.');
    const result = await transaction.run(
      'INSERT INTO carriers (name, mode, status, phone, contact_name, tenant_id) VALUES (?, ?, ?, ?, ?, ?)',
      [name, mode, 'Available', phone || null, contactName || null, tenantId]
    );
    return { id: result.id, name, mode, status: 'Available', phone: phone || null, contactName: contactName || null };
  });
}

async function updateCarrierStatus(tenantId, id, status) {
  assertTenant(tenantId);
  return withTransaction(async (transaction) => {
    const carrier = await transaction.get('SELECT id, name, status FROM carriers WHERE id = ? AND tenant_id = ?', [id, tenantId]);
    if (!carrier) throw httpError(404, 'Carrier not found.');
    const activeAssignment = await transaction.get(
      "SELECT id FROM shipments WHERE carrier_id = ? AND status NOT IN ('Delivered', 'Cancelled') LIMIT 1",
      [id]
    );
    if (activeAssignment) throw httpError(409, 'Carrier has an active load. Deliver or cancel it before changing availability.');
    await transaction.run('UPDATE carriers SET status = ? WHERE id = ?', [status, id]);
    return { id: carrier.id, name: carrier.name, status };
  });
}

/* ---------------- analytics, dashboard and alerts ---------------- */

const ANALYTICS_RANGES = [7, 30, 90];

async function getAnalyticsPayload(tenantId, { days = 7 } = {}) {
  assertTenant(tenantId);
  const rangeDays = ANALYTICS_RANGES.includes(Number(days)) ? Number(days) : 7;
  const [statusRows, dailyRows, shipmentTotals, carriers] = await Promise.all([
    all('SELECT status, COUNT(*) AS total FROM shipments WHERE tenant_id = ? GROUP BY status', [tenantId]),
    all("SELECT date(created_at) AS day, COUNT(*) AS total FROM shipments WHERE tenant_id = ? AND date(created_at) >= date('now', ?) GROUP BY date(created_at)", [tenantId, `-${rangeDays - 1} days`]),
    get(`SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status NOT IN ('Delivered', 'Cancelled') THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN status = 'Pending Approval' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status = 'Delivered' THEN 1 ELSE 0 END) AS delivered,
      SUM(CASE WHEN status = 'Exception' THEN 1 ELSE 0 END) AS exceptions,
      AVG(CASE WHEN rate IS NOT NULL THEN rate END) AS averageRate
      FROM shipments WHERE tenant_id = ?`, [tenantId]),
    listCarriers(tenantId)
  ]);

  const statuses = {
    New: 0,
    Sourcing: 0,
    'Pending Approval': 0,
    Dispatched: 0,
    'In Transit': 0,
    Delivered: 0,
    Exception: 0,
    Cancelled: 0
  };
  statusRows.forEach((row) => {
    if (Object.hasOwn(statuses, row.status)) statuses[row.status] = Number(row.total);
  });

  const dailyTotals = new Map(dailyRows.map((row) => [row.day, Number(row.total)]));
  const weeklyVolume = Array.from({ length: rangeDays }, (_, index) => {
    const date = new Date();
    date.setUTCDate(date.getUTCDate() - (rangeDays - 1 - index));
    const day = date.toISOString().slice(0, 10);
    return {
      day,
      label: new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }).format(new Date(`${day}T00:00:00Z`)),
      total: dailyTotals.get(day) || 0
    };
  });

  return {
    stats: {
      totalShipments: Number(shipmentTotals.total) || 0,
      activeShipments: Number(shipmentTotals.active) || 0,
      pendingApproval: Number(shipmentTotals.pending) || 0,
      completed: Number(shipmentTotals.delivered) || 0,
      exceptions: Number(shipmentTotals.exceptions) || 0,
      availableCarriers: carriers.filter((carrier) => carrier.status === 'Available').length,
      totalCarriers: carriers.length,
      averageRate: Number(shipmentTotals.averageRate) || 0
    },
    statuses,
    rangeDays,
    weeklyVolume
  };
}

async function getAnalyticsReport(tenantId, { days = 7 } = {}) {
  const base = await getAnalyticsPayload(tenantId, { days });
  const [equipmentRows, laneRows, customerRows, revenueRow, carrierStats] = await Promise.all([
    all("SELECT COALESCE(equipment, 'Unspecified') AS label, COUNT(*) AS total FROM shipments WHERE tenant_id = ? GROUP BY COALESCE(equipment, 'Unspecified') ORDER BY total DESC", [tenantId]),
    all(`SELECT origin, destination, COUNT(*) AS total, AVG(CASE WHEN status <> 'Cancelled' THEN rate END) AS averageRate
      FROM shipments WHERE tenant_id = ? GROUP BY origin, destination ORDER BY total DESC, origin LIMIT 5`, [tenantId]),
    all(`SELECT customer, COUNT(*) AS total,
      SUM(CASE WHEN status NOT IN ('Delivered', 'Cancelled') THEN 1 ELSE 0 END) AS active,
      COALESCE(SUM(CASE WHEN status <> 'Cancelled' THEN rate END), 0) AS revenue
      FROM shipments WHERE tenant_id = ? GROUP BY customer ORDER BY total DESC, revenue DESC, customer LIMIT 5`, [tenantId]),
    // rate = what we pay the carrier; customer_rate = what the customer pays us. Margin needs both.
    get(`SELECT COALESCE(SUM(rate), 0) AS revenue, COUNT(rate) AS pricedLoads,
      COALESCE(SUM(CASE WHEN rate IS NOT NULL AND customer_rate IS NOT NULL THEN customer_rate - rate END), 0) AS margin,
      COALESCE(SUM(CASE WHEN rate IS NOT NULL AND customer_rate IS NOT NULL THEN customer_rate END), 0) AS marginBase,
      SUM(CASE WHEN rate IS NOT NULL AND customer_rate IS NOT NULL THEN 1 ELSE 0 END) AS marginLoads
      FROM shipments WHERE tenant_id = ? AND status <> 'Cancelled'`, [tenantId]),
    listCarriersWithStats(tenantId)
  ]);
  const total = base.stats.totalShipments;
  const closed = base.statuses.Delivered + base.statuses.Cancelled;
  return {
    ...base,
    stats: {
      ...base.stats,
      bookedRevenue: Number(revenueRow?.revenue) || 0,
      pricedLoads: Number(revenueRow?.pricedLoads) || 0,
      grossMargin: Number(revenueRow?.margin) || 0,
      marginLoads: Number(revenueRow?.marginLoads) || 0,
      marginRate: Number(revenueRow?.marginBase) ? Number(revenueRow.margin) / Number(revenueRow.marginBase) : null,
      deliveryRate: closed ? base.statuses.Delivered / closed : null,
      exceptionRate: total ? base.stats.exceptions / total : null,
      busyCarriers: carrierStats.filter((carrier) => carrier.status === 'Busy').length
    },
    equipment: equipmentRows.map((row) => ({ label: row.label, total: Number(row.total) })),
    topLanes: laneRows.map((row) => ({
      origin: row.origin,
      destination: row.destination,
      total: Number(row.total),
      averageRate: row.averageRate === null ? null : Number(row.averageRate)
    })),
    topCustomers: customerRows.map((row) => ({
      customer: row.customer,
      total: Number(row.total),
      active: Number(row.active) || 0,
      revenue: Number(row.revenue) || 0
    })),
    carrierPerformance: carrierStats
  };
}

async function getDashboardPayload(tenantId, { days = 7 } = {}) {
  const shipments = await listShipments(tenantId, { limit: 20 });
  const carriers = await listCarriers(tenantId);
  const analytics = await getAnalyticsPayload(tenantId, { days });

  const recentShipments = shipments.map((shipment) => ({
    id: `SHP-${shipment.id}`,
    customer: shipment.customer,
    origin: shipment.origin,
    destination: shipment.destination,
    pickup: shipment.pickup || 'Today',
    delivery: shipment.delivery || 'Next Day',
    status: shipment.status || 'Pending Approval'
  }));

  const latestShipment = shipments[0] || null;

  return {
    ...analytics,
    shipments: recentShipments,
    route: latestShipment ? {
      origin: latestShipment.origin,
      destination: latestShipment.destination,
      weight: latestShipment.weight,
      equipment: latestShipment.equipment,
      pickup: latestShipment.pickup,
      delivery: latestShipment.delivery
    } : null,
    assistant: {
      title: 'VEYRA AI Assistant',
      prompt: 'Create a shipment for 10,000 kg dry van from Dallas to Houston'
    },
    carriers
  };
}

// Counts behind the notification bell, computed in SQL so they stay right at any volume.
async function getAlerts(tenantId, { staleHours = 12 } = {}) {
  assertTenant(tenantId);
  const row = await get(`
    SELECT
      SUM(CASE WHEN status = 'Exception' THEN 1 ELSE 0 END) AS exceptions,
      SUM(CASE WHEN status = 'Pending Approval' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status = 'New' THEN 1 ELSE 0 END) AS fresh,
      SUM(CASE WHEN status = 'Sourcing' THEN 1 ELSE 0 END) AS sourcing,
      SUM(CASE WHEN status IN ('Dispatched', 'In Transit') AND (last_tracked_at IS NULL OR last_tracked_at < datetime('now', ?)) THEN 1 ELSE 0 END) AS staleTracking
    FROM shipments WHERE tenant_id = ?
  `, [`-${Number(staleHours)} hours`, tenantId]);
  const carriers = await get("SELECT SUM(CASE WHEN status = 'Available' THEN 1 ELSE 0 END) AS available, COUNT(*) AS total FROM carriers WHERE tenant_id = ?", [tenantId]);
  return {
    exceptions: Number(row?.exceptions) || 0,
    pendingApproval: Number(row?.pending) || 0,
    new: Number(row?.fresh) || 0,
    sourcing: Number(row?.sourcing) || 0,
    staleTracking: Number(row?.staleTracking) || 0,
    staleHours,
    availableCarriers: Number(carriers?.available) || 0,
    totalCarriers: Number(carriers?.total) || 0
  };
}

module.exports = {
  db,
  BCRYPT_COST,
  DEFAULT_TENANT_ID,
  ALLOWED_ROLES,
  TRACKABLE_STATUSES,
  CARRIER_MODES,
  CARRIER_MANUAL_STATUSES,
  initialize,
  checkIntegrity,
  getTenant,
  listTenants,
  createTenantWithAdmin,
  setTenantGpsTokenHash,
  findTenantByGpsTokenHash,
  findUserByEmail,
  findUserById,
  updateUser,
  createUser,
  listUsers,
  createAuthSession,
  isAuthSessionActive,
  revokeAuthSession,
  revokeUserSessions,
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
  listCarriers,
  listCarriersWithStats,
  getScoutData,
  createCarrier,
  updateCarrierStatus,
  getAnalyticsPayload,
  getAnalyticsReport,
  getDashboardPayload,
  getAlerts
};
