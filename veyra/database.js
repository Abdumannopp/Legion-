const bcrypt = require('bcryptjs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

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
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'operator'
    )
  `);
  await ensureColumns('users', [['disabled_at', 'INTEGER']]);

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
    ['last_tracked_at', 'TEXT']
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
  await ensureColumns('carriers', [['phone', 'TEXT'], ['contact_name', 'TEXT']]);

  // Check calls: each row is one "where is the truck now" update for a dispatched load.
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

  const seedUsers = [
    { name: 'Alex Carter', email: 'admin@veyra.ai', password: 'admin123', role: 'admin' },
    { name: 'Emma Wilson', email: 'ops@veyra.ai', password: 'ops123', role: 'operations' },
    { name: 'Demo Operator', email: 'demo@veyra.ai', password: 'demo123', role: 'operator' }
  ];

  if (isProduction) {
    const userCount = await get('SELECT COUNT(*) AS total FROM users');
    if (Number(userCount?.total) === 0) {
      const { INITIAL_ADMIN_NAME, INITIAL_ADMIN_EMAIL, INITIAL_ADMIN_PASSWORD } = process.env;
      if (!INITIAL_ADMIN_NAME || !INITIAL_ADMIN_EMAIL || !INITIAL_ADMIN_PASSWORD || INITIAL_ADMIN_PASSWORD.length < 12) {
        throw new Error('Set INITIAL_ADMIN_NAME, INITIAL_ADMIN_EMAIL, and an INITIAL_ADMIN_PASSWORD of at least 12 characters before first production startup.');
      }
      const hashedPassword = await bcrypt.hash(INITIAL_ADMIN_PASSWORD, BCRYPT_COST);
      await run(
        'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
        [INITIAL_ADMIN_NAME.trim(), INITIAL_ADMIN_EMAIL.trim().toLowerCase(), hashedPassword, 'admin']
      );
    }
  } else {
    for (const user of seedUsers) {
      const exists = await get('SELECT id FROM users WHERE email = ?', [user.email]);
      if (!exists) {
        const hashedPassword = await bcrypt.hash(user.password, BCRYPT_COST);
        await run(
          'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
          [user.name, user.email, hashedPassword, user.role]
        );
      }
    }

    const carrierCount = await get('SELECT COUNT(*) AS total FROM carriers');
    if (!carrierCount || Number(carrierCount.total) === 0) {
      await run('INSERT INTO carriers (name, mode, status, phone, contact_name) VALUES (?, ?, ?, ?, ?)', ['Atlas Freight', 'Truckload', 'Available', '+1 214 555 0100', 'Dana Brooks']);
      await run('INSERT INTO carriers (name, mode, status, phone, contact_name) VALUES (?, ?, ?, ?, ?)', ['North Wind Logistics', 'LTL', 'Available', '+1 312 555 0142', 'Sam Ortiz']);
      // Available (not Busy): a carrier is only Busy while it has an active load.
      await run('INSERT INTO carriers (name, mode, status, phone, contact_name) VALUES (?, ?, ?, ?, ?)', ['Blue Ridge Cargo', 'Expedited', 'Available', '+1 404 555 0178', 'Lee Grant']);
    }

    const shipmentCount = await get('SELECT COUNT(*) AS total FROM shipments');
    if (!shipmentCount || Number(shipmentCount.total) === 0) {
      await run(
        'INSERT INTO shipments (customer, origin, destination, pickup, delivery, status, weight, equipment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        ['ABC Retail', 'Dallas, TX', 'Houston, TX', 'Oct 3', 'Oct 4', 'New', '4500 kg', 'Dry Van']
      );
      await run(
        'INSERT INTO shipments (customer, origin, destination, pickup, delivery, status, weight, equipment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        ['Global Parts', 'Chicago, IL', 'Atlanta, GA', 'Oct 3', 'Oct 5', 'Pending Approval', '3850 kg', 'Reefer']
      );
      await run(
        'INSERT INTO shipments (customer, origin, destination, pickup, delivery, status, weight, equipment) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        ['Prime Goods', 'Los Angeles, CA', 'Phoenix, AZ', 'Oct 2', 'Oct 3', 'Sourcing', '5400 kg', 'Flatbed']
      );
    }
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
    'CREATE INDEX IF NOT EXISTS idx_shipment_events_shipment ON shipment_events (shipment_id, id)',
    'CREATE INDEX IF NOT EXISTS idx_carriers_status ON carriers (status)',
    'CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires ON auth_sessions (expires_at)',
    'CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions (user_id)',
    'CREATE INDEX IF NOT EXISTS idx_tracking_updates_shipment ON tracking_updates (shipment_id, id)'
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
  return get('SELECT id, name, email, role, disabled_at AS disabledAt FROM users WHERE id = ?', [Number(id)]);
}

const ALLOWED_ROLES = ['admin', 'operations', 'operator'];

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

// Change a user's role and/or access. Any change revokes that user's sessions,
// so a demoted or disabled user loses access immediately, not when the token expires.
async function updateUser(id, { role, active }, actorId) {
  return withTransaction(async (transaction) => {
    const user = await transaction.get('SELECT id, name, email, role, disabled_at FROM users WHERE id = ?', [id]);
    if (!user) throw httpError(404, 'User not found.');
    if (Number(actorId) === Number(id)) throw httpError(409, 'You cannot change your own role or access.');

    const nextRole = role === undefined ? user.role : role;
    const nextDisabled = active === undefined ? user.disabled_at : (active ? null : Math.floor(Date.now() / 1000));
    if (!ALLOWED_ROLES.includes(nextRole)) throw httpError(400, 'Unknown role.');

    const losesAdmin = user.role === 'admin' && !user.disabled_at && (nextRole !== 'admin' || nextDisabled);
    if (losesAdmin) {
      const others = await transaction.get(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin' AND disabled_at IS NULL AND id <> ?",
        [id]
      );
      if (!Number(others?.total)) throw httpError(409, 'At least one active administrator must remain.');
    }

    await transaction.run('UPDATE users SET role = ?, disabled_at = ? WHERE id = ?', [nextRole, nextDisabled, id]);
    await revokeUserSessions(id, transaction.run);
    return { id: user.id, name: user.name, email: user.email, role: nextRole, active: !nextDisabled };
  });
}

async function createUser({ name, email, password, role = 'operator' }) {
  const safeRole = ALLOWED_ROLES.includes(role) ? role : 'operator';
  const result = await run(
    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
    [name, email, password, safeRole]
  );

  return {
    id: result.id,
    name,
    email,
    role: safeRole,
    password
  };
}

async function listUsers() {
  const rows = await all('SELECT id, name, email, role, disabled_at FROM users ORDER BY id');
  return rows.map((row) => ({ id: row.id, name: row.name, email: row.email, role: row.role, active: !row.disabled_at }));
}

const SHIPMENT_SELECT = `SELECT shipments.*, carriers.name AS carrierName, carriers.phone AS carrierPhone
  FROM shipments LEFT JOIN carriers ON carriers.id = shipments.carrier_id`;

async function listShipments({ limit = 50, offset = 0 } = {}) {
  const safeLimit = Math.min(Math.max(Math.trunc(Number(limit)) || 50, 1), 200);
  const safeOffset = Math.max(Math.trunc(Number(offset)) || 0, 0);
  return all(
    `${SHIPMENT_SELECT} ORDER BY shipments.created_at DESC, shipments.id DESC LIMIT ? OFFSET ?`,
    [safeLimit, safeOffset]
  );
}

async function getShipment(id) {
  return get(`${SHIPMENT_SELECT} WHERE shipments.id = ?`, [id]);
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

async function updateShipmentStatus(id, status, actorId, note) {
  return withTransaction(async (transaction) => {
    const current = await transaction.get('SELECT id, status, carrier_id FROM shipments WHERE id = ?', [id]);
    if (!current) {
      const error = new Error('Shipment not found.');
      error.statusCode = 404;
      throw error;
    }

    if (!(STATUS_TRANSITIONS[current.status] || []).includes(status)) {
      const error = new Error(`Cannot move shipment from ${current.status} to ${status}.`);
      error.statusCode = 409;
      throw error;
    }

    const result = await transaction.run(
      'UPDATE shipments SET status = ? WHERE id = ? AND status = ?',
      [status, id, current.status]
    );
    if (result.changes !== 1) {
      const error = new Error('Shipment state changed before the update could be applied.');
      error.statusCode = 409;
      throw error;
    }

    if (['Delivered', 'Cancelled'].includes(status) && current.carrier_id) {
      const carrier = await transaction.get('SELECT id, status FROM carriers WHERE id = ?', [current.carrier_id]);
      if (!carrier) {
        const error = new Error('Assigned carrier no longer exists.');
        error.statusCode = 409;
        throw error;
      }

      const otherActiveAssignment = await transaction.get(
        "SELECT id FROM shipments WHERE carrier_id = ? AND id <> ? AND status NOT IN ('Delivered', 'Cancelled') LIMIT 1",
        [current.carrier_id, id]
      );
      if (otherActiveAssignment) {
        const error = new Error('Assigned carrier is still attached to another active shipment.');
        error.statusCode = 409;
        throw error;
      }

      if (carrier.status === 'Busy') {
        const released = await transaction.run(
          "UPDATE carriers SET status = 'Available' WHERE id = ? AND status = 'Busy'",
          [current.carrier_id]
        );
        if (released.changes !== 1) {
          const error = new Error('Carrier availability changed during shipment completion.');
          error.statusCode = 409;
          throw error;
        }
      } else if (carrier.status !== 'Available') {
        const error = new Error('Assigned carrier has an invalid availability state.');
        error.statusCode = 409;
        throw error;
      }
    }

    await recordShipmentEvent(id, current.status, status, note, actorId, transaction.run);
    return { changes: result.changes, id, status };
  });
}

async function createShipment({ customer, origin, destination, pickup, delivery, status, weight, equipment, reference, trackingNumber, customerRate, actorId }) {
  return withTransaction(async (transaction) => {
    const result = await transaction.run(
      'INSERT INTO shipments (customer, origin, destination, pickup, delivery, status, weight, equipment, reference, tracking_number, customer_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [customer, origin, destination, pickup, delivery, status, weight, equipment, reference || null, trackingNumber || null, customerRate ?? null]
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
      customerRate: customerRate ?? null
    };
  });
}

// details: optional { customerRate, driverName, driverPhone, truckPlate } agreed at booking.
async function dispatchShipment(id, carrierId, rate, actorId, details = {}) {
  return withTransaction(async (transaction) => {
    const shipment = await transaction.get('SELECT id, status, carrier_id FROM shipments WHERE id = ?', [id]);
    if (!shipment) {
      const error = new Error('Shipment not found.');
      error.statusCode = 404;
      throw error;
    }
    if (!['Sourcing', 'Pending Approval'].includes(shipment.status) || shipment.carrier_id) {
      const error = new Error('Shipment must be unassigned and in sourcing or pending approval before dispatch.');
      error.statusCode = 409;
      throw error;
    }

    const carrier = await transaction.get('SELECT id, name, status FROM carriers WHERE id = ?', [carrierId]);
    if (!carrier) {
      const error = new Error('Carrier not found.');
      error.statusCode = 404;
      throw error;
    }
    if (carrier.status !== 'Available') {
      const error = new Error('Selected carrier is not available.');
      error.statusCode = 409;
      throw error;
    }

    const activeAssignment = await transaction.get(
      "SELECT id FROM shipments WHERE carrier_id = ? AND status NOT IN ('Delivered', 'Cancelled') LIMIT 1",
      [carrierId]
    );
    if (activeAssignment) {
      const error = new Error('Selected carrier already has an active shipment.');
      error.statusCode = 409;
      throw error;
    }

    const claimedCarrier = await transaction.run(
      "UPDATE carriers SET status = 'Busy' WHERE id = ? AND status = 'Available'",
      [carrierId]
    );
    if (claimedCarrier.changes !== 1) {
      const error = new Error('Selected carrier is no longer available.');
      error.statusCode = 409;
      throw error;
    }

    const { customerRate, driverName, driverPhone, truckPlate } = details;
    const assignedShipment = await transaction.run(
      `UPDATE shipments SET carrier_id = ?, rate = ?, status = 'Dispatched',
         customer_rate = COALESCE(?, customer_rate), driver_name = ?, driver_phone = ?, truck_plate = ?
       WHERE id = ? AND status = ? AND carrier_id IS NULL`,
      [carrierId, rate, customerRate ?? null, driverName || null, driverPhone || null, truckPlate || null, id, shipment.status]
    );
    if (assignedShipment.changes !== 1) {
      const error = new Error('Shipment state changed before dispatch could be applied.');
      error.statusCode = 409;
      throw error;
    }

    const truck = [truckPlate && `truck ${truckPlate}`, driverName && `driver ${driverName}`].filter(Boolean).join(', ');
    const note = `Assigned to ${carrier.name} at ${Number(rate).toFixed(2)}${truck ? ` (${truck})` : ''}`;
    await recordShipmentEvent(id, shipment.status, 'Dispatched', note, actorId, transaction.run);
    return { id, status: 'Dispatched', carrier: carrier.name, rate };
  });
}

async function addTrackingUpdate(shipmentId, { location, eta, note }, actorId) {
  return withTransaction(async (transaction) => {
    const shipment = await transaction.get('SELECT id, status FROM shipments WHERE id = ?', [shipmentId]);
    if (!shipment) throw httpError(404, 'Shipment not found.');
    if (!TRACKABLE_STATUSES.includes(shipment.status)) {
      throw httpError(409, `Location updates are only possible while a load is ${TRACKABLE_STATUSES.join(', ')}.`);
    }
    const result = await transaction.run(
      'INSERT INTO tracking_updates (shipment_id, actor_id, location, eta, note) VALUES (?, ?, ?, ?, ?)',
      [shipmentId, actorId || null, location, eta || null, note || null]
    );
    const created = await transaction.get('SELECT created_at FROM tracking_updates WHERE id = ?', [result.id]);
    // Keep the newest position and ETA on the shipment itself so lists can show it without a join.
    await transaction.run(
      'UPDATE shipments SET last_location = ?, eta = COALESCE(?, eta), last_tracked_at = ? WHERE id = ?',
      [location, eta || null, created.created_at, shipmentId]
    );
    return { id: result.id, shipmentId: `SHP-${shipmentId}`, location, eta: eta || null, note: note || null, createdAt: created.created_at };
  });
}

async function listTrackingUpdates(shipmentId) {
  return all(
    `SELECT tracking_updates.id, tracking_updates.location, tracking_updates.eta, tracking_updates.note,
       tracking_updates.created_at AS createdAt, users.name AS actorName
     FROM tracking_updates LEFT JOIN users ON users.id = tracking_updates.actor_id
     WHERE tracking_updates.shipment_id = ? ORDER BY tracking_updates.id DESC`,
    [shipmentId]
  );
}

async function listShipmentEvents(id) {
  return all(
    'SELECT id, shipment_id AS shipmentId, from_status AS fromStatus, to_status AS status, note, actor_id AS actorId, created_at AS createdAt FROM shipment_events WHERE shipment_id = ? ORDER BY id DESC',
    [id]
  );
}

async function listCarriers() {
  return all('SELECT * FROM carriers ORDER BY id');
}

const CARRIER_MODES = ['Truckload', 'LTL', 'Expedited', 'Reefer', 'Flatbed', 'Intermodal'];
const CARRIER_MANUAL_STATUSES = ['Available', 'Inactive'];

async function listCarriersWithStats() {
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
    GROUP BY carriers.id
    ORDER BY carriers.id
  `);
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

async function createCarrier({ name, mode, phone, contactName }) {
  // Check and insert in one transaction so two people cannot add the same carrier twice.
  return withTransaction(async (transaction) => {
    const existing = await transaction.get('SELECT id FROM carriers WHERE lower(name) = lower(?)', [name]);
    if (existing) throw httpError(409, 'A carrier with this name already exists.');
    const result = await transaction.run(
      'INSERT INTO carriers (name, mode, status, phone, contact_name) VALUES (?, ?, ?, ?, ?)',
      [name, mode, 'Available', phone || null, contactName || null]
    );
    return { id: result.id, name, mode, status: 'Available', phone: phone || null, contactName: contactName || null };
  });
}

async function updateCarrierStatus(id, status) {
  return withTransaction(async (transaction) => {
    const carrier = await transaction.get('SELECT id, name, status FROM carriers WHERE id = ?', [id]);
    if (!carrier) {
      const error = new Error('Carrier not found.');
      error.statusCode = 404;
      throw error;
    }
    const activeAssignment = await transaction.get(
      "SELECT id FROM shipments WHERE carrier_id = ? AND status NOT IN ('Delivered', 'Cancelled') LIMIT 1",
      [id]
    );
    if (activeAssignment) {
      const error = new Error('Carrier has an active load. Deliver or cancel it before changing availability.');
      error.statusCode = 409;
      throw error;
    }
    await transaction.run('UPDATE carriers SET status = ? WHERE id = ?', [status, id]);
    return { id: carrier.id, name: carrier.name, status };
  });
}

const ANALYTICS_RANGES = [7, 30, 90];

async function getAnalyticsPayload({ days = 7 } = {}) {
  const rangeDays = ANALYTICS_RANGES.includes(Number(days)) ? Number(days) : 7;
  const [statusRows, dailyRows, shipmentTotals, carriers] = await Promise.all([
    all('SELECT status, COUNT(*) AS total FROM shipments GROUP BY status'),
    all("SELECT date(created_at) AS day, COUNT(*) AS total FROM shipments WHERE date(created_at) >= date('now', ?) GROUP BY date(created_at)", [`-${rangeDays - 1} days`]),
    get(`SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status NOT IN ('Delivered', 'Cancelled') THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN status = 'Pending Approval' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status = 'Delivered' THEN 1 ELSE 0 END) AS delivered,
      SUM(CASE WHEN status = 'Exception' THEN 1 ELSE 0 END) AS exceptions,
      AVG(CASE WHEN rate IS NOT NULL THEN rate END) AS averageRate
      FROM shipments`),
    listCarriers()
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

async function getAnalyticsReport({ days = 7 } = {}) {
  const base = await getAnalyticsPayload({ days });
  const [equipmentRows, laneRows, customerRows, revenueRow, carrierStats] = await Promise.all([
    all("SELECT COALESCE(equipment, 'Unspecified') AS label, COUNT(*) AS total FROM shipments GROUP BY COALESCE(equipment, 'Unspecified') ORDER BY total DESC"),
    all(`SELECT origin, destination, COUNT(*) AS total, AVG(CASE WHEN status <> 'Cancelled' THEN rate END) AS averageRate
      FROM shipments GROUP BY origin, destination ORDER BY total DESC, origin LIMIT 5`),
    all(`SELECT customer, COUNT(*) AS total,
      SUM(CASE WHEN status NOT IN ('Delivered', 'Cancelled') THEN 1 ELSE 0 END) AS active,
      COALESCE(SUM(CASE WHEN status <> 'Cancelled' THEN rate END), 0) AS revenue
      FROM shipments GROUP BY customer ORDER BY total DESC, revenue DESC, customer LIMIT 5`),
    // rate = what we pay the carrier; customer_rate = what the customer pays us. Margin needs both.
    get(`SELECT COALESCE(SUM(rate), 0) AS revenue, COUNT(rate) AS pricedLoads,
      COALESCE(SUM(CASE WHEN rate IS NOT NULL AND customer_rate IS NOT NULL THEN customer_rate - rate END), 0) AS margin,
      COALESCE(SUM(CASE WHEN rate IS NOT NULL AND customer_rate IS NOT NULL THEN customer_rate END), 0) AS marginBase,
      SUM(CASE WHEN rate IS NOT NULL AND customer_rate IS NOT NULL THEN 1 ELSE 0 END) AS marginLoads
      FROM shipments WHERE status <> 'Cancelled'`),
    listCarriersWithStats()
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

async function getDashboardPayload({ days = 7 } = {}) {
  const shipments = await listShipments({ limit: 20 });
  const carriers = await listCarriers();
  const analytics = await getAnalyticsPayload({ days });

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
      prompt: 'Create a shipment for 10,000 lb dry van from Dallas to Houston'
    },
    carriers
  };
}

module.exports = {
  db,
  BCRYPT_COST,
  ALLOWED_ROLES,
  TRACKABLE_STATUSES,
  initialize,
  findUserByEmail,
  findUserById,
  updateUser,
  createAuthSession,
  isAuthSessionActive,
  revokeAuthSession,
  revokeUserSessions,
  addTrackingUpdate,
  listTrackingUpdates,
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
  listCarriersWithStats,
  createCarrier,
  updateCarrierStatus,
  CARRIER_MODES,
  CARRIER_MANUAL_STATUSES,
  checkIntegrity,
  getAnalyticsPayload,
  getAnalyticsReport,
  getDashboardPayload
};
