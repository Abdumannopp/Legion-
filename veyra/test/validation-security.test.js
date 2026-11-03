const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-validation-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'v.db');
process.env.PORT = '0';
// This file fires many requests on purpose; raise the limiters so validation (not 429) is what's tested.
process.env.API_RATE_LIMIT_MAX = '5000';
process.env.REGISTER_RATE_LIMIT_MAX = '500';
process.env.LOGIN_RATE_LIMIT_MAX = '500';
process.env.LOGIN_RATE_LIMIT_IP_MAX = '500';

const { app, initialize } = require('../server');
const { db, checkIntegrity } = require('../database');

let server;
let base;
let admin;

const dbAll = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (e, rows) => (e ? reject(e) : resolve(rows))));
const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function done(e) { return e ? reject(e) : resolve(this); }));

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  const res = await fetch(`${base}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'admin@veyra.ai', password: 'admin123' })
  });
  admin = res.headers.get('set-cookie').split(';')[0];
});

after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

const call = (method, url, body, cookie = admin, raw = false) => fetch(`${base}${url}`, {
  method,
  headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
  body: body === undefined ? undefined : raw ? body : JSON.stringify(body)
});

const validShipment = () => ({
  customer: 'Valid Co', origin: 'Austin, TX', destination: 'Denver, CO',
  pickup: '2026-11-03', delivery: '2026-11-05', weight: 5000, equipment: 'Dry Van'
});

function assertSafeBody(text) {
  assert.ok(!/SQLITE|node_modules|\/home\/|\bat .+\(.+:\d+:\d+\)|stack/i.test(text), `leaky error body: ${text.slice(0, 200)}`);
}

test('login rejects non-string and missing credentials with 400, not 500', async () => {
  for (const body of [{ email: {}, password: 'x' }, { email: 123, password: 'abc12345' }, { email: ['a@b.co'], password: 'x' }, { email: 'a@b.co' }, {}, { email: 'a@b.co', password: 'x'.repeat(200) }]) {
    const res = await call('POST', '/api/login', body, null);
    assert.equal(res.status, 400, JSON.stringify(body));
  }
});

test('registration enforces password strength and email format', async () => {
  const send = (password, email = 'new.user@example.com') => call('POST', '/api/register', { name: 'New User', email, password }, null);
  assert.equal((await send('allletters')).status, 400);
  assert.equal((await send('12345678')).status, 400);
  assert.equal((await send('short1')).status, 400);
  assert.equal((await send('x'.repeat(80) + '1')).status, 400);
  assert.equal((await send('goodpass1', 'not-an-email')).status, 400);
  assert.equal((await call('POST', '/api/register', { name: 'n'.repeat(500), email: 'long@example.com', password: 'goodpass1' }, null)).status, 400);
});

test('malformed and oversized JSON get safe 4xx responses', async () => {
  const bad = await call('POST', '/api/login', '{"email": ', null, true);
  assert.equal(bad.status, 400);
  const text = await bad.text();
  assertSafeBody(text);
  assert.equal(JSON.parse(text).success, false);

  const huge = await call('POST', '/api/shipments', { ...validShipment(), customer: 'a'.repeat(80 * 1024) });
  assert.equal(huge.status, 413);
  assertSafeBody(await huge.text());
});

test('shipment creation rejects invalid, ambiguous and malicious fields', async () => {
  const mutations = [
    { pickup: '11' }, { pickup: '2026-02-30' }, { pickup: '2026-13-01' }, { pickup: 'tomorrow' }, { delivery: '2026-11-02' },
    { weight: '1e3' }, { weight: true }, { weight: null }, { weight: [5] }, { weight: 0 }, { weight: -5 }, { weight: 2000000 }, { weight: 'abc' },
    { equipment: 'Spaceship' }, { equipment: ['Dry Van'] },
    { customer: ['x'] }, { customer: '' }, { customer: '   ' }, { origin: 123 }, { destination: {} },
    { customer: 'c'.repeat(121) }, { reference: 'r'.repeat(81) }, { reference: { a: 1 } }, { trackingNumber: 't'.repeat(81) }
  ];
  for (const change of mutations) {
    const res = await call('POST', '/api/shipments', { ...validShipment(), ...change });
    assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(change)}`);
    assertSafeBody(await res.text());
  }
  assert.equal((await call('POST', '/api/shipments', { ...validShipment(), weight: '12000' })).status, 201);
});

test('status updates validate the status value and the shipment id', async () => {
  const created = await (await call('POST', '/api/shipments', validShipment())).json();
  const id = created.shipment.id;
  for (const status of ['Teleported', '', null, ['Sourcing'], { a: 1 }, 7]) {
    assert.equal((await call('PATCH', `/api/admin/shipments/${id}/status`, { status })).status, 400, JSON.stringify(status));
  }
  assert.equal((await call('PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing', note: 'n'.repeat(501) })).status, 400);
  assert.equal((await call('PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing', note: 5 })).status, 400);
  for (const badId of ['SHP-1e3', '0x10', '-1', '0', '1.5', 'abc', '99999999999', 'SHP-']) {
    assert.equal((await call('PATCH', `/api/admin/shipments/${encodeURIComponent(badId)}/status`, { status: 'Sourcing' })).status, 400, badId);
    assert.equal((await call('GET', `/api/shipments/${encodeURIComponent(badId)}`)).status, 400, badId);
  }
  assert.equal((await call('PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' })).status, 200);
  assert.equal((await call('PATCH', `/api/admin/shipments/${id}/status`, { status: 'Delivered' })).status, 409);
});

test('dispatch validates carrier id and rate types and bounds', async () => {
  const created = await (await call('POST', '/api/shipments', validShipment())).json();
  const id = created.shipment.id;
  await call('PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  for (const body of [
    { carrierId: '1', rate: 100 }, { carrierId: 1.5, rate: 100 }, { carrierId: -1, rate: 100 }, { carrierId: 1, rate: 'abc' },
    { carrierId: 1, rate: 0 }, { carrierId: 1, rate: -5 }, { carrierId: 1, rate: 1e9 }, { carrierId: 1, rate: true }, { carrierId: 1, rate: [10] }, { carrierId: 1 }, {}
  ]) {
    assert.equal((await call('POST', `/api/admin/shipments/${id}/dispatch`, body)).status, 400, JSON.stringify(body));
  }
  assert.equal((await call('POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: 9999, rate: 100 })).status, 404);
});

test('query parameters are bounded and unknown values fall back safely', async () => {
  const weird = await call('GET', '/api/analytics?days=9999');
  assert.equal(weird.status, 200);
  assert.equal((await weird.json()).weeklyVolume.length, 7);
  assert.equal((await (await call('GET', '/api/dashboard?days=30')).json()).weeklyVolume.length, 30);
  assert.equal((await (await call('GET', '/api/dashboard?days=abc')).json()).weeklyVolume.length, 7);
  assert.equal((await call('GET', '/api/shipments?limit=-5&page=abc')).status, 200);
  assert.equal((await call('GET', '/api/shipments?limit=999999')).status, 200);
});

test('API errors never expose internals', async () => {
  for (const [method, url, body] of [
    ['GET', '/api/does-not-exist'], ['GET', '/api/shipments/%00'], ['POST', '/api/carriers', { name: "x'); DROP TABLE carriers;--", mode: 'LTL' }],
    ['GET', '/api/shipments/1%27%20OR%201%3D1'], ['PATCH', '/api/carriers/abc/status', { status: 'Inactive' }]
  ]) {
    const res = await call(method, url, body);
    assert.ok(res.status >= 400 && res.status < 500 || res.status === 201, `${method} ${url} -> ${res.status}`);
    assertSafeBody(await res.text());
  }
  // The SQL-injection-looking carrier name is stored as plain data and the table survives.
  assert.ok((await dbAll('SELECT COUNT(*) AS total FROM carriers'))[0].total >= 3);
});

test('security headers are set on every response', async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), 'inline scripts must stay blocked');
  assert.equal((await fetch(`${base}/api/health`)).headers.get('x-powered-by'), null);
});

test('database enforces foreign keys, has indexes and passes integrity checks', async () => {
  assert.equal((await dbAll('PRAGMA foreign_keys'))[0].foreign_keys, 1);
  const health = await checkIntegrity();
  assert.deepEqual(health, { ok: true, integrity: ['ok'], foreignKeyViolations: 0 });

  const names = (await dbAll("SELECT name FROM sqlite_master WHERE type = 'index'")).map((row) => row.name);
  for (const index of ['idx_shipments_status', 'idx_shipments_carrier', 'idx_shipments_created', 'idx_shipment_events_shipment', 'idx_carriers_status']) {
    assert.ok(names.includes(index), `missing ${index}`);
  }

  await assert.rejects(dbRun("INSERT INTO shipments (customer, origin, destination, status, carrier_id) VALUES ('x','a','b','New', 987654)"), /FOREIGN KEY/);
  await assert.rejects(dbRun("INSERT INTO shipment_events (shipment_id, to_status) VALUES (987654, 'New')"), /FOREIGN KEY/);
});

test('XSS: payloads are stored as inert data and the frontend never uses HTML sinks', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  const res = await call('POST', '/api/shipments', { ...validShipment(), customer: payload, reference: '"><script>alert(2)</script>' });
  assert.equal(res.status, 201);
  const list = await call('GET', '/api/shipments');
  assert.match(list.headers.get('content-type'), /application\/json/);
  assert.equal(list.headers.get('x-content-type-options'), 'nosniff');
  assert.ok((await list.json()).some((shipment) => shipment.customer === payload));

  const publicDir = path.join(__dirname, '..', 'public');
  const sinks = /\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|\beval\s*\(|new Function\s*\(|setTimeout\s*\(\s*['"`]/;
  for (const file of fs.readdirSync(publicDir).filter((name) => /\.(js|html)$/.test(name))) {
    const source = fs.readFileSync(path.join(publicDir, file), 'utf8');
    assert.ok(!sinks.test(source), `${file} uses an unsafe HTML/code sink`);
  }
  const html = fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');
  assert.ok(!/<script(?![^>]*\ssrc=)[^>]*>/i.test(html), 'index.html must not contain inline scripts');
  assert.ok(!/\son[a-z]+\s*=/i.test(html), 'index.html must not contain inline event handlers');
});
