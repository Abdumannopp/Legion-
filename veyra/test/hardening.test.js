const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-hardening-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'h.db');
process.env.PORT = '0';

const { app, initialize } = require('../server');
const { db } = require('../database');

let server;
let base;

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

async function login(email, password) {
  const res = await fetch(`${base}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password })
  });
  assert.equal(res.status, 200);
  return res.headers.get('set-cookie').split(';')[0];
}
const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', cookie }, body: body ? JSON.stringify(body) : undefined
});

test('database, source and config files are not served', async () => {
  for (const p of ['/data/veyra.db', '/server.js', '/database.js', '/package.json', '/deploy/Caddyfile', '/node_modules/express/package.json', '/test/hardening.test.js']) {
    const res = await fetch(`${base}${p}`);
    const type = res.headers.get('content-type') || '';
    assert.ok(res.status === 404 || type.includes('text/html'), `${p} leaked (${res.status} ${type})`);
    assert.ok(!type.includes('javascript') && !type.includes('octet-stream') && !type.includes('json'), `${p} leaked`);
  }
  assert.equal((await fetch(`${base}/script.js`)).status, 200);
});

test('unknown API routes return JSON 404', async () => {
  const res = await fetch(`${base}/api/nope`);
  assert.equal(res.status, 404);
  assert.equal((await res.json()).success, false);
});

test('Sourcing cannot jump to Dispatched without carrier and rate', async () => {
  const admin = await login('admin@veyra.ai', 'admin123');
  const created = await (await call(admin, 'POST', '/api/shipments', {
    customer: 'T', origin: 'A', destination: 'B', pickup: '2026-11-05', delivery: '2026-11-06', weight: 100, equipment: 'Dry Van'
  })).json();
  const id = created.shipment.id;
  assert.equal((await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' })).status, 200);
  assert.equal((await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Dispatched' })).status, 409);
  assert.equal((await call(admin, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: 1, rate: 900 })).status, 200);
});

test('operator cannot change status or dispatch', async () => {
  const op = await login('demo@veyra.ai', 'demo123');
  assert.equal((await call(op, 'PATCH', '/api/admin/shipments/SHP-1/status', { status: 'Sourcing' })).status, 403);
  assert.equal((await call(op, 'POST', '/api/admin/shipments/SHP-1/dispatch', { carrierId: 1, rate: 1 })).status, 403);
});

test('shipment input length is enforced and old shipments stay reachable', async () => {
  const admin = await login('admin@veyra.ai', 'admin123');
  const tooLong = await call(admin, 'POST', '/api/shipments', {
    customer: 'A'.repeat(5000), origin: 'A', destination: 'B', pickup: '2026-11-05', delivery: '2026-11-06', weight: 1, equipment: 'Dry Van'
  });
  assert.equal(tooLong.status, 400);
  for (let i = 0; i < 25; i += 1) {
    await call(admin, 'POST', '/api/shipments', { customer: `C${i}`, origin: 'A', destination: 'B', pickup: '2026-11-05', delivery: '2026-11-06', weight: 1, equipment: 'Dry Van' });
  }
  const list = await (await call(admin, 'GET', '/api/shipments')).json();
  assert.ok(list.length > 20);
  const first = await call(admin, 'GET', '/api/shipments/SHP-1');
  assert.equal(first.status, 200);
  assert.equal((await call(admin, 'GET', '/api/shipments/SHP-99999')).status, 404);
});

test('registration does not reveal whether an email exists', async () => {
  const res = await fetch(`${base}/api/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ name: 'X', email: 'admin@veyra.ai', password: 'longenough1' })
  });
  assert.equal(res.status, 409);
  assert.ok(!/already exists/i.test((await res.json()).message));
});
