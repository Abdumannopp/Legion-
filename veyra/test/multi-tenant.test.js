const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-tenants-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'm.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
process.env.API_RATE_LIMIT_MAX = '5000';

const { app, initialize } = require('../server');
const { db } = require('../database');

let server;
let base;
let adminA;
let opsA;
let adminB;
let shipmentA;
let carrierA;

const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined
});

async function login(email, password) {
  const res = await call(null, 'POST', '/api/login', { email, password });
  assert.equal(res.status, 200, `login ${email}`);
  return res.headers.get('set-cookie').split(';')[0];
}

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  adminA = await login('admin@veyra.ai', 'admin123');
  opsA = await login('ops@veyra.ai', 'ops123');

  const created = await call(adminA, 'POST', '/api/shipments', {
    customer: 'Company A Customer', origin: 'Tashkent', destination: 'Samarkand',
    pickup: '2026-11-10', delivery: '2026-11-11', weight: 1000, equipment: 'Dry Van'
  });
  shipmentA = (await created.json()).shipment.id;
  carrierA = (await (await call(adminA, 'POST', '/api/carriers', { name: 'A Only Trucking', mode: 'Truckload' })).json()).carrier.id;
});

after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('only the platform owner can add customer companies', async () => {
  const body = { companyName: 'Bravo Logistics', adminName: 'Bea Admin', adminEmail: 'bea@bravo.example', adminPassword: 'BravoPass2026' };
  assert.equal((await call(opsA, 'POST', '/api/platform/tenants', body)).status, 403);
  assert.equal((await call(opsA, 'GET', '/api/platform/tenants')).status, 403);

  const res = await call(adminA, 'POST', '/api/platform/tenants', body);
  assert.equal(res.status, 201);
  const result = await res.json();
  assert.equal(result.tenant.name, 'Bravo Logistics');
  assert.equal(result.admin.role, 'admin');

  assert.equal((await call(adminA, 'POST', '/api/platform/tenants', { ...body, adminEmail: 'other@bravo.example' })).status, 409, 'duplicate company');
  assert.equal((await call(adminA, 'POST', '/api/platform/tenants', { ...body, companyName: 'Charlie' })).status, 409, 'duplicate email');
  assert.equal((await call(adminA, 'POST', '/api/platform/tenants', { ...body, companyName: '', adminEmail: 'x@y.example' })).status, 400);

  const list = (await (await call(adminA, 'GET', '/api/platform/tenants')).json()).tenants;
  assert.ok(list.some((tenant) => tenant.name === 'Bravo Logistics' && tenant.users === 1));

  adminB = await login('bea@bravo.example', 'BravoPass2026');
  const me = (await (await call(adminB, 'GET', '/api/me')).json()).user;
  assert.equal(me.tenantName, 'Bravo Logistics');
  assert.equal(me.isPlatformAdmin, false);
  assert.equal((await call(adminB, 'GET', '/api/platform/tenants')).status, 403, 'a company admin is not the platform owner');
});

test("a company never sees or changes another company's data", async () => {
  // Lists are empty for the new company.
  assert.deepEqual(await (await call(adminB, 'GET', '/api/shipments')).json(), []);
  assert.deepEqual(await (await call(adminB, 'GET', '/api/carriers')).json(), []);
  const users = (await (await call(adminB, 'GET', '/api/admin/users')).json()).users;
  assert.deepEqual(users.map((u) => u.email), ['bea@bravo.example']);
  const search = await (await call(adminB, 'GET', `/api/shipments/search?q=${encodeURIComponent('Company A')}`)).json();
  assert.equal(search.total, 0);
  const analytics = await (await call(adminB, 'GET', '/api/analytics')).json();
  assert.equal(analytics.stats.totalShipments, 0);
  assert.equal(analytics.stats.totalCarriers, 0);

  // Direct access by id behaves as if the record did not exist.
  assert.equal((await call(adminB, 'GET', `/api/shipments/${shipmentA}`)).status, 404);
  assert.deepEqual((await (await call(adminB, 'GET', `/api/shipments/${shipmentA}/events`)).json()).events, []);
  assert.equal((await call(adminB, 'GET', `/api/shipments/${shipmentA}/tracking`)).status, 404);
  assert.equal((await call(adminB, 'GET', `/api/shipments/${shipmentA}/messages`)).status, 404);
  assert.equal((await call(adminB, 'PATCH', `/api/admin/shipments/${shipmentA}/status`, { status: 'Sourcing' })).status, 404);
  assert.equal((await call(adminB, 'POST', `/api/shipments/${shipmentA}/tracking`, { location: 'x' })).status, 404);
  assert.equal((await call(adminB, 'PATCH', `/api/carriers/${carrierA}/status`, { status: 'Inactive' })).status, 404);
  assert.equal((await call(adminB, 'GET', `/api/agents/scout/${shipmentA}`)).status, 404);
  assert.equal((await call(adminB, 'PATCH', '/api/admin/users/2', { active: false })).status, 404, "cannot disable company A's user");

  // Company B's load cannot be booked with company A's carrier.
  const created = await call(adminB, 'POST', '/api/shipments', {
    customer: 'Bravo Customer', origin: 'Almaty', destination: 'Astana', pickup: '2026-11-10', delivery: '2026-11-12', weight: 500, equipment: 'Reefer'
  });
  const shipmentB = (await created.json()).shipment.id;
  await call(adminB, 'PATCH', `/api/admin/shipments/${shipmentB}/status`, { status: 'Sourcing' });
  assert.equal((await call(adminB, 'POST', `/api/admin/shipments/${shipmentB}/dispatch`, { carrierId: carrierA, rate: 100 })).status, 404);

  // Same carrier name is fine in a different company.
  assert.equal((await call(adminB, 'POST', '/api/carriers', { name: 'A Only Trucking', mode: 'Reefer' })).status, 201);

  // And company A still sees only its own.
  const listA = await (await call(adminA, 'GET', '/api/shipments')).json();
  assert.ok(listA.every((shipment) => shipment.customer !== 'Bravo Customer'));
  assert.equal((await call(adminA, 'GET', `/api/shipments/${shipmentB}`)).status, 404);
});

test('a company admin adds users only to their own company', async () => {
  const res = await call(adminB, 'POST', '/api/admin/users', { name: 'Bravo Ops', email: 'ops@bravo.example', password: 'BravoOps2026', role: 'operations' });
  assert.equal(res.status, 201);
  const usersA = (await (await call(adminA, 'GET', '/api/admin/users')).json()).users;
  assert.ok(!usersA.some((user) => user.email === 'ops@bravo.example'));
  const opsB = await login('ops@bravo.example', 'BravoOps2026');
  assert.equal((await (await call(opsB, 'GET', '/api/me')).json()).user.tenantName, 'Bravo Logistics');
});
