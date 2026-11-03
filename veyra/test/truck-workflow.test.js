const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-truck-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 't.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
process.env.WEIGHT_UNIT = 'kg';
process.env.CURRENCY = 'UZS';
process.env.MAX_RATE = '100000000';
process.env.API_RATE_LIMIT_MAX = '5000';

const { app, initialize } = require('../server');
const { db } = require('../database');

let server;
let base;
let admin;
let operator;

async function login(email, password) {
  const res = await fetch(`${base}/api/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password })
  });
  assert.equal(res.status, 200);
  return res.headers.get('set-cookie').split(';')[0];
}

const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined
});

async function newCarrier(name) {
  const res = await call(admin, 'POST', '/api/carriers', { name, mode: 'Truckload', phone: '+998 90 123 45 67', contactName: 'Akmal' });
  assert.equal(res.status, 201);
  return (await res.json()).carrier;
}

async function sourcingLoad(extra = {}) {
  const res = await call(admin, 'POST', '/api/shipments', {
    customer: 'Navoiy Textile', origin: 'Tashkent, UZ', destination: 'Almaty, KZ',
    pickup: '2026-11-10', delivery: '2026-11-12', weight: 18000, equipment: 'Tent / Curtainsider', ...extra
  });
  assert.equal(res.status, 201);
  const { shipment } = await res.json();
  assert.equal((await call(admin, 'PATCH', `/api/admin/shipments/${shipment.id}/status`, { status: 'Sourcing' })).status, 200);
  return shipment;
}

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  operator = await login('demo@veyra.ai', 'demo123');
});

after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('config exposes the region settings the UI needs, without signing in', async () => {
  const res = await call(null, 'GET', '/api/config');
  assert.equal(res.status, 200);
  const config = await res.json();
  assert.equal(config.weightUnit, 'kg');
  assert.equal(config.currency, 'UZS');
  assert.ok(config.equipment.includes('Tent / Curtainsider'));
  assert.equal(config.registration, 'open');
});

test('weight is stored in the configured unit and the customer price is kept', async () => {
  const shipment = await sourcingLoad({ customerRate: 15000000 });
  const detail = await (await call(admin, 'GET', `/api/shipments/${shipment.id}`)).json();
  assert.equal(detail.weight, '18000 kg');
  assert.equal(detail.customerRate, 15000000);
  assert.equal(detail.margin, null, 'no margin until the carrier rate is known');
  assert.equal((await call(admin, 'POST', '/api/shipments', { ...shipment, id: undefined, pickup: '2026-11-10', delivery: '2026-11-12', weight: 1, customerRate: -5 })).status, 400);
});

test('dispatch books the truck with driver details and shows the margin', async () => {
  const carrier = await newCarrier('Silk Road Trucking');
  const shipment = await sourcingLoad();
  const res = await call(admin, 'POST', `/api/admin/shipments/${shipment.id}/dispatch`, {
    carrierId: carrier.id, rate: 12500000, customerRate: 15000000,
    driverName: 'Bobur Karimov', driverPhone: '+998 91 555 22 11', truckPlate: '01 A 123 BC'
  });
  assert.equal(res.status, 200);
  const detail = await (await call(admin, 'GET', `/api/shipments/${shipment.id}`)).json();
  assert.equal(detail.status, 'Dispatched');
  assert.equal(detail.carrierName, 'Silk Road Trucking');
  assert.equal(detail.carrierPhone, '+998 90 123 45 67');
  assert.equal(detail.driverName, 'Bobur Karimov');
  assert.equal(detail.truckPlate, '01 A 123 BC');
  assert.equal(detail.rate, 12500000);
  assert.equal(detail.margin, 2500000);

  const events = (await (await call(admin, 'GET', `/api/shipments/${shipment.id}/events`)).json()).events;
  assert.match(events[0].note, /truck 01 A 123 BC, driver Bobur Karimov/);
});

test('dispatch rejects malformed driver and price details', async () => {
  const carrier = await newCarrier('Ferghana Haulage');
  const shipment = await sourcingLoad();
  for (const body of [
    { driverPhone: 'call me maybe' },
    { truckPlate: 'X'.repeat(21) },
    { driverName: { a: 1 } },
    { customerRate: 'abc' },
    { customerRate: 0 }
  ]) {
    const res = await call(admin, 'POST', `/api/admin/shipments/${shipment.id}/dispatch`, { carrierId: carrier.id, rate: 100, ...body });
    assert.equal(res.status, 400, JSON.stringify(body));
  }
});

test('location updates: only for booked loads, by dispatchers, and they update the load', async () => {
  const carrier = await newCarrier('Samarkand Express');
  const shipment = await sourcingLoad();
  const url = `/api/shipments/${shipment.id}/tracking`;

  assert.equal((await call(operator, 'POST', url, { location: 'Chimkent, KZ' })).status, 409, 'not booked yet');

  await call(admin, 'POST', `/api/admin/shipments/${shipment.id}/dispatch`, { carrierId: carrier.id, rate: 9000000 });
  assert.equal((await call(operator, 'POST', url, {})).status, 400, 'location required');
  assert.equal((await call(operator, 'POST', url, { location: 'Chimkent', eta: '2026-13-01' })).status, 400, 'bad ETA');
  assert.equal((await call(operator, 'POST', url, { location: 'Chimkent', eta: 'tomorrow' })).status, 400, 'bad ETA');
  assert.equal((await call(operator, 'POST', url, { location: 'x'.repeat(161) })).status, 400, 'too long');

  const first = await call(operator, 'POST', url, { location: 'Gisht Kuprik border', eta: '2026-11-12', note: 'Waiting at customs' });
  assert.equal(first.status, 201);
  const second = await call(operator, 'POST', url, { location: 'Chimkent, KZ', eta: '2026-11-12T18:30' });
  assert.equal(second.status, 201);

  const detail = await (await call(admin, 'GET', `/api/shipments/${shipment.id}`)).json();
  assert.equal(detail.lastLocation, 'Chimkent, KZ');
  assert.equal(detail.eta, '2026-11-12T18:30');
  assert.ok(detail.lastTrackedAt);

  const list = await (await call(operator, 'GET', url)).json();
  assert.equal(list.updates.length, 2);
  assert.equal(list.updates[0].location, 'Chimkent, KZ');
  assert.equal(list.updates[1].note, 'Waiting at customs');
  assert.equal(list.updates[1].actorName, 'Demo Operator');

  assert.equal((await call(null, 'GET', url)).status, 401);
  assert.equal((await call(admin, 'GET', '/api/shipments/SHP-99999/tracking')).status, 404);
});

test('a booked truck can be cancelled before pickup and the carrier is released', async () => {
  const carrier = await newCarrier('Bukhara Logistics');
  const shipment = await sourcingLoad();
  await call(admin, 'POST', `/api/admin/shipments/${shipment.id}/dispatch`, { carrierId: carrier.id, rate: 5000000 });
  const busy = (await (await call(admin, 'GET', '/api/carriers')).json()).find((c) => c.id === carrier.id);
  assert.equal(busy.status, 'Busy');

  assert.equal((await call(admin, 'PATCH', `/api/admin/shipments/${shipment.id}/status`, { status: 'Cancelled' })).status, 200);
  const released = (await (await call(admin, 'GET', '/api/carriers')).json()).find((c) => c.id === carrier.id);
  assert.equal(released.status, 'Available');
  assert.equal(released.revenue, 0, 'cancelled loads are not booked revenue');
  assert.equal(released.phone, '+998 90 123 45 67');
  assert.equal(released.contactName, 'Akmal');
});

test('carrier phone is validated and the new carrier id is returned', async () => {
  assert.equal((await call(admin, 'POST', '/api/carriers', { name: 'Bad Phone LLC', mode: 'LTL', phone: 'not a phone' })).status, 400);
  const created = await newCarrier('Termez Transit');
  assert.ok(Number.isInteger(created.id) && created.id > 0);
  assert.equal((await call(admin, 'POST', '/api/carriers', { name: 'termez transit', mode: 'LTL' })).status, 409);
});

test('analytics reports margin and ignores cancelled money', async () => {
  const data = await (await call(admin, 'GET', '/api/analytics?days=7')).json();
  assert.equal(data.stats.grossMargin, 2500000);
  assert.equal(data.stats.marginLoads, 1);
  assert.ok(Math.abs(data.stats.marginRate - (2500000 / 15000000)) < 1e-9);
  // 12.5M + 9M booked; the 5M cancelled load is excluded.
  assert.equal(data.stats.bookedRevenue, 21500000);
});
