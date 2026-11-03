const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-carriers-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'c.db');
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

test('carrier list includes load statistics', async () => {
  const ops = await login('ops@veyra.ai', 'ops123');
  const res = await call(ops, 'GET', '/api/carriers');
  assert.equal(res.status, 200);
  const carriers = await res.json();
  assert.ok(Array.isArray(carriers) && carriers.length >= 3);
  for (const key of ['totalLoads', 'activeLoads', 'deliveredLoads', 'revenue', 'currentShipment']) {
    assert.ok(key in carriers[0], `missing ${key}`);
  }
});

test('operations can add a carrier; duplicates and bad input are rejected', async () => {
  const ops = await login('ops@veyra.ai', 'ops123');
  const created = await call(ops, 'POST', '/api/carriers', { name: 'Desert Line', mode: 'Reefer' });
  assert.equal(created.status, 201);
  const body = await created.json();
  assert.equal(body.carrier.status, 'Available');
  assert.equal((await call(ops, 'POST', '/api/carriers', { name: 'desert line', mode: 'LTL' })).status, 409);
  assert.equal((await call(ops, 'POST', '/api/carriers', { name: '', mode: 'LTL' })).status, 400);
  assert.equal((await call(ops, 'POST', '/api/carriers', { name: 'X', mode: 'Rocket' })).status, 400);
});

test('operators cannot manage carriers', async () => {
  const operator = await login('demo@veyra.ai', 'demo123');
  assert.equal((await call(operator, 'POST', '/api/carriers', { name: 'Nope Co', mode: 'LTL' })).status, 403);
  assert.equal((await call(operator, 'PATCH', '/api/carriers/1/status', { status: 'Inactive' })).status, 403);
  assert.equal((await call(operator, 'GET', '/api/analytics')).status, 403);
});

test('availability toggles, inactive carriers cannot be dispatched, busy carriers are locked', async () => {
  const admin = await login('admin@veyra.ai', 'admin123');
  const carriers = await (await call(admin, 'GET', '/api/carriers')).json();
  const carrier = carriers.find((c) => c.status === 'Available');

  assert.equal((await call(admin, 'PATCH', `/api/carriers/${carrier.id}/status`, { status: 'Busy' })).status, 400);
  assert.equal((await call(admin, 'PATCH', `/api/carriers/${carrier.id}/status`, { status: 'Inactive' })).status, 200);

  const created = await (await call(admin, 'POST', '/api/shipments', {
    customer: 'Lane Test', origin: 'Austin, TX', destination: 'Denver, CO', pickup: '2026-11-03', delivery: '2026-11-05', weight: 5000, equipment: 'Reefer'
  })).json();
  const id = created.shipment.id;
  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  assert.equal((await call(admin, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate: 900 })).status, 409);

  assert.equal((await call(admin, 'PATCH', `/api/carriers/${carrier.id}/status`, { status: 'Available' })).status, 200);
  assert.equal((await call(admin, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate: 900 })).status, 200);
  assert.equal((await call(admin, 'PATCH', `/api/carriers/${carrier.id}/status`, { status: 'Inactive' })).status, 409);

  const after = (await (await call(admin, 'GET', '/api/carriers')).json()).find((c) => c.id === carrier.id);
  assert.equal(after.status, 'Busy');
  assert.equal(after.activeLoads, 1);
  assert.equal(after.currentShipment, id);
  assert.equal(after.revenue, 900);
});

test('analytics report supports ranges and breakdowns', async () => {
  const admin = await login('admin@veyra.ai', 'admin123');
  const week = await (await call(admin, 'GET', '/api/analytics')).json();
  assert.equal(week.weeklyVolume.length, 7);
  const month = await (await call(admin, 'GET', '/api/analytics?days=30')).json();
  assert.equal(month.rangeDays, 30);
  assert.equal(month.weeklyVolume.length, 30);
  const fallback = await (await call(admin, 'GET', '/api/analytics?days=9999')).json();
  assert.equal(fallback.weeklyVolume.length, 7);
  for (const key of ['equipment', 'topLanes', 'topCustomers', 'carrierPerformance']) {
    assert.ok(Array.isArray(month[key]), `missing ${key}`);
  }
  assert.ok(month.stats.bookedRevenue >= 900);
  assert.equal(month.equipment.reduce((sum, row) => sum + row.total, 0), month.stats.totalShipments);
});
