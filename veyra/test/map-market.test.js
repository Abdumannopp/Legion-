// Document type change, market prices, map (road distance, off-route) with a fake map service.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-map-'));
Object.assign(process.env, {
  NODE_ENV: 'development', DATABASE_PATH: path.join(dir, 'm.db'), PORT: '0', BCRYPT_COST: '10', API_RATE_LIMIT_MAX: '5000',
  CURRENCY: 'USD', MESSAGE_LANGUAGE: 'en', GEO_PROVIDER: 'osm', OFF_ROUTE_KM: '50', OPENROUTER_API_KEY: 'sk-or-test'
});
const { app, initialize } = require('../server');
const { db } = require('../database');
const aiGateway = require('../ai/gateway');
const geo = require('../integrations/geo');
const nexus = require('../agents/nexus');

let server; let base; let admin; let operator; let other;
let mapCalls = [];
const call = (cookie, method, url, body) => fetch(`${base}${url}`, { method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
const json = async (...args) => (await call(...args)).json();
const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, (e) => (e ? reject(e) : resolve())));
async function login(email, password) {
  const res = await call(null, 'POST', '/api/login', { email, password });
  return res.headers.get('set-cookie').split(';')[0];
}
const places = { 'tashkent, uz': { lat: '41.3', lon: '69.24' }, 'almaty, kz': { lat: '43.24', lon: '76.89' } };
const pdf = () => Buffer.from(`%PDF-1.4\n${Math.random()}\n${' '.repeat(300)}\n%%EOF`);

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  operator = await login('demo@veyra.ai', 'demo123');
  other = await login((await (async () => {
    await call(admin, 'POST', '/api/platform/tenants', { companyName: 'Map Other', adminName: 'Omar', adminEmail: 'omar@map.example', adminPassword: 'map-other-pass-12' });
    return { email: 'omar@map.example' };
  })()).email, 'map-other-pass-12');
  geo.setTransport(async (url) => {
    mapCalls.push(url);
    if (url.includes('/search')) {
      const q = decodeURIComponent(/q=([^&]+)/.exec(url)[1]).toLowerCase();
      return new Response(JSON.stringify(places[q] ? [places[q]] : []), { status: 200 });
    }
    // A straight road from Tashkent (41.3, 69.24) to Almaty (43.24, 76.89).
    const coordinates = Array.from({ length: 11 }, (_, i) => [69.24 + (7.65 * i) / 10, 41.3 + (1.94 * i) / 10]);
    return new Response(JSON.stringify({ routes: [{ distance: 810000, duration: 36000, geometry: { coordinates } }] }), { status: 200 });
  });
  aiGateway.setTransport(async () => new Response(JSON.stringify({ choices: [{ message: { content: '{}' } }] }), { status: 200 }));
});
after(async () => {
  await nexus.idle();
  geo.setTransport(null); aiGateway.setTransport(null);
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

const newLoad = async (extra = {}, cookie = admin) => (await json(cookie, 'POST', '/api/shipments', {
  customer: 'C', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 100, equipment: 'Reefer', ...extra
})).shipment.id;

test('geometry helpers: distance to a road and thinning', () => {
  const line = [[0, 0], [0, 1]]; // along the equator, 1 degree = ~111 km
  assert.ok(Math.abs(geo.distanceToLineKm({ lat: 0.5, lng: 0.5 }, line) - 55.6) < 1);
  assert.ok(geo.distanceToLineKm({ lat: 0, lng: 0.5 }, line) < 0.01);
  assert.ok(Math.abs(geo.distanceToLineKm({ lat: 0, lng: 2 }, line) - 111.3) < 1, 'beyond the end it measures to the end point');
  assert.equal(geo.thin(Array.from({ length: 1000 }, (_, i) => i), 100).length, 100);
});

test('document type: a person corrects it, it is read again, other companies cannot', async () => {
  const id = await newLoad();
  const res = await fetch(`${base}/api/shipments/${id}/documents?type=other&filename=scan.pdf`, { method: 'POST', headers: { 'content-type': 'application/pdf', cookie: admin }, body: pdf() });
  assert.equal(res.status, 201);
  const doc = (await res.json()).document;
  await nexus.idle();
  assert.equal(doc.type, 'other');
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}/documents/${doc.id}`, { type: 'invoice' })).status, 400);
  assert.equal((await call(other, 'PATCH', `/api/shipments/${id}/documents/${doc.id}`, { type: 'cmr' })).status, 404);
  const changed = await json(admin, 'PATCH', `/api/shipments/${id}/documents/${doc.id}`, { type: 'cmr' });
  assert.equal(changed.document.type, 'cmr');
  await nexus.idle();
  const docs = (await json(admin, 'GET', `/api/shipments/${id}/documents`)).documents;
  assert.equal(docs[0].type, 'cmr');
  assert.notEqual(docs[0].extractionStatus, 'skipped', 'a CMR is now read');
});

test('market prices: lines are checked one by one, PULSE compares with them, other companies do not see them', async () => {
  assert.equal((await call(operator, 'POST', '/api/market-rates', { lines: 'A; B; 1' })).status, 403, 'a plain operator cannot change prices');
  const saved = await json(admin, 'POST', '/api/market-rates', { lines: 'Tashkent, UZ; Almaty, KZ; Reefer; 1 000\nTashkent, UZ; Almaty, KZ; 900\nbad line\nX; Y; Spaceship; 5\nX; Y; -3' });
  assert.equal(saved.created, 2);
  assert.deepEqual(saved.errors.map((e) => e.line), [3, 4, 5]);
  const again = await json(admin, 'POST', '/api/market-rates', { lines: 'tashkent, uz; ALMATY, KZ; Reefer; 1100' });
  assert.deepEqual([again.created, again.updated], [0, 1], 'the same lane is replaced, not doubled');
  const id = await newLoad();
  const pulse = await json(admin, 'GET', `/api/agents/pulse/${id}?rate=2000`);
  assert.equal(pulse.market.rate, 1100, 'the trailer-specific price wins over the any-trailer price');
  assert.ok(pulse.flags.some((f) => f.code === 'above_market'));
  assert.equal(pulse.enoughHistory, true);
  const calm = await json(admin, 'GET', `/api/agents/pulse/${id}?rate=1200`);
  assert.equal(calm.flags.length, 0);
  assert.deepEqual((await json(other, 'GET', '/api/market-rates')).rates, []);
  assert.equal((await json(admin, 'GET', '/api/market-rates')).rates.length, 2);
  const [first] = (await json(admin, 'GET', '/api/market-rates')).rates;
  assert.equal((await call(other, 'DELETE', `/api/market-rates/${first.id}`)).status, 404);
  assert.equal((await call(admin, 'DELETE', `/api/market-rates/${first.id}`)).status, 200);
});

test('ROUTE with a map: road distance, an estimate without history, cached afterwards', async () => {
  mapCalls = [];
  const id = await newLoad({ pickup: '2030-05-10', delivery: '2030-05-10' });
  const plan = await json(admin, 'GET', `/api/agents/route/${id}`);
  assert.equal(plan.map.distanceKm, 810);
  assert.equal(plan.map.drivingHours, 10);
  assert.equal(plan.map.withRestsHours, 13.5);
  assert.equal(plan.schedule.verdict, 'ok');
  assert.match(plan.schedule.text, /by road it takes about 14 h/);
  assert.match(plan.arrival.basis, /estimated from the map/);
  const requests = mapCalls.length;
  assert.equal(requests, 3, 'two places and one road');
  await json(admin, 'GET', `/api/agents/route/${id}`);
  assert.equal(mapCalls.length, requests, 'the second time everything comes from the cache');
  const unknown = await newLoad({ origin: 'Nowhereville', destination: 'Almaty, KZ' });
  const none = await json(admin, 'GET', `/api/agents/route/${unknown}`);
  assert.equal(none.map, null);
  assert.equal(none.schedule.verdict, 'unknown', 'a place the map does not know leaves the history-based advice alone');
});

test('SENTINEL off-route: a truck far from the road is flagged, one on the road is not, stale GPS is ignored', async () => {
  const carrier = (await json(admin, 'POST', '/api/carriers', { name: 'Map Carrier', mode: 'Truckload', phone: '+998 71 200 00 11' })).carrier;
  const trucks = {};
  for (const plate of ['01 ON 111 AA', '01 OFF 222 BB', '01 OLD 333 CC']) {
    const id = await newLoad({ pickup: '2030-05-10', delivery: '2030-05-20' });
    const c = plate === '01 ON 111 AA' ? carrier : (await json(admin, 'POST', '/api/carriers', { name: `Map Carrier ${plate}`, mode: 'Truckload', phone: '+998 71 200 00 22' })).carrier;
    await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
    await call(admin, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: c.id, rate: 1000, driverPhone: '+998 91 555 22 11', truckPlate: plate });
    await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'In Transit' });
    trucks[plate] = id;
  }
  const token = (await json(admin, 'POST', '/api/integrations/gps/token')).token;
  const gps = (truckPlate, lat, lng) => fetch(`${base}/api/integrations/gps`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify({ positions: [{ truckPlate, lat, lng }] }) });
  await gps('01 ON 111 AA', 42.3, 73.0);   // on the road
  await gps('01 OFF 222 BB', 45.5, 69.5);  // about 250 km north of the road
  await gps('01 OLD 333 CC', 45.5, 69.5);
  await dbRun("UPDATE tracking_updates SET created_at = datetime('now', '-10 hours') WHERE shipment_id = ?", [Number(trucks['01 OLD 333 CC'].slice(4))]);
  const offRisks = async () => (await json(admin, 'GET', '/api/agents/sentinel')).risks.filter((r) => r.type === 'off_route').map((r) => r.shipmentId);
  assert.deepEqual(await offRisks(), [trucks['01 OFF 222 BB']]);
  await nexus.sentinelSweep();
  const task = (await json(admin, 'GET', '/api/tasks')).tasks.find((t) => /away from the road/.test(t.title));
  assert.equal(task.shipmentId, trucks['01 OFF 222 BB']);
  // The truck comes back to the road: the warning closes by itself.
  await dbRun("UPDATE tracking_updates SET created_at = datetime('now', '-1 hours') WHERE shipment_id = ?", [Number(trucks['01 OFF 222 BB'].slice(4))]);
  await gps('01 OFF 222 BB', 42.4, 73.2);
  await nexus.sentinelSweep();
  assert.equal((await json(admin, 'GET', '/api/tasks')).tasks.some((t) => /away from the road/.test(t.title)), false);
});

test('without GEO_PROVIDER the map is off: no network, no off-route risk', async () => {
  const before = process.env.GEO_PROVIDER;
  process.env.GEO_PROVIDER = '';
  try {
    mapCalls = [];
    assert.equal(await geo.route('A', 'B'), null);
    assert.equal((await json(admin, 'GET', '/api/integrations/status')).map.enabled, false);
    assert.equal(mapCalls.length, 0);
  } finally {
    process.env.GEO_PROVIDER = before;
  }
});
