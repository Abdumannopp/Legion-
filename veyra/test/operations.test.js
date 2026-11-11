// Passwords, load corrections, payments and invoice, customer tracking link, backups, activity log.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-ops-'));
Object.assign(process.env, {
  NODE_ENV: 'development', DATABASE_PATH: path.join(dir, 'o.db'), PORT: '0', BCRYPT_COST: '10', API_RATE_LIMIT_MAX: '5000',
  CURRENCY: 'USD', MESSAGE_LANGUAGE: 'en', BACKUP_KEEP: '2', NEXUS_ENABLED: 'false'
});
const { app, initialize } = require('../server');
const { db } = require('../database');

let server; let base; let admin; let ops; let operator; let other;
const call = (cookie, method, url, body) => fetch(`${base}${url}`, { method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
const json = async (...args) => (await call(...args)).json();
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => (e ? reject(e) : resolve(row))));
async function loginRes(email, password) { return call(null, 'POST', '/api/login', { email, password }); }
async function login(email, password) {
  const res = await loginRes(email, password);
  assert.equal(res.status, 200, `login ${email}`);
  return res.headers.get('set-cookie').split(';')[0];
}
const num = (id) => Number(String(id).slice(4));
const newLoad = async (extra = {}, cookie = admin) => (await json(cookie, 'POST', '/api/shipments', {
  customer: 'Navoiy Textile', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 18000,
  equipment: 'Reefer', customerRate: 2400, customerPhone: '+998 90 777 66 55', ...extra
})).shipment.id;
let carriers = 0;
async function deliver(id, cookie = admin) {
  carriers += 1;
  const carrier = (await json(cookie, 'POST', '/api/carriers', { name: `Ops Carrier ${carriers}`, mode: 'Truckload', phone: '+998 71 200 00 44' })).carrier;
  await call(cookie, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  await call(cookie, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate: 2000, driverPhone: '+998 91 555 22 11', truckPlate: '01 A 123 BC' });
  await call(cookie, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'In Transit' });
  await call(cookie, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Delivered' });
}

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  ops = await login('ops@veyra.ai', 'ops123');
  operator = await login('demo@veyra.ai', 'demo123');
  await call(admin, 'POST', '/api/platform/tenants', { companyName: 'Ops Other', adminName: 'Olga', adminEmail: 'olga@ops.example', adminPassword: 'ops-other-pass-123' });
  other = await login('olga@ops.example', 'ops-other-pass-123');
});
after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ---------- passwords ---------- */

test('own password: needs the current one, signs out other devices, keeps this one', async () => {
  const created = await call(admin, 'POST', '/api/admin/users', { name: 'Pass Tester', email: 'pass@veyra.ai', password: 'first-pass-1', role: 'operator' });
  assert.equal(created.status, 201);
  const deviceA = await login('pass@veyra.ai', 'first-pass-1');
  const deviceB = await login('pass@veyra.ai', 'first-pass-1');
  assert.equal((await call(null, 'POST', '/api/me/password', { currentPassword: 'first-pass-1', newPassword: 'second-pass-2' })).status, 401);
  assert.equal((await call(deviceA, 'POST', '/api/me/password', { currentPassword: 'wrong', newPassword: 'second-pass-2' })).status, 403);
  assert.equal((await call(deviceA, 'POST', '/api/me/password', { currentPassword: 'first-pass-1', newPassword: 'short' })).status, 400);
  assert.equal((await call(deviceA, 'POST', '/api/me/password', { currentPassword: 'first-pass-1', newPassword: 'first-pass-1' })).status, 400);
  const changed = await call(deviceA, 'POST', '/api/me/password', { currentPassword: 'first-pass-1', newPassword: 'second-pass-2' });
  assert.equal(changed.status, 200);
  const fresh = changed.headers.get('set-cookie').split(';')[0];
  assert.equal((await call(fresh, 'GET', '/api/me')).status, 200, 'this device stays signed in');
  assert.equal((await call(deviceA, 'GET', '/api/me')).status, 401, 'the old session of this device is gone');
  assert.equal((await call(deviceB, 'GET', '/api/me')).status, 401, 'the other device is signed out');
  assert.equal((await loginRes('pass@veyra.ai', 'first-pass-1')).status, 401);
  assert.equal((await loginRes('pass@veyra.ai', 'second-pass-2')).status, 200);
});

test('admin reset: only an admin, only in their own company, the person is signed out', async () => {
  const users = (await json(admin, 'GET', '/api/admin/users')).users;
  const target = users.find((u) => u.email === 'pass@veyra.ai');
  const me = users.find((u) => u.email === 'admin@veyra.ai');
  const session = await login('pass@veyra.ai', 'second-pass-2');
  assert.equal((await call(ops, 'POST', `/api/admin/users/${target.id}/password`, { newPassword: 'third-pass-3' })).status, 403);
  assert.equal((await call(other, 'POST', `/api/admin/users/${target.id}/password`, { newPassword: 'third-pass-3' })).status, 404, 'another company cannot reset it');
  assert.equal((await call(admin, 'POST', `/api/admin/users/${me.id}/password`, { newPassword: 'third-pass-3' })).status, 400);
  assert.equal((await call(admin, 'POST', `/api/admin/users/${target.id}/password`, { newPassword: 'weak' })).status, 400);
  assert.equal((await call(admin, 'POST', `/api/admin/users/${target.id}/password`, { newPassword: 'third-pass-3' })).status, 200);
  assert.equal((await call(session, 'GET', '/api/me')).status, 401);
  assert.equal((await loginRes('pass@veyra.ai', 'third-pass-3')).status, 200);
  const log = (await json(admin, 'GET', '/api/audit')).entries;
  assert.ok(log.some((e) => e.action === 'password.reset' && e.detail === 'pass@veyra.ai' && e.actor));
  assert.ok(!JSON.stringify(log).includes('third-pass-3'), 'no password in the log');
  assert.equal((await call(ops, 'GET', '/api/audit')).status, 403);
  assert.ok(!(await json(other, 'GET', '/api/audit')).entries.some((e) => /pass@veyra\.ai/.test(e.detail || '')), 'each company sees only its own log');
});

/* ---------- editing a load ---------- */

test('a load can be corrected: validated, written to its history, not after delivery, not by another company', async () => {
  const id = await newLoad();
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, {})).status, 400);
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, { pickup: '10.05.2030' })).status, 400);
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, { delivery: '2030-05-01' })).status, 400, 'delivery before pickup');
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, { equipment: 'Spaceship' })).status, 400);
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, { weight: -5 })).status, 400);
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, { status: 'Delivered' })).status, 400, 'status is not an editable field');
  assert.equal((await call(other, 'PATCH', `/api/shipments/${id}`, { customer: 'Hacked' })).status, 404);
  const res = await json(admin, 'PATCH', `/api/shipments/${id}`, { delivery: '2030-05-14', weight: 19500, customerRate: 2600, customer: 'Navoiy Textile' });
  assert.equal(res.changed.length, 3, 'the unchanged customer is not counted');
  assert.deepEqual([res.shipment.delivery, res.shipment.weight, res.shipment.customerRate], ['2030-05-14', '19500 kg', 2600]);
  const events = (await json(admin, 'GET', `/api/shipments/${id}/events`)).events;
  assert.equal(events[0].status, 'Updated');
  assert.match(events[0].note, /Delivery: 2030-05-12 → 2030-05-14/);
  assert.equal((await json(admin, 'GET', `/api/shipments/${id}`)).status, 'New', 'the status is untouched');
  assert.equal((await json(admin, 'PATCH', `/api/shipments/${id}`, { customerRate: null })).shipment.customerRate, null, 'a price can be cleared');
  await deliver(id);
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}`, { weight: 1 })).status, 409);
});

/* ---------- payments ---------- */

test('payments: invoice, paid flags, open money, and who may see it', async () => {
  const id = await newLoad({ customerRate: 2400 });
  assert.equal((await call(admin, 'PATCH', `/api/shipments/${id}/payment`, { carrierPaid: true })).status, 409, 'no carrier yet');
  await deliver(id);
  assert.equal((await call(operator, 'PATCH', `/api/shipments/${id}/payment`, { customerPaid: true })).status, 403);
  assert.equal((await call(operator, 'GET', '/api/finance/summary')).status, 403);
  assert.equal((await call(other, 'PATCH', `/api/shipments/${id}/payment`, { customerPaid: true })).status, 404);
  assert.equal((await call(ops, 'PATCH', `/api/shipments/${id}/payment`, { customerPaid: 'yes' })).status, 400);
  assert.equal((await call(ops, 'PATCH', `/api/shipments/${id}/payment`, {})).status, 400);

  const before = await json(ops, 'GET', '/api/finance/summary');
  const mine = before.open.find((row) => row.id === id);
  assert.deepEqual([mine.customerRate, mine.rate, mine.invoicedAt], [2400, 2000, null]);
  const invoiced = await json(ops, 'PATCH', `/api/shipments/${id}/payment`, { invoiceNumber: 'INV-2030-001', invoiced: true });
  assert.equal(invoiced.shipment.invoiceNumber, 'INV-2030-001');
  assert.ok(invoiced.shipment.invoicedAt);
  const paid = await json(ops, 'PATCH', `/api/shipments/${id}/payment`, { customerPaid: true });
  assert.ok(paid.shipment.customerPaidAt);
  assert.equal((await json(ops, 'PATCH', `/api/shipments/${id}/payment`, { customerPaid: true })).changed.length, 0, 'saying it twice changes nothing');
  const mid = await json(ops, 'GET', '/api/finance/summary');
  assert.equal(mid.receivable, before.receivable - 2400);
  assert.equal(mid.payable, before.payable, 'the carrier is still owed');
  await json(ops, 'PATCH', `/api/shipments/${id}/payment`, { carrierPaid: true });
  const end = await json(ops, 'GET', '/api/finance/summary');
  assert.equal(end.payable, before.payable - 2000);
  assert.ok(!end.open.some((row) => row.id === id), 'fully settled loads leave the list');
  await json(ops, 'PATCH', `/api/shipments/${id}/payment`, { customerPaid: false });
  assert.equal((await json(ops, 'GET', '/api/finance/summary')).receivable, before.receivable, 'a mistake can be undone');
  assert.deepEqual((await json(other, 'GET', '/api/finance/summary')).open, []);
  const events = (await json(admin, 'GET', `/api/shipments/${id}/events`)).events;
  assert.ok(events.some((e) => e.status === 'Payment' && /Customer paid/.test(e.note)));
  // Payment notes must not disturb delivery timing used by ROUTE.
  const delivered = await dbGet("SELECT COUNT(*) AS n FROM shipment_events WHERE shipment_id = ? AND to_status = 'Delivered'", [num(id)]);
  assert.equal(delivered.n, 1);
});

test('invoice page: printable, escaped, needs a price, finance permission only', async () => {
  const id = await newLoad({ customer: '<script>alert(1)</script> & Sons', customerRate: 1234.5 });
  const res = await call(ops, 'GET', `/api/shipments/${id}/invoice`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/html/);
  const html = await res.text();
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt; &amp; Sons'));
  assert.ok(!html.includes('<script>alert(1)'), 'customer text cannot become markup');
  assert.ok(html.includes('$1,234.50'));
  assert.ok(!/<script(?![^>]*src=)/.test(html) && !/ on\w+=/.test(html), 'no inline script or handlers');
  assert.equal((await call(operator, 'GET', `/api/shipments/${id}/invoice`)).status, 403);
  assert.equal((await call(other, 'GET', `/api/shipments/${id}/invoice`)).status, 404);
  const free = await newLoad({ customerRate: undefined });
  assert.equal((await call(ops, 'GET', `/api/shipments/${free}/invoice`)).status, 409);
});

/* ---------- customer tracking link ---------- */

test('tracking link: shows status only, a new link replaces the old one, removal works', async () => {
  const id = await newLoad({ reference: 'PO-778' });
  assert.equal((await call(other, 'POST', `/api/shipments/${id}/share`)).status, 404);
  const first = await json(admin, 'POST', `/api/shipments/${id}/share`);
  assert.match(first.path, /^\/track\/[a-f0-9]{48}$/);
  const token = first.path.split('/').pop();
  const stored = await dbGet('SELECT share_token_hash AS h FROM shipments WHERE id = ?', [num(id)]);
  assert.ok(stored.h && stored.h !== token, 'only a hash is stored');
  const pub = await call(null, 'GET', `/api/public/track/${token}`);
  assert.equal(pub.status, 200);
  const data = await pub.json();
  assert.deepEqual([data.load, data.status, data.origin, data.reference], [id, 'New', 'Tashkent, UZ', 'PO-778']);
  const text = JSON.stringify(data);
  for (const secret of ['2400', '+998', 'Navoiy', 'rate', 'carrier', 'driver', 'margin']) assert.ok(!text.includes(secret), `the customer link does not show ${secret}`);
  assert.equal((await call(null, 'GET', `/track/${token}`)).status, 200);
  assert.match(await (await call(null, 'GET', `/track/${token}`)).text(), /track\.js/);
  assert.equal((await call(null, 'GET', '/api/public/track/' + 'a'.repeat(48))).status, 404);
  assert.equal((await call(null, 'GET', '/api/public/track/short')).status, 404);
  assert.equal((await json(admin, 'GET', `/api/shipments/${id}`)).shared, true);
  const second = await json(admin, 'POST', `/api/shipments/${id}/share`);
  assert.equal((await call(null, 'GET', `/api/public/track/${token}`)).status, 404, 'the old link stops working');
  assert.equal((await call(null, 'GET', `/api/public/track/${second.path.split('/').pop()}`)).status, 200);
  assert.equal((await call(admin, 'DELETE', `/api/shipments/${id}/share`)).status, 200);
  assert.equal((await call(null, 'GET', `/api/public/track/${second.path.split('/').pop()}`)).status, 404);
});

/* ---------- backups ---------- */

test('backups: platform owner only, a real database copy, old copies are pruned, names cannot escape the folder', async () => {
  assert.equal((await call(other, 'GET', '/api/platform/backups')).status, 403, 'a customer company admin cannot');
  assert.equal((await call(ops, 'POST', '/api/platform/backups')).status, 403);
  const made = [];
  for (let i = 0; i < 3; i += 1) {
    const res = await call(admin, 'POST', '/api/platform/backups');
    assert.equal(res.status, 201);
    made.push((await res.json()).backup.name);
    await new Promise((r) => setTimeout(r, 1100));
  }
  const list = (await json(admin, 'GET', '/api/platform/backups')).backups;
  assert.deepEqual(list.map((b) => b.name), [made[2], made[1]], 'only the newest two are kept');
  const file = await call(admin, 'GET', `/api/platform/backups/${made[2]}/file`);
  assert.equal(file.status, 200);
  const bytes = Buffer.from(await file.arrayBuffer());
  assert.equal(bytes.subarray(0, 15).toString(), 'SQLite format 3');
  assert.ok(bytes.length > 20000);
  assert.equal((await call(other, 'GET', `/api/platform/backups/${made[2]}/file`)).status, 403);
  assert.equal((await call(admin, 'GET', '/api/platform/backups/..%2F..%2Fo.db/file')).status, 404);
  assert.equal((await call(admin, 'GET', `/api/platform/backups/${made[0]}/file`)).status, 404, 'the pruned copy is gone');
  const log = (await json(admin, 'GET', '/api/audit')).entries;
  assert.ok(log.some((e) => e.action === 'backup.downloaded' && e.detail === made[2]));
});
