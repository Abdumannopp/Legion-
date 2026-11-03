const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-nexus-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'n.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
process.env.API_RATE_LIMIT_MAX = '5000';
process.env.WEIGHT_UNIT = 'kg';
process.env.CURRENCY = 'UZS';
process.env.MAX_RATE = '100000000';
process.env.MESSAGE_LANGUAGE = 'en';
process.env.OPENROUTER_API_KEY = 'sk-or-test';
delete process.env.OPENROUTER_MODEL;
process.env.MESSAGING_PROVIDER = 'twilio';
process.env.TWILIO_ACCOUNT_SID = 'AC00000000000000000000000000000000';
process.env.TWILIO_AUTH_TOKEN = 'platformtokenplatformtoken00';
process.env.TWILIO_SMS_FROM = '+15550001111';
process.env.TWILIO_WHATSAPP_FROM = '+15550002222';

const { app, initialize } = require('../server');
const { db } = require('../database');
const aiGateway = require('../ai/gateway');
const messaging = require('../integrations/messaging');
const nexus = require('../agents/nexus');

let server;
let base;
let admin;
let operator;
let inboxToken;
let sends = [];

const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined
});
const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, (e) => (e ? reject(e) : resolve())));
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => (e ? reject(e) : resolve(row))));

async function login(email, password) {
  const res = await call(null, 'POST', '/api/login', { email, password });
  assert.equal(res.status, 200);
  return res.headers.get('set-cookie').split(';')[0];
}

function fakeModel(replies) {
  const requests = [];
  aiGateway.setTransport(async (url, init) => {
    requests.push(JSON.parse(init.body));
    const next = replies.shift();
    const payload = { model: 'test/model', choices: [{ message: { content: JSON.stringify(next) } }], usage: { prompt_tokens: 100, completion_tokens: 30 } };
    return new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  return requests;
}

const orderReply = (extra = {}) => ({
  customer: 'Navoiy Textile', customerPhone: '+998 90 111 22 33', reference: 'PO-1', origin: 'Tashkent, UZ', destination: 'Almaty, KZ',
  pickup: '2026-11-10', delivery: '2026-11-12', weight: 20, weightUnit: 't', equipment: 'Tent / Curtainsider', customerRate: 15000000,
  customerRateCurrency: 'UZS', questions: [], confidence: 0.9, ...extra
});

const postmark = (extra = {}) => ({ From: 'Dilya <dilya@navoiy.example>', Subject: 'Truck needed', TextBody: 'Need a tent truck Tashkent-Almaty 20 t on 10 Nov', MessageID: `m-${Math.random()}`, ...extra });
const inbound = (body, token = inboxToken) => call(null, 'POST', `/api/integrations/inbox/${token}`, body);

async function bookedLoad({ driverPhone = '+998 91 555 22 11', customerPhone = '+998 90 777 66 55' } = {}) {
  const created = await call(admin, 'POST', '/api/shipments', {
    customer: 'Navoiy Textile', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2026-11-10', delivery: '2026-11-12',
    weight: 18000, equipment: 'Tent / Curtainsider', ...(customerPhone ? { customerPhone } : {})
  });
  const id = (await created.json()).shipment.id;
  const carrier = (await (await call(admin, 'POST', '/api/carriers', { name: `Carrier ${id}`, mode: 'Truckload', phone: '+998 71 200 00 00' })).json()).carrier;
  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  return { id, carrier, dispatch: () => call(admin, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate: 9000000, truckPlate: '01 A 123 BC', driverName: 'Bobur', ...(driverPhone ? { driverPhone } : {}) }) };
}

const tasks = async (cookie = admin) => (await (await call(cookie, 'GET', '/api/tasks')).json()).tasks;

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  operator = await login('demo@veyra.ai', 'demo123');
  messaging.setTransport(async (url, init) => {
    sends.push({ url, init });
    return new Response(JSON.stringify({ sid: `SM${sends.length}` }), { status: 201, headers: { 'content-type': 'application/json' } });
  });
  const token = await (await call(admin, 'POST', '/api/settings/inbox/token')).json();
  inboxToken = token.token;
});

after(async () => {
  nexus.stopSweeper();
  aiGateway.setTransport(null);
  messaging.setTransport(null);
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ---------------- inbox ---------------- */

test('the inbox address is admin-only, shown once, and unknown addresses are refused', async () => {
  assert.equal((await call(operator, 'POST', '/api/settings/inbox/token')).status, 403);
  assert.match(inboxToken, /^inbox_[0-9a-f]{48}$/);
  assert.equal((await inbound(postmark(), 'inbox_wrong')).status, 404);
  const status = await (await call(admin, 'GET', '/api/integrations/status')).json();
  assert.equal(status.inbox.configured, true);
  assert.ok(!JSON.stringify(status).includes(inboxToken), 'the token is never shown again');
  const stored = await dbGet('SELECT inbox_token_hash FROM tenants WHERE id = 1');
  assert.notEqual(stored.inbox_token_hash, inboxToken, 'only a hash is stored');
});

test('an order email is read by FLOW and becomes a task, never a load', async () => {
  const requests = fakeModel([orderReply()]);
  const loadsBefore = (await (await call(admin, 'GET', '/api/shipments/search')).json()).allCount;
  const res = await inbound(postmark({ MessageID: 'order-1' }));
  assert.equal(res.status, 201);
  await nexus.idle();

  const item = (await (await call(operator, 'GET', '/api/inbox')).json()).items.find((i) => i.from.includes('dilya@navoiy.example'));
  assert.equal(item.status, 'parsed');
  assert.equal(item.parsed.draft.weight, 20000, '20 t -> kg');
  const task = (await tasks()).find((t) => t.kind === 'review_intake' && t.inboxId === item.id);
  assert.match(task.title, /Navoiy Textile · Tashkent, UZ → Almaty, KZ/);
  assert.equal(task.payload.parsed.draft.customerRate, 15000000);
  assert.equal((await (await call(admin, 'GET', '/api/shipments/search')).json()).allCount, loadsBefore, 'no load was created');
  assert.match(requests[0].messages[1].content, /Subject: Truck needed/);

  // The same email delivered twice (providers retry) is stored once.
  const again = await (await inbound(postmark({ MessageID: 'order-1' }))).json();
  assert.equal(again.duplicate, true);
  await nexus.idle();
  assert.equal((await tasks()).filter((t) => t.kind === 'review_intake' && t.inboxId === item.id).length, 1);
});

test('Mailgun-style forms, HTML-only emails and empty emails are understood', async () => {
  fakeModel([orderReply({ customer: 'Form Co' }), orderReply({ customer: 'Html Co' })]);
  const form = await fetch(`${base}/api/integrations/inbox/${inboxToken}`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ sender: 'a@form.example', subject: 'Order', 'body-plain': 'Load 10 t Tashkent-Almaty', 'Message-Id': '<form-1@x>' }).toString()
  });
  assert.equal(form.status, 201);
  const html = await inbound({ from: 'b@html.example', subject: 'HTML order', html: '<style>p{}</style><p>Need a <b>truck</b>&nbsp;to Almaty</p><script>alert(1)</script>', messageId: 'html-1' });
  assert.equal(html.status, 201);
  await nexus.idle();
  const items = (await (await call(admin, 'GET', '/api/inbox')).json()).items;
  const htmlItem = items.find((i) => i.from === 'b@html.example');
  assert.equal(htmlItem.body, 'Need a truck to Almaty', 'tags and scripts are removed');
  assert.ok(items.find((i) => i.from === 'a@form.example'));
  const empty = await (await inbound({ from: 'c@x.example', subject: 'nothing', TextBody: '   ' })).json();
  assert.equal(empty.ignored, 'empty');
});

test('only allowed senders are read, the rest is stored as blocked and costs no AI call', async () => {
  assert.equal((await call(operator, 'PUT', '/api/settings/inbox', { allowedSenders: ['customer.example'] })).status, 403);
  assert.equal((await call(admin, 'PUT', '/api/settings/inbox', { allowedSenders: ['not valid!'] })).status, 400);
  assert.equal((await call(admin, 'PUT', '/api/settings/inbox', { allowedSenders: ['Customer.Example', '@Partner.example', 'boss@one.example'] })).status, 200);
  const requests = fakeModel([orderReply({ customer: 'Allowed Co' }), orderReply({ customer: 'Boss Co' })]);

  const blocked = await (await inbound(postmark({ From: 'spam@evil.example', MessageID: 'spam-1' }))).json();
  assert.equal(blocked.accepted, false);
  const allowedDomain = await (await inbound(postmark({ From: 'Anna <anna@customer.example>', MessageID: 'ok-1' }))).json();
  const allowedAddress = await (await inbound(postmark({ From: 'boss@one.example', MessageID: 'ok-2' }))).json();
  const otherAtSameDomain = await (await inbound(postmark({ From: 'x@one.example', MessageID: 'spam-2' }))).json();
  assert.equal(allowedDomain.accepted, true);
  assert.equal(allowedAddress.accepted, true);
  assert.equal(otherAtSameDomain.accepted, false, 'an address entry does not allow the whole domain');
  await nexus.idle();
  assert.equal(requests.length, 2, 'blocked mail never reached the AI');

  const blockedItem = (await (await call(admin, 'GET', '/api/inbox')).json()).items.find((i) => i.from === 'spam@evil.example');
  assert.equal(blockedItem.status, 'blocked');
  assert.ok(!(await tasks()).some((t) => t.inboxId === blockedItem.id));
  await call(admin, 'PUT', '/api/settings/inbox', { allowedSenders: [] });
});

test('without AI the email still becomes a task, and the daily AI cap is respected', async () => {
  const saved = process.env.OPENROUTER_API_KEY;
  delete process.env.OPENROUTER_API_KEY;
  try {
    await inbound(postmark({ MessageID: 'noai-1', From: 'noai@x.example' }));
    await nexus.idle();
    const task = (await tasks()).find((t) => t.payload?.from === 'noai@x.example');
    assert.equal(task.payload.note, 'AI is off.');
    assert.equal(task.payload.parsed, null);
    const item = (await (await call(admin, 'GET', '/api/inbox')).json()).items.find((i) => i.from === 'noai@x.example');
    assert.equal(item.status, 'new');
    assert.equal((await call(admin, 'POST', `/api/inbox/${item.id}/parse`)).status, 503);
  } finally {
    process.env.OPENROUTER_API_KEY = saved;
  }

  nexus.configure({ aiDailyLimit: 0 });
  try {
    const requests = fakeModel([orderReply()]);
    await inbound(postmark({ MessageID: 'cap-1', From: 'cap@x.example' }));
    await nexus.idle();
    assert.equal(requests.length, 0);
    assert.match((await tasks()).find((t) => t.payload?.from === 'cap@x.example').payload.note, /daily AI limit/);
  } finally {
    nexus.configure({ aiDailyLimit: 300 });
  }

  // A person can still ask FLOW to read it by hand.
  fakeModel([orderReply({ customer: 'Manual Co' })]);
  const item = (await (await call(admin, 'GET', '/api/inbox')).json()).items.find((i) => i.from === 'cap@x.example');
  const parsed = await (await call(admin, 'POST', `/api/inbox/${item.id}/parse`)).json();
  assert.equal(parsed.draft.customer, 'Manual Co');
});

test('creating a load from an email closes its task; the email cannot be used twice', async () => {
  fakeModel([orderReply()]);
  await inbound(postmark({ MessageID: 'convert-1', From: 'convert@x.example' }));
  await nexus.idle();
  const item = (await (await call(admin, 'GET', '/api/inbox')).json()).items.find((i) => i.from === 'convert@x.example');
  const load = { customer: 'Navoiy Textile', origin: 'A', destination: 'B', pickup: '2026-11-10', delivery: '2026-11-11', weight: 100, equipment: 'Reefer' };
  assert.equal((await call(admin, 'POST', '/api/shipments', { ...load, inboxId: 99999 })).status, 400);
  const created = await call(admin, 'POST', '/api/shipments', { ...load, inboxId: item.id });
  assert.equal(created.status, 201);
  assert.ok(!(await tasks()).some((t) => t.inboxId === item.id), 'the task is closed');
  assert.ok(!(await (await call(admin, 'GET', '/api/inbox')).json()).items.some((i) => i.id === item.id), 'the email left the inbox');
  assert.equal((await call(admin, 'POST', '/api/shipments', { ...load, inboxId: item.id })).status, 400, 'already converted');

  const other = (await (await call(admin, 'GET', '/api/inbox')).json()).items[0];
  assert.equal((await call(operator, 'POST', `/api/inbox/${other.id}/dismiss`)).status, 200);
  assert.ok(!(await tasks()).some((t) => t.inboxId === other.id), 'dismissing the email closes its task');
});

/* ---------------- NEXUS: prepares, never acts ---------------- */

test('Sourcing makes SCOUT prepare a carrier task; booking closes it and drafts the messages', async () => {
  sends = [];
  const { id, carrier, dispatch } = await bookedLoad();
  await nexus.idle();
  const book = (await tasks()).find((t) => t.kind === 'book_carrier' && t.shipmentId === id);
  assert.ok(book, 'a carrier task exists');
  assert.ok(book.payload.recommendations.some((r) => r.carrierId === carrier.id));

  assert.equal((await dispatch()).status, 200);
  await nexus.idle();
  const open = await tasks();
  assert.ok(!open.some((t) => t.kind === 'book_carrier' && t.shipmentId === id), 'the carrier task is closed');
  const messages = open.filter((t) => t.kind === 'message' && t.shipmentId === id);
  assert.deepEqual(messages.map((t) => t.payload.recipient).sort(), ['carrier', 'customer', 'driver']);
  const driver = messages.find((t) => t.payload.recipient === 'driver');
  assert.match(driver.payload.body, /pickup 2026-11-10/);
  assert.equal(sends.length, 0, 'NEXUS sent nothing by itself');
});

test('a person approves a drafted message: it is sent once, can be edited, and closes the task', async () => {
  sends = [];
  const { id, dispatch } = await bookedLoad();
  await dispatch();
  await nexus.idle();
  const driver = (await tasks()).find((t) => t.kind === 'message' && t.shipmentId === id && t.payload.recipient === 'driver');

  assert.equal((await call(operator, 'POST', `/api/tasks/${driver.id}/approve`, {})).status, 400, 'a channel is required');
  assert.equal((await call(operator, 'POST', `/api/tasks/${driver.id}/approve`, { channel: 'sms', body: '' })).status, 400);
  const res = await call(operator, 'POST', `/api/tasks/${driver.id}/approve`, { channel: 'sms', body: 'Edited: call me when you load.' });
  assert.equal(res.status, 201);
  assert.equal(sends.length, 1);
  const form = new URLSearchParams(sends[0].init.body);
  assert.equal(form.get('To'), '+998915552211', 'the number comes from the load');
  assert.equal(form.get('Body'), 'Edited: call me when you load.');
  assert.ok(!(await tasks()).some((t) => t.id === driver.id));
  assert.equal((await call(operator, 'POST', `/api/tasks/${driver.id}/approve`, { channel: 'sms' })).status, 409, 'not twice');
  assert.equal(sends.length, 1);
  const history = (await (await call(admin, 'GET', `/api/shipments/${id}/messages`)).json()).messages;
  assert.equal(history.length, 1);
  assert.equal(history[0].sentBy, 'Demo Operator');

  const customer = (await tasks()).find((t) => t.kind === 'message' && t.shipmentId === id && t.payload.recipient === 'customer');
  assert.equal((await call(operator, 'POST', `/api/tasks/${customer.id}/dismiss`)).status, 200);
  assert.equal(sends.length, 1, 'dismissing sends nothing');
  const notMessage = (await tasks()).find((t) => t.kind === 'book_carrier' || t.kind === 'review_intake');
  if (notMessage) assert.equal((await call(operator, 'POST', `/api/tasks/${notMessage.id}/approve`, { channel: 'sms' })).status, 400);
});

test('no phone on the load means no message task for that person', async () => {
  const { id, dispatch } = await bookedLoad({ driverPhone: null, customerPhone: null });
  await dispatch();
  await nexus.idle();
  const messages = (await tasks()).filter((t) => t.kind === 'message' && t.shipmentId === id);
  assert.deepEqual(messages.map((t) => t.payload.recipient), ['carrier']);
});

test('Delivered drafts a thank-you and closes the load\'s other tasks; Exception raises one that clears itself', async () => {
  const { id, dispatch } = await bookedLoad();
  await dispatch();
  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'In Transit' });
  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Exception' });
  await nexus.idle();
  const attention = (await tasks()).find((t) => t.kind === 'attention' && t.shipmentId === id);
  assert.match(attention.title, /is in Exception/);

  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'In Transit' });
  await nexus.idle();
  assert.ok(!(await tasks()).some((t) => t.kind === 'attention' && t.shipmentId === id), 'the Exception task cleared itself');

  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Delivered' });
  await nexus.idle();
  const remaining = (await tasks()).filter((t) => t.shipmentId === id);
  assert.deepEqual(remaining.map((t) => `${t.kind}:${t.payload?.purpose}`), ['message:delivered']);

  const cancelled = await bookedLoad();
  await cancelled.dispatch();
  await nexus.idle();
  await call(admin, 'PATCH', `/api/admin/shipments/${cancelled.id}/status`, { status: 'Cancelled' });
  await nexus.idle();
  assert.deepEqual((await tasks()).filter((t) => t.shipmentId === cancelled.id), [], 'cancelling closes every task of the load');
});

test('the sweeper asks quiet trucks for a location once per silence', async () => {
  sends = [];
  const { id, dispatch } = await bookedLoad();
  await dispatch();
  await nexus.idle();
  assert.equal(await nexus.sweep(), 0, 'a truck booked a minute ago is not overdue');

  await dbRun("UPDATE shipment_events SET created_at = datetime('now', '-1 day') WHERE shipment_id = ? AND to_status = 'Dispatched'", [Number(id.replace('SHP-', ''))]);
  assert.equal(await nexus.sweep(), 1);
  const task = (await tasks()).find((t) => t.shipmentId === id && /no update/.test(t.title));
  assert.equal(task.payload.purpose, 'location_request');
  assert.equal(await nexus.sweep(), 0, 'not again for the same silence');
  assert.equal(sends.length, 0, 'asking for a location also waits for approval');

  // The truck reports, then goes quiet again: a new task.
  await call(operator, 'POST', `/api/shipments/${id}/tracking`, { location: 'Chimkent' });
  await dbRun("UPDATE shipments SET last_tracked_at = datetime('now', '-1 day') WHERE id = ?", [Number(id.replace('SHP-', ''))]);
  assert.equal(await nexus.sweep(), 1);

  const noPhone = await bookedLoad({ driverPhone: null });
  await noPhone.dispatch();
  await dbRun("UPDATE shipment_events SET created_at = datetime('now', '-1 day') WHERE shipment_id = ? AND to_status = 'Dispatched'", [Number(noPhone.id.replace('SHP-', ''))]);
  await nexus.sweep();
  const reminder = (await tasks()).find((t) => t.shipmentId === noPhone.id && t.kind === 'attention');
  assert.match(reminder.title, /call the driver/);
});

test('the notification counts include open tasks and do not flag fresh trucks', async () => {
  const alerts = (await (await call(admin, 'GET', '/api/alerts')).json()).alerts;
  assert.ok(alerts.openTasks > 0);
  const { id, dispatch } = await bookedLoad();
  const before = (await (await call(admin, 'GET', '/api/alerts')).json()).alerts.staleTracking;
  await dispatch();
  const after = (await (await call(admin, 'GET', '/api/alerts')).json()).alerts.staleTracking;
  assert.equal(after, before, `${id} was booked just now and is not overdue`);
});

/* ---------------- companies stay apart ---------------- */

test("another company never sees, approves or dismisses this company's tasks and emails", async () => {
  const created = await call(admin, 'POST', '/api/platform/tenants', { companyName: 'Bravo Logistics', adminName: 'Bea', adminEmail: 'bea@bravo.example', adminPassword: 'BravoPass2026' });
  assert.equal(created.status, 201);
  const adminB = await login('bea@bravo.example', 'BravoPass2026');
  const mine = await tasks(admin);
  assert.ok(mine.length > 0);
  assert.deepEqual(await tasks(adminB), []);
  assert.deepEqual((await (await call(adminB, 'GET', '/api/inbox')).json()).items, []);
  const target = mine.find((t) => t.kind === 'message');
  assert.equal((await call(adminB, 'POST', `/api/tasks/${target.id}/dismiss`)).status, 404);
  assert.equal((await call(adminB, 'POST', `/api/tasks/${target.id}/approve`, { channel: 'sms' })).status, 404);
  assert.equal((await call(adminB, 'POST', `/api/inbox/${(await (await call(admin, 'GET', '/api/inbox')).json()).items[0].id}/dismiss`)).status, 404);
  assert.ok((await tasks(admin)).some((t) => t.id === target.id), 'still open for its owner');
  // Company A's inbox address does not deliver into company B and vice versa.
  const before = (await (await call(admin, 'GET', '/api/inbox')).json()).items.length;
  const tokenB = (await (await call(adminB, 'POST', '/api/settings/inbox/token')).json()).token;
  fakeModel([orderReply({ customer: 'B Customer' })]);
  await inbound(postmark({ MessageID: 'b-1', From: 'b@b.example' }), tokenB);
  await nexus.idle();
  assert.equal((await (await call(admin, 'GET', '/api/inbox')).json()).items.length, before);
  assert.equal((await (await call(adminB, 'GET', '/api/inbox')).json()).items.length, 1);
  assert.equal((await tasks(adminB)).length, 1);
});
