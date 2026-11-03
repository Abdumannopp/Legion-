const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-twilio-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'm.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
process.env.API_RATE_LIMIT_MAX = '5000';
// The platform owner's own (server-wide) Twilio account.
process.env.MESSAGING_PROVIDER = 'twilio';
process.env.TWILIO_ACCOUNT_SID = 'ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
process.env.TWILIO_AUTH_TOKEN = 'platformtokenplatformtoken00';
process.env.TWILIO_SMS_FROM = '+15550001111';
process.env.TWILIO_WHATSAPP_FROM = '';
delete process.env.MESSAGING_SHARED_ALL_TENANTS;
process.env.SECRETS_KEY = 'a-test-key-that-is-long-enough-1234567890';

const { app, initialize } = require('../server');
const { db } = require('../database');
const messaging = require('../integrations/messaging');
const secrets = require('../lib/secrets');

const BRAVO_SID = 'ACbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const BRAVO_TOKEN = 'bravoSecretTokenValue1234567890ab';

let server;
let base;
let adminA;
let adminB;
let opsA;
let calls = [];
let verifyOk = true;

const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined
});
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => (e ? reject(e) : resolve(row))));

async function login(email, password) {
  const res = await call(null, 'POST', '/api/login', { email, password });
  assert.equal(res.status, 200);
  return res.headers.get('set-cookie').split(';')[0];
}

async function bookedLoad(cookie) {
  const created = await call(cookie, 'POST', '/api/shipments', {
    customer: 'Customer', origin: 'Tashkent', destination: 'Almaty', pickup: '2026-11-10', delivery: '2026-11-12', weight: 1000, equipment: 'Reefer'
  });
  const id = (await created.json()).shipment.id;
  const carrier = (await (await call(cookie, 'POST', '/api/carriers', { name: `C ${id}`, mode: 'Reefer' })).json()).carrier;
  await call(cookie, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  await call(cookie, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate: 100, driverName: 'Bobur', driverPhone: '+998 91 555 22 11' });
  return id;
}
const send = (cookie, id, channel = 'sms') => call(cookie, 'POST', `/api/shipments/${id}/messages`, { recipient: 'driver', channel, body: 'Where are you?' });
const settings = (cookie, body) => call(cookie, 'PUT', '/api/settings/messaging', body);

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  adminA = await login('admin@veyra.ai', 'admin123');
  opsA = await login('ops@veyra.ai', 'ops123');
  await call(adminA, 'POST', '/api/platform/tenants', { companyName: 'Bravo Logistics', adminName: 'Bea', adminEmail: 'bea@bravo.example', adminPassword: 'BravoPass2026' });
  adminB = await login('bea@bravo.example', 'BravoPass2026');
  messaging.setTransport(async (url, init) => {
    calls.push({ url, init });
    if (init.method === 'GET') return new Response('{}', { status: verifyOk ? 200 : 401 });
    return new Response(JSON.stringify({ sid: 'SM1' }), { status: 201, headers: { 'content-type': 'application/json' } });
  });
});

after(async () => {
  messaging.setTransport(null);
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('secrets: round trip, tamper detection and a different key', () => {
  const secret = 'correct-horse-battery-staple-0123456789';
  const stored = secrets.encrypt({ token: secret });
  assert.match(stored, /^v1:/);
  assert.ok(!stored.includes(secret) && !Buffer.from(stored.split(':')[3], 'base64').includes(secret), 'the secret is not in the stored text');
  assert.deepEqual(secrets.decrypt(stored), { token: secret });
  assert.equal(secrets.decrypt(stored.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A'))), null, 'a changed byte is detected');
  assert.equal(secrets.decrypt('garbage'), null);
  assert.equal(secrets.decrypt(null), null);
  const saved = process.env.SECRETS_KEY;
  process.env.SECRETS_KEY = 'a-completely-different-key-0987654321';
  try {
    assert.equal(secrets.decrypt(stored), null, 'another key cannot read it');
  } finally {
    process.env.SECRETS_KEY = saved;
  }
});

test('without its own account a second company cannot use the owner\'s Twilio', async () => {
  const id = await bookedLoad(adminB);
  assert.deepEqual((await (await call(adminB, 'GET', '/api/messaging/status')).json()).channels, []);
  calls = [];
  const res = await send(adminB, id);
  assert.equal(res.status, 503);
  assert.equal(calls.length, 0, 'nothing was sent through the owner\'s account');
  // The owner's own company still works with the server-wide settings.
  const idA = await bookedLoad(adminA);
  assert.deepEqual((await (await call(adminA, 'GET', '/api/messaging/status')).json()).channels, ['sms']);
  assert.equal((await send(adminA, idA)).status, 201);
  assert.equal(calls[0].init.headers.Authorization, `Basic ${Buffer.from('ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:platformtokenplatformtoken00').toString('base64')}`);
});

test('only an administrator can set the company\'s account, and the input is checked', async () => {
  const good = { accountSid: BRAVO_SID, authToken: BRAVO_TOKEN, smsFrom: '+15559990000', whatsappFrom: '+15559990001' };
  assert.equal((await settings(opsA, good)).status, 403);
  assert.equal((await settings(null, good)).status, 401);
  assert.equal((await settings(adminB, { ...good, accountSid: 'nonsense' })).status, 400);
  assert.equal((await settings(adminB, { ...good, authToken: 'short' })).status, 400);
  assert.equal((await settings(adminB, { ...good, smsFrom: '0901234567' })).status, 400, 'not international format');
  assert.equal((await settings(adminB, { ...good, smsFrom: '', whatsappFrom: '' })).status, 400, 'at least one sender');
  const missingToken = await settings(adminB, { accountSid: BRAVO_SID, smsFrom: '+15559990000' });
  assert.equal(missingToken.status, 400, 'a first save needs the token');
});

test('credentials are verified with Twilio first and wrong ones are refused', async () => {
  verifyOk = false;
  calls = [];
  const res = await settings(adminB, { accountSid: BRAVO_SID, authToken: BRAVO_TOKEN, smsFrom: '+15559990000' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).message, /did not accept/);
  assert.equal(calls[0].init.method, 'GET');
  assert.equal(calls[0].url, `https://api.twilio.com/2010-04-01/Accounts/${BRAVO_SID}.json`);
  assert.deepEqual((await (await call(adminB, 'GET', '/api/messaging/status')).json()).channels, [], 'nothing was saved');
  verifyOk = true;
});

test('saved credentials are encrypted, never returned, and used only for that company', async () => {
  const res = await settings(adminB, { accountSid: BRAVO_SID, authToken: BRAVO_TOKEN, smsFrom: '+1 555 999 0000', whatsappFrom: 'whatsapp:+15559990001' });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(!body.includes(BRAVO_TOKEN), 'the token is not in the response');
  const status = await (await call(adminB, 'GET', '/api/messaging/status')).json();
  assert.equal(status.source, 'company');
  assert.deepEqual(status.channels, ['sms', 'whatsapp']);
  assert.equal(status.accountHint, 'AC…bbbb');
  assert.equal(status.smsFrom, '+15559990000');
  for (const url of ['/api/messaging/status', '/api/integrations/status', '/api/config', '/api/me']) {
    assert.ok(!(await (await call(adminB, 'GET', url)).text()).includes(BRAVO_TOKEN), `${url} never shows the token`);
  }

  const row = await dbGet('SELECT messaging_config FROM tenants WHERE name = ?', ['Bravo Logistics']);
  assert.match(row.messaging_config, /^v1:/);
  assert.ok(!row.messaging_config.includes(BRAVO_TOKEN), 'the database holds only ciphertext');

  const idB = await bookedLoad(adminB);
  calls = [];
  assert.equal((await send(adminB, idB, 'whatsapp')).status, 201);
  assert.match(calls[0].url, new RegExp(`/Accounts/${BRAVO_SID}/Messages.json$`), 'sent through the company\'s own account');
  assert.equal(calls[0].init.headers.Authorization, `Basic ${Buffer.from(`${BRAVO_SID}:${BRAVO_TOKEN}`).toString('base64')}`);
  assert.equal(new URLSearchParams(calls[0].init.body).get('From'), 'whatsapp:+15559990001');

  // The owner's company is unaffected.
  assert.deepEqual((await (await call(adminA, 'GET', '/api/messaging/status')).json()).channels, ['sms']);
});

test('the token can stay unchanged when only the numbers change; a different account needs a token', async () => {
  const same = await settings(adminB, { accountSid: BRAVO_SID, smsFrom: '+15559990002', whatsappFrom: '' });
  assert.equal(same.status, 200);
  const status = await (await call(adminB, 'GET', '/api/messaging/status')).json();
  assert.deepEqual(status.channels, ['sms']);
  assert.equal(status.smsFrom, '+15559990002');
  calls = [];
  await send(adminB, await bookedLoad(adminB));
  assert.equal(calls.at(-1).init.headers.Authorization, `Basic ${Buffer.from(`${BRAVO_SID}:${BRAVO_TOKEN}`).toString('base64')}`, 'the saved token was kept');
  const other = await settings(adminB, { accountSid: 'ACcccccccccccccccccccccccccccccccc', smsFrom: '+15559990002' });
  assert.equal(other.status, 400, 'a new account needs its own token');
});

test('removing the company\'s account turns sending off again; sharing the owner\'s account is an explicit switch', async () => {
  const removed = await call(adminB, 'DELETE', '/api/settings/messaging');
  assert.equal(removed.status, 200);
  assert.deepEqual((await removed.json()).messaging.channels, []);
  const id = await bookedLoad(adminB);
  assert.equal((await send(adminB, id)).status, 503);
  assert.equal((await call(opsA, 'DELETE', '/api/settings/messaging')).status, 403);

  process.env.MESSAGING_SHARED_ALL_TENANTS = 'true';
  try {
    assert.deepEqual((await (await call(adminB, 'GET', '/api/messaging/status')).json()).channels, ['sms']);
    assert.equal((await call(adminB, 'GET', '/api/messaging/status')).status, 200);
    assert.equal((await (await call(adminB, 'GET', '/api/messaging/status')).json()).source, 'platform');
  } finally {
    delete process.env.MESSAGING_SHARED_ALL_TENANTS;
  }
});

test('if the encryption key changes, saved credentials are treated as missing, not as an error', async () => {
  await settings(adminB, { accountSid: BRAVO_SID, authToken: BRAVO_TOKEN, smsFrom: '+15559990000' });
  assert.deepEqual((await (await call(adminB, 'GET', '/api/messaging/status')).json()).channels, ['sms']);
  const saved = process.env.SECRETS_KEY;
  process.env.SECRETS_KEY = 'a-completely-different-key-0987654321';
  try {
    assert.deepEqual((await (await call(adminB, 'GET', '/api/messaging/status')).json()).channels, []);
    assert.equal((await send(adminB, await bookedLoad(adminB))).status, 503);
  } finally {
    process.env.SECRETS_KEY = saved;
  }
});
