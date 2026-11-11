// Gmail / Outlook through their APIs (OAuth), live traffic, and border waiting times. All providers are fakes.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-mailapi-'));
Object.assign(process.env, {
  NODE_ENV: 'development', DATABASE_PATH: path.join(dir, 'a.db'), PORT: '0', BCRYPT_COST: '10', API_RATE_LIMIT_MAX: '5000',
  CURRENCY: 'USD', MESSAGE_LANGUAGE: 'en', OPENROUTER_API_KEY: 'sk-or-test', PUBLIC_URL: 'https://veyra.test',
  GOOGLE_CLIENT_ID: 'g-client', GOOGLE_CLIENT_SECRET: 'g-secret-value', MICROSOFT_CLIENT_ID: 'm-client', MICROSOFT_CLIENT_SECRET: 'm-secret-value',
  GEO_PROVIDER: 'osm', TRAFFIC_PROVIDER: 'tomtom', TOMTOM_API_KEY: 'tt-secret-key-123'
});
const { app, initialize } = require('../server');
const { db } = require('../database');
const aiGateway = require('../ai/gateway');
const mailapi = require('../integrations/mailapi');
const geo = require('../integrations/geo');
const traffic = require('../integrations/traffic');
const nexus = require('../agents/nexus');

let server; let base; let admin; let operator; let other;
const call = (cookie, method, url, body) => fetch(`${base}${url}`, { method, redirect: 'manual', headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
const json = async (...args) => (await call(...args)).json();
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => (e ? reject(e) : resolve(row))));
async function login(email, password) {
  return (await call(null, 'POST', '/api/login', { email, password })).headers.get('set-cookie').split(';')[0];
}
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

const pdf = (text) => Buffer.from(`%PDF-1.4\n${text}\n${' '.repeat(300)}\n%%EOF`);
function rawEmail({ subject, text = 'hi', id, file }) {
  const b = 'bnd123';
  const body = `--${b}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${text}\r\n` + (file ? `--${b}\r\nContent-Type: application/pdf; name="${file.name}"\r\nContent-Disposition: attachment; filename="${file.name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${file.content.toString('base64')}\r\n` : '') + `--${b}--\r\n`;
  return Buffer.from(`From: Driver <driver@carrier.example>\r\nSubject: ${subject}\r\nMessage-ID: <${id}@x>\r\nContent-Type: multipart/mixed; boundary="${b}"\r\n\r\n${body}`, 'latin1');
}

// ---- fake Google / Microsoft ----
const mailbox = { gmail: [], outlook: [] };
const fakeState = { requests: [], refreshFails: false, tomtom: 0 };
const json200 = (data) => new Response(JSON.stringify(data), { status: 200, headers: { 'content-type': 'application/json' } });
mailapi.setTransport(async (url, init = {}) => {
  fakeState.requests.push(url);
  const u = new URL(url);
  const form = init.body ? Object.fromEntries(new URLSearchParams(init.body)) : {};
  if (u.hostname === 'oauth2.googleapis.com' || u.hostname === 'login.microsoftonline.com') {
    if (form.grant_type === 'refresh_token' && fakeState.refreshFails) return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'Token has been revoked.' }), { status: 400, headers: { 'content-type': 'application/json' } });
    assert.ok(form.client_secret, 'the client secret is sent to the token endpoint');
    if (form.grant_type === 'authorization_code') {
      assert.equal(form.redirect_uri, 'https://veyra.test/api/integrations/mail-oauth/callback');
      if (form.code === 'no-refresh') return json200({ access_token: 'at' });
      return json200({ access_token: 'at-1', refresh_token: `rt-secret-${u.hostname.startsWith('oauth2') ? 'g' : 'm'}-9876` });
    }
    return json200({ access_token: 'at-2' });
  }
  assert.ok(String(init.headers?.Authorization).startsWith('Bearer at-'), 'the access token is used');
  if (u.hostname === 'gmail.googleapis.com') {
    if (u.pathname.endsWith('/profile')) return json200({ emailAddress: 'orders@gmail.example' });
    if (u.pathname.endsWith('/messages')) return json200({ messages: mailbox.gmail.map((m) => ({ id: m.id })) });
    const m = mailbox.gmail.find((x) => u.pathname.endsWith(`/${x.id}`));
    return json200(u.searchParams.get('format') === 'raw' ? { raw: m.raw.toString('base64url') } : { internalDate: String(m.at), sizeEstimate: m.raw.length });
  }
  if (u.hostname === 'graph.microsoft.com') {
    if (u.pathname === '/v1.0/me') return json200({ mail: 'orders@outlook.example' });
    if (u.pathname.endsWith('/messages')) return json200({ value: mailbox.outlook.filter((m) => m.at > Date.parse(/receivedDateTime gt ([^&]+)/.exec(decodeURIComponent(u.search))[1].replace(/'/g, ''))).map((m) => ({ id: m.id, receivedDateTime: new Date(m.at).toISOString() })) });
    const m = mailbox.outlook.find((x) => u.pathname.includes(x.id));
    return new Response(m.raw, { status: 200, headers: { 'content-type': 'message/rfc822' } });
  }
  throw new Error(`unexpected request ${url}`);
});
const places = { 'tashkent, uz': { lat: '41.3', lon: '69.24' }, 'almaty, kz': { lat: '43.24', lon: '76.89' } };
let mapCalls = 0;
geo.setTransport(async (url) => {
  mapCalls += 1;
  if (url.includes('/search')) return json200(places[decodeURIComponent(/q=([^&]+)/.exec(url)[1]).toLowerCase()] ? [places[decodeURIComponent(/q=([^&]+)/.exec(url)[1]).toLowerCase()]] : []);
  return json200({ routes: [{ distance: 810000, duration: 36000, geometry: { coordinates: [[69.24, 41.3], [76.89, 43.24]] } }] });
});
traffic.setTransport(async (url) => {
  fakeState.tomtom += 1;
  if (process.env.TOMTOM_FAIL) throw new Error(`connect failed for ${url}`);
  return json200({ routes: [{ summary: { travelTimeInSeconds: 40000, trafficDelayInSeconds: 5400 } }] });
});

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  operator = await login('demo@veyra.ai', 'demo123');
  await call(admin, 'POST', '/api/platform/tenants', { companyName: 'Api Other', adminName: 'Anna', adminEmail: 'anna@api.example', adminPassword: 'api-other-pass-123' });
  other = await login('anna@api.example', 'api-other-pass-123');
  aiGateway.setTransport(async () => new Response(JSON.stringify({ choices: [{ message: { content: '{}' } }] }), { status: 200 }));
});
after(async () => {
  await nexus.idle();
  [mailapi, geo, traffic].forEach((m) => m.setTransport(null));
  aiGateway.setTransport(null);
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

const status = async (cookie = admin) => (await json(cookie, 'GET', '/api/integrations/status')).mailbox;
async function connect(provider, code = 'good-code', cookie = admin) {
  const start = await call(cookie, 'GET', `/api/settings/mail-oauth/${provider}/start`);
  assert.equal(start.status, 302);
  const url = new URL(start.headers.get('location'));
  const callback = await call(cookie, 'GET', `/api/integrations/mail-oauth/callback?code=${code}&state=${encodeURIComponent(url.searchParams.get('state'))}`);
  return { start: url, callback: callback.headers.get('location') };
}
const waitForCheck = async () => { for (let i = 0; i < 50 && !(await status()).lastCheckedAt; i += 1) await pause(40); };

test('sign-in with Google: consent address, signed state, refresh token kept encrypted and never shown', async () => {
  const s = await status();
  assert.deepEqual(s.providers, { gmail: true, outlook: true });
  assert.equal((await call(operator, 'GET', '/api/settings/mail-oauth/gmail/start')).status, 403);
  const { start, callback } = await connect('gmail');
  assert.equal(start.hostname, 'accounts.google.com');
  assert.equal(start.searchParams.get('client_id'), 'g-client');
  assert.equal(start.searchParams.get('redirect_uri'), 'https://veyra.test/api/integrations/mail-oauth/callback');
  assert.match(start.searchParams.get('scope'), /gmail\.readonly/);
  assert.ok(!/mail\.send|gmail\.modify|gmail\.compose/.test(start.searchParams.get('scope')), 'read-only permission only');
  assert.ok(!start.search.includes('g-secret-value'), 'the client secret is never in the browser address');
  assert.equal(callback, '/?mailbox=connected');
  const after = await status();
  assert.deepEqual([after.configured, after.provider, after.host, after.user], [true, 'gmail', 'Gmail', 'orders@gmail.example']);
  const everything = JSON.stringify(after) + JSON.stringify(await json(admin, 'GET', '/api/integrations/status'));
  assert.ok(!everything.includes('rt-secret'), 'no token in any response');
  const stored = await dbGet('SELECT imap_config AS c FROM tenants WHERE id = 1');
  assert.ok(stored.c.startsWith('v1:') && !stored.c.includes('rt-secret'), 'stored encrypted');
  assert.equal((await status(other)).configured, false);
});

test('sign-in safety: a forged, expired-style or foreign state is refused; a missing long-term token is explained', async () => {
  const forged = await call(admin, 'GET', '/api/integrations/mail-oauth/callback?code=x&state=not-a-token');
  assert.match(decodeURIComponent(forged.headers.get('location')), /mailbox=error.*not valid/);
  // A state made for the first company's admin cannot be used by another company's admin.
  const start = await call(admin, 'GET', '/api/settings/mail-oauth/outlook/start');
  const state = new URL(start.headers.get('location')).searchParams.get('state');
  const stolen = await call(other, 'GET', `/api/integrations/mail-oauth/callback?code=x&state=${encodeURIComponent(state)}`);
  assert.match(decodeURIComponent(stolen.headers.get('location')), /another person/);
  assert.equal((await status(other)).configured, false);
  const denied = await call(admin, 'GET', `/api/integrations/mail-oauth/callback?error=access_denied&error_description=No&state=${encodeURIComponent(state)}`);
  assert.match(denied.headers.get('location'), /mailbox=error/);
  const { callback } = await connect('outlook', 'no-refresh');
  assert.match(decodeURIComponent(callback), /long-term/);
  assert.equal((await status()).provider, 'gmail', 'a failed sign-in does not replace the working mailbox');
});

test('Gmail: old mail is not imported, new mail with a CMR is, nothing twice, a revoked token is reported', async () => {
  const id = (await json(admin, 'POST', '/api/shipments', { customer: 'C', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 100, equipment: 'Reefer' })).shipment.id;
  mailbox.gmail.push({ id: 'g-old', at: Date.now() - 3600000, raw: rawEmail({ subject: 'old', id: 'old', file: { name: 'old.pdf', content: pdf('old') } }) });
  await call(admin, 'DELETE', '/api/settings/imap');
  await connect('gmail');
  await waitForCheck();
  await pause(30);
  mailbox.gmail.push({ id: 'g-new', at: Date.now(), raw: rawEmail({ subject: `CMR ${id}`, id: 'new', file: { name: 'cmr_scan.pdf', content: pdf('new') } }) });
  const check = await (await call(admin, 'POST', '/api/settings/imap/check')).json();
  assert.equal(check.imported, 1);
  await nexus.idle();
  const docs = (await json(admin, 'GET', `/api/shipments/${id}/documents`)).documents;
  assert.deepEqual(docs.map((d) => [d.filename, d.type]), [['cmr_scan.pdf', 'cmr']]);
  assert.equal((await (await call(admin, 'POST', '/api/settings/imap/check')).json()).imported, 0, 'the same message is not imported twice');
  assert.ok(!fakeState.requests.some((u) => /modify|trash|delete|send/i.test(new URL(u).pathname)), 'nothing in the mailbox is changed');
  fakeState.refreshFails = true;
  const failed = await call(admin, 'POST', '/api/settings/imap/check');
  assert.equal(failed.status, 502);
  assert.match((await status()).lastError, /revoked/);
  fakeState.refreshFails = false;
  assert.equal((await call(admin, 'POST', '/api/settings/imap/check')).status, 200, 'works again when the problem is gone');
});

test('Outlook: mail that arrives after connecting is read as a MIME message with its file', async () => {
  await call(admin, 'DELETE', '/api/settings/imap');
  assert.match((await connect('outlook')).callback, /connected/);
  await waitForCheck();
  assert.equal((await status()).provider, 'outlook');
  await pause(30);
  const id = (await json(admin, 'POST', '/api/shipments', { customer: 'C', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 100, equipment: 'Reefer' })).shipment.id;
  mailbox.outlook.push({ id: 'o-1', at: Date.now(), raw: rawEmail({ subject: `POD ${id}`, id: 'o1', file: { name: 'pod.pdf', content: pdf('outlook') } }) });
  const check = await (await call(admin, 'POST', '/api/settings/imap/check')).json();
  assert.equal(check.imported, 1);
  await nexus.idle();
  assert.equal((await json(admin, 'GET', `/api/shipments/${id}/documents`)).documents[0].type, 'pod');
  assert.equal((await call(admin, 'DELETE', '/api/settings/imap')).status, 200);
  assert.equal((await status()).configured, false);
});

test('provider not set up on the server: no button, a clear message', async () => {
  const saved = process.env.GOOGLE_CLIENT_ID;
  process.env.GOOGLE_CLIENT_ID = '';
  try {
    assert.equal((await status()).providers.gmail, false);
    const start = await call(admin, 'GET', '/api/settings/mail-oauth/gmail/start');
    assert.match(decodeURIComponent(start.headers.get('location')), /not set up/);
  } finally { process.env.GOOGLE_CLIENT_ID = saved; }
});

/* ---------- border waiting times and traffic ---------- */

test('border waits: lines are checked, either direction matches, other companies are separate', async () => {
  assert.equal((await call(operator, 'POST', '/api/border-waits', { lines: 'UZ; KZ; 6' })).status, 403);
  const saved = await json(admin, 'POST', '/api/border-waits', { lines: 'uz; kz; 6\nxx\nUZ; UZ; 2\nUZ; RU; 999\nUZ; TJ; 3,5' });
  assert.deepEqual([saved.created, saved.updated, saved.errors.map((e) => e.line)], [2, 0, [2, 3, 4]]);
  const again = await json(admin, 'POST', '/api/border-waits', { lines: 'KZ; UZ; 8' });
  assert.deepEqual([again.created, again.updated], [0, 1], 'KZ-UZ and UZ-KZ are the same border');
  const list = (await json(admin, 'GET', '/api/border-waits')).waits;
  assert.deepEqual(list.map((w) => [w.pair, w.hours]), [['KZ-UZ', 8], ['TJ-UZ', 3.5]]);
  assert.deepEqual((await json(other, 'GET', '/api/border-waits')).waits, []);
  assert.equal((await call(other, 'DELETE', `/api/border-waits/${list[1].id}`)).status, 404);
  assert.equal((await call(admin, 'DELETE', `/api/border-waits/${list[1].id}`)).status, 200);
});

test('ROUTE adds the border wait to a map estimate, and live traffic only for a truck on the road', async () => {
  const id = (await json(admin, 'POST', '/api/shipments', { customer: 'C', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 100, equipment: 'Reefer' })).shipment.id;
  traffic.clearCache();
  const planned = await json(admin, 'GET', `/api/agents/route/${id}`);
  assert.deepEqual(planned.border, { pair: 'KZ-UZ', hours: 8, counted: true });
  assert.equal(planned.map.withRestsHours, 21.5, '10 h driving x 1.35 + 8 h at the border');
  assert.equal(planned.traffic, null, 'no traffic request for a load that has not left');
  assert.equal(fakeState.tomtom, 0);
  assert.match(planned.schedule.text, /by road it takes about 22 h/);

  const carrier = (await json(admin, 'POST', '/api/carriers', { name: 'Traffic Carrier', mode: 'Truckload', phone: '+998 71 200 00 33' })).carrier;
  await call(admin, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  await call(admin, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate: 1000, driverPhone: '+998 91 555 22 11', truckPlate: '01 T 111 TT' });
  const live = await json(admin, 'GET', `/api/agents/route/${id}`);
  assert.deepEqual(live.traffic, { delayMinutes: 90, travelHours: 11.1, counted: true });
  assert.equal(live.map.withRestsHours, 23, '13.5 + 8 + 1.5 h of traffic delay');
  assert.equal(fakeState.tomtom, 1);
  await json(admin, 'GET', `/api/agents/route/${id}`);
  assert.equal(fakeState.tomtom, 1, 'the second look comes from the 30-minute cache');
});

test('traffic: the API key never appears in errors; switched off without a key', async () => {
  traffic.clearCache();
  process.env.TOMTOM_FAIL = '1';
  try {
    await assert.rejects(() => traffic.current('Tashkent, UZ', 'Almaty, KZ'), (error) => !error.message.includes('tt-secret-key-123') && /\*\*\*/.test(error.message));
  } finally { delete process.env.TOMTOM_FAIL; }
  const key = process.env.TOMTOM_API_KEY;
  process.env.TOMTOM_API_KEY = '';
  try {
    assert.equal(traffic.enabled(), false);
    assert.equal(await traffic.current('Tashkent, UZ', 'Almaty, KZ'), null);
    assert.equal((await json(admin, 'GET', '/api/integrations/status')).map.traffic, false);
  } finally { process.env.TOMTOM_API_KEY = key; }
});
