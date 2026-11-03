const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-users-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'u.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
process.env.API_RATE_LIMIT_MAX = '5000';
process.env.LOGIN_RATE_LIMIT_ACCOUNT_MAX = '5';

const { app, initialize } = require('../server');
const { db } = require('../database');

let server;
let base;
let admin;

const post = (url, body, headers = {}) => fetch(`${base}${url}`, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body)
});
const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined
});

async function login(email, password) {
  const res = await post('/api/login', { email, password });
  assert.equal(res.status, 200, `login ${email}`);
  return res.headers.get('set-cookie').split(';')[0];
}

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
});

after(async () => {
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('admin adds a team member who can then sign in', async () => {
  const res = await call(admin, 'POST', '/api/admin/users', { name: 'Dilnoza Rahimova', email: 'Dilnoza@Example.com', password: 'Dispatch2026', role: 'operator' });
  assert.equal(res.status, 201);
  const { user } = await res.json();
  assert.equal(user.email, 'dilnoza@example.com');
  assert.equal(user.active, true);
  assert.equal(user.password, undefined);

  const cookie = await login('dilnoza@example.com', 'Dispatch2026');
  const me = await (await call(cookie, 'GET', '/api/me')).json();
  assert.equal(me.user.role, 'operator');

  assert.equal((await call(admin, 'POST', '/api/admin/users', { name: 'Dup', email: 'dilnoza@example.com', password: 'Dispatch2026', role: 'operator' })).status, 409);
  for (const body of [
    { name: 'X', email: 'x@example.com', password: 'short1', role: 'operator' },
    { name: 'X', email: 'x@example.com', password: 'Dispatch2026', role: 'superuser' },
    { name: '', email: 'x@example.com', password: 'Dispatch2026', role: 'operator' },
    { name: 'X', email: 'not-an-email', password: 'Dispatch2026', role: 'operator' }
  ]) {
    assert.equal((await call(admin, 'POST', '/api/admin/users', body)).status, 400, JSON.stringify(body));
  }
});

test('only admins manage users', async () => {
  const ops = await login('ops@veyra.ai', 'ops123');
  assert.equal((await call(ops, 'GET', '/api/admin/users')).status, 200, 'operations may read the team');
  assert.equal((await call(ops, 'POST', '/api/admin/users', { name: 'X', email: 'y@example.com', password: 'Dispatch2026', role: 'admin' })).status, 403);
  assert.equal((await call(ops, 'PATCH', '/api/admin/users/1', { active: false })).status, 403);
});

test('a role change applies to the open session immediately', async () => {
  const created = await (await call(admin, 'POST', '/api/admin/users', { name: 'Promo Ted', email: 'ted@example.com', password: 'Dispatch2026', role: 'operator' })).json();
  const cookie = await login('ted@example.com', 'Dispatch2026');
  assert.equal((await call(cookie, 'GET', '/api/analytics')).status, 403);

  const res = await call(admin, 'PATCH', `/api/admin/users/${created.user.id}`, { role: 'operations' });
  assert.equal(res.status, 200);
  // Sessions are revoked on change, so the old cookie no longer works; a new login carries the new role.
  assert.equal((await call(cookie, 'GET', '/api/me')).status, 401);
  const fresh = await login('ted@example.com', 'Dispatch2026');
  assert.equal((await call(fresh, 'GET', '/api/analytics')).status, 200);
});

test('a disabled account is locked out at once and cannot sign in', async () => {
  const created = await (await call(admin, 'POST', '/api/admin/users', { name: 'Leaving Lee', email: 'lee@example.com', password: 'Dispatch2026', role: 'operator' })).json();
  const cookie = await login('lee@example.com', 'Dispatch2026');
  assert.equal((await call(cookie, 'GET', '/api/shipments')).status, 200);

  assert.equal((await call(admin, 'PATCH', `/api/admin/users/${created.user.id}`, { active: false })).status, 200);
  assert.equal((await call(cookie, 'GET', '/api/shipments')).status, 401);
  const relogin = await post('/api/login', { email: 'lee@example.com', password: 'Dispatch2026' });
  assert.equal(relogin.status, 401);

  const list = (await (await call(admin, 'GET', '/api/admin/users')).json()).users;
  assert.equal(list.find((u) => u.email === 'lee@example.com').active, false);

  assert.equal((await call(admin, 'PATCH', `/api/admin/users/${created.user.id}`, { active: true })).status, 200);
  await login('lee@example.com', 'Dispatch2026');
});

test('admins cannot lock themselves out or remove the last admin', async () => {
  assert.equal((await call(admin, 'PATCH', '/api/admin/users/1', { active: false })).status, 409, 'own account');
  for (const body of [{}, { role: 'owner' }, { active: 'no' }]) {
    assert.equal((await call(admin, 'PATCH', '/api/admin/users/2', body)).status, 400, JSON.stringify(body));
  }
  assert.equal((await call(admin, 'PATCH', '/api/admin/users/99999', { active: false })).status, 404);

  // Demoting another admin is fine while an active admin (the actor) remains; their session ends at once.
  const second = await (await call(admin, 'POST', '/api/admin/users', { name: 'Second Admin', email: 'admin2@example.com', password: 'Dispatch2026', role: 'admin' })).json();
  const admin2 = await login('admin2@example.com', 'Dispatch2026');
  assert.equal((await call(admin, 'PATCH', `/api/admin/users/${second.user.id}`, { role: 'operations' })).status, 200);
  assert.equal((await call(admin2, 'GET', '/api/me')).status, 401, 'demoted admin session revoked');
});

test('password guessing spread across many IP addresses is still limited per account', async () => {
  let last;
  for (let i = 0; i < 6; i += 1) {
    last = await post('/api/login', { email: 'ops@veyra.ai', password: 'wrong-guess' }, { 'x-forwarded-for': `203.0.113.${i + 1}` });
  }
  assert.equal(last.status, 429);
  assert.ok(Number(last.headers.get('retry-after')) > 0);
});
