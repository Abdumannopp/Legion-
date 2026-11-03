const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

// Runs the server the way it runs on a real host: production mode, no demo users.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-prod-'));
process.env.NODE_ENV = 'production';
process.env.JWT_SECRET = 'test-only-secret-0123456789abcdef';
process.env.INITIAL_ADMIN_NAME = 'Owner';
process.env.INITIAL_ADMIN_EMAIL = 'owner@example.com';
process.env.INITIAL_ADMIN_PASSWORD = 'a-long-initial-password-1';
process.env.DATABASE_PATH = path.join(dir, 'p.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
delete process.env.REGISTRATION_INVITE_CODE;
delete process.env.ALLOW_OPEN_REGISTRATION;

const { app, initialize } = require('../server');
const { db } = require('../database');

let server;
let base;

const post = (url, body) => fetch(`${base}${url}`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
});

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

test('production closes public sign-up by default', async () => {
  const config = await (await fetch(`${base}/api/config`)).json();
  assert.equal(config.registration, 'closed');
  const res = await post('/api/register', { name: 'Stranger', email: 'stranger@example.com', password: 'Password123' });
  assert.equal(res.status, 403);
});

test('production has no demo accounts, only the configured owner', async () => {
  assert.equal((await post('/api/login', { email: 'admin@veyra.ai', password: 'admin123' })).status, 401);
  const res = await post('/api/login', { email: 'owner@example.com', password: 'a-long-initial-password-1' });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('set-cookie'), /HttpOnly/i);
  assert.match(res.headers.get('set-cookie'), /Secure/i);
});
