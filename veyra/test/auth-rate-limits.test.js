const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const testDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-auth-rate-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(testDirectory, 'auth-rate.db');
process.env.PORT = '0';

const { app, initialize } = require('../server');
const { db } = require('../database');

let server;

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  await new Promise((resolve, reject) => {
    db.close((error) => (error ? reject(error) : resolve()));
  });
  fs.rmSync(testDirectory, { recursive: true, force: true });
});

test('valid login still succeeds for a normal user', async () => {
  const port = server.address().port;
  const response = await fetch(`http://127.0.0.1:${port}/api/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'demo@veyra.ai', password: 'demo123' })
  });

  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.success, true);
  assert.equal(payload.user.email, 'demo@veyra.ai');
});

test('login rate limiter blocks repeated failed attempts with 429', async () => {
  const port = server.address().port;
  const email = 'rate.limit@example.com';

  let lastStatus = 200;
  for (let index = 0; index < 9; index += 1) {
    const response = await fetch(`http://127.0.0.1:${port}/api/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password: 'wrong-password' })
    });
    lastStatus = response.status;
  }

  assert.equal(lastStatus, 429);
});

test('registration rate limiter returns 429 after the configured attempt budget', async () => {
  const port = server.address().port;
  let lastResponse;

  for (let index = 0; index < 6; index += 1) {
    lastResponse = await fetch(`http://127.0.0.1:${port}/api/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({})
    });
  }

  assert.equal(lastResponse.status, 429);
  assert.ok(Number(lastResponse.headers.get('retry-after')) > 0);
});
