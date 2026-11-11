// Mailbox reading over IMAP (against a fake local IMAP server), and the email parser.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-imap-'));
Object.assign(process.env, {
  NODE_ENV: 'development', DATABASE_PATH: path.join(dir, 'i.db'), PORT: '0', BCRYPT_COST: '10', API_RATE_LIMIT_MAX: '5000',
  CURRENCY: 'USD', MESSAGE_LANGUAGE: 'en', OPENROUTER_API_KEY: 'sk-or-test', DOC_MAX_MB: '1', INBOX_MAX_MB: '2'
});
const { app, initialize } = require('../server');
const { db } = require('../database');
const aiGateway = require('../ai/gateway');
const imap = require('../integrations/imap');
const nexus = require('../agents/nexus');
const { parseEmail, decodeWords } = require('../lib/mime');

let server; let base; let admin; let operator; let other;
let fake;
const call = (cookie, method, url, body) => fetch(`${base}${url}`, { method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
const json = async (...args) => (await call(...args)).json();
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => (e ? reject(e) : resolve(row))));
async function login(email, password) {
  return (await call(null, 'POST', '/api/login', { email, password })).headers.get('set-cookie').split(';')[0];
}

// ---- a tiny fake IMAP server ----
function startFakeImap() {
  const state = { password: 'right-pass', uidValidity: 7, messages: [], commands: [], connections: 0 };
  const srv = net.createServer((socket) => {
    state.connections += 1;
    socket.write('* OK fake imap ready\r\n');
    let pending = '';
    socket.on('data', (chunk) => {
      pending += chunk.toString('latin1');
      let index;
      while ((index = pending.indexOf('\r\n')) !== -1) {
        const line = pending.slice(0, index);
        pending = pending.slice(index + 2);
        const [tag, command, ...rest] = line.split(' ');
        state.commands.push(`${command} ${rest.join(' ')}`.trim());
        const upper = command.toUpperCase();
        if (upper === 'LOGIN') {
          const ok = rest.join(' ').includes(`"${state.password}"`);
          socket.write(ok ? `${tag} OK LOGIN completed\r\n` : `${tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n`);
        } else if (upper === 'EXAMINE') {
          const next = (state.messages.at(-1)?.uid || 0) + 1;
          socket.write(`* 3 EXISTS\r\n* OK [UIDVALIDITY ${state.uidValidity}] ok\r\n* OK [UIDNEXT ${next}] ok\r\n${tag} OK [READ-ONLY] EXAMINE completed\r\n`);
        } else if (upper === 'UID' && rest[0].toUpperCase() === 'SEARCH') {
          const from = Number(/UID (\d+):\*/.exec(line)[1]);
          const uids = state.messages.map((m) => m.uid).filter((uid) => uid >= from);
          const answer = uids.length ? uids : (state.messages.length ? [state.messages.at(-1).uid] : []);
          socket.write(`* SEARCH ${answer.join(' ')}\r\n${tag} OK SEARCH completed\r\n`);
        } else if (upper === 'UID' && rest[0].toUpperCase() === 'FETCH') {
          const message = state.messages.find((m) => m.uid === Number(rest[1]));
          if (/RFC822\.SIZE/.test(line)) socket.write(`* 1 FETCH (UID ${message.uid} RFC822.SIZE ${message.raw.length})\r\n${tag} OK FETCH completed\r\n`);
          else {
            socket.write(Buffer.concat([Buffer.from(`* 1 FETCH (UID ${message.uid} BODY[] {${message.raw.length}}\r\n`), message.raw, Buffer.from(`)\r\n${tag} OK FETCH completed\r\n`)]));
          }
        } else if (upper === 'LOGOUT') {
          socket.write(`* BYE\r\n${tag} OK LOGOUT completed\r\n`);
          socket.end();
        } else {
          socket.write(`${tag} BAD unknown command\r\n`);
        }
      }
    });
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve({ srv, state, port: srv.address().port })));
}

const pdf = (text) => Buffer.from(`%PDF-1.4\n${text}\n${' '.repeat(300)}\n%%EOF`);
const wrap64 = (buffer) => buffer.toString('base64').replace(/(.{76})/g, '$1\r\n');
function email({ from = 'Driver <driver@carrier.example>', subject, text = 'hello', messageId, files = [], extra = '' }) {
  const boundary = `b${crypto.randomBytes(6).toString('hex')}`;
  const parts = [`--${boundary}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n${text}\r\n`];
  for (const file of files) {
    parts.push(`--${boundary}\r\nContent-Type: application/pdf; name="${file.name}"\r\nContent-Disposition: attachment; filename="${file.name}"\r\nContent-Transfer-Encoding: base64\r\n\r\n${wrap64(file.content)}\r\n`);
  }
  return Buffer.from(`From: ${from}\r\nTo: orders@company.example\r\nSubject: ${subject}\r\nMessage-ID: <${messageId}>\r\n${extra}MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="${boundary}"\r\n\r\n${parts.join('')}--${boundary}--\r\n`, 'latin1');
}
let uidCounter = 0;
const deliver = (raw) => { uidCounter += 1; fake.state.messages.push({ uid: 100 + uidCounter, raw }); };

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  operator = await login('demo@veyra.ai', 'demo123');
  await call(admin, 'POST', '/api/platform/tenants', { companyName: 'Imap Other', adminName: 'Ivan', adminEmail: 'ivan@imap.example', adminPassword: 'imap-other-pass-12' });
  other = await login('ivan@imap.example', 'imap-other-pass-12');
  fake = await startFakeImap();
  process.env.IMAP_ALLOW_PRIVATE = 'true';
  imap.setConnector(async () => net.connect(fake.port, '127.0.0.1'));
  aiGateway.setTransport(async () => new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({ customer: 'Navoiy', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 18, weightUnit: 't', equipment: 'Reefer', questions: [], confidence: 0.9 }) } }] }), { status: 200 }));
});
after(async () => {
  await nexus.idle();
  imap.setConnector(null); aiGateway.setTransport(null);
  await new Promise((r) => fake.srv.close(r));
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

const settings = { host: 'imap.company.example', port: 993, user: 'orders@company.example', password: 'right-pass', mailbox: 'INBOX' };
const status = async (cookie = admin) => (await json(cookie, 'GET', '/api/integrations/status')).mailbox;

test('email parser: nested multipart, base64 file, quoted-printable and encoded words', () => {
  assert.equal(decodeWords('=?utf-8?B?0KHQsNC70L7QvA==?= =?UTF-8?Q?yuk_=C2=B7_1?='), 'Саломyuk · 1');
  const file = pdf('cmr');
  const nested = Buffer.from([
    'From: =?utf-8?Q?Dilya_=D0=A1?= <dilya@navoiy.example>', 'Subject: =?utf-8?B?0JfQsNC60LDQtyBTSFAtMTI=?=', 'Message-ID: <abc@x>',
    'Content-Type: multipart/mixed; boundary="outer"', '', '--outer', 'Content-Type: multipart/alternative; boundary="inner"', '',
    '--inner', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'Salom=2C yuk kerak =\r\nTashkent', '--inner',
    'Content-Type: text/html; charset=utf-8', '', '<p>Salom</p>', '--inner--', '--outer', 'Content-Type: application/pdf', "Content-Disposition: attachment; filename*=UTF-8''cmr%20%D1%81%D0%BA%D0%B0%D0%BD.pdf",
    'Content-Transfer-Encoding: base64', '', wrap64(file), '--outer--', ''].join('\r\n'), 'latin1');
  const parsed = parseEmail(nested);
  assert.equal(parsed.subject, 'Заказ SHP-12');
  assert.equal(parsed.from, 'Dilya С <dilya@navoiy.example>');
  assert.equal(parsed.messageId, 'abc@x');
  assert.equal(parsed.text, 'Salom, yuk kerak Tashkent');
  assert.equal(parsed.html, '<p>Salom</p>');
  assert.equal(parsed.attachments.length, 1);
  assert.equal(parsed.attachments[0].filename, 'cmr скан.pdf');
  assert.ok(parsed.attachments[0].content.equals(file), 'the file is byte-identical');
  assert.doesNotThrow(() => parseEmail(Buffer.from('garbage\r\n\r\nno structure')));
  assert.doesNotThrow(() => parseEmail(Buffer.from('Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n--x\r\n--x')));
});

test('private network addresses are recognised', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.9', '172.20.0.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:10.0.0.1']) assert.equal(imap.isPrivateAddress(ip), true, ip);
  for (const ip of ['8.8.8.8', '172.32.0.1', '2606:4700::1111']) assert.equal(imap.isPrivateAddress(ip), false, ip);
});

test('settings: admin only, checked by logging in, the password is never shown, a private address is refused', async () => {
  assert.equal((await call(operator, 'PUT', '/api/settings/imap', settings)).status, 403);
  assert.equal((await call(admin, 'PUT', '/api/settings/imap', { ...settings, host: 'not a host' })).status, 400);
  assert.equal((await call(admin, 'PUT', '/api/settings/imap', { ...settings, password: '' })).status, 400);
  const wrong = await call(admin, 'PUT', '/api/settings/imap', { ...settings, password: 'wrong-pass' });
  assert.equal(wrong.status, 400);
  assert.match((await wrong.json()).message, /user name and password/);
  assert.equal((await status()).configured, false, 'nothing is saved after a failed check');

  imap.setConnector(null);
  process.env.IMAP_ALLOW_PRIVATE = 'false';
  const blocked = await call(admin, 'PUT', '/api/settings/imap', { ...settings, host: 'localhost' });
  assert.equal(blocked.status, 400);
  assert.match((await blocked.json()).message, /private network/);
  process.env.IMAP_ALLOW_PRIVATE = 'true';
  imap.setConnector(async () => net.connect(fake.port, '127.0.0.1'));

  deliver(email({ subject: 'old mail before connecting', messageId: 'old-1' }));
  const saved = await call(admin, 'PUT', '/api/settings/imap', settings);
  assert.equal(saved.status, 200);
  const text = JSON.stringify(await saved.json()) + JSON.stringify(await status());
  assert.ok(!text.includes('right-pass'), 'the password is not in any response');
  const stored = await dbGet('SELECT imap_config AS c FROM tenants WHERE id = 1');
  assert.ok(stored.c.startsWith('v1:') && !stored.c.includes('right-pass'), 'stored encrypted');
  assert.equal((await status()).configured, true);
  assert.equal((await status()).host, 'imap.company.example');
  assert.equal((await status(other)).configured, false);
});

test('old mail is not imported; new mail is: a CMR for a named load, an order, and a blocked sender', async () => {
  await new Promise((r) => setTimeout(r, 100)); // the first check after saving only remembers the end of the mailbox
  const before = await json(admin, 'GET', '/api/inbox');
  assert.equal(before.items.length, 0, 'the old message was not imported');

  const loadRes = await json(admin, 'POST', '/api/shipments', { customer: 'Navoiy', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12', weight: 100, equipment: 'Reefer' });
  const id = loadRes.shipment.id;
  deliver(email({ subject: `CMR for ${id}`, text: 'CMR attached', messageId: 'cmr-1', files: [{ name: 'scan_1.pdf', content: pdf('one') }] }));
  deliver(email({ from: 'buyer@navoiy.example', subject: 'New order', text: 'Need a reefer Tashkent to Almaty, 18 t', messageId: 'order-1' }));
  const check = await json(admin, 'POST', '/api/settings/imap/check');
  assert.equal(check.success, true);
  assert.equal(check.imported, 2);
  await nexus.idle();

  const docs = (await json(admin, 'GET', `/api/shipments/${id}/documents`)).documents;
  assert.deepEqual(docs.map((d) => [d.filename, d.type]), [['scan_1.pdf', 'cmr']]);
  const tasks = (await json(admin, 'GET', '/api/tasks')).tasks;
  assert.ok(tasks.some((t) => t.kind === 'review_intake' && /Tashkent/.test(t.title)), 'the order became a task');
  assert.ok(tasks.some((t) => /from an email/.test(t.title) && t.shipmentId === id));

  const again = await json(admin, 'POST', '/api/settings/imap/check');
  assert.equal(again.imported, 0, 'nothing new, nothing imported twice');
  assert.equal((await status()).lastError, null);
  assert.ok((await status()).lastCheckedAt);
  assert.ok(!fake.state.commands.some((c) => /^UID STORE|^STORE|^SELECT|^DELETE|^EXPUNGE/i.test(c)), 'the mailbox is only read, never changed');
  assert.ok(fake.state.commands.every((c) => !/BODY\[/.test(c) || /BODY\.PEEK/.test(c)), 'messages are not marked as read');
  assert.equal((await json(other, 'GET', '/api/inbox')).items.length, 0);
});

test('a failing mailbox is reported, wrong password included, and reading resumes when it works again', async () => {
  fake.state.password = 'changed-pass';
  deliver(email({ subject: 'waits', text: 'order while locked out', messageId: 'wait-1' }));
  const failed = await call(admin, 'POST', '/api/settings/imap/check');
  assert.equal(failed.status, 502);
  assert.match((await status()).lastError, /user name and password/);
  fake.state.password = 'right-pass';
  const ok = await json(admin, 'POST', '/api/settings/imap/check');
  assert.equal(ok.imported, 1, 'the message that arrived while it failed is read now, not lost');
  assert.equal((await status()).lastError, null);
});

test('a renumbered mailbox is not re-imported; an oversized message is skipped; removal works', async () => {
  fake.state.uidValidity = 99;
  deliver(email({ subject: 'after renumbering', text: 'x', messageId: 'renum-1' }));
  assert.equal((await json(admin, 'POST', '/api/settings/imap/check')).imported, 0, 'a new numbering starts from the end, it does not re-read everything');
  deliver(email({ subject: 'huge', text: 'x', messageId: 'huge-1', files: [{ name: 'big.pdf', content: pdf('x'.repeat(2.5 * 1024 * 1024)) }] }));
  deliver(email({ subject: 'small', text: 'a normal order Tashkent Almaty', messageId: 'small-1' }));
  const check = await json(admin, 'POST', '/api/settings/imap/check');
  assert.equal(check.imported, 1);
  assert.equal(check.skipped, 1);
  assert.equal((await call(operator, 'DELETE', '/api/settings/imap')).status, 403);
  assert.equal((await call(admin, 'DELETE', '/api/settings/imap')).status, 200);
  assert.equal((await status()).configured, false);
  assert.equal((await call(admin, 'POST', '/api/settings/imap/check')).status, 400);
});
