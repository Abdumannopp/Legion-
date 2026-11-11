// Email attachments, multipart email (SendGrid / Mailgun), delivery reports, ROUTE, PULSE and SENTINEL.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, before, test } = require('node:test');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'veyra-next-'));
process.env.NODE_ENV = 'development';
process.env.DATABASE_PATH = path.join(dir, 'x.db');
process.env.PORT = '0';
process.env.BCRYPT_COST = '10';
process.env.API_RATE_LIMIT_MAX = '5000';
process.env.WEIGHT_UNIT = 'kg';
process.env.CURRENCY = 'USD';
process.env.MESSAGE_LANGUAGE = 'en';
process.env.OPENROUTER_API_KEY = 'sk-or-test';
process.env.MESSAGING_PROVIDER = 'twilio';
process.env.TWILIO_ACCOUNT_SID = 'AC00000000000000000000000000000000';
process.env.TWILIO_AUTH_TOKEN = 'platform-token-for-signature-tests';
process.env.TWILIO_SMS_FROM = '+15550001111';
process.env.TWILIO_WHATSAPP_FROM = '+15550002222';
process.env.PUBLIC_URL = 'https://veyra.test';
process.env.DOC_MAX_MB = '1';
process.env.INBOX_MAX_MB = '3';
process.env.INBOX_MAX_ATTACHMENTS = '3';

const { app, initialize } = require('../server');
const { db } = require('../database');
const aiGateway = require('../ai/gateway');
const messaging = require('../integrations/messaging');
const nexus = require('../agents/nexus');
const { parseMultipart } = require('../lib/multipart');
const { guessDocumentType, mentionedShipmentIds } = require('../lib/inbound-email');
const routeAgent = require('../agents/route');
const pulseAgent = require('../agents/pulse');
const sentinelAgent = require('../agents/sentinel');

let server;
let base;
let admin;
let otherAdmin;
let inboxToken;
let sends = [];
let aiCalls = 0;

const call = (cookie, method, url, body) => fetch(`${base}${url}`, {
  method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) }, body: body ? JSON.stringify(body) : undefined
});
const dbRun = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, (e) => (e ? reject(e) : resolve())));
const dbGet = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (e, row) => (e ? reject(e) : resolve(row))));
const dbAll = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (e, rows) => (e ? reject(e) : resolve(rows))));

async function login(email, password) {
  const res = await call(null, 'POST', '/api/login', { email, password });
  assert.equal(res.status, 200);
  return res.headers.get('set-cookie').split(';')[0];
}

const pdf = (text, size = 400) => Buffer.concat([Buffer.from(`%PDF-1.4\n${text}\n`), Buffer.alloc(size, 0x20), Buffer.from('\n%%EOF')]);
const png = (size) => Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), crypto.randomBytes(size)]);

function multipart(fields, files) {
  const boundary = `----veyra${crypto.randomBytes(8).toString('hex')}`;
  const chunks = [];
  for (const [name, value] of Object.entries(fields)) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
  }
  for (const file of files) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${file.field}"; filename="${file.filename}"\r\nContent-Type: ${file.type || 'application/octet-stream'}\r\n\r\n`), file.content, Buffer.from('\r\n'));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return { body: Buffer.concat(chunks), contentType: `multipart/form-data; boundary=${boundary}` };
}

const postMultipart = (fields, files, token = inboxToken) => {
  const form = multipart(fields, files);
  return fetch(`${base}/api/integrations/inbox/${token}`, { method: 'POST', headers: { 'content-type': form.contentType }, body: form.body });
};

async function newLoad(cookie = admin, extra = {}) {
  const res = await call(cookie, 'POST', '/api/shipments', {
    customer: 'Navoiy Textile', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-05-10', delivery: '2030-05-12',
    weight: 18000, equipment: 'Tent / Curtainsider', customerPhone: '+998 90 777 66 55', ...extra
  });
  assert.equal(res.status, 201);
  return (await res.json()).shipment.id;
}

let carrierCount = 0;
async function newCarrier(cookie = admin) {
  carrierCount += 1;
  return (await (await call(cookie, 'POST', '/api/carriers', { name: `Next Carrier ${carrierCount}`, mode: 'Truckload', phone: '+998 71 200 00 00' })).json()).carrier;
}

async function book(id, { rate = 1000, customerRate, driverPhone = '+998 91 555 22 11', truckPlate = '01 A 123 BC', cookie = admin } = {}) {
  const carrier = await newCarrier(cookie);
  await call(cookie, 'PATCH', `/api/admin/shipments/${id}/status`, { status: 'Sourcing' });
  const res = await call(cookie, 'POST', `/api/admin/shipments/${id}/dispatch`, { carrierId: carrier.id, rate, customerRate, driverPhone, truckPlate });
  assert.equal(res.status, 200);
  return carrier;
}

const setStatus = (id, status, cookie = admin) => call(cookie, 'PATCH', `/api/admin/shipments/${id}/status`, { status });
const tasks = async (cookie = admin) => (await (await call(cookie, 'GET', '/api/tasks')).json()).tasks;
const documents = async (id, cookie = admin) => (await (await call(cookie, 'GET', `/api/shipments/${id}/documents`)).json()).documents;
const num = (id) => Number(String(id).replace('SHP-', ''));

before(async () => {
  await initialize();
  server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
  admin = await login('admin@veyra.ai', 'admin123');
  messaging.setTransport(async (url, init) => {
    sends.push(new URLSearchParams(init.body));
    return new Response(JSON.stringify({ sid: `SM${sends.length}` }), { status: 201, headers: { 'content-type': 'application/json' } });
  });
  aiGateway.setTransport(async () => {
    aiCalls += 1;
    const content = JSON.stringify({ documentType: 'cmr', sender: 'Navoiy Textile', origin: 'Tashkent', destination: 'Almaty', weightKg: 18000, truckPlate: '01A123BC', confidence: 0.9 });
    return new Response(JSON.stringify({ model: 'test/model', choices: [{ message: { content } }], usage: { prompt_tokens: 10, completion_tokens: 10 } }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  inboxToken = (await (await call(admin, 'POST', '/api/settings/inbox/token')).json()).token;
  const created = await call(admin, 'POST', '/api/platform/tenants', { companyName: 'Other Logistics', adminName: 'Olim', adminEmail: 'olim@other.example', adminPassword: 'other-company-pass-1' });
  assert.equal(created.status, 201);
  otherAdmin = await login('olim@other.example', 'other-company-pass-1');
});

after(async () => {
  await nexus.idle();
  messaging.setTransport(null);
  aiGateway.setTransport(null);
  await new Promise((r) => server.close(r));
  await new Promise((r) => db.close(r));
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ---------- multipart parser ---------- */

test('multipart parser: fields, binary files, and refusal of broken or oversized forms', () => {
  const binary = crypto.randomBytes(5000);
  const form = multipart({ subject: 'Salom', text: 'line1\r\nline2' }, [{ field: 'attachment1', filename: 'a "b".pdf'.replace(/"/g, ''), content: binary }]);
  const parsed = parseMultipart(form.body, form.contentType);
  assert.equal(parsed.fields.subject, 'Salom');
  assert.equal(parsed.fields.text, 'line1\r\nline2');
  assert.equal(parsed.files.length, 1);
  assert.ok(parsed.files[0].content.equals(binary), 'file bytes are unchanged');
  assert.throws(() => parseMultipart(Buffer.from('nothing here'), form.contentType), /not a valid multipart/);
  assert.throws(() => parseMultipart(form.body, 'multipart/form-data'), /not a valid multipart/);
  const many = multipart(Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`f${i}`, 'x'])), []);
  assert.throws(() => parseMultipart(many.body, many.contentType), /too many parts/);
});

test('document type and load number are guessed from names and words', () => {
  assert.equal(guessDocumentType('CMR_123.pdf'), 'cmr');
  assert.equal(guessDocumentType('scan.pdf', 'here is the cmr'), 'cmr');
  assert.equal(guessDocumentType('POD-signed.jpg'), 'pod');
  assert.equal(guessDocumentType('IMG_0001.jpg', 'yuk topshirildi'), 'pod');
  assert.equal(guessDocumentType('podium.pdf'), null);
  assert.equal(guessDocumentType('invoice.pdf'), null);
  assert.deepEqual(mentionedShipmentIds('re: SHP-12 and shp 7, also SHP#12'), [12, 7]);
});

/* ---------- email attachments ---------- */

test('SendGrid-style multipart email that names a load: the CMR goes straight to that load and is read', async () => {
  const id = await newLoad();
  await book(id);
  await nexus.idle();
  const before = aiCalls;
  const file = pdf('cmr one');
  const res = await postMultipart(
    { from: 'Driver <driver@carrier.example>', subject: `CMR for ${id}`, text: 'CMR attached', headers: 'Received: x\r\nMessage-ID: <sg-1@mail.example>\r\nX: y' },
    [{ field: 'attachment1', filename: 'IMG_1001.pdf', type: 'application/pdf', content: file }, { field: 'attachment2', filename: 'logo.png', type: 'image/png', content: png(500) }]
  );
  assert.equal(res.status, 201);
  const body = await res.json();
  assert.equal(body.attachedTo, id);
  assert.equal(body.documents, 1, 'the tiny signature logo is not kept');
  await nexus.idle();
  const docs = await documents(id);
  assert.equal(docs.length, 1);
  assert.equal(docs[0].type, 'cmr');
  assert.equal(docs[0].filename, 'IMG_1001.pdf');
  assert.equal(docs[0].extractionStatus, 'done', 'VAULT read the file');
  assert.equal(aiCalls, before + 1, 'one AI call for the document, none for the email text');
  const download = await call(admin, 'GET', `/api/shipments/${id}/documents/${docs[0].id}/file`);
  assert.ok(Buffer.from(await download.arrayBuffer()).equals(file), 'the stored file is byte-identical');
  const task = (await tasks()).find((t) => t.shipmentId === id && /from an email/.test(t.title));
  assert.ok(task, 'a person is told');
  assert.equal((await (await call(admin, 'GET', '/api/inbox')).json()).items.some((item) => item.subject === `CMR for ${id}`), false, 'the email is not waiting in the inbox');
  // The provider retries the same email: nothing is added twice.
  const again = await postMultipart({ from: 'driver@carrier.example', subject: `CMR for ${id}`, text: 'CMR attached', headers: 'Message-ID: <sg-1@mail.example>' },
    [{ field: 'attachment1', filename: 'IMG_1001.pdf', content: file }]);
  assert.equal((await again.json()).duplicate, true);
  assert.equal((await documents(id)).length, 1);
});

test('Mailgun-style multipart and Postmark JSON attachments are accepted; fake and oversized files are dropped', async () => {
  const id = await newLoad();
  const mailgun = await postMultipart(
    { sender: 'ops@customer.example', subject: `Documents ${id}`, 'body-plain': 'see files', 'Message-Id': '<mg-1@mail.example>', 'attachment-count': '3' },
    [
      { field: 'attachment-1', filename: 'pod_signed.pdf', content: pdf('pod') },
      { field: 'attachment-2', filename: 'virus.pdf', content: Buffer.from('MZ this is not a pdf at all, just an exe pretending') },
      { field: 'attachment-3', filename: 'big.pdf', content: pdf('big', 1024 * 1024 + 10) }
    ]
  );
  assert.equal(mailgun.status, 201);
  const result = await mailgun.json();
  assert.equal(result.documents, 1);
  assert.equal(result.filesSkipped, 2);
  await nexus.idle();
  assert.deepEqual((await documents(id)).map((d) => [d.filename, d.type]), [['pod_signed.pdf', 'pod']]);

  const postmark = await call(null, 'POST', `/api/integrations/inbox/${inboxToken}`, {
    From: 'ops@customer.example', Subject: `more for ${id}`, TextBody: 'cmr scan', MessageID: 'pm-1',
    Attachments: [{ Name: '../../etc/passwd.pdf', Content: pdf('cmr two').toString('base64'), ContentType: 'application/pdf' }]
  });
  assert.equal((await postmark.json()).documents, 1);
  await nexus.idle();
  const names = (await documents(id)).map((d) => d.filename);
  assert.ok(names.includes('passwd.pdf'), 'the path is stripped from the file name');
});

test('an order email with a file: the file waits with the email and moves to the load made from it', async () => {
  const file = pdf('order sheet');
  const res = await postMultipart({ from: 'buyer@navoiy.example', subject: 'New order', text: 'Need a truck Tashkent - Almaty, 18 t', headers: 'Message-ID: <order-1@x>' },
    [{ field: 'attachment1', filename: 'order.pdf', content: file }]);
  assert.equal(res.status, 201);
  const { id: inboxId, files } = await res.json();
  assert.equal(files, 1);
  await nexus.idle();
  const item = (await (await call(admin, 'GET', '/api/inbox')).json()).items.find((entry) => entry.id === inboxId);
  assert.equal(item.attachments.length, 1);
  assert.equal(item.attachments[0].filename, 'order.pdf');
  const fileRes = await call(admin, 'GET', `/api/inbox/${inboxId}/attachments/${item.attachments[0].id}/file`);
  assert.equal(fileRes.status, 200);
  assert.match(fileRes.headers.get('content-disposition'), /attachment/);
  assert.ok(Buffer.from(await fileRes.arrayBuffer()).equals(file));
  // Another company cannot see or take the file.
  assert.equal((await call(otherAdmin, 'GET', `/api/inbox/${inboxId}/attachments/${item.attachments[0].id}/file`)).status, 404);
  assert.equal((await call(otherAdmin, 'POST', `/api/inbox/${inboxId}/attach`, { shipmentId: 'SHP-1' })).status, 404);

  const created = await call(admin, 'POST', '/api/shipments', {
    customer: 'Navoiy Textile', origin: 'Tashkent, UZ', destination: 'Almaty, KZ', pickup: '2030-06-01', delivery: '2030-06-03', weight: 18000, equipment: 'Tent / Curtainsider', inboxId
  });
  const body = await created.json();
  assert.equal(body.documentsAttached, 1);
  await nexus.idle();
  const docs = await documents(body.shipment.id);
  assert.deepEqual(docs.map((d) => [d.filename, d.type]), [['order.pdf', 'other']]);
  assert.equal((await dbGet('SELECT COUNT(*) AS n FROM inbox_attachments WHERE inbox_id = ?', [inboxId])).n, 0, 'the file was moved, not copied');
});

test('files only, no load named: a task appears and a person attaches them to a load', async () => {
  const id = await newLoad();
  const res = await postMultipart({ from: 'driver@carrier.example', subject: 'photo', headers: 'Message-ID: <only-files@x>' },
    [{ field: 'attachment1', filename: 'IMG_7.png', content: png(30000) }]);
  assert.equal(res.status, 201);
  const { id: inboxId } = await res.json();
  const before = aiCalls;
  await nexus.idle();
  assert.equal(aiCalls, before, 'no AI call for an email without text');
  const task = (await tasks()).find((t) => t.inboxId === inboxId);
  assert.equal(task.kind, 'review_intake');
  assert.equal(task.payload.files.length, 1);
  assert.equal((await call(admin, 'POST', `/api/inbox/${inboxId}/attach`, { shipmentId: 'SHP-999999' })).status, 404);
  const attach = await call(admin, 'POST', `/api/inbox/${inboxId}/attach`, { shipmentId: id });
  assert.equal(attach.status, 200);
  assert.equal((await attach.json()).documents, 1);
  await nexus.idle();
  assert.equal((await documents(id))[0].type, 'cmr');
  assert.equal((await tasks()).some((t) => t.inboxId === inboxId), false, 'the task is closed');
});

test('blocked senders: their files are never stored; another company\'s load number is not matched', async () => {
  await call(admin, 'PUT', '/api/settings/inbox', { allowedSenders: ['carrier.example', 'customer.example', 'navoiy.example'] });
  const blocked = await postMultipart({ from: 'stranger@evil.example', subject: 'SHP-1 cmr', text: 'x', headers: 'Message-ID: <blocked@x>' },
    [{ field: 'attachment1', filename: 'cmr.pdf', content: pdf('evil') }]);
  const body = await blocked.json();
  assert.equal(body.accepted, false);
  assert.equal((await dbGet('SELECT COUNT(*) AS n FROM inbox_attachments WHERE inbox_id = ?', [body.id])).n, 0);

  const foreign = await newLoad(otherAdmin);
  const res = await postMultipart({ from: 'driver@carrier.example', subject: `CMR ${foreign}`, text: 'cmr', headers: 'Message-ID: <foreign@x>' },
    [{ field: 'attachment1', filename: 'cmr.pdf', content: pdf('foreign') }]);
  const result = await res.json();
  assert.equal(result.attachedTo, undefined, 'a load of another company is not a match');
  await nexus.idle();
  assert.equal((await documents(foreign, otherAdmin)).length, 0);
  await call(admin, 'PUT', '/api/settings/inbox', { allowedSenders: [] });
});

test('the inbox address is checked before a large body is read, and an oversized email is refused', async () => {
  const big = multipart({ from: 'a@b.example', subject: 'x', text: 'y' }, [{ field: 'attachment1', filename: 'a.pdf', content: pdf('x', 3 * 1024 * 1024 + 100) }]);
  const wrong = await fetch(`${base}/api/integrations/inbox/inbox_wrongtoken`, { method: 'POST', headers: { 'content-type': big.contentType }, body: big.body });
  assert.equal(wrong.status, 404);
  const tooLarge = await fetch(`${base}/api/integrations/inbox/${inboxToken}`, { method: 'POST', headers: { 'content-type': big.contentType }, body: big.body });
  assert.equal(tooLarge.status, 413);
  const broken = await fetch(`${base}/api/integrations/inbox/${inboxToken}`, { method: 'POST', headers: { 'content-type': 'multipart/form-data; boundary=abc' }, body: 'garbage' });
  assert.equal(broken.status, 200);
  assert.equal((await broken.json()).ignored, 'unreadable');
});

/* ---------- delivery reports ---------- */

function sign(url, params, token = process.env.TWILIO_AUTH_TOKEN) {
  const data = Object.keys(params).sort().reduce((text, key) => text + key + params[key], url);
  return crypto.createHmac('sha1', token).update(data).digest('base64');
}

async function report(callbackUrl, params, { signature } = {}) {
  const pathOnly = callbackUrl.replace('https://veyra.test', '');
  return fetch(`${base}${pathOnly}`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-twilio-signature': signature ?? sign(callbackUrl, params) },
    body: new URLSearchParams(params).toString()
  });
}

test('delivery reports: sent -> delivered -> read, signed by Twilio, never moving backwards', async () => {
  const id = await newLoad();
  await book(id);
  await nexus.idle();
  sends = [];
  const sent = await call(admin, 'POST', `/api/shipments/${id}/messages`, { recipient: 'driver', channel: 'whatsapp', body: 'Where are you?' });
  assert.equal(sent.status, 201);
  const callbackUrl = sends[0].get('StatusCallback');
  assert.match(callbackUrl, /^https:\/\/veyra\.test\/api\/integrations\/twilio\/status\/[a-f0-9]{48}$/);
  const sid = 'SM1';
  const list = async () => (await (await call(admin, 'GET', `/api/shipments/${id}/messages`)).json()).messages;
  assert.equal((await list())[0].deliveryStatus, null);
  const stored = await dbGet('SELECT callback_token_hash AS h FROM messages ORDER BY id DESC LIMIT 1');
  assert.ok(stored.h && !callbackUrl.includes(stored.h), 'only a hash of the secret is stored');

  assert.equal((await report(callbackUrl, { MessageSid: sid, MessageStatus: 'delivered' }, { signature: 'AAAA' })).status, 403, 'a wrong signature is refused');
  assert.equal((await report(callbackUrl, { MessageSid: sid, MessageStatus: 'delivered' }, { signature: sign(callbackUrl, { MessageSid: sid, MessageStatus: 'delivered' }, 'another-token') })).status, 403);
  assert.equal((await report(callbackUrl.replace(/.$/, (c) => (c === 'a' ? 'b' : 'a')), { MessageSid: sid, MessageStatus: 'delivered' })).status, 404, 'an unknown address is refused');
  assert.equal((await report(callbackUrl, { MessageSid: 'SMother', MessageStatus: 'delivered' })).status, 400, 'a report for another message is refused');
  assert.equal((await list())[0].deliveryStatus, null);

  assert.equal((await report(callbackUrl, { MessageSid: sid, MessageStatus: 'delivered' })).status, 204);
  assert.equal((await list())[0].deliveryStatus, 'delivered');
  await report(callbackUrl, { MessageSid: sid, MessageStatus: 'sent' });
  assert.equal((await list())[0].deliveryStatus, 'delivered', 'a late "sent" does not overwrite "delivered"');
  await report(callbackUrl, { MessageSid: sid, MessageStatus: 'read' });
  assert.equal((await list())[0].deliveryStatus, 'read');
  await report(callbackUrl, { MessageSid: sid, MessageStatus: 'failed', ErrorCode: '30003' });
  assert.equal((await list())[0].deliveryStatus, 'read', 'a read message cannot become failed');
  await report(callbackUrl, { MessageSid: sid, MessageStatus: 'hacked' });
  assert.equal((await list())[0].deliveryStatus, 'read');
});

test('an undelivered message makes a task to call instead', async () => {
  const id = await newLoad();
  await book(id);
  await nexus.idle();
  sends = [];
  await call(admin, 'POST', `/api/shipments/${id}/messages`, { recipient: 'driver', channel: 'sms', body: 'Hello' });
  const callbackUrl = sends[0].get('StatusCallback');
  const params = { MessageSid: 'SM1', MessageStatus: 'undelivered', ErrorCode: '30005' };
  assert.equal((await report(callbackUrl, params)).status, 204);
  assert.equal((await report(callbackUrl, params)).status, 204);
  await nexus.idle();
  const message = (await (await call(admin, 'GET', `/api/shipments/${id}/messages`)).json()).messages[0];
  assert.equal(message.deliveryStatus, 'undelivered');
  assert.equal(message.errorCode, '30005');
  const failed = (await tasks()).filter((t) => t.shipmentId === id && /was not delivered/.test(t.title));
  assert.equal(failed.length, 1, 'one task, even when the report comes twice');
  assert.match(failed[0].payload.text, /30005/);
  const risks = (await (await call(admin, 'GET', '/api/agents/sentinel')).json()).risks;
  assert.ok(risks.some((risk) => risk.shipmentId === id && risk.type === 'message_failed'));
});

/* ---------- ROUTE ---------- */

async function deliveredLoad({ hours, rate, customerRate, origin = 'Samarkand, UZ', destination = 'Moscow, RU', equipment = 'Tent / Curtainsider' }) {
  const id = await newLoad(admin, { origin, destination, equipment });
  await book(id, { rate, customerRate });
  await setStatus(id, 'In Transit');
  await setStatus(id, 'Delivered');
  await dbRun("UPDATE shipment_events SET created_at = datetime('now', ?) WHERE shipment_id = ? AND to_status = 'In Transit'", [`-${hours + 1} hours`, num(id)]);
  await dbRun("UPDATE shipment_events SET created_at = datetime('now', '-1 hours') WHERE shipment_id = ? AND to_status = 'Delivered'", [num(id)]);
  return id;
}

test('ROUTE: says nothing without history, then judges the schedule and finds a return truck', async () => {
  const lonely = await newLoad(admin, { origin: 'Nukus, UZ', destination: 'Aktau, KZ' });
  const none = await (await call(admin, 'GET', `/api/agents/route/${lonely}`)).json();
  assert.equal(none.schedule.verdict, 'unknown');
  assert.equal(none.arrival, null);

  for (const hours of [90, 100, 110]) await deliveredLoad({ hours, rate: 2000, customerRate: 2400 });
  await nexus.idle();
  const tight = await newLoad(admin, { origin: 'Samarkand, UZ', destination: 'Moscow, RU', pickup: '2030-07-01', delivery: '2030-07-03' });
  const plan = await (await call(admin, 'GET', `/api/agents/route/${tight}`)).json();
  assert.equal(plan.lane.loads, 3);
  assert.equal(plan.lane.typicalHours, 100);
  assert.equal(plan.schedule.verdict, 'tight', '3 days are allowed, the lane takes about 4');
  assert.equal(plan.arrival.late, true);
  const roomy = await newLoad(admin, { origin: 'samarkand, uz', destination: 'MOSCOW, RU', pickup: '2030-07-01', delivery: '2030-07-06' });
  const fine = await (await call(admin, 'GET', `/api/agents/route/${roomy}`)).json();
  assert.equal(fine.schedule.verdict, 'ok');
  assert.equal(fine.arrival.late, false);

  // A truck that unloads in Samarkand just before the pickup is a return-load candidate.
  const inbound = await newLoad(admin, { origin: 'Bukhara, UZ', destination: 'Samarkand, UZ', pickup: '2030-06-28', delivery: '2030-06-30' });
  const carrier = await book(inbound);
  const withTruck = await (await call(admin, 'GET', `/api/agents/route/${tight}`)).json();
  assert.equal(withTruck.returnTrucks.length, 1);
  assert.equal(withTruck.returnTrucks[0].name, carrier.name);
  assert.equal((await call(otherAdmin, 'GET', `/api/agents/route/${tight}`)).status, 404);
});

/* ---------- PULSE ---------- */

test('PULSE: lane prices, a suggested customer price, and warnings for unusual prices', async () => {
  const id = await newLoad(admin, { origin: 'Samarkand, UZ', destination: 'Moscow, RU' });
  const base0 = await (await call(admin, 'GET', `/api/agents/pulse/${id}`)).json();
  assert.equal(base0.carrier.typical, 2000);
  assert.equal(base0.customer.typical, 2400);
  assert.equal(base0.flags.length, 0);
  const priced = await (await call(admin, 'GET', `/api/agents/pulse/${id}?rate=2100`)).json();
  assert.equal(priced.suggestedCustomerPrice, 2520, 'carrier price plus the usual margin');
  const high = await (await call(admin, 'GET', `/api/agents/pulse/${id}?rate=3000&customerRate=2900`)).json();
  assert.deepEqual(high.flags.map((flag) => flag.code).sort(), ['carrier_high', 'loss']);
  assert.equal(high.margin.amount, -100);
  assert.equal((await call(admin, 'GET', `/api/agents/pulse/${id}?rate=abc`)).status, 400);
  assert.equal((await call(otherAdmin, 'GET', `/api/agents/pulse/${id}`)).status, 404);

  const fresh = await newLoad(admin, { origin: 'Termez, UZ', destination: 'Dushanbe, TJ' });
  const empty = await (await call(admin, 'GET', `/api/agents/pulse/${fresh}?rate=500&customerRate=510`)).json();
  assert.equal(empty.enoughHistory, false);
  assert.deepEqual(empty.flags.map((flag) => flag.code), ['thin_margin'], 'a thin margin is flagged even without history');

  // Booking at a losing price leaves a task.
  await book(id, { rate: 3000, customerRate: 2900 });
  await nexus.idle();
  const task = (await tasks()).find((t) => t.shipmentId === id && /Check the prices/.test(t.title));
  assert.ok(task);
  assert.match(task.payload.text, /loses/);
});

test('PULSE pure rules: same-trailer history is preferred when there is enough of it', () => {
  const history = [
    ...[100, 110, 120].map((rate) => ({ rate, customerRate: rate * 1.25, equipment: 'Reefer' })),
    ...[10, 11, 12, 13].map((rate) => ({ rate, customerRate: rate * 2, equipment: 'Dry Van' }))
  ];
  const result = pulseAgent.analyzePrices({ shipment: { equipment: 'Reefer', rate: null, customer_rate: null }, history });
  assert.equal(result.carrier.typical, 110);
  assert.match(result.basis, /Reefer/);
  const mixed = pulseAgent.analyzePrices({ shipment: { equipment: 'Flatbed', rate: null, customer_rate: null }, history });
  assert.equal(mixed.carrier.loads, 7);
});

/* ---------- SENTINEL ---------- */

test('SENTINEL pure rules: each risk appears only when it should', () => {
  const now = Date.parse('2030-03-10T12:00:00Z');
  const load = (extra) => ({ id: 1, customer: 'C', origin: 'A', destination: 'B', pickup: '2030-03-10', delivery: '2030-03-12', status: 'New', driverPhone: '+1', truckPlate: 'X', eta: null, lastSignOfLife: '2030-03-10 11:00:00', failedMessages: 0, ...extra });
  const types = (extra) => sentinelAgent.assessLoad(load(extra), { now, staleHours: 12 }).map((risk) => risk.type);
  assert.deepEqual(types({}), ['no_carrier']);
  assert.deepEqual(types({ pickup: '2030-03-11' }), ['no_carrier']);
  assert.deepEqual(types({ pickup: '2030-03-15' }), []);
  assert.deepEqual(types({ status: 'Dispatched' }), []);
  assert.deepEqual(types({ status: 'Dispatched', pickup: '2030-03-09' }), ['late_pickup']);
  assert.deepEqual(types({ status: 'In Transit', pickup: '2030-03-05', delivery: '2030-03-09' }), ['late_delivery']);
  assert.deepEqual(types({ status: 'In Transit', pickup: '2030-03-09', eta: '2030-03-13T10:00' }), ['eta_after_delivery']);
  assert.deepEqual(types({ status: 'In Transit', pickup: '2030-03-09', eta: '2030-03-12T10:00' }), []);
  assert.deepEqual(types({ status: 'Dispatched', driverPhone: null }), ['missing_driver']);
  assert.deepEqual(types({ status: 'In Transit', pickup: '2030-03-09', lastSignOfLife: '2030-03-09 20:00:00' }), ['silent']);
  assert.deepEqual(types({ status: 'Exception', pickup: '2030-03-09' }), ['exception']);
  assert.deepEqual(types({ pickup: 'Today', delivery: 'Next Day' }), [], 'old free-text dates are ignored, not guessed');
  assert.equal(sentinelAgent.assessLoad(load({}), { now })[0].severity, 'high');
});

test('SENTINEL sweep: one task per risk, closed by itself when the risk is gone, per company', async () => {
  const today = new Date().toISOString().slice(0, 10);
  const id = await newLoad(admin, { pickup: today, delivery: '2031-01-01', origin: 'Fergana, UZ', destination: 'Osh, KG' });
  const foreign = await newLoad(otherAdmin, { pickup: today, delivery: '2031-01-01' });
  const riskTasks = async (cookie, load) => (await tasks(cookie)).filter((t) => t.shipmentId === load && /no truck booked/.test(t.title));
  await nexus.sentinelSweep();
  assert.equal((await riskTasks(admin, id)).length, 1);
  assert.equal((await riskTasks(otherAdmin, foreign)).length, 1);
  assert.equal((await riskTasks(admin, foreign)).length, 0, 'one company never sees another company\'s risk');
  assert.equal(await nexus.sentinelSweep(), 0, 'running again adds nothing');
  const listed = (await (await call(admin, 'GET', '/api/agents/sentinel')).json()).risks;
  assert.ok(listed.some((risk) => risk.shipmentId === id && risk.type === 'no_carrier' && risk.severity === 'high'));
  assert.ok(!listed.some((risk) => risk.shipmentId === foreign));

  await book(id);
  await nexus.idle();
  await nexus.sentinelSweep();
  assert.equal((await riskTasks(admin, id)).length, 0, 'the truck was booked, so the warning closed by itself');
  assert.equal((await riskTasks(otherAdmin, foreign)).length, 1);

  // A dismissed warning does not come back.
  const [task] = await riskTasks(otherAdmin, foreign);
  await call(otherAdmin, 'POST', `/api/tasks/${task.id}/dismiss`);
  await nexus.sentinelSweep();
  assert.equal((await riskTasks(otherAdmin, foreign)).length, 0);
  assert.equal((await dbAll("SELECT id FROM nexus_tasks WHERE dedupe_key LIKE 'risk:%' AND status = 'open' AND shipment_id = ?", [num(foreign)])).length, 0);
});

test('ROUTE pure rules: median and durations', () => {
  assert.equal(routeAgent.median([5, 1, 3]), 3);
  assert.equal(routeAgent.median([4, 2]), 3);
  assert.equal(routeAgent.parseDay('2030-02-30') === null || Number.isFinite(routeAgent.parseDay('2030-02-30')), true);
  assert.equal(routeAgent.parseDay('Today'), null);
});
