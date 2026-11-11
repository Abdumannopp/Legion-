// A small read-only IMAP client: connect over TLS, log in, look at the mailbox, fetch new messages.
// Written without dependencies on purpose (fewer things to trust). It uses only these commands:
// LOGIN, EXAMINE (read-only: nothing is marked read or changed in the mailbox), UID SEARCH, UID FETCH,
// LOGOUT. The password is sent only inside TLS, and the server certificate is always checked.
//
// A company points VEYRA at a mailbox (for example orders@theircompany.com); VEYRA reads new messages
// and treats them exactly like emails posted to the inbox address. Messages that were already in the
// mailbox before it was connected are not imported.
const tls = require('tls');
const dns = require('dns').promises;
const net = require('net');

const MAX_LITERAL = 40 * 1024 * 1024;
const MAX_UNREAD_BUFFER = 64 * 1024 * 1024;
const IDLE_TIMEOUT_MS = 30000;

let connector = null;
// Tests replace the network with a local fake server: connector(config) -> Promise<socket>.
function setConnector(fn) {
  connector = fn || null;
}

const isPrivateAddress = (address) => {
  const ip = String(address).toLowerCase().replace(/^::ffff:/, '');
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  return ip === '::1' || ip === '::' || /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip);
};

// The server must not be turned into a tool for probing its own network: private addresses are refused
// unless the owner allows them (IMAP_ALLOW_PRIVATE=true, e.g. a mail server in the same private network).
async function resolveHost(host) {
  let addresses;
  try {
    addresses = (await dns.lookup(host, { all: true })).map((entry) => entry.address);
  } catch (_) {
    throw new Error('That mail server name was not found. Check the spelling.');
  }
  if (!addresses.length) throw new Error('The mail server address could not be found.');
  if (process.env.IMAP_ALLOW_PRIVATE !== 'true' && addresses.some(isPrivateAddress)) {
    throw new Error('That address is inside a private network and is not allowed.');
  }
  return addresses[0];
}

async function openSocket(config) {
  if (connector) return connector(config);
  const address = await resolveHost(config.host);
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: address, port: config.port, servername: config.host, rejectUnauthorized: true });
    socket.setTimeout(IDLE_TIMEOUT_MS, () => socket.destroy(new Error('The mail server did not answer in time.')));
    socket.once('secureConnect', () => resolve(socket));
    socket.once('error', reject);
  });
}

const quote = (value) => {
  const text = String(value);
  if (/[\r\n\0]/.test(text)) throw new Error('Invalid character in mail settings.');
  return `"${text.replace(/(["\\])/g, '\\$1')}"`;
};

class Session {
  constructor(socket) {
    this.socket = socket;
    this.buffer = Buffer.alloc(0);
    this.queue = [];
    this.waiter = null;
    this.failure = null;
    this.tagNumber = 0;
    socket.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > MAX_UNREAD_BUFFER) return this.fail(new Error('The mail server sent too much data.'));
      try {
        this.pump();
      } catch (error) {
        this.fail(error);
      }
      return undefined;
    });
    socket.on('error', (error) => this.fail(error));
    socket.on('close', () => this.fail(new Error('The mail server closed the connection.')));
  }

  fail(error) {
    if (!this.failure) this.failure = error;
    if (this.waiter) {
      const { reject } = this.waiter;
      this.waiter = null;
      reject(this.failure);
    }
    this.socket.destroy();
  }

  // One logical response: a line, plus the literals ({n}\r\n<n bytes>) that interrupt it.
  nextLogical() {
    let position = 0;
    let text = '';
    const literals = [];
    for (;;) {
      const end = this.buffer.indexOf('\r\n', position);
      if (end === -1) return null;
      const line = this.buffer.subarray(position, end).toString('latin1');
      text += line;
      position = end + 2;
      const match = /\{(\d+)\}$/.exec(line);
      if (!match) break;
      const size = Number(match[1]);
      if (size > MAX_LITERAL) throw new Error('A message is too large to read.');
      if (this.buffer.length < position + size) return null;
      literals.push(Buffer.from(this.buffer.subarray(position, position + size)));
      position += size;
    }
    this.buffer = this.buffer.subarray(position);
    return { text, literals };
  }

  pump() {
    for (let item = this.nextLogical(); item; item = this.nextLogical()) {
      if (this.waiter) {
        const { resolve } = this.waiter;
        this.waiter = null;
        resolve(item);
      } else {
        this.queue.push(item);
      }
    }
  }

  read() {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail(new Error('The mail server did not answer in time.')), IDLE_TIMEOUT_MS);
      this.waiter = { resolve: (value) => { clearTimeout(timer); resolve(value); }, reject: (error) => { clearTimeout(timer); reject(error); } };
    });
  }

  // Sends one command and collects everything up to its tagged answer.
  async command(text) {
    this.tagNumber += 1;
    const tag = `V${this.tagNumber}`;
    this.socket.write(`${tag} ${text}\r\n`);
    const untagged = [];
    for (;;) {
      const item = await this.read();
      if (item.text.startsWith(`${tag} `)) {
        const status = item.text.slice(tag.length + 1).split(' ')[0].toUpperCase();
        if (status !== 'OK') throw new Error(item.text.slice(tag.length + 1, tag.length + 120));
        return untagged;
      }
      untagged.push(item);
    }
  }
}

async function open(config) {
  const session = new Session(await openSocket(config));
  const greeting = await session.read();
  if (!/^\* (OK|PREAUTH)/i.test(greeting.text)) throw new Error('This is not an IMAP mail server.');
  try {
    await session.command(`LOGIN ${quote(config.user)} ${quote(config.password)}`);
  } catch (_) {
    session.socket.destroy();
    throw new Error('The mail server did not accept the user name and password.');
  }
  return session;
}

async function close(session) {
  try {
    session.socket.write(`V999 LOGOUT\r\n`);
  } catch (_) { /* already closed */ }
  session.socket.destroy();
}

function examine(untagged) {
  const text = untagged.map((item) => item.text).join('\n');
  const number = (name) => Number((new RegExp(`\\[${name} (\\d+)\\]`, 'i').exec(text) || [])[1]);
  return { uidValidity: number('UIDVALIDITY'), uidNext: number('UIDNEXT') };
}

// { ok: true } or { ok: false, reason }: can we log in and open the mailbox?
async function checkAccess(config) {
  let session;
  try {
    session = await open(config);
    examine(await session.command(`EXAMINE ${quote(config.mailbox)}`));
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: String(error.message || 'The mail server could not be reached.').slice(0, 200) };
  } finally {
    if (session) await close(session);
  }
}

// New messages since state.lastUid. state = { uidValidity, lastUid } or null (first time).
// Returns { messages: [{ uid, raw }], skipped, state }. The first time only the position is remembered:
// the mailbox history is not imported. If the server renumbered the mailbox (UIDVALIDITY changed) the same applies.
async function fetchNew(config, state, { maxMessages = 20, maxBytes = 15 * 1024 * 1024 } = {}) {
  const session = await open(config);
  try {
    const box = examine(await session.command(`EXAMINE ${quote(config.mailbox)}`));
    if (!box.uidValidity || !box.uidNext) throw new Error('The mailbox could not be read.');
    if (!state || state.uidValidity !== box.uidValidity || !Number.isInteger(state.lastUid)) {
      return { messages: [], skipped: 0, state: { uidValidity: box.uidValidity, lastUid: box.uidNext - 1 } };
    }
    const found = await session.command(`UID SEARCH UID ${state.lastUid + 1}:*`);
    // A range that starts past the last message still returns that last message, so older ones are filtered out.
    const uids = found.flatMap((item) => (/^\* SEARCH/i.test(item.text) ? item.text.replace(/^\* SEARCH/i, '').trim().split(/\s+/) : []))
      .map(Number).filter((uid) => Number.isInteger(uid) && uid > state.lastUid).sort((a, b) => a - b).slice(0, maxMessages);
    const messages = [];
    let skipped = 0;
    let lastUid = state.lastUid;
    for (const uid of uids) {
      const sizeReply = await session.command(`UID FETCH ${uid} (RFC822.SIZE)`);
      const size = Number((/RFC822\.SIZE (\d+)/i.exec(sizeReply.map((item) => item.text).join(' ')) || [])[1]);
      if (Number.isFinite(size) && size > maxBytes) {
        skipped += 1;
      } else {
        const reply = await session.command(`UID FETCH ${uid} (BODY.PEEK[])`);
        const literal = reply.find((item) => item.literals.length)?.literals[0];
        if (literal) messages.push({ uid, raw: literal });
        else skipped += 1;
      }
      lastUid = uid;
    }
    return { messages, skipped, state: { uidValidity: box.uidValidity, lastUid } };
  } finally {
    await close(session);
  }
}

module.exports = { checkAccess, fetchNew, setConnector, isPrivateAddress };
