// Reading a Gmail or Outlook / Microsoft 365 mailbox through the provider's own API (OAuth), for companies
// that cannot or do not want to use IMAP and an app password. Read-only: the permissions asked for are
// "read mail" and nothing else; messages are never marked read, moved or deleted.
//
// The platform owner registers ONE app per provider (Google Cloud / Microsoft Entra) and sets the client id and
// secret in the server settings. Each company then signs in to its own mailbox with a consent screen; VEYRA keeps
// only a refresh token (encrypted, like the Twilio token) and never sees the mailbox password.
// Mail present when the mailbox is connected is not imported.
const querystring = require('querystring');

const PROVIDERS = {
  gmail: {
    label: 'Gmail',
    clientId: () => process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: () => process.env.GOOGLE_CLIENT_SECRET || '',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scope: 'https://www.googleapis.com/auth/gmail.readonly openid email',
    extraAuth: { access_type: 'offline', prompt: 'consent', include_granted_scopes: 'false' }
  },
  outlook: {
    label: 'Outlook',
    clientId: () => process.env.MICROSOFT_CLIENT_ID || '',
    clientSecret: () => process.env.MICROSOFT_CLIENT_SECRET || '',
    authUrl: () => `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT || 'common'}/oauth2/v2.0/authorize`,
    tokenUrl: () => `https://login.microsoftonline.com/${process.env.MICROSOFT_TENANT || 'common'}/oauth2/v2.0/token`,
    scope: 'offline_access Mail.Read User.Read',
    extraAuth: { prompt: 'select_account' }
  }
};

let transport = (url, init) => fetch(url, init);
function setTransport(fn) {
  transport = fn || ((url, init) => fetch(url, init));
}

const value = (entry, name) => (typeof entry[name] === 'function' ? entry[name]() : entry[name]);
const isProvider = (name) => Object.prototype.hasOwnProperty.call(PROVIDERS, name);
const enabled = (name) => isProvider(name) && Boolean(PROVIDERS[name].clientId() && PROVIDERS[name].clientSecret());

async function request(url, init = {}) {
  const response = await transport(url, { ...init, signal: AbortSignal.timeout(20000) });
  const type = String(response.headers?.get?.('content-type') || '');
  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.json();
      detail = body.error_description || body.error?.message || (typeof body.error === 'string' ? body.error : '');
    } catch (_) { /* no details */ }
    const error = new Error(`${detail || 'The mail service refused the request'} (${response.status})`.slice(0, 200));
    error.status = response.status;
    throw error;
  }
  return type.includes('json') || !type ? response.json().catch(() => ({})) : response;
}

// The address the person is sent to, to allow VEYRA to read their mail.
function authorizeUrl(provider, { redirectUri, state }) {
  const entry = PROVIDERS[provider];
  const params = { client_id: entry.clientId(), redirect_uri: redirectUri, response_type: 'code', scope: entry.scope, state, ...entry.extraAuth };
  return `${value(entry, 'authUrl')}?${querystring.stringify(params)}`;
}

async function tokenRequest(provider, params) {
  const entry = PROVIDERS[provider];
  return request(value(entry, 'tokenUrl'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: querystring.stringify({ client_id: entry.clientId(), client_secret: entry.clientSecret(), ...params })
  });
}

// Returns { refreshToken, accessToken, email }. Throws a readable error if the sign-in did not work.
async function exchangeCode(provider, { code, redirectUri }) {
  const tokens = await tokenRequest(provider, { grant_type: 'authorization_code', code, redirect_uri: redirectUri });
  if (!tokens.refresh_token) throw new Error('The mail service did not allow long-term reading. Try again and accept every permission.');
  const email = await whoAmI(provider, tokens.access_token);
  return { refreshToken: tokens.refresh_token, accessToken: tokens.access_token, email };
}

async function accessToken(provider, refreshToken) {
  const tokens = await tokenRequest(provider, { grant_type: 'refresh_token', refresh_token: refreshToken });
  if (!tokens.access_token) throw new Error('The mail service did not give access. Connect the mailbox again.');
  return tokens.access_token;
}

async function whoAmI(provider, token) {
  const headers = { Authorization: `Bearer ${token}` };
  if (provider === 'gmail') return String((await request('https://gmail.googleapis.com/gmail/v1/users/me/profile', { headers })).emailAddress || '');
  const me = await request('https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName', { headers });
  return String(me.mail || me.userPrincipalName || '');
}

const base64urlToBuffer = (text) => Buffer.from(String(text).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// New messages since state.after (milliseconds). state null = first time: remember "now", import nothing.
// Returns { messages: [{ id, raw, rewind }], skipped, state } like the IMAP reader. `rewind` is the position just
// before a message, so a message the daily limit turned away is read again next round.
async function fetchNew(settings, state, { maxMessages = 20, maxBytes = 15 * 1024 * 1024, now = Date.now() } = {}) {
  const provider = settings.provider;
  if (!isProvider(provider)) throw new Error('Unknown mail provider.');
  if (!Number.isFinite(state?.after)) return { messages: [], skipped: 0, state: { after: now } };
  const token = await accessToken(provider, settings.refreshToken);
  const headers = { Authorization: `Bearer ${token}` };
  const messages = [];
  let skipped = 0;
  let after = state.after;

  if (provider === 'gmail') {
    // Gmail's "after:" works in whole seconds, so start one second early; the exact time is filtered below.
    const query = encodeURIComponent(`after:${Math.floor(state.after / 1000) - 1}`);
    const list = await request(`https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${query}&labelIds=INBOX&maxResults=50`, { headers });
    const found = [];
    for (const item of list.messages || []) {
      const meta = await request(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(item.id)}?format=minimal`, { headers });
      const at = Number(meta.internalDate);
      if (Number.isFinite(at) && at > state.after) found.push({ id: item.id, at, size: Number(meta.sizeEstimate) || 0 });
    }
    found.sort((a, b) => a.at - b.at);
    for (const item of found.slice(0, maxMessages)) {
      if (item.size > maxBytes) {
        skipped += 1;
      } else {
        const full = await request(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(item.id)}?format=raw`, { headers });
        if (full.raw) messages.push({ id: item.id, raw: base64urlToBuffer(full.raw), rewind: { after: item.at - 1 } });
        else skipped += 1;
      }
      after = Math.max(after, item.at);
    }
  } else {
    const since = new Date(state.after).toISOString();
    const filter = encodeURIComponent(`receivedDateTime gt ${since}`);
    const list = await request(`https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$filter=${filter}&$orderby=receivedDateTime asc&$top=${maxMessages}&$select=id,receivedDateTime`.replace(/ /g, '%20'), { headers });
    for (const item of list.value || []) {
      const at = Date.parse(item.receivedDateTime);
      if (!Number.isFinite(at)) continue;
      const raw = await request(`https://graph.microsoft.com/v1.0/me/messages/${encodeURIComponent(item.id)}/$value`, { headers });
      const bytes = Buffer.from(await raw.arrayBuffer());
      if (bytes.length > maxBytes) skipped += 1;
      else messages.push({ id: item.id, raw: bytes, rewind: { after: at - 1 } });
      after = Math.max(after, at);
    }
  }
  return { messages, skipped, state: { after } };
}

// Can we get an access token and see the mailbox? { ok: true } or { ok: false, reason }.
async function checkAccess(settings) {
  try {
    await whoAmI(settings.provider, await accessToken(settings.provider, settings.refreshToken));
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: error.message };
  }
}

module.exports = { PROVIDERS, isProvider, enabled, authorizeUrl, exchangeCode, fetchNew, checkAccess, setTransport };
