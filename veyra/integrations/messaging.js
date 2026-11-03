// SMS and WhatsApp delivery through Twilio.
//
// Whose Twilio account sends a message?
// - A company that saved its own Twilio settings (Integrations panel): always its own account.
// - Otherwise only the platform owner's company (tenant 1) may use the server-wide settings from the
//   environment. Other companies never spend the owner's Twilio money unless the owner explicitly
//   sets MESSAGING_SHARED_ALL_TENANTS=true.
// Not configured = sending is off; the app still drafts messages so a dispatcher can copy them.
// Credentials never leave the server: not in responses, not in logs.
const { httpError } = require('../lib/validation');

let transport = (url, init) => fetch(url, init);

function setTransport(fn) {
  transport = fn || ((url, init) => fetch(url, init));
}

function envConfig() {
  if (String(process.env.MESSAGING_PROVIDER || '').toLowerCase() !== 'twilio') return null;
  const config = {
    sid: process.env.TWILIO_ACCOUNT_SID || '',
    token: process.env.TWILIO_AUTH_TOKEN || '',
    smsFrom: process.env.TWILIO_SMS_FROM || '',
    whatsappFrom: process.env.TWILIO_WHATSAPP_FROM || ''
  };
  return config.sid && config.token ? config : null;
}

// tenant: { id, messagingSettings } as returned by getTenant. Returns { config, source } or { config: null }.
function resolveConfig(tenant, defaultTenantId = 1) {
  const own = tenant?.messagingSettings;
  if (own?.sid && own?.token) return { config: own, source: 'company' };
  const shared = envConfig();
  if (shared && (tenant?.id === defaultTenantId || process.env.MESSAGING_SHARED_ALL_TENANTS === 'true')) {
    return { config: shared, source: 'platform' };
  }
  return { config: null, source: null };
}

function channelsOf(config) {
  if (!config) return [];
  return [config.smsFrom && 'sms', config.whatsappFrom && 'whatsapp'].filter(Boolean);
}

// What the browser may know: which channels work and where they come from. Never the credentials.
function publicStatus(tenant, defaultTenantId) {
  const { config, source } = resolveConfig(tenant, defaultTenantId);
  return {
    source,
    channels: channelsOf(config),
    smsFrom: config?.smsFrom || null,
    whatsappFrom: config?.whatsappFrom || null,
    accountHint: source === 'company' ? `${config.sid.slice(0, 2)}…${config.sid.slice(-4)}` : null
  };
}

// Twilio needs international format: +998901234567.
function toE164(phone) {
  const digits = String(phone || '').replace(/[\s()-]/g, '');
  return /^\+\d{8,15}$/.test(digits) ? digits : null;
}

function basicAuth(config) {
  return `Basic ${Buffer.from(`${config.sid}:${config.token}`).toString('base64')}`;
}

// Asks Twilio whether these credentials work, before they are saved.
// Returns { ok: true } or { ok: false, reason }.
async function verifyCredentials(config) {
  try {
    const response = await transport(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.sid)}.json`, {
      method: 'GET',
      headers: { Authorization: basicAuth(config) },
      signal: AbortSignal.timeout(10000)
    });
    if (response.ok) return { ok: true };
    if (response.status === 401 || response.status === 403 || response.status === 404) {
      return { ok: false, reason: 'Twilio did not accept the Account SID and Auth Token.' };
    }
    return { ok: false, reason: `Twilio could not be checked right now (status ${response.status}). Try again in a minute.` };
  } catch (_) {
    return { ok: false, reason: 'Twilio could not be reached. Check the internet connection of the server.' };
  }
}

async function send(config, { channel, to, body }) {
  if (!channelsOf(config).includes(channel)) {
    throw httpError(503, `${channel === 'whatsapp' ? 'WhatsApp' : 'SMS'} sending is not configured. Copy the text and send it from your phone, or ask the administrator to add Twilio settings.`);
  }
  const number = toE164(to);
  if (!number) throw httpError(400, 'The phone number must be in international format, e.g. +998 90 123 45 67.');
  const params = new URLSearchParams({
    To: channel === 'whatsapp' ? `whatsapp:${number}` : number,
    From: channel === 'whatsapp' ? `whatsapp:${config.whatsappFrom}` : config.smsFrom,
    Body: body
  });
  let response;
  try {
    response = await transport(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.sid)}/Messages.json`, {
      method: 'POST',
      headers: { Authorization: basicAuth(config), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      signal: AbortSignal.timeout(15000)
    });
  } catch (error) {
    return { status: 'failed', provider: 'twilio', error: 'Could not reach the messaging provider.' };
  }
  let data = null;
  try {
    data = await response.json();
  } catch (_) {
    data = null;
  }
  if (!response.ok) {
    return { status: 'failed', provider: 'twilio', error: String(data?.message || `Provider returned ${response.status}`).slice(0, 300) };
  }
  return { status: 'sent', provider: 'twilio', providerMessageId: data?.sid || null };
}

module.exports = { send, verifyCredentials, resolveConfig, publicStatus, channelsOf, envConfig, toE164, setTransport };
