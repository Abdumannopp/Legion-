// SMS and WhatsApp delivery.
// Provider: Twilio (one account covers SMS and WhatsApp in most countries).
// Not configured = sending is off; the app still drafts messages so a dispatcher can copy them
// into their own phone. Credentials are read from the environment and never sent to the browser.
const { httpError } = require('../lib/validation');

let transport = (url, init) => fetch(url, init);

function setTransport(fn) {
  transport = fn || ((url, init) => fetch(url, init));
}

function config() {
  return {
    provider: String(process.env.MESSAGING_PROVIDER || '').toLowerCase(),
    sid: process.env.TWILIO_ACCOUNT_SID || '',
    token: process.env.TWILIO_AUTH_TOKEN || '',
    smsFrom: process.env.TWILIO_SMS_FROM || '',
    whatsappFrom: process.env.TWILIO_WHATSAPP_FROM || ''
  };
}

// Which channels can actually send right now.
function availableChannels() {
  const c = config();
  if (c.provider !== 'twilio' || !c.sid || !c.token) return [];
  return [c.smsFrom && 'sms', c.whatsappFrom && 'whatsapp'].filter(Boolean);
}

function status() {
  const channels = availableChannels();
  return { provider: channels.length ? 'twilio' : null, channels };
}

// Twilio needs international format: +998901234567.
function toE164(phone) {
  const digits = String(phone || '').replace(/[\s()-]/g, '');
  return /^\+\d{8,15}$/.test(digits) ? digits : null;
}

async function send({ channel, to, body }) {
  if (!availableChannels().includes(channel)) {
    throw httpError(503, `${channel === 'whatsapp' ? 'WhatsApp' : 'SMS'} sending is not configured. Copy the text and send it from your phone, or ask the administrator to add Twilio settings.`);
  }
  const number = toE164(to);
  if (!number) throw httpError(400, 'The phone number must be in international format, e.g. +998 90 123 45 67.');
  const c = config();
  const params = new URLSearchParams({
    To: channel === 'whatsapp' ? `whatsapp:${number}` : number,
    From: channel === 'whatsapp' ? `whatsapp:${c.whatsappFrom}` : c.smsFrom,
    Body: body
  });
  let response;
  try {
    response = await transport(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(c.sid)}/Messages.json`, {
      method: 'POST',
      headers: {
        Authorization: `Basic ${Buffer.from(`${c.sid}:${c.token}`).toString('base64')}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
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

module.exports = { send, status, availableChannels, toE164, setTransport };
