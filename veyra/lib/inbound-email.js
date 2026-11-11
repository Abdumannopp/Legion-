// Turns what an email service posts to the inbox address into one shape:
//   { from, subject, text, messageId, attachments: [{ filename, content }] }
// Understood: Postmark (JSON, base64 attachments), Mailgun (form or multipart, attachment-N),
// SendGrid Inbound Parse (multipart, attachmentN, raw "headers"), Zapier / Make and other generic JSON.
const { parseMultipart } = require('./multipart');

const stripHtml = (html) => String(html)
  .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
  .replace(/<br\s*\/?>/gi, '\n')
  .replace(/<\/(p|div|tr|li|h\d)>/gi, '\n')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/[ \t]+/g, ' ').replace(/\n\s*\n\s*\n+/g, '\n\n').trim();

const firstText = (...values) => values.find((value) => typeof value === 'string' && value.trim()) || '';

// SendGrid sends the original email headers as one text field.
function headerValue(rawHeaders, name) {
  if (typeof rawHeaders !== 'string') return '';
  const match = new RegExp(`^${name}:\\s*(.+)$`, 'im').exec(rawHeaders);
  return match ? match[1].trim() : '';
}

function base64ToBuffer(value, maxBytes) {
  if (typeof value !== 'string' || !value) return null;
  // Four base64 characters carry three bytes: refuse before decoding something huge.
  if (value.length > Math.ceil(maxBytes / 3) * 4 + 16) return null;
  try {
    const buffer = Buffer.from(value, 'base64');
    return buffer.length ? buffer : null;
  } catch (_) {
    return null;
  }
}

function jsonAttachments(body, maxBytes) {
  const list = Array.isArray(body.Attachments) ? body.Attachments : Array.isArray(body.attachments) ? body.attachments : [];
  return list.slice(0, 30).map((entry) => {
    if (!entry || typeof entry !== 'object') return null;
    const content = base64ToBuffer(entry.Content ?? entry.content ?? entry.data, maxBytes);
    if (!content) return null;
    return { filename: firstText(entry.Name, entry.filename, entry.name, entry.fileName), content };
  }).filter(Boolean);
}

function normalize(fields, attachments) {
  const b = fields && typeof fields === 'object' ? fields : {};
  const from = firstText(b.from, b.From, b.sender, b.FromFull?.Email, b.fromEmail);
  const text = firstText(b.text, b.TextBody, b['stripped-text'], b['body-plain'], b.body, stripHtml(firstText(b.html, b.HtmlBody, b['body-html'])));
  return {
    from: from.trim(),
    subject: firstText(b.subject, b.Subject).trim(),
    text: text.trim(),
    messageId: firstText(b.messageId, b.MessageID, b['Message-Id'], b['message-id'], headerValue(b.headers, 'Message-ID')).trim().slice(0, 300),
    attachments
  };
}

// body: a parsed object (JSON or simple form) or a Buffer (multipart). maxFileBytes bounds each attachment.
function parseInbound(body, contentType, maxFileBytes) {
  if (Buffer.isBuffer(body)) {
    const { fields, files } = parseMultipart(body, contentType);
    return normalize(fields, files
      .filter((file) => /^attachment[-_]?\d*$/i.test(file.field) || /^file\d*$/i.test(file.field))
      .map((file) => ({ filename: file.filename, content: file.content })));
  }
  const object = body && typeof body === 'object' ? body : {};
  return normalize(object, jsonAttachments(object, maxFileBytes));
}

function senderAddress(from) {
  const match = /<([^>]+)>/.exec(from);
  return (match ? match[1] : from).trim().toLowerCase();
}

// An empty allow-list accepts everyone; otherwise the sender or its domain must be listed.
function senderAllowed(from, allowedSenders) {
  if (!allowedSenders.length) return true;
  const address = senderAddress(from);
  const domain = address.includes('@') ? address.split('@').pop() : '';
  return allowedSenders.some((entry) => {
    const allowed = entry.toLowerCase().replace(/^@/, '');
    return allowed === address || (domain && allowed === domain);
  });
}

// Load numbers an email mentions: "SHP-12", "shp 12", "SHP12".
function mentionedShipmentIds(text) {
  const ids = new Set();
  const pattern = /\bSHP[\s#-]{0,2}(\d{1,9})\b/gi;
  let match;
  while ((match = pattern.exec(String(text || ''))) && ids.size < 5) ids.add(Number(match[1]));
  return [...ids].filter((id) => id > 0);
}

// What kind of document a file probably is, from its name and the email's words.
function guessDocumentType(filename, context = '') {
  const name = String(filename || '').toLowerCase();
  const words = `${name} ${String(context).toLowerCase()}`;
  const cmr = /(^|[^a-z])cmr([^a-z]|$)|смр|цмр/;
  const pod = /(^|[^a-z])pod([^a-z]|$)|proof[\s_-]?of[\s_-]?delivery|delivery[\s_-]?(note|receipt)/;
  if (cmr.test(name)) return 'cmr';
  if (pod.test(name)) return 'pod';
  if (pod.test(words) || /topshirildi|yetkazildi|доставлен/.test(words)) return 'pod';
  if (cmr.test(words)) return 'cmr';
  return null;
}

module.exports = { parseInbound, senderAllowed, senderAddress, stripHtml, mentionedShipmentIds, guessDocumentType };
