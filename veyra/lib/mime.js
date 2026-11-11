// Reads a raw email (RFC 822 / MIME) into { from, subject, messageId, text, html, attachments }.
// Handles nested multipart, base64 and quoted-printable, encoded headers (=?utf-8?B?...?=) and the common
// character sets. Limits on depth, number of parts and size keep a hostile email from costing much.
const MAX_DEPTH = 6;
const MAX_PARTS = 80;

const decoder = (charset) => {
  try {
    return new TextDecoder(String(charset || 'utf-8').toLowerCase().replace(/^["']|["']$/g, ''), { fatal: false });
  } catch (_) {
    return new TextDecoder('utf-8');
  }
};

function decodeQuotedPrintable(text) {
  const bytes = [];
  const clean = text.replace(/=\r?\n/g, '');
  for (let i = 0; i < clean.length; i += 1) {
    const hex = clean[i] === '=' ? clean.slice(i + 1, i + 3) : '';
    if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else {
      bytes.push(clean.charCodeAt(i) & 0xff);
    }
  }
  return Buffer.from(bytes);
}

// "=?utf-8?B?0KHQsNC70L7QvA==?=" -> "Салом". Anything that does not decode is left as it is.
function decodeWords(value) {
  return String(value || '')
    .replace(/(\?=)\s+(=\?)/g, '$1$2')
    .replace(/=\?([^?\s]+)\?([BbQq])\?([^?]*)\?=/g, (whole, charset, encoding, data) => {
      try {
        const bytes = encoding.toUpperCase() === 'B'
          ? Buffer.from(data, 'base64')
          : decodeQuotedPrintable(data.replace(/_/g, ' '));
        return decoder(charset.split('*')[0]).decode(bytes);
      } catch (_) {
        return whole;
      }
    });
}

function splitHeaderBody(buffer) {
  const crlf = buffer.indexOf('\r\n\r\n');
  const lf = buffer.indexOf('\n\n');
  let end;
  let gap;
  if (crlf !== -1 && (lf === -1 || crlf <= lf)) { end = crlf; gap = 4; } else if (lf !== -1) { end = lf; gap = 2; } else { end = buffer.length; gap = 0; }
  return { head: buffer.subarray(0, end).toString('latin1'), body: buffer.subarray(Math.min(buffer.length, end + gap)) };
}

function parseHeaders(head) {
  const headers = {};
  for (const line of head.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
    const index = line.indexOf(':');
    if (index > 0) {
      const name = line.slice(0, index).trim().toLowerCase();
      if (headers[name] === undefined) headers[name] = line.slice(index + 1).trim();
    }
  }
  return headers;
}

// Value and parameters of "text/plain; charset=utf-8" or "attachment; filename*=UTF-8''a%20b.pdf".
function parseStructured(value) {
  const [main, ...rest] = String(value || '').split(/;(?=(?:[^"]*"[^"]*")*[^"]*$)/);
  const params = {};
  for (const part of rest) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const name = part.slice(0, index).trim().toLowerCase();
    let raw = part.slice(index + 1).trim().replace(/^"|"$/g, '');
    if (name.endsWith('*')) {
      const match = /^([^']*)'[^']*'(.*)$/.exec(raw);
      if (match) {
        const bytes = Buffer.from(match[2].replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))), 'latin1');
        raw = decoder(match[1] || 'utf-8').decode(bytes);
      }
      params[name.slice(0, -1)] = raw;
    } else if (params[name] === undefined) {
      params[name] = decodeWords(raw);
    }
  }
  return { value: main.trim().toLowerCase(), params };
}

function decodeBody(body, encoding) {
  const kind = String(encoding || '').toLowerCase();
  if (kind === 'base64') return Buffer.from(body.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  if (kind === 'quoted-printable') return decodeQuotedPrintable(body.toString('latin1'));
  return body;
}

function walk(buffer, depth, state, out) {
  if (depth > MAX_DEPTH || state.parts > MAX_PARTS) return;
  state.parts += 1;
  const { head, body } = splitHeaderBody(buffer);
  const headers = parseHeaders(head);
  const type = parseStructured(headers['content-type'] || 'text/plain');
  const disposition = parseStructured(headers['content-disposition'] || '');

  if (type.value.startsWith('multipart/') && type.params.boundary) {
    const marker = `--${type.params.boundary}`;
    const text = body.toString('latin1');
    // Work on the latin1 view (one byte = one char) so offsets match the buffer exactly.
    const pieces = [];
    let from = text.indexOf(marker);
    while (from !== -1) {
      const lineEnd = text.indexOf('\n', from);
      const next = text.indexOf(`\n${marker}`, from + marker.length);
      if (lineEnd === -1) break;
      const start = lineEnd + 1;
      const end = next === -1 ? text.length : (text[next - 1] === '\r' ? next - 1 : next);
      pieces.push(body.subarray(start, end));
      if (next === -1 || text.startsWith('--', next + 1 + marker.length)) break;
      from = next + 1;
    }
    pieces.forEach((piece) => walk(piece, depth + 1, state, out));
    return;
  }

  const content = decodeBody(body, headers['content-transfer-encoding']);
  const filename = disposition.params.filename || type.params.name || null;
  const isAttachment = disposition.value === 'attachment' || Boolean(filename);
  if (type.value === 'message/rfc822' && !filename) return;
  if (!isAttachment && (type.value === 'text/plain' || type.value === 'text/html')) {
    const text = decoder(type.params.charset).decode(content);
    if (type.value === 'text/plain') out.text += `${out.text ? '\n' : ''}${text}`;
    else out.html += `${out.html ? '\n' : ''}${text}`;
    return;
  }
  if (isAttachment || type.value.startsWith('image/') || type.value === 'application/pdf') {
    out.attachments.push({ filename: filename || '', contentType: type.value, content });
  }
}

function firstAddress(value) {
  return decodeWords(value || '').trim();
}

function parseEmail(raw) {
  const buffer = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'latin1');
  const { head } = splitHeaderBody(buffer);
  const headers = parseHeaders(head);
  const out = { text: '', html: '', attachments: [] };
  walk(buffer, 0, { parts: 0 }, out);
  return {
    from: firstAddress(headers.from),
    subject: decodeWords(headers.subject || '').trim(),
    messageId: String(headers['message-id'] || '').trim().replace(/^<|>$/g, '').slice(0, 300),
    text: out.text.trim(),
    html: out.html,
    attachments: out.attachments
  };
}

module.exports = { parseEmail, decodeWords, decodeQuotedPrintable };
