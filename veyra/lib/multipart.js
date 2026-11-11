// A small multipart/form-data reader for the email webhook (SendGrid and Mailgun post emails
// with attachments this way). It works on a body that is already in memory (the caller limits
// its size), has hard limits on the number of parts and header size, and never touches the disk.
const MAX_PARTS = 60;
const MAX_HEADER_BYTES = 8 * 1024;
const MAX_FIELD_BYTES = 1024 * 1024;

function boundaryOf(contentType) {
  const match = /boundary=(?:"([^"]{1,200})"|([^;\s]{1,200}))/i.exec(String(contentType || ''));
  return match ? (match[1] || match[2]) : null;
}

function parseHeaders(text) {
  const headers = {};
  for (const line of text.split('\r\n')) {
    const index = line.indexOf(':');
    if (index > 0) headers[line.slice(0, index).trim().toLowerCase()] = line.slice(index + 1).trim();
  }
  return headers;
}

function dispositionParam(disposition, name) {
  const quoted = new RegExp(`(?:^|;)\\s*${name}="((?:[^"\\\\]|\\\\.)*)"`, 'i').exec(disposition);
  if (quoted) return quoted[1].replace(/\\(.)/g, '$1');
  const bare = new RegExp(`(?:^|;)\\s*${name}=([^;]+)`, 'i').exec(disposition);
  return bare ? bare[1].trim() : null;
}

// Returns { fields: { name: text }, files: [{ field, filename, contentType, content }] }.
// Throws an Error with statusCode 400 when the body is not well-formed multipart.
function parseMultipart(body, contentType) {
  const fail = (message) => Object.assign(new Error(message), { statusCode: 400 });
  const boundary = boundaryOf(contentType);
  if (!boundary || !Buffer.isBuffer(body)) throw fail('The request is not a valid multipart form.');
  const delimiter = Buffer.from(`--${boundary}`);
  const fields = {};
  const files = [];
  let position = body.indexOf(delimiter);
  if (position === -1) throw fail('The request is not a valid multipart form.');
  let parts = 0;

  while (position !== -1) {
    let cursor = position + delimiter.length;
    // "--" right after the boundary marks the end of the form.
    if (body[cursor] === 0x2d && body[cursor + 1] === 0x2d) break;
    if (body[cursor] === 0x0d && body[cursor + 1] === 0x0a) cursor += 2;
    else throw fail('The request is not a valid multipart form.');

    const headerEnd = body.indexOf('\r\n\r\n', cursor);
    if (headerEnd === -1 || headerEnd - cursor > MAX_HEADER_BYTES) throw fail('The request is not a valid multipart form.');
    const next = body.indexOf(delimiter, headerEnd + 4);
    if (next === -1) throw fail('The request is not a valid multipart form.');
    parts += 1;
    if (parts > MAX_PARTS) throw fail('The form has too many parts.');

    const headers = parseHeaders(body.subarray(cursor, headerEnd).toString('utf8'));
    // The content ends before the CRLF that precedes the next boundary.
    const content = body.subarray(headerEnd + 4, Math.max(headerEnd + 4, next - 2));
    const disposition = headers['content-disposition'] || '';
    const name = dispositionParam(disposition, 'name');
    const filename = dispositionParam(disposition, 'filename');
    if (name) {
      if (filename !== null) {
        files.push({ field: name, filename, contentType: (headers['content-type'] || '').split(';')[0].trim().toLowerCase(), content: Buffer.from(content) });
      } else if (content.length <= MAX_FIELD_BYTES && fields[name] === undefined) {
        fields[name] = content.toString('utf8');
      }
    }
    position = next;
  }
  return { fields, files };
}

module.exports = { parseMultipart, boundaryOf };
