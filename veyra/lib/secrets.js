// Encrypts small secrets (a company's Twilio credentials) before they are stored in the database,
// so a copy of the database file alone does not reveal them.
//
// AES-256-GCM, key derived from SECRETS_KEY (or, if that is not set, from JWT_SECRET).
// Changing the key makes stored secrets unreadable; the app then treats them as "not configured"
// and an administrator has to enter them again. Nothing here is ever sent to the browser.
const crypto = require('crypto');

function masterKey() {
  const material = process.env.SECRETS_KEY || process.env.JWT_SECRET || (process.env.NODE_ENV === 'development' ? 'veyra-dev-secret' : '');
  if (!material) throw new Error('SECRETS_KEY or JWT_SECRET is required to store secrets.');
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(material), Buffer.from('veyra-secrets-v1'), Buffer.from('tenant-settings'), 32));
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64'), cipher.getAuthTag().toString('base64'), ciphertext.toString('base64')].join(':');
}

// Returns the original value, or null when the data is missing, damaged or the key changed.
function decrypt(stored) {
  if (typeof stored !== 'string') return null;
  const [version, iv, tag, ciphertext] = stored.split(':');
  if (version !== 'v1' || !iv || !tag || !ciphertext) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey(), Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(tag, 'base64'));
    const plain = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]);
    return JSON.parse(plain.toString('utf8'));
  } catch (_) {
    return null;
  }
}

module.exports = { encrypt, decrypt };
