// Input checks shared by the HTTP routes and the AI agents.
// Agents never write anything a person could not have typed: their output goes
// through exactly these validators before it reaches the database or the UI.

function readPositiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function parsePositiveNumber(value, max) {
  const isNumeric = typeof value === 'number' || (typeof value === 'string' && /^\d+(\.\d{1,2})?$/.test(value.trim()));
  const number = isNumeric ? Number(value) : NaN;
  return Number.isFinite(number) && number > 0 && number <= max ? number : null;
}

function parseMoney(value, max) {
  const amount = parsePositiveNumber(value, max);
  return amount === null ? null : Math.round(amount * 100) / 100;
}

function parseIsoDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  return Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== value ? null : date;
}

function parseShipmentId(raw) {
  const match = /^(?:SHP-)?([1-9]\d{0,9})$/.exec(String(raw));
  return match ? Number(match[1]) : null;
}

function isPhone(value) {
  return typeof value === 'string' && /^[+\d][\d\s()-]{4,}$/.test(value.trim()) && value.trim().length <= 40;
}

// "01 a 123-bc" and "01A123BC" are the same truck.
function normalizePlate(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

// Optional free-text field: undefined/null/'' mean "not given". Returns { value } or { error }.
function readOptionalText(body, field, maxLength) {
  const value = body?.[field];
  if (value === undefined || value === null || value === '') return { value: null };
  if (typeof value !== 'string' || value.trim().length > maxLength) return { error: `${field} must be text of at most ${maxLength} characters.` };
  return { value: value.trim() || null };
}

function readOptionalPhone(body, field) {
  const result = readOptionalText(body, field, 40);
  if (result.error || !result.value) return result;
  return isPhone(result.value) ? result : { error: `${field} must be a phone number (digits, spaces, + ( ) -).` };
}

// ETA: a date (YYYY-MM-DD) or a date and time (YYYY-MM-DDTHH:MM).
function parseEta(value) {
  if (value === undefined || value === null || value === '') return { value: null };
  const message = 'ETA must be a date (YYYY-MM-DD) or date and time (YYYY-MM-DDTHH:MM).';
  if (typeof value !== 'string') return { error: message };
  const match = /^(\d{4}-\d{2}-\d{2})(?:T([01]\d|2[0-3]):([0-5]\d))?$/.exec(value.trim());
  if (!match || !parseIsoDate(match[1])) return { error: message };
  return { value: value.trim() };
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

module.exports = {
  readPositiveInteger,
  parsePositiveNumber,
  parseMoney,
  parseIsoDate,
  parseShipmentId,
  isPhone,
  normalizePlate,
  readOptionalText,
  readOptionalPhone,
  parseEta,
  httpError
};
