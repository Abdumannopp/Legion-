/**
 * Pure helpers for `npm run setup`, kept separate so they can be tested.
 *
 * The rule they enforce: re-running setup must never throw away something
 * the operator configured. It used to rewrite server/.env from a template,
 * which silently blanked SMTP settings, AI keys and the public address on
 * every re-run — and re-running setup is what the docs suggest when
 * something looks wrong.
 */

const LINE = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;

/** KEY=value pairs from a .env text (comments and blank lines ignored). */
export function parseEnv(text) {
  const out = new Map();
  for (const raw of (text ?? "").split(/\r?\n/)) {
    const m = LINE.exec(raw.trim());
    if (m) out.set(m[1], m[2]);
  }
  return out;
}

/**
 * Fills `template` (a full .env text with defaults) with the operator's
 * existing values. Keys in `force` take the template's value regardless —
 * secrets setup just decided, or settings the operator asked setup to change
 * (e.g. --domain). An empty old value counts as unset. Keys only in the old
 * file are kept at the end, so nothing
 * the operator added by hand disappears.
 */
export function mergeEnv(template, existingText, force = new Set()) {
  const existing = parseEnv(existingText);
  const seen = new Set();
  const lines = template.split("\n").map((line) => {
    const m = LINE.exec(line);
    if (!m) return line;
    seen.add(m[1]);
    // A value the operator actually set wins. A key left empty is "not set":
    // it takes the template's default (e.g. when switching to the hosted mode).
    if (!force.has(m[1]) && existing.get(m[1])) return `${m[1]}=${existing.get(m[1])}`;
    return line;
  });
  const extra = [...existing].filter(([k]) => !seen.has(k));
  if (extra.length) {
    lines.push("# --- Kept from your previous configuration ---", ...extra.map(([k, v]) => `${k}=${v}`), "");
  }
  return lines.join("\n");
}

/** Sets one key in a .env text, replacing it if present or appending it. */
export function setEnvValue(text, key, value) {
  const re = new RegExp(`^${key}=.*$`, "m");
  if (re.test(text)) return text.replace(re, `${key}=${value}`);
  return `${text.replace(/\n*$/, "\n")}${key}=${value}\n`;
}

const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

/**
 * The public hostname from `--domain`. Accepts "legion.example.com"; refuses
 * anything with a scheme, path or port so a typo cannot end up as a broken
 * FRONTEND_URL. Returns null when no domain was given.
 */
export function parseDomain(argv, env = {}) {
  let value = env.LEGION_DOMAIN || null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--domain") value = argv[i + 1] ?? "";
    else if (argv[i].startsWith("--domain=")) value = argv[i].slice("--domain=".length);
  }
  if (value === null) return null;
  const host = value.trim().toLowerCase();
  if (!HOSTNAME.test(host)) {
    throw new Error(
      `"${value}" is not a domain name. Give just the name, e.g. --domain legion.example.com ` +
      "(no https://, no path, no port)."
    );
  }
  return host;
}

/** `--saas` (or LEGION_SAAS=1): set this installation up as the hosted service. */
export function parseSaas(argv, env = {}) {
  return argv.includes("--saas") || env.LEGION_SAAS === "1";
}
