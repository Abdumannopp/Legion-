/**
 * One-command setup for Legion.
 *
 *   npm run setup
 *
 * Finds a PostgreSQL server, creates Legion's role and database if they are
 * missing, writes server/.env with freshly generated secrets, and applies the
 * schema. Safe to re-run: existing secrets and data are preserved.
 *
 * Deliberately plain JavaScript, run by `node` directly:
 *
 *  - No tsx. It is a devDependency, and an installation that skipped dev
 *    dependencies would fail here with a cryptic "'tsx' is not recognized".
 *  - No compiled output. Setup must work before the first `npm run build`,
 *    so the schema is applied straight from src/db/schema.sql.
 *
 * The only prerequisite is `npm install`, and the check below says so plainly
 * if it is missing.
 */
import { createInterface } from "node:readline/promises";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mergeEnv, parseDomain, parseSaas } from "./env-file.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const serverRoot = resolve(here, "..");
const ENV_PATH = join(serverRoot, ".env");
/**
 * The dashboard reads its own file, and reads it at *build* time, because
 * NEXT_PUBLIC_* values end up in the browser bundle. Writing only server/.env
 * left the privacy and terms pages with no way to learn who operates the
 * installation, so setup seeds this one too.
 */
const FRONTEND_ENV_PATH = join(resolve(serverRoot, "..", "frontend"), ".env.local");
const SCHEMA_PATH = join(serverRoot, "src", "db", "schema.sql");

const DB_NAME = "legion";
const DB_USER = "legion";

const c = {
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};
const ok = (s) => console.log(`${c.green("OK")}  ${s}`);
const warn = (s) => console.log(`${c.yellow("!")}   ${s}`);

function die(message, hint) {
  console.error(`\n${c.red("ERROR  " + message)}`);
  if (hint) console.error(hint);
  process.exit(1);
}

// Loaded here rather than at the top so a missing node_modules produces an
// instruction instead of a stack trace.
let pg;
try {
  pg = (await import("pg")).default;
} catch {
  die(
    "Dependencies are not installed.",
    `\n  Run this first, from the ${c.cyan("legion")} folder:\n\n    ${c.cyan("npm install")}\n\n  Then run ${c.cyan("npm run setup")} again.`
  );
}

const randomHex = (bytes) => randomBytes(bytes).toString("hex");

/** Candidate superuser connections, tried in order before asking for a password. */
function candidates() {
  const host = process.env.PGHOST || "localhost";
  const port = Number(process.env.PGPORT || 5432);
  const list = [];

  if (process.env.ADMIN_DATABASE_URL) {
    list.push({ label: "ADMIN_DATABASE_URL", config: { connectionString: process.env.ADMIN_DATABASE_URL } });
  }
  // Linux/macOS package installs commonly trust the local OS user.
  list.push({ label: `${host}:${port} as postgres (no password)`, config: { host, port, user: "postgres", database: "postgres" } });
  const osUser = process.env.USER || process.env.USERNAME;
  if (osUser) {
    list.push({ label: `${host}:${port} as ${osUser}`, config: { host, port, user: osUser, database: "postgres" } });
  }
  // The Windows installer's most common choice.
  list.push({ label: `${host}:${port} as postgres/postgres`, config: { host, port, user: "postgres", password: "postgres", database: "postgres" } });
  return list;
}

async function tryConnect(config) {
  const client = new pg.Client({ connectionTimeoutMillis: 4_000, ...config });
  try {
    await client.connect();
    return client;
  } catch {
    await client.end().catch(() => {});
    return null;
  }
}

const INSTALL_HINT = [
  "  Check that PostgreSQL is installed and running:",
  "    Windows  - Services -> postgresql-x64-... -> Running",
  "    macOS    - brew services list",
  "    Linux    - sudo systemctl status postgresql",
  "",
  "  Not installed yet? https://www.postgresql.org/download/",
].join("\n");

/**
 * Is anything accepting TCP connections there?
 *
 * This separates the two failures that otherwise look identical: nothing
 * listening means PostgreSQL is absent or stopped, while a successful connect
 * followed by a rejected login means it is running and the credentials are
 * wrong. Telling someone to "check the password" when the server was never
 * installed sends them looking in the wrong place entirely.
 */
async function isPortOpen(host, port, timeoutMs = 3_000) {
  const { Socket } = await import("node:net");
  return new Promise((resolve) => {
    const socket = new Socket();
    const done = (result) => {
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

async function findAdminConnection() {
  for (const { label, config } of candidates()) {
    const client = await tryConnect(config);
    if (client) {
      ok(`Connected to PostgreSQL (${label})`);
      return client;
    }
  }

  // Before asking for a password, find out whether there is a server at all.
  const defaultHost = process.env.PGHOST || "localhost";
  const defaultPort = Number(process.env.PGPORT || 5432);
  const serverPresent = await isPortOpen(defaultHost, defaultPort);

  if (!serverPresent) {
    die(
      `Nothing is listening on ${defaultHost}:${defaultPort} — PostgreSQL does not appear to be installed or running.`,
      [
        "",
        `  ${c.cyan("Legion needs PostgreSQL. It is a one-time install.")}`,
        "",
        "  1. Download it:  https://www.postgresql.org/download/",
        "  2. Run the installer and accept every default.",
        `  3. ${c.yellow("Write down the password it asks you to choose")} — you need it in a moment.`,
        "  4. Run this again:",
        "",
        `       ${c.cyan("npm run setup")}`,
        "",
        c.dim("  Already installed? Then it is not running. On Windows open"),
        c.dim("  Services, find postgresql-x64-..., and press Start."),
      ].join("\n")
    );
  }

  warn(`PostgreSQL is running on ${defaultHost}:${defaultPort}, but Legion could not log in.`);
  console.log(c.dim("    Enter the password you chose when installing PostgreSQL.\n"));

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    for (let attempt = 1; attempt <= 3; attempt++) {
      const host = (await rl.question(`    Host [${defaultHost}]: `)).trim() || defaultHost;
      const port = Number((await rl.question(`    Port [${defaultPort}]: `)).trim() || defaultPort);
      const user = (await rl.question("    Superuser name [postgres]: ")).trim() || "postgres";
      const password = await rl.question("    Superuser password: ");

      if (!password.trim()) {
        warn("The password cannot be empty — it is the one you chose during installation.\n");
        continue;
      }

      const client = await tryConnect({ host, port, user, password, database: "postgres" });
      if (client) {
        ok("Connected to PostgreSQL");
        return client;
      }
      if (attempt < 3) warn(`That did not work (attempt ${attempt} of 3). Try again.\n`);
    }

    die(
      "Could not log in to PostgreSQL.",
      [
        "",
        "  The server is running, so this is a credentials problem.",
        "",
        "  Forgotten the password? The simplest fix is to reinstall PostgreSQL",
        "  and choose a password you will remember — nothing of yours is stored",
        "  in it yet.",
      ].join("\n")
    );
  } finally {
    rl.close();
  }
}

/**
 * Creates the role and database if missing. Both halves are idempotent.
 *
 * Deliberately not SUPERUSER, CREATEROLE, CREATEDB, BYPASSRLS or
 * REPLICATION: the API refuses to start as a role with any of those in
 * production. See packages/agent-identity's stricter `legion_app` role
 * (server/src/db/provision-cli.js) for an optional, further-hardened
 * alternative that doesn't even own its own database.
 */
async function ensureDatabase(admin, password) {
  const role = await admin.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [DB_USER]);
  if (role.rowCount === 0) {
    // Identifiers cannot be parameterised; DB_USER is a constant in this file,
    // never user input. The password goes through escapeLiteral.
    await admin.query(`CREATE ROLE ${DB_USER} LOGIN PASSWORD ${admin.escapeLiteral(password)}`);
    ok(`Created database role "${DB_USER}"`);
  } else {
    // The role predates this run. Its password almost certainly does not match
    // the one about to be written to .env, so align them rather than leaving
    // Legion unable to log in to its own database.
    await admin.query(`ALTER ROLE ${DB_USER} LOGIN PASSWORD ${admin.escapeLiteral(password)}`);
    ok(`Database role "${DB_USER}" already existed - password synchronised`);
  }

  const db = await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [DB_NAME]);
  if (db.rowCount === 0) {
    await admin.query(`CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}`);
    ok(`Created database "${DB_NAME}"`);
  } else {
    ok(`Database "${DB_NAME}" already exists`);
  }
}

/** Reads a key from an existing .env so re-running preserves secrets. */
function existingEnvValue(key) {
  if (!existsSync(ENV_PATH)) return null;
  const match = readFileSync(ENV_PATH, "utf8").match(new RegExp(`^${key}=(.*)$`, "m"));
  return match ? match[1].trim() : null;
}

async function main() {
  console.log(c.cyan("\nLegion setup\n"));

  const major = Number(process.versions.node.split(".")[0]);
  if (major < 20) {
    die(`Node.js 20 or newer is required (found ${process.versions.node}).`, "  https://nodejs.org/");
  }
  ok(`Node.js ${process.versions.node}`);

  // `npm run setup -- --domain legion.example.com`: the public HTTPS address
  // this installation will be reached at (see DEPLOY-ONLINE.md).
  let domain;
  try {
    domain = parseDomain(process.argv.slice(2), process.env);
  } catch (error) {
    die(error.message);
  }
  if (domain) ok(`Public address: https://${domain}`);

  // `--saas`: the hosted service — anyone can sign up, 14-day trial, Paddle
  // billing, email confirmation (SAAS.md). It must be on a public HTTPS domain.
  const saas = parseSaas(process.argv.slice(2), process.env);
  if (saas && !domain) {
    die("--saas needs --domain as well: the hosted service must run on a public HTTPS address.",
      `  ${c.cyan("npm run setup -- --saas --domain legion.example.com")}`);
  }
  if (saas) ok("Mode: hosted service (sign-up, trial, Paddle billing)");

  if (!existsSync(SCHEMA_PATH)) {
    die(`Cannot find ${SCHEMA_PATH}`, "  Run this from inside the Legion folder.");
  }

  // Secrets survive a re-run: regenerating JWT_SECRET would sign everyone out.
  const reusing = existsSync(ENV_PATH);
  // …except a value anyone else could know: a template copied from
  // .env.example, a development default, or something too short or repetitive
  // to be random (same rule as server/src/config.ts isWeakJwtSecret).
  const existingJwt = existingEnvValue("JWT_SECRET");
  const weakJwt = (v) => !v || v.trim().length < 32 || v.startsWith("local-") || new Set(v).size < 10 ||
    /replace[-_ ]?(?:with|me)|change[-_ ]?me|changeme|your[-_ ]?(?:jwt[-_ ]?)?secret|placeholder|example|long[-_ ]?random[-_ ]?string/i.test(v);
  if (existingJwt && weakJwt(existingJwt)) {
    warn("JWT_SECRET in server/.env was a placeholder or too weak — replaced with a random one (existing sessions end).");
  }
  const jwtSecret = existingJwt && !weakJwt(existingJwt) ? existingJwt : randomHex(32);
  if (existingEnvValue("NODE_ENV") === "development") {
    warn("server/.env sets NODE_ENV=development. That is for `npm run dev` on a laptop; remove it on a server.");
  }
  const webhookSecret = existingEnvValue("SECURITY_EVENT_WEBHOOK_SECRET") || randomHex(32);
  // The keyring that encrypts TOTP seeds and webhook secrets at rest. Kept on a
  // re-run (replacing it would make every stored secret unreadable), and safe to
  // ADD to an existing install: secrets written before it are still readable and
  // are re-encrypted under it at the next start.
  const encryptionKeys = existingEnvValue("LEGION_ENCRYPTION_KEYS") || `k1:${randomHex(32)}`;
  // Superseded by LEGION_ENCRYPTION_KEYS; only carried over if an install has one.
  const webhookKey = existingEnvValue("WEBHOOK_ENCRYPTION_KEY");
  const dbPassword = existingEnvValue("__DB_PASSWORD") || randomHex(16);

  const admin = await findAdminConnection();
  const adminHost = admin.host || process.env.PGHOST || "localhost";
  const adminPort = admin.port || Number(process.env.PGPORT || 5432);
  try {
    await ensureDatabase(admin, dbPassword);
  } finally {
    await admin.end().catch(() => {});
  }

  const databaseUrl = `postgresql://${DB_USER}:${dbPassword}@${adminHost}:${adminPort}/${DB_NAME}`;

  const template = `# Legion configuration - generated by "npm run setup"
#
# Keep this file private. Losing JWT_SECRET signs everyone out; losing the
# database password locks Legion out of its own data.

DEPLOYMENT_MODE=${saas ? "saas" : "self-hosted"}
${saas ? `# Strict checks: refuses to start without HTTPS, secure cookies and working SMTP.
NODE_ENV=production
` : ""}PORT=8000
FRONTEND_URL=${domain ? `https://${domain}` : "http://localhost:3000"}

# Which network interface the API listens on. 127.0.0.1 means "only this
# machine" - right when a reverse proxy on this same server provides HTTPS.
# Set 0.0.0.0 only on a trusted internal network with its own firewall.
LEGION_BIND_ADDRESS=127.0.0.1

DATABASE_URL=${databaseUrl}
# Kept so re-running setup does not change the password.
__DB_PASSWORD=${dbPassword}

JWT_SECRET=${jwtSecret}
# Encrypts two-factor secrets and webhook secrets stored in the database.
# Back this up with .env, NOT with the database: losing it locks out every user
# with two-factor sign-in. To rotate, put a new "id:key" FIRST and keep the old
# one after it (see INSTALL.md, "Encryption keys").
LEGION_ENCRYPTION_KEYS=${encryptionKeys}
${webhookKey ? `# Legacy, read-only: lets webhook secrets from before LEGION_ENCRYPTION_KEYS be
# re-encrypted. Safe to delete once "npm run secrets -w server -- status" shows no legacy-v1.
WEBHOOK_ENCRYPTION_KEY=${webhookKey}` : ""}
# Deprecated: no longer authenticates anything (see WAZUH.md). Kept so alert ids
# stay stable across upgrades.
SECURITY_EVENT_WEBHOOK_SECRET=${webhookSecret}

# Set to true only once Legion is behind HTTPS.
COOKIE_SECURE=${domain ? "true" : "false"}

# The path the BROWSER sees for /auth/refresh. Behind the bundled nginx the API
# lives under /api, so the refresh cookie must be scoped to /api/auth or the
# browser never sends it back and sessions end when the access token expires.
REFRESH_COOKIE_PATH=${domain ? "/api/auth" : "/auth"}

# Which proxies may tell Legion a client's real address (X-Forwarded-For).
# Default: loopback only — nginx on this machine. Never a wildcard.
# TRUSTED_PROXIES=loopback
# Extra browser origins allowed to call the API (comma-separated, exact).
# FRONTEND_URL is always allowed.
# CORS_ORIGINS=

${saas ? `# --- Email (required for the hosted service) ---------------------------------
# Sign-up confirmation, password reset, invitations and alert emails.
# Defaults are for Resend (SAAS.md, step 2): paste your Resend API key as
# SMTP_PASSWORD. Any other SMTP provider works too.
SMTP_HOST=smtp.resend.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=resend
SMTP_PASSWORD=
SMTP_FROM=Legion <no-reply@${domain}>
ALERT_EMAIL_MIN_SEVERITY=high

# --- Billing: Paddle (SAAS.md, step 3) ---------------------------------------
# sandbox while testing, production once Paddle has approved your website.
# Must match NEXT_PUBLIC_PADDLE_ENVIRONMENT in frontend/.env.local.
PADDLE_ENVIRONMENT=sandbox
PADDLE_API_KEY=
PADDLE_WEBHOOK_SECRET=
# Free days every new workspace gets. Keep NEXT_PUBLIC_TRIAL_DAYS the same.
TRIAL_DAYS=14
` : `# --- Email (optional) --------------------------------------------------------
# Without SMTP, password-reset and invitation links are printed to this
# server's console instead of being emailed.
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=Legion <no-reply@example.com>
ALERT_EMAIL_MIN_SEVERITY=high
`}
# --- AI (optional) -----------------------------------------------------------
# Empty means no alert data ever leaves this machine.
#
# OpenRouter reaches many vendors' models with one key, including free ones.
# Pick one at https://openrouter.ai/models, or leave OPENROUTER_MODEL empty to
# use your OpenRouter account default.
OPENROUTER_API_KEY=
OPENROUTER_MODEL=

# Groq is the alternative. With both keys set, OpenRouter wins unless
# AI_PROVIDER=groq.
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile
AI_PROVIDER=
`;
  // Everything the operator already configured (SMTP, AI keys, their public
  // address…) survives a re-run. Only what setup itself owns is rewritten,
  // plus the public address when --domain asks for it.
  const force = new Set(["DATABASE_URL", "__DB_PASSWORD", "JWT_SECRET", "SECURITY_EVENT_WEBHOOK_SECRET"]);
  if (domain) { force.add("FRONTEND_URL"); force.add("COOKIE_SECURE"); force.add("REFRESH_COOKIE_PATH"); }
  if (saas) { force.add("DEPLOYMENT_MODE"); force.add("NODE_ENV"); }
  const previous = reusing ? readFileSync(ENV_PATH, "utf8") : "";
  writeFileSync(ENV_PATH, mergeEnv(template, previous, force), { mode: 0o600 });
  try { chmodSync(ENV_PATH, 0o600); } catch { /* Windows ignores POSIX modes */ }
  ok(reusing ? "Updated server/.env (existing secrets kept)" : "Wrote server/.env with new secrets");

  // The operator's own answers (their name on the legal pages, Paddle keys…)
  // are never overwritten; only the API address (--domain) and the mode
  // (--saas) are, when asked for.
  const frontendTemplate = `# Dashboard configuration - generated by "npm run setup"
#
# These are read when the dashboard is BUILT, not when it starts. After
# changing anything here, run "npm run build" again.

NEXT_PUBLIC_API_URL=${domain ? `https://${domain}/api` : "http://localhost:8000"}

# ${saas ? "Who sells the service: your company, or your legal name as a sole\n# proprietor. Paddle requires it in the Terms." : "Your organisation. You run this installation, so the built-in privacy and\n# terms pages describe you, not the vendor - they name whatever you put here."}
# Left empty, those pages say so plainly instead of naming anyone.
NEXT_PUBLIC_OPERATOR_NAME=
NEXT_PUBLIC_SUPPORT_EMAIL=
${saas ? `
# --- Hosted service (SAAS.md) ---
NEXT_PUBLIC_DEPLOYMENT_MODE=saas
# Where your server is, e.g. "Germany (Hetzner)" - named in the Privacy Policy.
NEXT_PUBLIC_DATA_LOCATION=
NEXT_PUBLIC_TRIAL_DAYS=14
# Paddle > Developer tools > Authentication > client-side token, and the
# plan's price id (pri_...). Environment must match PADDLE_ENVIRONMENT.
NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=
NEXT_PUBLIC_PADDLE_PRICE_ID=
# Optional: shown before Paddle's localized price loads, e.g. 49 USD.
# Don't use the "$" sign here: it is read as a variable and comes out empty.
NEXT_PUBLIC_PRICE_LABEL=
` : ""}`;
  const frontendForce = new Set();
  if (domain) frontendForce.add("NEXT_PUBLIC_API_URL");
  if (saas) frontendForce.add("NEXT_PUBLIC_DEPLOYMENT_MODE");
  const frontendExisted = existsSync(FRONTEND_ENV_PATH);
  const frontendPrevious = frontendExisted ? readFileSync(FRONTEND_ENV_PATH, "utf8") : "";
  writeFileSync(FRONTEND_ENV_PATH, mergeEnv(frontendTemplate, frontendPrevious, frontendForce));
  ok(frontendExisted ? "Updated frontend/.env.local (your values kept)" : "Wrote frontend/.env.local");

  // Applied straight from the .sql file so setup works before any build. Every
  // statement is IF NOT EXISTS, so this is safe on an existing database too.
  const appClient = new pg.Client({ connectionString: databaseUrl, connectionTimeoutMillis: 10_000 });
  try {
    await appClient.connect();
    await appClient.query(readFileSync(SCHEMA_PATH, "utf8"));
    ok("Database schema applied");
  } catch (error) {
    die(`Could not apply the schema: ${error.message}`, INSTALL_HINT);
  } finally {
    await appClient.end().catch(() => {});
  }

  if (saas) {
    console.log(`
${c.green("Setup complete - hosted service.")}

  Before it can take customers, fill in (details in SAAS.md):
    server/.env          SMTP_PASSWORD (Resend API key), PADDLE_API_KEY, PADDLE_WEBHOOK_SECRET
    frontend/.env.local  NEXT_PUBLIC_OPERATOR_NAME, NEXT_PUBLIC_SUPPORT_EMAIL,
                         NEXT_PUBLIC_DATA_LOCATION, NEXT_PUBLIC_PADDLE_CLIENT_TOKEN,
                         NEXT_PUBLIC_PADDLE_PRICE_ID
  Then:
    ${c.cyan("npm run build")}
    ${c.cyan("sudo systemctl restart legion")}   (or npm start)

  Your own account: sign up at ${c.cyan(`https://${domain}/signup`)} like any customer.
`);
    return;
  }

  console.log(`
${c.green("Setup complete.")}

  Start Legion:
    ${c.cyan("npm run build")}
    ${c.cyan("npm start")}

  Then open ${c.cyan(domain ? `https://${domain}` : "http://localhost:3000")} and create the first
  administrator account. You will need the one-time setup token that
  the server prints when it starts (also saved in server/.legion-setup-token).
  It stops working once the administrator exists.

  Before other people use this installation, put your organisation's name
  and contact address in ${c.cyan("frontend/.env.local")} and build again -
  they are what the privacy and terms pages will show.
`);
}

main().catch((error) => die(error?.message ?? String(error)));
