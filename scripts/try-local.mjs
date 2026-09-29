/**
 * Legion in test mode — no PostgreSQL install, no Docker.
 *
 *   npm run try
 *
 * Starts a PostgreSQL server bundled as an npm package, points Legion at it,
 * and runs both the API and the dashboard. Everything lives in
 * .legion-testdb/ next to this file; delete that folder to start over.
 *
 * FOR EVALUATION ONLY. The bundled server is convenient, not durable:
 *
 *  - the package that provides it has no stable release yet,
 *  - the data folder is disposable and excluded from backups,
 *  - nothing here is configured the way a real installation should be.
 *
 * Real installations use a PostgreSQL you installed yourself — `npm run setup`
 * — or Docker. See SINOV.md.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
// The PostgreSQL data directory must be empty for initdb, so anything else we
// keep (the chosen ports) lives beside it rather than inside it.
const STATE_DIR = join(root, ".legion-testdb");
const DATA_DIR = join(STATE_DIR, "pgdata");
const ENV_PATH = join(root, "server", ".env");
const SCHEMA_PATH = join(root, "server", "src", "db", "schema.sql");

// Deliberately unusual, so it cannot collide with a PostgreSQL the machine
// already runs on 5432.
const PORT = 54329;

const DB_USER = "legion";
const DB_PASSWORD = "legion-local-test";
const DB_NAME = "postgres";
const DATABASE_URL = `postgresql://${DB_USER}:${DB_PASSWORD}@127.0.0.1:${PORT}/${DB_NAME}`;

const c = {
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};
const ok = (s) => console.log(`${c.green("OK")}  ${s}`);

/** Rejections are not always Errors — embedded-postgres can reject with
 *  undefined, which made the previous handler crash instead of explaining. */
function describe(error) {
  if (!error) return "the database process exited without an error message";
  return error.message || String(error);
}

function die(message, hint) {
  console.error(`\n${c.red("ERROR  " + message)}`);
  if (hint) console.error(hint);
  process.exit(1);
}

const PORTS_FILE = join(STATE_DIR, "ports.json");

/** Is this port free to bind on localhost? */
async function isPortFree(port) {
  const { createServer } = await import("node:net");
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(false));
    server.once("listening", () => server.close(() => resolve(true)));
    server.listen(port, "127.0.0.1");
  });
}

/**
 * Walks upward from `preferred` until something is free.
 *
 * Developers usually have other projects running, and 3000 in particular is
 * taken on most machines. Failing with "port in use" would send someone
 * non-technical hunting through config files.
 */
async function findFreePort(preferred, label) {
  for (let port = preferred; port < preferred + 40; port++) {
    if (await isPortFree(port)) {
      if (port !== preferred) {
        console.log(c.dim(`  ${label} port ${preferred} is busy — using ${port} instead.`));
      }
      return port;
    }
  }
  die(`No free port found for ${label} near ${preferred}.`);
}

/**
 * The bundled PostgreSQL binaries live in a per-platform package, and its
 * postinstall script re-creates symlinks that npm cannot store in a tarball.
 *
 * Recent npm versions block install scripts by default and only print a
 * warning, so the package can look installed while the server it provides is
 * unusable. Checking for the binary turns that into an instruction instead of
 * a crash deep inside the library.
 */
function bundledPostgresProblem() {
  const platformPackage = {
    win32: { x64: "windows-x64", arm64: "windows-arm64" },
    darwin: { x64: "darwin-x64", arm64: "darwin-arm64" },
    linux: { x64: "linux-x64", arm64: "linux-arm64" },
  }[process.platform]?.[process.arch];

  if (!platformPackage) {
    return `There is no bundled PostgreSQL for ${process.platform}/${process.arch}.`;
  }

  // The package exports map hides package.json from require.resolve, so look
  // in the places npm actually installs it: hoisted at the workspace root, or
  // nested next to this script.
  const packageDir = [
    join(root, "node_modules", "@embedded-postgres", platformPackage),
    join(here, "..", "node_modules", "@embedded-postgres", platformPackage),
  ].find((candidate) => existsSync(candidate));

  if (!packageDir) {
    return `The bundled PostgreSQL package for ${platformPackage} is not installed.`;
  }

  const exe = process.platform === "win32" ? ".exe" : "";
  const binDir = join(packageDir, "native", "bin");
  const missing = ["initdb", "postgres"].filter((name) => !existsSync(join(binDir, name + exe)));
  if (missing.length) {
    return `The bundled PostgreSQL is installed but incomplete — missing ${missing.join(" and ")}.`;
  }
  return null;
}

const SCRIPTS_BLOCKED_HINT = [
  "",
  "  This usually means npm blocked the package's install step.",
  "  npm prints a warning about it during `npm install`:",
  "",
  `    ${c.dim("npm warn allow-scripts ... @embedded-postgres/... (install scripts present)")}`,
  "",
  "  Allow it and reinstall:",
  "",
  `    ${c.cyan("npm approve-scripts --allow-scripts-pending")}`,
  `    ${c.cyan("npm install")}`,
  `    ${c.cyan("npm run try")}`,
  "",
  "  Prefer not to? Install PostgreSQL yourself and use",
  `    ${c.cyan("npm run setup")}   ${c.dim("(see SINOV.md)")}`,
].join("\n");

let EmbeddedPostgres;
try {
  EmbeddedPostgres = (await import("embedded-postgres")).default;
} catch {
  die("The bundled PostgreSQL package is not installed.", [
    "",
    `  Run this from the ${c.cyan("legion")} folder:`,
    "",
    `    ${c.cyan("npm install")}`,
    "",
    "  If it is still missing afterwards, your platform may not have a",
    "  prebuilt PostgreSQL. Use `npm run setup` with an installed",
    "  PostgreSQL instead — see SINOV.md.",
  ].join("\n"));
}

console.log(c.cyan("\nLegion — test mode\n"));
console.log(c.yellow("  Bundled database, for trying Legion out only."));
console.log(c.dim("  Real installs: npm run setup (see SINOV.md)\n"));

const major = Number(process.versions.node.split(".")[0]);
if (major < 20) die(`Node.js 20 or newer is required (found ${process.versions.node}).`);
ok(`Node.js ${process.versions.node}`);

const bundledProblem = bundledPostgresProblem();
if (bundledProblem) die(bundledProblem, SCRIPTS_BLOCKED_HINT);
ok("Bundled PostgreSQL present");

// Only the parent: initdb creates and owns DATA_DIR itself, and refuses to
// run if it already contains anything.
mkdirSync(STATE_DIR, { recursive: true });

// PG_VERSION is written last by initdb, so its absence next to a non-empty
// folder means an earlier attempt died partway. initdb would then refuse
// ("directory exists but is not empty") and the server would refuse to start
// on the half-built cluster. Since this data is disposable by definition,
// clearing it is the right move rather than asking someone to do it by hand.
if (existsSync(DATA_DIR) && !existsSync(join(DATA_DIR, "PG_VERSION"))) {
  console.log(c.dim("  Removing an incomplete database from an earlier attempt…"));
  rmSync(DATA_DIR, { recursive: true, force: true });
}

const firstRun = !existsSync(join(DATA_DIR, "PG_VERSION"));

// Pick ports before anything is written or built: the dashboard bakes the API
// address in at build time, so a changed API port means a stale build.
const apiPort = await findFreePort(8000, "API");
const webPort = await findFreePort(3000, "Dashboard");
const apiUrl = `http://localhost:${apiPort}`;
const webUrl = `http://localhost:${webPort}`;

const previousPorts = existsSync(PORTS_FILE)
  ? JSON.parse(readFileSync(PORTS_FILE, "utf8"))
  : null;
// A different API port invalidates the compiled dashboard, which would
// otherwise keep calling the old address and fail with no visible reason.
const apiPortChanged = previousPorts && previousPorts.apiPort !== apiPort;
writeFileSync(PORTS_FILE, JSON.stringify({ apiPort, webPort }, null, 2));

/**
 * PostgreSQL's own output, kept but not printed.
 *
 * An earlier version discarded it to keep the console tidy, which meant a
 * failed start produced "the database process exited" and nothing else — the
 * one place the reason was written had been silenced. Now it is buffered and
 * replayed only when something goes wrong.
 */
const pgOutput = [];
const capture = (line) => {
  const text = String(line ?? "").trimEnd();
  if (text) pgOutput.push(text);
  // Keep the buffer bounded; the tail is what matters.
  if (pgOutput.length > 60) pgOutput.shift();
};

function pgDiagnostics() {
  if (!pgOutput.length) return "  (the database produced no output at all)";
  return pgOutput.slice(-15).map((line) => `    ${line}`).join("\n");
}

const postgres = new EmbeddedPostgres({
  databaseDir: DATA_DIR,
  user: DB_USER,
  password: DB_PASSWORD,
  port: PORT,
  persistent: true,
  onLog: capture,
  onError: capture,
});

let stopping = false;
async function shutdown(code = 0) {
  if (stopping) return;
  stopping = true;
  console.log(c.dim("\nStopping…"));
  try { await postgres.stop(); } catch { /* already gone */ }
  process.exit(code);
}
process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

if (firstRun) {
  console.log(c.dim("  Preparing the database (first run only, ~30s)…"));
  await postgres.initialise().catch((error) =>
    die(`Could not prepare the database: ${describe(error)}`, [
      "",
      "  What the database reported:",
      pgDiagnostics(),
      "",
      "  Two common causes:",
      "    - npm blocked the package's install step (see below)",
      "    - antivirus software blocked it (Windows)",
      SCRIPTS_BLOCKED_HINT,
    ].join("\n"))
  );
}

await postgres.start().catch((error) =>
  die(`Could not start the database: ${describe(error)}`, [
    "",
    "  What the database reported:",
    pgDiagnostics(),
    "",
    `  Port ${PORT} may already be in use, or the folder`,
    `  ${STATE_DIR}`,
    "  may be damaged — deleting it starts over:",
    "",
    `    ${c.cyan(process.platform === "win32" ? "rmdir /s /q .legion-testdb" : "rm -rf .legion-testdb")}`,
    `    ${c.cyan("npm run try")}`,
    "",
    ...(process.platform === "win32"
      ? [
          "  On Windows the bundled PostgreSQL also needs the Microsoft Visual",
          "  C++ runtime. If it is missing, the process exits immediately and",
          "  silently. Install it once:",
          `    ${c.cyan("https://aka.ms/vs/17/release/vc_redist.x64.exe")}`,
          "",
        ]
      : []),
    // Deliberately no "npm blocked the install step" hint here: the binary
    // check already passed, and the database's own output above is a far
    // better lead than a guess.
  ].join("\n"))
);
ok(`Database running on port ${PORT}`);

// Apply the schema directly from the .sql file so this works before any build.
const client = postgres.getPgClient();
await client.connect();
try {
  await client.query(readFileSync(SCHEMA_PATH, "utf8"));
  ok("Schema applied");
} catch (error) {
  await client.end().catch(() => {});
  await shutdown(1);
  die(`Could not apply the schema: ${describe(error)}`);
}
await client.end().catch(() => {});

// Keep the secrets stable across runs so sessions survive a restart.
const previous = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
const keep = (key, fallback) => previous.match(new RegExp(`^${key}=(.*)$`, "m"))?.[1]?.trim() || fallback;
const jwtSecret = keep("JWT_SECRET", randomBytes(32).toString("hex"));
const webhookSecret = keep("SECURITY_EVENT_WEBHOOK_SECRET", randomBytes(32).toString("hex"));
// Encrypts two-factor and webhook secrets at rest (kept across re-runs).
const encryptionKeys = keep("LEGION_ENCRYPTION_KEYS", `k1:${randomBytes(32).toString("hex")}`);
const webhookKey = keep("WEBHOOK_ENCRYPTION_KEY", "");

writeFileSync(ENV_PATH, `# Legion — TEST MODE (generated by "npm run try")
#
# This points at the bundled test database. Running "npm run setup" replaces
# this file with a configuration for a real PostgreSQL.

DEPLOYMENT_MODE=self-hosted
PORT=${apiPort}
FRONTEND_URL=${webUrl}

DATABASE_URL=${DATABASE_URL}

JWT_SECRET=${jwtSecret}
LEGION_ENCRYPTION_KEYS=${encryptionKeys}
WEBHOOK_ENCRYPTION_KEY=${webhookKey}
SECURITY_EVENT_WEBHOOK_SECRET=${webhookSecret}

COOKIE_SECURE=false
SEED_DEMO_DATA=false

# Empty: no alert data leaves this machine.
OPENROUTER_API_KEY=
GROQ_API_KEY=
SMTP_HOST=
`);
ok("Configuration written");

// --- Build if needed ---------------------------------------------------------

function run(command, args, label) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd: root,
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    child.on("error", rejectPromise);
    child.on("exit", (code) =>
      code === 0 ? resolvePromise() : rejectPromise(new Error(`${label} failed (exit ${code})`))
    );
  });
}

const needsBuild =
  !existsSync(join(root, "server", "dist", "index.js")) ||
  !existsSync(join(root, "frontend", ".next")) ||
  apiPortChanged;

if (needsBuild) {
  console.log(c.dim(
    apiPortChanged
      ? "\n  The API port changed, so the dashboard is being rebuilt…\n"
      : "\n  Building Legion (first run only, a minute or two)…\n"
  ));
  // Baked into the dashboard bundle at build time.
  process.env.NEXT_PUBLIC_API_URL = apiUrl;
  await run("npm", ["run", "build"], "Build").catch(async (error) => {
    await shutdown(1);
    die(error.message);
  });
}

// --- Run ---------------------------------------------------------------------

console.log(`
${c.green("Legion is starting.")}

  Dashboard:  ${c.cyan(webUrl)}
  API:        ${c.cyan(apiUrl)}

  Open the dashboard and create the first administrator account.
  The one-time setup token it asks for is printed below by the server.

  ${c.dim("Stop with Ctrl+C.  Start fresh: delete the .legion-testdb folder.")}
`);

process.env.DATABASE_URL = DATABASE_URL;
process.env.JWT_SECRET = jwtSecret;
process.env.PORT = String(apiPort);
process.env.FRONTEND_URL = webUrl;
process.env.NEXT_PUBLIC_API_URL = apiUrl;
// Next.js reads this when `next start` has no -p flag.
process.env.WEB_PORT = String(webPort);

const app = spawn("npm", ["start"], {
  cwd: root,
  stdio: "inherit",
  shell: process.platform === "win32",
  env: process.env,
});
app.on("exit", (code) => shutdown(code ?? 0));
app.on("error", async (error) => {
  console.error(c.red(`Could not start Legion: ${describe(error)}`));
  await shutdown(1);
});
