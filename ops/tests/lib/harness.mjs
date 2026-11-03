/**
 * Shared pieces for the production validation scripts (ops/tests/*.mjs):
 * a throwaway database, the built API as a real process, a local SMTP sink
 * that records what Legion sends, signed sensor requests, cookie sessions and
 * a realtime (WebSocket) client. Nothing here is mocked inside Legion: the API
 * runs from server/dist exactly as `npm start` runs it.
 */
import { spawn, spawnSync } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import net from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import pg from "pg";

export const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const require = createRequire(join(REPO, "server", "package.json"));
export const WebSocket = require("ws");

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function until(fn, ms = 20_000, every = 250) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => null);
    if (v) return v;
    if (Date.now() > end) return null;
    await sleep(every);
  }
}

// --- results ------------------------------------------------------------------

export function reporter(title) {
  const results = [];
  let section = "";
  return {
    section(name) { section = name; console.log(`\n▶ ${name}`); },
    check(name, cond, detail = "") {
      results.push({ section, name, pass: Boolean(cond), detail: cond ? "" : String(detail).slice(0, 500) });
      console.log(`  ${cond ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m"} ${name}${cond || !detail ? "" : ` — ${String(detail).slice(0, 300)}`}`);
      return Boolean(cond);
    },
    note(name, value) {
      results.push({ section, name, note: value });
      console.log(`  \x1b[36mINFO\x1b[0m ${name}: ${typeof value === "string" ? value : JSON.stringify(value)}`);
    },
    results,
    summary() {
      const failed = results.filter((r) => r.pass === false);
      const passed = results.filter((r) => r.pass === true).length;
      console.log(`\n${title}: ${passed} passed, ${failed.length} failed`);
      for (const f of failed) console.log(`  FAILED [${f.section}] ${f.name}: ${f.detail}`);
      return failed.length;
    },
  };
}

// --- database -----------------------------------------------------------------

export function dbUrl(admin, db, user, password) {
  const u = new URL(admin);
  u.pathname = `/${db}`;
  if (user) { u.username = user; u.password = password; }
  return u.toString();
}
export async function sql(admin, db, text, params = []) {
  const c = new pg.Client({ connectionString: dbUrl(admin, db) });
  await c.connect();
  try { return (await c.query(text, params)).rows; } finally { await c.end(); }
}

/** A fresh database and the API's own (non-superuser) role, via the real provision-cli. */
export async function freshDatabase(admin, prefix) {
  const id = randomBytes(4).toString("hex");
  const db = `${prefix}_${id}`, role = `${prefix}_app_${id}`, password = randomBytes(24).toString("hex");
  await sql(admin, "postgres", `CREATE DATABASE "${db}"`);
  const r = spawnSync("node", [join(REPO, "server", "dist", "db", "provision-cli.js")], {
    env: { PATH: process.env.PATH, DATABASE_ADMIN_URL: dbUrl(admin, db), APP_DB_USER: role, APP_DB_PASSWORD: password }, encoding: "utf8",
  });
  if (r.status !== 0) throw new Error(`provision failed: ${r.stderr || r.stdout}`);
  return {
    db, role, url: dbUrl(admin, db, role, password),
    async drop() {
      await sql(admin, "postgres", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", [db]).catch(() => {});
      await sql(admin, "postgres", `DROP DATABASE IF EXISTS "${db}"`).catch(() => {});
      await sql(admin, "postgres", `DROP ROLE IF EXISTS "${role}"`).catch(() => {});
    },
  };
}

// --- the API --------------------------------------------------------------------

/** Starts server/dist/index.js with `env`; resolves once /health says the database is up. */
export async function startApi(env, { name = "api", port } = {}) {
  const logs = [];
  const proc = spawn("node", ["dist/index.js"], { cwd: join(REPO, "server"), env: { PATH: process.env.PATH, PORT: String(port), ...env } });
  proc.stdout.on("data", (d) => logs.push(String(d)));
  proc.stderr.on("data", (d) => logs.push(String(d)));
  let exited = null;
  proc.on("exit", (code, signal) => { exited = { code, signal }; });
  const base = `http://127.0.0.1:${port}`;
  const up = await until(async () => {
    if (exited) throw new Error(`exited ${JSON.stringify(exited)}`);
    const r = await fetch(`${base}/health`);
    return r.status === 200 && (await r.json()).database === "up";
  }, 40_000, 300);
  return {
    name, port, base, proc, logs, log: () => logs.join(""), up: Boolean(up),
    get exited() { return exited; },
    async stop(signal = "SIGTERM") {
      if (exited) return;
      proc.kill(signal);
      await until(async () => exited, 15_000, 100);
    },
  };
}

export async function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

// --- SMTP sink ----------------------------------------------------------------------

/**
 * A minimal SMTP server: accepts every message and keeps it. `fail` makes it
 * refuse (450) at RCPT so the sender sees a real delivery failure; `stop()`
 * closes the port so the sender sees connection refusal.
 */
export async function smtpSink(port) {
  const messages = [];
  const sockets = new Set();
  let mode = "accept";
  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.on("close", () => sockets.delete(sock));
    let buf = "", inData = false, data = "", from = "", to = [];
    sock.write("220 sink ESMTP\r\n");
    sock.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let i;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            messages.push({ from, to, data, at: Date.now() });
            sock.write("250 OK queued\r\n");
            data = ""; to = [];
          } else data += (line.startsWith("..") ? line.slice(1) : line) + "\n";
          continue;
        }
        const cmd = line.slice(0, 4).toUpperCase();
        if (cmd === "EHLO" || cmd === "HELO") sock.write("250-sink\r\n250 8BITMIME\r\n");
        else if (cmd === "MAIL") { from = line; sock.write("250 OK\r\n"); }
        else if (cmd === "RCPT") {
          if (mode === "fail") sock.write("450 mailbox temporarily unavailable\r\n");
          else { to.push(line); sock.write("250 OK\r\n"); }
        }
        else if (cmd === "DATA") { inData = true; sock.write("354 go ahead\r\n"); }
        else if (cmd === "RSET" || cmd === "NOOP") sock.write("250 OK\r\n");
        else if (cmd === "QUIT") { sock.write("221 bye\r\n"); sock.end(); }
        else sock.write("502 not implemented\r\n");
      }
    });
    sock.on("error", () => {});
  });
  await new Promise((r) => server.listen(port, "127.0.0.1", r));
  return {
    port, messages,
    setMode(m) { mode = m; },
    async stop() { for (const s of sockets) s.destroy(); await new Promise((r) => server.close(() => r())); },
    async restart() { await new Promise((r) => server.listen(port, "127.0.0.1", r)); },
  };
}

/** Decodes a quoted-printable body enough to find links in it. */
export function decodeQP(s) {
  return s.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

// --- HTTP clients -------------------------------------------------------------------

/** JSON over fetch, with optional bearer token, forwarded address and extra headers. */
export function client(base, { token, ip, headers = {} } = {}) {
  const jar = new Map();
  const call = async (path, { method = "GET", body, raw, h = {}, tokenOverride } = {}) => {
    const hdrs = { ...headers, ...h };
    const bearer = tokenOverride === undefined ? token : tokenOverride;
    if (bearer) hdrs.authorization = `Bearer ${bearer}`;
    if (ip) hdrs["x-forwarded-for"] = ip;
    if (body !== undefined && raw === undefined) hdrs["content-type"] = "application/json";
    if (jar.size && !hdrs.cookie) hdrs.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await fetch(`${base}${path}`, { method, headers: hdrs, body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined), redirect: "manual" });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(";");
      const eq = pair.indexOf("=");
      const k = pair.slice(0, eq).trim(), v = pair.slice(eq + 1).trim();
      if (v === "" || /max-age=0|expires=thu, 01 jan 1970/i.test(c)) jar.delete(k); else jar.set(k, v);
    }
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, headers: res.headers, body: json ?? text, text, setCookies: res.headers.getSetCookie?.() ?? [] };
  };
  return { call, jar, setToken(t) { token = t; }, get token() { return token; } };
}

/** The v2 sensor signature, exactly as integrations/custom-legion.py computes it. */
export function signedWebhook(base, keyId, secret, body, { ts = Math.floor(Date.now() / 1000), nonce = randomBytes(16).toString("base64url"), ip } = {}) {
  const sig = "v2=" + createHmac("sha256", secret).update(`v2.${ts}.${nonce}.`).update(body).digest("hex");
  const headers = { "content-type": "application/json", "x-legion-key-id": keyId, "x-legion-timestamp": String(ts), "x-legion-nonce": nonce, "x-legion-signature": sig };
  if (ip) headers["x-forwarded-for"] = ip;
  return () => fetch(`${base}/security-events/webhook`, { method: "POST", headers, body });
}

/** A Wazuh alert (alerts.json format) — the shape the manager hands to integrations. */
export function wazuhAlert(n, { level = 10, ruleId = "5763", description = "sshd: brute force trying to get access to the system. Authentication failed.", agent = "web-01", srcip = "45.155.205.12" } = {}) {
  return {
    timestamp: new Date().toISOString().replace("Z", "+0000"),
    rule: { level, description, id: ruleId, mitre: { id: ["T1110"], tactic: ["Credential Access"], technique: ["Brute Force"] }, firedtimes: 1, groups: ["syslog", "sshd"] },
    agent: { id: "001", name: agent, ip: "10.0.0.10" }, manager: { name: "wazuh-manager" },
    id: `1727400000.${n}`, full_log: `Failed password for admin from ${srcip} port 50122 ssh2`, decoder: { name: "sshd" },
    location: "/var/log/auth.log", data: { srcip, srcuser: "admin" },
  };
}
export const webhookBody = (alert) => JSON.stringify({ provider: "wazuh", event: alert });

/** Opens the realtime socket with a session cookie; collects frames. */
export function realtime(base, cookie, origin) {
  return new Promise((resolve) => {
    const frames = [];
    const ws = new WebSocket(base.replace(/^http/, "ws") + "/ws/alerts", { headers: { cookie, ...(origin ? { origin } : {}) } });
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    ws.on("unexpected-response", (_req, res) => done({ ok: false, status: res.statusCode, frames, ws }));
    ws.on("error", (e) => done({ ok: false, status: 0, error: String(e), frames, ws }));
    ws.on("open", () => done({ ok: true, status: 101, frames, ws }));
    ws.on("message", (m) => { try { frames.push(JSON.parse(String(m))); } catch { frames.push(String(m)); } });
  });
}

/** Six-digit TOTP (RFC 6238, SHA-1, 30 s) for an otpauth base32 secret. */
export function totp(base32, at = Date.now(), step = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of base32.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Math.floor(at / 1000 / 30) + step;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h.readUInt32BE(off) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
  return code;
}
