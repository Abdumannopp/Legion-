#!/usr/bin/env node
/**
 * The main user journeys, in a real browser, against the built API and the
 * built dashboard — what a new customer does in their first hour:
 *
 *   sign up → confirm email → sign in → workspace creation → connect Wazuh
 *   (key, config block, first event) → first alert (and a test alert) →
 *   incident review → first AI agent → agent permission change → an action
 *   that waits for approval, approved in the dashboard → an action Legion
 *   blocks, explained → resume → emergency stop → billing / plan visibility
 *   → an error explained → the same screen in another language.
 *
 * Every step checks what the person sees (text on the page), not only what
 * the API returned. The Wazuh event is delivered by the real integration
 * script (integrations/custom-legion.py) with the key the wizard showed.
 *
 *   npm --prefix server run build && npm --prefix frontend run build
 *   E2E_ADMIN_DATABASE_URL=postgresql://legion:…@127.0.0.1:5432/postgres node ops/tests/e2e-journeys.mjs
 *
 * The dashboard is built against http://localhost:8000 (NEXT_PUBLIC_API_URL's
 * default), so the API runs on 8000 and the dashboard on 3000; both must be
 * free. E2E_SCREENSHOTS=<dir> saves a screenshot of each step.
 */
import { spawn, spawnSync, execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const ADMIN_URL = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN_URL) { console.error("Set E2E_ADMIN_DATABASE_URL (a superuser URL; a throwaway database is created)."); process.exit(2); }

function loadPlaywright() {
  for (const base of [join(REPO, "frontend"), REPO, execSync("npm root -g").toString().trim()]) {
    try { return createRequire(join(base, "noop.js"))("playwright"); } catch { /* next */ }
  }
  console.error("Playwright is not installed (npm i -g playwright)."); process.exit(2);
}
const { chromium } = loadPlaywright();

const id = randomBytes(4).toString("hex");
const DB = `legion_ux_${id}`;
const APP_ROLE = `legion_app_ux_${id}`;
const APP_PASSWORD = randomBytes(24).toString("hex");
const API = "http://localhost:8000";
const WEB = "http://localhost:3000";
const WORK = mkdtempSync(join(tmpdir(), "legion-ux-"));
const SHOTS = process.env.E2E_SCREENSHOTS;
if (SHOTS) mkdirSync(SHOTS, { recursive: true });

let failures = 0;
const ok = (name) => console.log(`  \x1b[32mPASS\x1b[0m ${name}`);
const bad = (name, detail = "") => { failures++; console.log(`  \x1b[31mFAIL\x1b[0m ${name}${detail ? ` — ${String(detail).slice(0, 400)}` : ""}`); };
const check = (name, cond, detail) => (cond ? ok(name) : bad(name, detail));
const dbUrl = (db, user, password) => { const u = new URL(ADMIN_URL); u.pathname = `/${db}`; if (user) { u.username = user; u.password = password; } return u.toString(); };
async function sql(db, text, params = []) {
  const c = new pg.Client({ connectionString: dbUrl(db) });
  await c.connect();
  try { return (await c.query(text, params)).rows; } finally { await c.end(); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 20_000) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn().catch(() => null); if (v) return v; if (Date.now() > end) return null; await sleep(300); }
}

let apiProc, webProc, browser;
const apiLog = [];
let step = 0;
async function shot(page, name) {
  if (SHOTS) await page.screenshot({ path: join(SHOTS, `${String(++step).padStart(2, "0")}-${name}.png`), fullPage: true });
}
/** Visible text of the page — what the person reads. */
const text = (page) => page.locator("body").innerText();
async function sees(page, name, wanted, ms = 10_000) {
  // Case-insensitive: headings styled in capitals read that way in innerText.
  const found = await until(async () => (await text(page)).toLowerCase().includes(wanted.toLowerCase()), ms);
  check(name, found, `"${wanted}" not on ${page.url()}`);
  return found;
}

async function main() {
  console.log("▶ setup: fresh database, API (hosted mode, no SMTP), dashboard");
  await sql("postgres", `CREATE DATABASE "${DB}"`);
  const prov = spawnSync("node", [join(REPO, "server", "dist", "db", "provision-cli.js")], {
    env: { PATH: process.env.PATH, DATABASE_ADMIN_URL: dbUrl(DB), APP_DB_USER: APP_ROLE, APP_DB_PASSWORD: APP_PASSWORD }, encoding: "utf8",
  });
  check("database provisioned", prov.status === 0, prov.stderr || prov.stdout);
  apiProc = spawn("node", ["dist/index.js"], {
    cwd: join(REPO, "server"),
    env: {
      PATH: process.env.PATH, DEPLOYMENT_MODE: "saas", PORT: "8000",
      DATABASE_URL: dbUrl(DB, APP_ROLE, APP_PASSWORD), JWT_SECRET: randomBytes(32).toString("hex"),
      FRONTEND_URL: WEB, COOKIE_SECURE: "false", LEGION_ENCRYPTION_KEYS: `ux:${randomBytes(32).toString("hex")}`,
      SEED_DEMO_DATA: "false", DATA_FILE: join(WORK, "legion.json"), TRIAL_DAYS: "14",
    },
  });
  apiProc.stdout.on("data", (d) => apiLog.push(String(d)));
  apiProc.stderr.on("data", (d) => apiLog.push(String(d)));
  const nextBin = createRequire(join(REPO, "frontend", "package.json")).resolve("next/dist/bin/next");
  webProc = spawn("node", [nextBin, "start", "-H", "localhost", "-p", "3000"], { cwd: join(REPO, "frontend"), env: { ...process.env } });
  const apiUp = await until(() => fetch(`${API}/health`).then((r) => r.ok), 30_000);
  const webUp = await until(() => fetch(`${WEB}/login`).then((r) => r.ok), 60_000);
  check("API and dashboard are up", apiUp && webUp, apiLog.join("").slice(-600));
  if (!apiUp || !webUp) return;

  browser = await chromium.launch();
  const context = await browser.newContext({ locale: "en-US", timezoneId: "Asia/Tashkent" });
  const page = await context.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(e.message));

  // ---------------------------------------------------------------------------
  console.log("▶ 1. sign up");
  const email = `owner-${id}@example.com`, password = "correct-horse-battery-staple";
  await page.goto(`${WEB}/signup`);
  await page.fill("#company", "Acme Security");
  await page.fill("#email", email);
  await page.fill("#password", password);
  await page.check('input[type="checkbox"]');
  await page.click('button[type="submit"]');
  await sees(page, "sign-up asks to confirm the email", "We sent a confirmation link to");
  await shot(page, "signup-sent");
  const verifyUrl = await until(async () => new RegExp(`Email verification URL for ${email.replace(/[.]/g, "\\.")} [^:]*: (\\S+)`).exec(apiLog.join(""))?.[1]);
  check("confirmation link issued", Boolean(verifyUrl));
  await page.goto(verifyUrl);
  await sees(page, "email confirmed", "Email confirmed");
  await page.goto(`${WEB}/login`);
  await page.fill('input[type="email"]', email);
  await page.fill('input[type="password"]', password);
  await page.click('button[type="submit"]');
  await page.waitForURL(`${WEB}/`, { timeout: 15_000 }).catch(() => {});

  console.log("▶ 2. first screen: honest status and what to do first");
  await sees(page, "status says nothing is connected yet", "Not connected yet");
  await sees(page, "the reason is explained", "No sensor is connected, so Legion can't see threats");
  await sees(page, "getting-started checklist is shown", "Getting started");
  await sees(page, "first step: connect a sensor", "Connect a security sensor");
  const t0 = await text(page);
  check("no misleading security score", !/Security score/i.test(t0));
  check("no internal persona names on the first screen", !/Sentinel|Hunter|Guardian|Executor/.test(t0));
  await shot(page, "dashboard-new");

  // ---------------------------------------------------------------------------
  console.log("▶ 3. workspace creation");
  await page.getByRole("button", { name: "New workspace" }).click();
  await page.getByPlaceholder("Workspace name").fill("Acme Lab");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await page.waitForLoadState("load");
  const ws = await until(async () => {
    const r = await page.request.get(`${API}/workspaces`); const b = await r.json();
    const lab = b.workspaces?.find((w) => w.name === "Acme Lab");
    return lab && b.current === lab.id ? b : null;
  });
  check("new workspace created and opened", Boolean(ws));
  const home = ws?.workspaces.find((w) => w.name === "Acme Security");
  const lab = ws?.workspaces.find((w) => w.name === "Acme Lab");
  await sees(page, "the new workspace starts with its own empty status", "Not connected yet");
  await page.getByRole("button", { name: "Acme Security" }).click();
  const back = await until(async () => (await (await page.request.get(`${API}/workspaces`)).json()).current === home?.id);
  check("switched back to the first workspace", Boolean(back));
  await page.waitForLoadState("load");

  // ---------------------------------------------------------------------------
  console.log("▶ 4. connect an integration (Wazuh)");
  await page.goto(`${WEB}/connect`);
  await sees(page, "connect page explains itself without Wazuh jargon", "Connect the tools that watch your computers");
  await sees(page, "setup opens straight away when nothing is connected", "Create a connection key");
  await sees(page, "other integrations are listed as coming soon", "Coming soon");
  await page.getByPlaceholder("e.g. Production Wazuh").fill("Production Wazuh");
  await page.getByRole("button", { name: "Create key" }).click();
  await sees(page, "key is shown once, with a warning", "shown only once");
  const block = await page.getByTestId("ossec-block").innerText();
  const apiKey = /<api_key>(whk_[^<]+)<\/api_key>/.exec(block)?.[1];
  check("config block carries the new key and this API's address", Boolean(apiKey) && block.includes(`${API}/security-events/webhook`), block);
  await sees(page, "waits for the first event", "Waiting for the first event from Wazuh");
  await shot(page, "connect-waiting");

  const alert = {
    timestamp: new Date().toISOString().replace("Z", "+0000"),
    rule: { level: 10, id: "5763", description: "sshd: brute force trying to get access to the system. Authentication failed.", mitre: { id: ["T1110"], tactic: ["Credential Access"], technique: ["Brute Force"] }, groups: ["syslog", "sshd", "authentication_failures"], firedtimes: 1 },
    agent: { id: "001", name: "web-01", ip: "10.0.0.10" }, manager: { name: "wazuh-manager" }, id: `1727400000.${Date.now()}`,
    full_log: "Failed password for admin from 45.155.205.12 port 50122 ssh2", decoder: { name: "sshd" }, location: "/var/log/auth.log",
    data: { srcip: "45.155.205.12", srcuser: "admin" },
  };
  const alertFile = join(WORK, "alert.json");
  writeFileSync(alertFile, JSON.stringify(alert));
  const delivered = spawnSync("python3", [join(REPO, "integrations", "custom-legion.py"), alertFile, apiKey ?? "", `${API}/security-events/webhook`], {
    env: { ...process.env, LEGION_INTEGRATION_LOG: join(WORK, "integrations.log"), LEGION_SPOOL_DIR: join(WORK, "spool") }, encoding: "utf8", timeout: 30_000,
  });
  check("Wazuh integration script delivers the event with that key", delivered.status === 0, delivered.stderr);
  await sees(page, "the page notices the first event by itself", "Connected — Legion received an event from Wazuh", 20_000);
  await page.getByRole("button", { name: "Send a test alert" }).click();
  await sees(page, "test alert sent and labelled as a test", "Test alert sent");
  await shot(page, "connect-connected");

  // ---------------------------------------------------------------------------
  console.log("▶ 5. first alert");
  await page.goto(`${WEB}/`);
  await sees(page, "status now asks for attention (a high threat is open)", "Needs your attention");
  await sees(page, "and says why", "There are open high-severity threats.");
  await sees(page, "the Wazuh source shows as receiving", "Receiving events");
  await sees(page, "the alert is listed", "sshd: brute force");
  const t1 = await text(page);
  check("alerts show where they came from", t1.includes("Wazuh"));
  check("the test alert is marked as a test", /Test alert: Legion is working/.test(t1) && /\bTest\b/.test(t1));
  check("connect and first-event steps are no longer asked for", !t1.includes("Link Wazuh (or another sensor)") && !t1.includes("Legion confirms the connection when the first real event arrives"));
  await page.getByTestId("alert-row").filter({ hasText: "sshd: brute force" }).locator("p").first().click();
  await sees(page, "alert explains what to do", "What to do");
  await shot(page, "dashboard-first-alert");

  console.log("▶ 6. incident review");
  await page.getByRole("link", { name: "Full details" }).first().click();
  await sees(page, "incident shows its source in plain words", "Source");
  await sees(page, "incident source is Wazuh", "Wazuh");
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
  await sees(page, "status changes to investigating", "Investigating");
  const alertId = page.url().split("/incident/")[1];
  await shot(page, "incident");

  // ---------------------------------------------------------------------------
  console.log("▶ 7. first AI agent");
  await page.goto(`${WEB}/agents`);
  await sees(page, "agents page explains what Legion does for agents", "Legion checks every action your AI agents take");
  await sees(page, "empty state says what to do", "No AI agents yet");
  await page.getByRole("button", { name: "Add an agent" }).click();
  await page.getByPlaceholder("e.g. Triage assistant").fill("Night triage");
  await page.getByText("Triage assistant", { exact: true }).click();
  await sees(page, "the preset shows what it can do in words", "Change alert status (for example, resolve)");
  await sees(page, "and what no agent can ever do", "Invite, remove or change people");
  await page.getByRole("button", { name: "Add agent" }).click();
  await sees(page, "secret shown once, with instructions", "shown only once");
  const created = page.getByTestId("agent-created");
  const codes = await created.locator("code").allInnerTexts();
  const [agentId, secret] = codes;
  check("agent ID and secret are shown", /^[0-9a-f-]{36}$/.test(agentId ?? "") && (secret ?? "").length > 20, codes.join(" | "));
  await shot(page, "agent-created");
  await page.getByRole("button", { name: "I've saved it" }).click();
  await page.waitForURL(`${WEB}/agents/${agentId}`);
  await sees(page, "agent page: can do", "Can do");
  await sees(page, "agent page: can't do", "Can't do");
  await sees(page, "agent is working", "Working");

  console.log("▶ 8. agent permission change");
  await page.getByRole("button", { name: "Change", exact: true }).click();
  await page.getByLabel("Read databases").check();
  await page.getByRole("button", { name: "Save changes" }).click();
  await sees(page, "saved, with when it applies", "The change applies to the agent's next action");
  await sees(page, "new permission listed", "Read databases");
  await shot(page, "agent-permissions");

  // ---------------------------------------------------------------------------
  console.log("▶ 9. allow: a risky action waits for a person, who approves it");
  const cur = await (await page.request.get(`${API}/firewall/policy`)).json();
  const policy = cur.policy ?? cur;
  policy.responses.confirm.permissions = [...new Set([...policy.responses.confirm.permissions, "alerts:update_status"])];
  const put = await page.request.put(`${API}/firewall/policy`, { data: policy });
  check("admin requires approval for alert status changes", put.ok(), await put.text());
  const agentToken = (await (await fetch(`${API}/agent/v1/token`, { method: "POST", headers: { authorization: `Bearer ${secret}` } })).json()).access_token;
  const agentCall = (path, init = {}) => fetch(`${API}${path}`, { ...init, headers: { "content-type": "application/json", authorization: `Bearer ${agentToken}`, ...(init.headers ?? {}) } });
  const asked = await agentCall(`/agent/v1/alerts/${alertId}/status`, { method: "PATCH", body: JSON.stringify({ status: "resolved" }) });
  const askedBody = await asked.json();
  check("the agent is told to wait for approval", asked.status === 403 && askedBody.error?.code === "approval_required", JSON.stringify(askedBody));
  await page.reload();
  await page.getByRole("tab", { name: /Waiting for you/ }).click();
  await sees(page, "approval explains what the agent wants, in words", "Change alert status (for example, resolve)");
  await sees(page, "approval explains it is once only", "exactly this, once");
  await shot(page, "agent-approval");
  await page.getByRole("button", { name: "Approve once" }).click();
  await sees(page, "approved", "The agent may now do this once.");
  const retry = await agentCall(`/agent/v1/alerts/${alertId}/status`, { method: "PATCH", body: JSON.stringify({ status: "resolved" }), headers: { "x-legion-approval-id": askedBody.error?.approval?.id } });
  check("the approved action goes through, once", retry.status === 200, String(retry.status));

  console.log("▶ 10. block: Legion stops an agent reaching another workspace, and says why");
  const grab = await agentCall("/agent/v1/tools/authorize", { method: "POST", body: JSON.stringify({ call: { kind: "database", operation: "query", sql: "SELECT id FROM alerts WHERE tenant_id = $1 LIMIT 5", params: [lab?.id] } }) });
  check("the API refuses and contains the agent", grab.status === 403 && (await grab.json()).decision === "QUARANTINE");
  await page.reload();
  await sees(page, "agent shows as paused", "Paused");
  await sees(page, "and why it can't act", "Paused — it can't do anything until an admin resumes it.");
  await page.getByRole("tab", { name: "What it did" }).click();
  await sees(page, "activity names the decision in words", "Blocked — agent paused");
  await sees(page, "activity explains why", "It tried to reach data that belongs to another workspace.");
  await sees(page, "activity says what to do", "keep the agent paused and check who controls it");
  await sees(page, "the approval request shows in the history", "Asked for approval");
  await sees(page, "and the approved action, as approved", "Allowed — a person approved it");
  const t2 = await text(page);
  check("rule ids stay out of the main text (they are under technical details)", !t2.includes("sql.foreign_tenant"));
  await shot(page, "agent-blocked");
  await page.goto(`${WEB}/`);
  await sees(page, "dashboard reports what Legion blocked", "What Legion blocked");
  await sees(page, "dashboard names the agent and the reason", "Night triage");
  await sees(page, "dashboard reason is in words", "Legion paused or stopped an AI agent this week.");
  await shot(page, "dashboard-blocked");

  console.log("▶ 11. resume, then emergency stop");
  await page.goto(`${WEB}/agents/${agentId}`);
  await page.getByRole("button", { name: "Resume" }).click();
  await sees(page, "resumed", "Resumed.");
  await sees(page, "working again", "Working");
  await page.getByRole("button", { name: "Emergency stop" }).click();
  await sees(page, "stop dialog offers two plain choices", "It's compromised");
  const stopBtn = page.getByRole("button", { name: "Stop this agent" });
  check("stop needs a reason first", await stopBtn.isDisabled());
  await page.getByText("It's compromised").click();
  await page.getByPlaceholder("e.g. It posted customer data to an unknown website").fill("Tried to read another workspace's alerts");
  await stopBtn.click();
  await sees(page, "stopped, and admins told", "Stopped. Admins have been notified.");
  const oldKey = await fetch(`${API}/agent/v1/token`, { method: "POST", headers: { authorization: `Bearer ${secret}` } });
  check("after a confirmed compromise the old key no longer works", oldKey.status === 401, String(oldKey.status));
  await shot(page, "agent-stopped");

  // ---------------------------------------------------------------------------
  console.log("▶ 12. billing / plan visibility");
  await page.goto(`${WEB}/billing`);
  await sees(page, "plan: free trial with days left and end date", "Free trial —");
  await sees(page, "what the plan includes", "Real-time alerts from your security sensors");
  await shot(page, "billing");

  console.log("▶ 13. an error, explained");
  await page.goto(`${WEB}/agents/00000000-0000-4000-8000-000000000000`);
  await sees(page, "what happened", "We couldn't find that");
  await sees(page, "why", "It may have been removed, or it belongs to a different workspace.");
  await sees(page, "what to do", "Check that you're in the right workspace");
  await shot(page, "error-explained");

  console.log("▶ 14. the same screens in another language and time zone");
  await context.addCookies([{ name: "legion-locale", value: "ru", url: WEB }]);
  await page.evaluate(() => { try { localStorage.setItem("legion-locale", "ru"); } catch { /* ignore */ } });
  await page.goto(`${WEB}/`);
  await sees(page, "dashboard in Russian", "Что заблокировал Legion");
  await page.goto(`${WEB}/agents/${agentId}`);
  await page.getByRole("tab", { name: "Что делал" }).click();
  await sees(page, "block explained in Russian", "Агент пытался получить данные другого рабочего пространства.");
  await shot(page, "agent-ru");

  check("no uncaught errors in the browser", pageErrors.length === 0, pageErrors.join(" | "));
}

try {
  await main();
} catch (err) {
  bad("unexpected error", err instanceof Error ? err.stack : String(err));
} finally {
  await browser?.close().catch(() => {});
  webProc?.kill("SIGTERM");
  apiProc?.kill("SIGTERM");
  await sleep(1500);
  await sql("postgres", "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", [DB]).catch(() => {});
  await sql("postgres", `DROP DATABASE IF EXISTS "${DB}"`).catch(() => {});
  await sql("postgres", `DROP ROLE IF EXISTS "${APP_ROLE}"`).catch(() => {});
  console.log(failures ? `\n${failures} check(s) failed` : "\nAll journey checks passed");
  process.exit(failures ? 1 : 0);
}
