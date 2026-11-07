#!/usr/bin/env node
/**
 * Protection modes, end to end, against the BUILT API (separate owner/runtime database roles, and
 * DB_RLS from the environment): Legion acts on its own only after an administrator allowed it, only
 * as far as they allowed, and tells them.
 *
 *   1. Manual (the default): a real attack alert arrives from a sensor → nothing is blocked.
 *   2. The administrator turns on hybrid with "block an address" (notice accepted) → the next attack
 *      from a public address is blocked within seconds, by Legion, and the administrators get a mail.
 *   3. A private address, and an address on the allowlist, are never blocked.
 *   4. The emergency stop halts it; lifting it resumes. Switching back to manual stops it for good.
 *   5. Everything is in the report and in the audit chain, which still verifies.
 *
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/e2e-protection.mjs
 */
import { randomBytes } from "node:crypto";
import { client, freePort, freshDatabase, reporter, signedWebhook, smtpSink, startApi, until, wazuhAlert, webhookBody } from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const R = reporter("protection modes");
const { check, section } = R;
const FRONTEND = "https://app.legion.test";
const PASSWORD = "Correct-horse-battery-1";
let db, api, smtp;

async function main() {
  db = await freshDatabase(ADMIN, "legion_prot");
  smtp = await smtpSink(await freePort());
  api = await startApi({
    NODE_ENV: "development", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url,
    JWT_SECRET: randomBytes(48).toString("hex"), PAYMENT_HASH_KEY: randomBytes(32).toString("hex"), LEGION_ENCRYPTION_KEYS: `prot:${randomBytes(32).toString("hex")}`,
    FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true", SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtp.port), SMTP_FROM: "Legion <no-reply@legion.test>",
    ALERT_EMAIL_MIN_SEVERITY: "off", RUNTIME_POLL_SECONDS: "1",
  }, { port: await freePort() });
  section("setup");
  check("the built API boots", api.up, api.log().slice(-500));
  if (!api.up) return;
  const setupToken = /(lst_[A-Za-z0-9_-]+)/.exec(api.log())?.[1];
  const c = client(api.base, { headers: { origin: FRONTEND } });
  await c.call("/auth/register", { method: "POST", body: { email: "soc@example.com", password: PASSWORD, tenant_name: "Protect Co", setup_token: setupToken } });
  const login = await c.call("/auth/login", { method: "POST", body: { username: "soc@example.com", password: PASSWORD } });
  c.setToken(login.body.access_token);
  const cred = await c.call("/security-events/credentials", { method: "POST", body: { label: "manager" } });
  check("sensor key issued", cred.status === 201);
  let n = 0;
  const attack = (ip, level = 10) => signedWebhook(api.base, cred.body.id, cred.body.secret, webhookBody(wazuhAlert(++n, { level, srcip: ip })))();
  const blocked = async () => ((await c.call("/security/blocks?active=true")).body?.blocks ?? []).map((b) => b.ip);
  const settle = (ms = 4000) => new Promise((r) => setTimeout(r, ms));

  section("manual is the default: Legion detects and does nothing on its own");
  const state = await c.call("/soc/protection");
  check("a new workspace is in manual mode", state.body.protection?.mode === "manual" && state.body.protection?.effective_mode === "manual", state.text);
  check("the sensor's alert is accepted", (await attack("185.220.101.201")).status === 202);
  await settle();
  check("…and nothing is blocked", (await blocked()).length === 0, JSON.stringify(await blocked()));

  section("the administrator allows it (hybrid: block an address)");
  const noAck = await c.call("/soc/protection", { method: "PUT", body: { mode: "hybrid", auto_actions: ["ip.block"] } });
  check("without accepting the notice it is refused", noAck.status === 400 && noAck.body.code === "acknowledgement_required", noAck.text);
  const bad = await c.call("/soc/protection", { method: "PUT", body: { mode: "hybrid", auto_actions: ["account.disable"], acknowledge: true } });
  check("an action Legion cannot really do cannot be allowed", bad.status === 422, bad.text);
  const on = await c.call("/soc/protection", { method: "PUT", body: { mode: "hybrid", auto_actions: ["ip.block"], acknowledge: true } });
  check("accepted and saved", on.status === 200 && on.body.protection.effective_mode === "hybrid", on.text);

  section("an attack from a public address is blocked by Legion, within seconds, and the administrators are told");
  const t0 = Date.now();
  check("the sensor's alert is accepted", (await attack("185.220.101.202")).status === 202);
  const done = await until(async () => (await blocked()).includes("185.220.101.202"), 30_000, 500);
  check(`the attacker is on the blocklist (${Math.round((Date.now() - t0) / 100) / 10}s)`, Boolean(done), JSON.stringify(await blocked()));
  const entry = ((await c.call("/security/blocks?active=true")).body.blocks ?? []).find((b) => b.ip === "185.220.101.202");
  check("…marked as done automatically, not by a person", entry?.automatic === true, JSON.stringify(entry));
  const mail = await until(async () => smtp.messages.find((m) => /Legion acted on its own/.test(m.data)) ?? null, 30_000, 500);
  check("the administrator received a mail saying what Legion did", Boolean(mail) && /185\.220\.101\.202/.test(mail.data), mail ? mail.data.slice(0, 300) : "no mail");
  check("the earlier alert (sent in manual mode) was NOT blocked afterwards", !(await blocked()).includes("185.220.101.201"));

  section("what must never be blocked");
  await attack("10.20.30.40"); await attack("192.168.7.7");
  await c.call("/security/auto-response", { method: "PATCH", body: { allowlist: "185.220.101.203" } });
  await attack("185.220.101.203");
  await settle(5000);
  const after = await blocked();
  check("private addresses and allowlisted ones are left alone", !after.some((ip) => ["10.20.30.40", "192.168.7.7", "185.220.101.203"].includes(ip)), JSON.stringify(after));
  const failed = (await c.call("/actions?status=failed")).body?.actions ?? [];
  check("an allowlisted address is refused at the moment of acting, and recorded as such", failed.some((a) => a.target === "185.220.101.203" && /allowlist/.test(a.error ?? "")), JSON.stringify(failed.map((a) => [a.target, a.error])));

  section("the emergency stop and switching off");
  const stop = await c.call("/actions/controls", { method: "POST", body: { paused: true, reason: "e2e" } });
  check("the emergency stop is accepted", stop.status === 200);
  await attack("185.220.101.204"); await settle(4000);
  check("nothing is blocked while it is on", !(await blocked()).includes("185.220.101.204"));
  await c.call("/actions/controls", { method: "POST", body: { paused: false } });
  check("lifting it lets the held action through", Boolean(await until(async () => (await blocked()).includes("185.220.101.204"), 30_000, 500)));
  const off = await c.call("/soc/protection", { method: "PUT", body: { mode: "manual" } });
  check("switching back to manual is accepted", off.status === 200 && off.body.protection.effective_mode === "manual");
  await attack("185.220.101.205"); await settle(4000);
  check("…and from then on nothing is blocked on its own", !(await blocked()).includes("185.220.101.205"));

  section("the record");
  const report = await c.call("/soc/protection/report?days=1");
  check("the report counts what Legion did on its own", report.body.totals?.automatic >= 2, JSON.stringify(report.body.totals));
  check("…and who changed the settings", (report.body.changes ?? []).length >= 2, JSON.stringify(report.body.changes));
  const verify = await c.call("/soc/audit/verify");
  check("the audit chain still verifies", verify.body.ok === true, verify.text.slice(0, 200));
  const events = (await c.call("/soc/audit?category=controls&limit=50")).body?.events ?? [];
  check("the settings changes are in the chained audit trail", events.filter((e) => e.event === "protection.changed").length >= 2);
}

try { await main(); } catch (e) { check("the run completed", false, e instanceof Error ? e.stack : String(e)); }
finally {
  await api?.stop().catch(() => {});
  await smtp?.stop().catch(() => {});
  await db?.drop().catch(() => {});
}
const failed = R.summary();
process.exit(failed ? 1 : 0);
