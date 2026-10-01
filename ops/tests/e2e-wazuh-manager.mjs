#!/usr/bin/env node
/**
 * The real chain, with a real Wazuh manager:
 *
 *   sshd log lines → Wazuh manager (analysisd rules, integratord)
 *     → integrations/custom-legion(.py) inside the manager
 *     → Legion webhook (built API, NODE_ENV=production) → PostgreSQL
 *     → outbox → worker → email (SMTP sink) + realtime frame (WebSocket) → API/UI
 *
 * then Legion is stopped while the manager keeps firing: the integration
 * spools, and once Legion is back every spooled event lands exactly once.
 *
 * Needs Docker (wazuh/wazuh-manager image) and host networking.
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/e2e-wazuh-manager.mjs [--json out.json]
 */
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  REPO, client, decodeQP, freePort, freshDatabase, realtime, reporter, smtpSink, sql, startApi, until, sleep,
} from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const IMAGE = process.env.WAZUH_IMAGE || "wazuh/wazuh-manager:4.9.2";
const jsonOut = process.argv.includes("--json") ? process.argv[process.argv.indexOf("--json") + 1] : null;
const R = reporter("real Wazuh chain");
const { check, section, note } = R;
const NAME = `legion-wazuh-${randomBytes(3).toString("hex")}`;
const FRONTEND = "https://app.legion.test";
const docker = (...args) => execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const dexec = (cmd) => spawnSync("docker", ["exec", NAME, "bash", "-lc", cmd], { encoding: "utf8" });

let db, smtp, api;
const env = {};

/** sshd lines in syslog format; 8+ failures from one address fire Wazuh's brute-force rule (level 10). */
function bruteForce(ip, n = 10) {
  const lines = [];
  for (let i = 0; i < n; i++) {
    const d = new Date();
    const stamp = d.toLocaleString("en-US", { month: "short", timeZone: "UTC" }) + " " + String(d.getUTCDate()).padStart(2, " ") + " " + d.toISOString().slice(11, 19);
    lines.push(`${stamp} web-01 sshd[${4000 + i}]: Failed password for invalid user admin${i} from ${ip} port ${50000 + i} ssh2`);
  }
  return lines.join("\n") + "\n";
}
const inject = (text) => dexec(`cat >> /var/log/legion-sshd.log <<'EOF'\n${text}EOF`);

async function main() {
  section("setup");
  try { docker("image", "inspect", IMAGE); } catch { check(`Docker image ${IMAGE} available`, false, "docker pull it first"); return; }
  db = await freshDatabase(ADMIN, "legion_wz");
  smtp = await smtpSink(await freePort());
  const port = await freePort();
  Object.assign(env, {
    NODE_ENV: "production", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url,
    JWT_SECRET: randomBytes(48).toString("hex"), LEGION_ENCRYPTION_KEYS: `wz:${randomBytes(32).toString("hex")}`,
    FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true", SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtp.port),
    NOTIFY_POLL_SECONDS: "2", ALERT_EMAIL_MIN_SEVERITY: "high",
  });
  api = await startApi(env, { port });
  check("built API up (production mode, self-hosted)", api.up, api.log().slice(-600));
  const setupToken = /(lst_[A-Za-z0-9_-]+)/.exec(api.log())?.[1];
  const c = client(api.base, { headers: { origin: FRONTEND } });
  const reg = await c.call("/auth/register", { method: "POST", body: { email: "soc@example.com", password: "Correct-horse-battery-1", tenant_name: "Real Wazuh Co", setup_token: setupToken } });
  check("first administrator created with the one-time setup token", reg.status === 201, reg.text);
  const login = await c.call("/auth/login", { method: "POST", body: { username: "soc@example.com", password: "Correct-horse-battery-1" } });
  c.setToken(login.body.access_token);
  const cookie = login.setCookies.map((x) => x.split(";")[0]).join("; ");
  await c.call("/notifications/settings", { method: "PATCH", body: { notification_email: "soc-team@example.com" } });
  const confirmMail = await until(async () => smtp.messages.find((m) => /confirm-notification-email\?token=/.test(decodeQP(m.data))));
  const confirmToken = confirmMail && /confirm-notification-email\?token=([A-Za-z0-9_-]+)/.exec(decodeQP(confirmMail.data))?.[1];
  const conf = await c.call("/notifications/confirm", { method: "POST", body: { token: confirmToken } });
  check("alert email address confirmed through the emailed link", conf.status === 200, conf.text);
  const cred = await c.call("/security-events/credentials", { method: "POST", body: { label: "real manager" } });
  check("sensor key issued", cred.status === 201);
  const ws = await realtime(api.base, cookie, FRONTEND);
  check("dashboard realtime socket open", ws.ok, String(ws.status));

  section("Wazuh manager (container)");
  docker("run", "-d", "--name", NAME, "--network", "host", IMAGE);
  const ready = await until(async () => /wazuh-analysisd is running/.test(dexec("/var/ossec/bin/wazuh-control status").stdout), 180_000, 3000);
  check(`real Wazuh manager running (${IMAGE})`, Boolean(ready), dexec("/var/ossec/bin/wazuh-control status").stdout);
  if (!ready) return;
  note("manager version", dexec("/var/ossec/bin/wazuh-control info -v").stdout.trim());
  for (const f of ["custom-legion", "custom-legion.py"]) docker("cp", join(REPO, "integrations", f), `${NAME}:/var/ossec/integrations/${f}`);
  dexec("chmod 750 /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py && chown root:wazuh /var/ossec/integrations/custom-legion /var/ossec/integrations/custom-legion.py && touch /var/log/legion-sshd.log");
  const block = `
<ossec_config>
  <integration>
    <name>custom-legion</name>
    <hook_url>${api.base}/security-events/webhook</hook_url>
    <api_key>${cred.body.api_key}</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/legion-sshd.log</location>
  </localfile>
</ossec_config>
`;
  dexec(`cat >> /var/ossec/etc/ossec.conf <<'EOF'${block}EOF`);
  const restart = dexec("/var/ossec/bin/wazuh-control restart");
  check("manager restarted with the Legion integration configured", restart.status === 0, restart.stderr || restart.stdout);
  await until(async () => /wazuh-integratord is running/.test(dexec("/var/ossec/bin/wazuh-control status").stdout), 120_000, 2000);
  check("integratord running", /wazuh-integratord is running/.test(dexec("/var/ossec/bin/wazuh-control status").stdout));
  await sleep(5000);

  section("chain: log → manager → webhook → Postgres → outbox → email + realtime → API");
  const t0 = Date.now();
  inject(bruteForce("45.155.205.12"));
  const alert = await until(async () => {
    const list = (await c.call("/alerts")).body;
    return Array.isArray(list) ? list.find((a) => a.source === "wazuh" && /brute force|authentication fail/i.test(a.title)) : null;
  }, 120_000, 1000);
  check("the manager's brute-force alert reached Legion's API", Boolean(alert), dexec("tail -20 /var/ossec/logs/integrations.log; tail -5 /var/ossec/logs/alerts/alerts.json").stdout);
  if (!alert) return;
  note("manager → API latency", `${Date.now() - t0} ms (includes the manager's log polling)`);
  note("alert", { title: alert.title, severity: alert.severity, source_ip: alert.source_ip, mitre: alert.mitre_technique });
  check("severity mapped from the Wazuh rule level", ["high", "critical"].includes(alert.severity), alert.severity);
  check("source IP carried from the event", alert.source_ip === "45.155.205.12", alert.source_ip);
  const row = await sql(ADMIN, db.db, "SELECT count(*)::int AS n FROM alerts WHERE id = $1", [alert.id]);
  check("stored in PostgreSQL", row[0].n === 1);
  const frame = await until(async () => ws.frames.find((f) => JSON.stringify(f).includes(alert.id)), 30_000);
  check("pushed to the open dashboard over the WebSocket", Boolean(frame));
  const email = await until(async () => smtp.messages.find((m) => m.to.some((t) => t.includes("soc-team@example.com")) && decodeQP(m.data).includes(alert.title.slice(0, 20))), 60_000);
  check("emailed to the confirmed address by the outbox worker", Boolean(email));
  const deliveries = await c.call("/notifications/deliveries");
  const job = Array.isArray(deliveries.body?.deliveries ?? deliveries.body) ? (deliveries.body.deliveries ?? deliveries.body).find((d) => d.kind === "alert_email" && d.subject_id === alert.id) : null;
  check("the outbox job is marked sent", job?.status === "sent", JSON.stringify(deliveries.body).slice(0, 300));
  const integLog = dexec("cat /var/ossec/logs/integrations.log 2>/dev/null; cat /var/ossec/logs/integrations-legion.log 2>/dev/null").stdout;
  check("the integration log on the manager carries no secret", !integLog.includes(cred.body.secret));

  section("Legion down: the manager keeps firing, the integration spools, nothing is lost");
  const before = (await c.call("/alerts")).body.length;
  // Wazuh's brute-force rule (5712) has ignore="60": after it fires, the manager
  // itself stays quiet for a minute. Wait it out so the outage burst really fires.
  await sleep(65_000);
  await api.stop();
  inject(bruteForce("203.0.113.77"));
  const fired = await until(async () => Number(dexec("grep -c '203.0.113.77' /var/ossec/logs/alerts/alerts.json || true").stdout.trim()) > 0, 90_000, 2000);
  check("the manager fired its alert while Legion was down", Boolean(fired));
  const spooled = await until(async () => {
    const r = dexec("ls /var/ossec/tmp/legion-spool/*/ 2>/dev/null | grep -c json || true");
    return Number(r.stdout.trim()) > 0;
  }, 120_000, 2000);
  check("while Legion is down, the integration spools the event on the manager", Boolean(spooled), dexec("tail -5 /var/ossec/logs/integrations.log").stdout);
  api = await startApi(env, { port });
  check("Legion restarted", api.up);
  // The next alert's delivery drains the spool first (oldest first).
  await sleep(65_000);
  inject(bruteForce("192.0.2.99"));
  const recovered = await until(async () => {
    const list = (await c.call("/alerts")).body;
    return Array.isArray(list) && list.some((a) => a.source_ip === "203.0.113.77") && list.some((a) => a.source_ip === "192.0.2.99") ? list : null;
  }, 150_000, 2000);
  check("after restart the spooled event and the new one both arrive", Boolean(recovered));
  const dupes = await sql(ADMIN, db.db, "SELECT source_ip, count(*)::int AS n FROM alerts WHERE source = 'wazuh' GROUP BY source_ip HAVING count(*) > 1 AND source_ip IN ('45.155.205.12','203.0.113.77','192.0.2.99')");
  note("alerts by address", await sql(ADMIN, db.db, "SELECT source_ip, title, count(*)::int AS n FROM alerts WHERE source = 'wazuh' GROUP BY source_ip, title ORDER BY 1"));
  check("…exactly once each (no duplicate from the re-send)", dupes.length === 0, JSON.stringify(dupes));
  check("the spool is empty again", Number(dexec("ls /var/ossec/tmp/legion-spool/*/ 2>/dev/null | grep -c json || true").stdout.trim()) === 0);
  note("alert count", { before_outage: before, after: recovered?.length });
}

try {
  await main();
} catch (err) {
  check("ran to completion", false, err instanceof Error ? err.stack : String(err));
} finally {
  spawnSync("docker", ["rm", "-f", NAME]);
  await api?.stop().catch(() => {});
  await smtp?.stop().catch(() => {});
  await db?.drop();
  const failed = R.summary();
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(R.results, null, 2));
  process.exit(failed ? 1 : 0);
}
