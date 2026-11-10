#!/usr/bin/env node
/**
 * Automatic response, end to end, with a REAL Wazuh manager:
 *
 *   automated SSH password guessing (35 attempts from one address in seconds)
 *     → Wazuh manager rules → custom-legion.py → Legion webhook
 *     → Legion recognises the burst as a campaign (velocity) and, with
 *       automatic response on, blocks the address (audited, expiring)
 *     → the manager's command wodle runs custom-legion.py --sync-blocklist
 *     → JSON line in /var/ossec/logs/legion-blocklist.log → rule 100950
 *     → Wazuh active response firewall-drop for that address
 *   and Legion's own block event does NOT come back as an alert; an
 *   administrator's unblock stops the re-announcement and Wazuh lifts the
 *   block at its timeout.
 *
 * The active response here runs on the manager itself (<location>server</location>)
 * so it can be observed without agents; production uses <location>all</location>
 * (integrations/wazuh/ossec-legion-response.xml). The manager image has no
 * iptables, so what is proven is that Wazuh EXECUTED firewall-drop with the
 * right address (its active-responses.log), not the kernel rule itself.
 *
 * Needs Docker (wazuh/wazuh-manager image).
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/e2e-wazuh-response.mjs
 */
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { REPO, client, freePort, freshDatabase, reporter, sql, startApi, until, sleep } from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const IMAGE = process.env.WAZUH_IMAGE || "wazuh/wazuh-manager:4.9.2";
const R = reporter("real Wazuh automatic response");
const { check, section, note } = R;
const NAME = `legion-wzr-${randomBytes(3).toString("hex")}`;
const FRONTEND = "https://app.legion.test";
const ATTACKER = "45.155.205.12";
const AR_TIMEOUT = 60;
const docker = (...args) => execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const dexec = (cmd) => spawnSync("docker", ["exec", NAME, "bash", "-lc", cmd], { encoding: "utf8" });

function failedLogins(ip, n) {
  const lines = [];
  for (let i = 0; i < n; i++) {
    const d = new Date();
    const stamp = d.toLocaleString("en-US", { month: "short", timeZone: "UTC" }) + " " + String(d.getUTCDate()).padStart(2, " ") + " " + d.toISOString().slice(11, 19);
    lines.push(`${stamp} web-01 sshd[${5000 + i}]: Failed password for invalid user svc${i} from ${ip} port ${40000 + i} ssh2`);
  }
  return lines.join("\n") + "\n";
}

let db, api;

async function main() {
  section("setup");
  try { docker("image", "inspect", IMAGE); } catch { check(`Docker image ${IMAGE} available`, false, "docker pull it first"); return; }
  const gateway = docker("network", "inspect", "bridge", "--format", "{{range .IPAM.Config}}{{.Gateway}}{{end}}").trim() || "172.17.0.1";
  db = await freshDatabase(ADMIN, "legion_wzr");
  const port = await freePort();
  api = await startApi({
    NODE_ENV: "development", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url,
    // The manager runs in its own network namespace and reaches Legion through the bridge.
    LEGION_BIND_ADDRESS: "0.0.0.0",
    JWT_SECRET: randomBytes(48).toString("hex"), PAYMENT_HASH_KEY: randomBytes(32).toString("hex"), LEGION_ENCRYPTION_KEYS: `wzr:${randomBytes(32).toString("hex")}`,
    FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true",
  }, { port });
  check("built API up", api.up, api.log().slice(-600));
  const setupToken = /(lst_[A-Za-z0-9_-]+)/.exec(api.log())?.[1];
  const c = client(api.base, { headers: { origin: FRONTEND } });
  await c.call("/auth/register", { method: "POST", body: { email: "soc@example.com", password: "Correct-horse-battery-1", tenant_name: "Response Co", setup_token: setupToken } });
  const login = await c.call("/auth/login", { method: "POST", body: { username: "soc@example.com", password: "Correct-horse-battery-1" } });
  c.setToken(login.body.access_token);
  const cred = await c.call("/security-events/credentials", { method: "POST", body: { label: "manager" } });
  check("sensor key issued", cred.status === 201);
  const auto = await c.call("/security/auto-response", { method: "PATCH", body: { mode: "auto", minutes: 30 } });
  check("automatic response switched on by the administrator", auto.status === 200 && auto.body.mode === "auto", auto.text);

  section("Wazuh manager with Legion's response configuration");
  docker("run", "-d", "--name", NAME, IMAGE);
  const ready = await until(async () => /wazuh-analysisd is running/.test(dexec("/var/ossec/bin/wazuh-control status").stdout), 240_000, 3000);
  check(`real Wazuh manager running (${IMAGE})`, Boolean(ready));
  if (!ready) return;
  for (const f of ["custom-legion", "custom-legion.py"]) docker("cp", join(REPO, "integrations", f), `${NAME}:/var/ossec/integrations/${f}`);
  docker("cp", join(REPO, "integrations", "wazuh", "legion_rules.xml"), `${NAME}:/var/ossec/etc/rules/legion_rules.xml`);
  const hook = `http://${gateway}:${port}/security-events/webhook`;
  dexec(`printf '%s\\n' '${cred.body.api_key}' > /var/ossec/etc/legion.key && chown root:wazuh /var/ossec/etc/legion.key && chmod 640 /var/ossec/etc/legion.key`);
  dexec("chmod 750 /var/ossec/integrations/custom-legion* && chown root:wazuh /var/ossec/integrations/custom-legion* /var/ossec/etc/rules/legion_rules.xml && touch /var/log/legion-sshd.log");
  // Documented setup step: the file exists before Wazuh starts watching it.
  dexec("touch /var/ossec/logs/legion-blocklist.log && chown wazuh:wazuh /var/ossec/logs/legion-blocklist.log");
  // The documented blocks (integrations/wazuh/ossec-legion-response.xml), with
  // the response on the manager itself and a short timeout so the test can see
  // it lifted. Level 3 forwards each failed login, as a busy SOC would.
  const conf = `
<ossec_config>
  <integration>
    <name>custom-legion</name>
    <hook_url>${hook}</hook_url>
    <api_key>${cred.body.api_key}</api_key>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/legion-sshd.log</location>
  </localfile>
  <wodle name="command">
    <disabled>no</disabled>
    <tag>legion-blocklist</tag>
    <command>/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-legion.py --sync-blocklist @/var/ossec/etc/legion.key ${hook}</command>
    <interval>1m</interval>
    <run_on_start>yes</run_on_start>
    <timeout>50</timeout>
    <ignore_output>yes</ignore_output>
  </wodle>
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/legion-blocklist.log</location>
  </localfile>
  <active-response>
    <command>firewall-drop</command>
    <location>server</location>
    <rules_id>100950</rules_id>
    <timeout>${AR_TIMEOUT}</timeout>
  </active-response>
</ossec_config>
`;
  dexec(`cat >> /var/ossec/etc/ossec.conf <<'EOF'${conf}EOF`);
  const test = dexec("/var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -3");
  check("Wazuh accepts legion_rules.xml (analysisd -t)", test.status === 0, test.stdout + test.stderr);
  const restart = dexec("/var/ossec/bin/wazuh-control restart");
  check("manager restarted with the integration, the wodle, the rule and the active response", restart.status === 0, restart.stderr || restart.stdout);
  await until(async () => /wazuh-integratord is running/.test(dexec("/var/ossec/bin/wazuh-control status").stdout), 120_000, 2000);
  await sleep(5000);

  section("an automated attack: 35 password guesses from one address in seconds");
  const t0 = Date.now();
  dexec(`cat >> /var/log/legion-sshd.log <<'EOF'\n${failedLogins(ATTACKER, 35)}EOF`);
  const campaign = await until(async () => {
    const list = (await c.call("/security/campaigns")).body?.campaigns ?? [];
    return list.find((x) => x.subject === ATTACKER) ?? null;
  }, 180_000, 2000);
  check("Legion recognised the attack as a campaign", Boolean(campaign), dexec("tail -5 /var/ossec/logs/integrations.log").stdout);
  if (!campaign) return;
  note("campaign", { rule: campaign.rule, alerts: campaign.alert_count, techniques: campaign.techniques, seconds_after_attack_began: Math.round((Date.now() - t0) / 1000) });
  const alerts = (await c.call("/alerts")).body;
  const announcement = Array.isArray(alerts) ? alerts.find((a) => a.id === campaign.alert_id) : null;
  check("…and announced it as one alert from the Hunter agent", announcement?.agent === "Hunter" && announcement?.source_ip === ATTACKER, JSON.stringify(announcement).slice(0, 300));
  const blocks = (await c.call("/security/blocks?active=true")).body?.blocks ?? [];
  const block = blocks.find((b) => b.ip === ATTACKER);
  check("…and blocked the address automatically (expiring, audited)", block?.automatic === true, JSON.stringify(blocks));
  const audit = await sql(ADMIN, db.db, "SELECT count(*)::int AS n FROM audit_log WHERE action = 'security.auto_block' AND resource_id = $1", [ATTACKER]);
  check("the automatic block is in the audit log", audit[0].n === 1);

  section("Wazuh enforces it");
  const written = await until(async () => dexec("cat /var/ossec/logs/legion-blocklist.log 2>/dev/null").stdout.includes(`"srcip":"${ATTACKER}"`) || null, 150_000, 3000);
  check("the manager's wodle fetched the signed blocklist and wrote the address", Boolean(written), dexec("tail -5 /var/ossec/logs/integrations.log").stdout);
  const ruleFired = await until(async () => {
    const lines = dexec("grep '\"id\":\"100950\"' /var/ossec/logs/alerts/alerts.json 2>/dev/null").stdout.trim().split("\n").filter(Boolean);
    return lines.find((l) => l.includes(ATTACKER)) ?? null;
  }, 90_000, 2000);
  check("Wazuh rule 100950 matched it, with the address as srcip", Boolean(ruleFired));
  const ar = await until(async () => {
    const log = dexec("cat /var/ossec/logs/active-responses.log 2>/dev/null").stdout;
    return log.includes("firewall-drop") && log.includes(ATTACKER) ? log : null;
  }, 60_000, 2000);
  check("Wazuh EXECUTED firewall-drop for that address (active response)", Boolean(ar), dexec("tail -20 /var/ossec/logs/active-responses.log 2>/dev/null; tail -5 /var/ossec/logs/ossec.log").stdout);
  if (ar) note("active-responses.log", ar.split("\n").filter((l) => l.includes(ATTACKER)).slice(0, 2).map((l) => l.slice(0, 220)));
  await sleep(5000);
  const echoed = ((await c.call("/alerts")).body ?? []).filter((a) => /Legion automatic response/i.test(a.title));
  check("Legion's own block event did not come back as an alert", echoed.length === 0, JSON.stringify(echoed).slice(0, 300));

  section("an administrator unblocks it");
  const un = await c.call(`/security/blocks/${ATTACKER}`, { method: "DELETE" });
  check("unblocked in Legion", un.status === 200, un.text);
  const forgotten = await until(async () => {
    const state = dexec("cat /var/ossec/tmp/legion-blocklist-state.json 2>/dev/null").stdout;
    return state && !state.includes(ATTACKER) ? state : null;
  }, 150_000, 3000);
  check("the manager stops re-announcing it (state no longer lists it)", Boolean(forgotten));
  const lifted = await until(async () => {
    const log = dexec("cat /var/ossec/logs/active-responses.log 2>/dev/null").stdout;
    return /delete/i.test(log.split("\n").filter((l) => l.includes(ATTACKER)).join("\n")) || null;
  }, (AR_TIMEOUT + 90) * 1000, 3000);
  check(`Wazuh lifted the block at its timeout (${AR_TIMEOUT}s here, 600s documented)`, Boolean(lifted), dexec("tail -10 /var/ossec/logs/active-responses.log").stdout);
  const integLog = dexec("cat /var/ossec/logs/integrations.log 2>/dev/null").stdout;
  check("no secret in the manager's integration log", !integLog.includes(cred.body.secret));
}

try {
  await main();
} catch (err) {
  check("ran to completion", false, err instanceof Error ? err.stack : String(err));
} finally {
  if (process.env.E2E_KEEP_CONTAINER !== "1") spawnSync("docker", ["rm", "-f", NAME]);
  await api?.stop().catch(() => {});
  await db?.drop().catch(() => {});
  process.exit(R.summary() ? 1 : 0);
}
