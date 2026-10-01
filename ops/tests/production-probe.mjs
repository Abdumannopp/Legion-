#!/usr/bin/env node
/**
 * Black-box security probe of the BUILT API in production mode
 * (NODE_ENV=production, hosted sign-up, Secure cookies, real SMTP delivery to
 * a local sink). It attacks the running process over HTTP and WebSocket the
 * way an outsider or a malicious customer would, and reads the database and
 * the process log afterwards for leaked secrets. No Legion code is imported.
 *
 *   npm --prefix server run build
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/production-probe.mjs [--json out.json]
 *
 * Each logical client sends its own X-Forwarded-For through loopback (the
 * default trusted proxy), as a reverse proxy would, so one client's limits do
 * not spill onto another; the rate-limit section then shows that a peer that
 * is NOT a trusted proxy cannot pick its own address that way.
 */
import { randomBytes, createHmac } from "node:crypto";
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { networkInterfaces } from "node:os";
import {
  REPO, client, decodeQP, freePort, freshDatabase, realtime, reporter, signedWebhook, smtpSink, sql, startApi,
  totp, until, wazuhAlert, webhookBody, sleep,
} from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const jsonOut = process.argv.includes("--json") ? process.argv[process.argv.indexOf("--json") + 1] : null;

const R = reporter("production probe");
const { check, section, note } = R;
const FRONTEND = "https://app.legion.test";
const SECRETS = {
  JWT_SECRET: randomBytes(48).toString("hex"),
  ENC: randomBytes(32).toString("hex"),
  METRICS: randomBytes(24).toString("hex"),
};
const seen = []; // every response body, for the leak scan
const ipOf = (() => { let n = 10; return () => `198.51.100.${n++}`; })();

let db, smtp, api, api2;

async function main() {
  db = await freshDatabase(ADMIN, "legion_probe");
  smtp = await smtpSink(await freePort());
  const port = await freePort();
  const env = {
    NODE_ENV: "production", DEPLOYMENT_MODE: "saas", DATABASE_URL: db.url,
    JWT_SECRET: SECRETS.JWT_SECRET, LEGION_ENCRYPTION_KEYS: `probe:${SECRETS.ENC}`,
    FRONTEND_URL: FRONTEND, COOKIE_SECURE: "true", SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtp.port),
    SMTP_FROM: "Legion <no-reply@legion.test>", HEALTH_METRICS_TOKEN: SECRETS.METRICS, SEED_DEMO_DATA: "true",
  };
  section("boot");
  api = await startApi(env, { port });
  check("the built API boots in production mode with a safe configuration", api.up, api.log().slice(-800));
  if (!api.up) return;
  const refused = await startApi({ ...env, COOKIE_SECURE: "false" }, { port: await freePort() }).catch((e) => ({ up: false, err: String(e) }));
  check("…and refuses to boot with an unsafe one (COOKIE_SECURE=false)", !refused.up, "booted");
  await refused.stop?.();
  check("demo data is never seeded in production, even when asked", !/demo/i.test((await sql(ADMIN, db.db, "SELECT string_agg(email, ',') AS e FROM users"))[0]?.e ?? ""));
  const B = api.base;
  const anon = client(B, { ip: ipOf() });

  // ---------------------------------------------------------------------------
  section("security headers, CORS, health disclosure");
  const h = await anon.call("/health");
  seen.push(h.text);
  check("public /health says only up/down", h.status === 200 && Object.keys(h.body).every((k) => ["status", "database"].includes(k)), JSON.stringify(h.body));
  check("no X-Powered-By", !h.headers.get("x-powered-by"));
  check("X-Content-Type-Options: nosniff", h.headers.get("x-content-type-options") === "nosniff");
  check("framing refused (X-Frame-Options DENY or frame-ancestors 'none')", h.headers.get("x-frame-options") === "DENY" || /frame-ancestors 'none'/.test(h.headers.get("content-security-policy") ?? ""));
  check("API responses carry a restrictive CSP", /default-src 'none'/.test(h.headers.get("content-security-policy") ?? ""), h.headers.get("content-security-policy"));
  check("Referrer-Policy set", Boolean(h.headers.get("referrer-policy")));
  check("HSTS sent (FRONTEND_URL is https)", /max-age=\d{7,}/.test(h.headers.get("strict-transport-security") ?? ""), h.headers.get("strict-transport-security"));
  const outboxNoToken = await anon.call("/health/outbox");
  const outboxToken = await anon.call("/health/outbox", { h: { authorization: `Bearer ${SECRETS.METRICS}` } });
  check("platform queue metrics need the metrics token", outboxNoToken.status === 401 || outboxNoToken.status === 404, String(outboxNoToken.status));
  check("…and work with it", outboxToken.status === 200, String(outboxToken.status));
  const pre = await fetch(`${B}/auth/login`, { method: "OPTIONS", headers: { origin: "https://evil.example", "access-control-request-method": "POST" } });
  check("CORS: a foreign origin gets no Access-Control-Allow-Origin", !pre.headers.get("access-control-allow-origin"));
  const preOk = await fetch(`${B}/auth/login`, { method: "OPTIONS", headers: { origin: FRONTEND, "access-control-request-method": "POST" } });
  check("CORS: the dashboard origin is allowed exactly, with credentials, never *",
    preOk.headers.get("access-control-allow-origin") === FRONTEND && preOk.headers.get("access-control-allow-credentials") === "true");
  const csrf = await fetch(`${B}/auth/logout`, { method: "POST", headers: { origin: "https://evil.example", "sec-fetch-site": "cross-site" } });
  check("CSRF: a cross-site state-changing request is refused", csrf.status === 403, String(csrf.status));
  // The dashboard (production build, next start): its own CSP with a per-request nonce.
  const webPort = await freePort();
  const nextBin = createRequire(join(REPO, "frontend", "package.json")).resolve("next/dist/bin/next");
  const web = spawn("node", [nextBin, "start", "-H", "127.0.0.1", "-p", String(webPort)], { cwd: join(REPO, "frontend"), env: { ...process.env, NODE_ENV: "production" }, stdio: "ignore" });
  const page = await until(async () => { const r = await fetch(`http://127.0.0.1:${webPort}/login`); return r.ok ? r : null; }, 60_000, 500);
  if (page) {
    const csp = page.headers.get("content-security-policy") ?? "";
    const page2 = await fetch(`http://127.0.0.1:${webPort}/login`);
    const nonce1 = /'nonce-([^']+)'/.exec(csp)?.[1], nonce2 = /'nonce-([^']+)'/.exec(page2.headers.get("content-security-policy") ?? "")?.[1];
    check("dashboard: CSP with a fresh nonce per response", Boolean(nonce1) && nonce1 !== nonce2, csp);
    check("dashboard: scripts need the nonce ('unsafe-inline' only as a CSP2 fallback), never 'unsafe-eval'", !/script-src[^;]*'unsafe-(eval|inline)'/.test(csp) || /script-src[^;]*'nonce-/.test(csp) && !/script-src[^;]*'unsafe-eval'/.test(csp), csp);
    check("dashboard: object-src 'none', base-uri and frame-ancestors restricted", /object-src 'none'/.test(csp) && /base-uri/.test(csp) && /frame-ancestors 'none'/.test(csp), csp);
    check("dashboard: X-Frame-Options DENY, nosniff, no X-Powered-By", page.headers.get("x-frame-options") === "DENY" && page.headers.get("x-content-type-options") === "nosniff" && !page.headers.get("x-powered-by"));
    note("dashboard CSP", csp);
  } else check("dashboard production build serves", false, "next start did not come up (build the frontend first)");
  web.kill("SIGTERM");
  const bad = await anon.call("/auth/login", { method: "POST", raw: "{not json", h: { "content-type": "application/json" } });
  seen.push(bad.text);
  check("malformed JSON → 400 without a stack trace", bad.status === 400 && !/at .*\.js:\d+|node_modules|Error:/.test(bad.text), bad.text.slice(0, 200));

  // ---------------------------------------------------------------------------
  section("sign-up, email confirmation (real SMTP), authentication");
  const orgs = {};
  for (const name of ["A", "B"]) {
    const email = `owner-${name.toLowerCase()}-${randomBytes(3).toString("hex")}@example.com`;
    const password = `Correct-Horse-${randomBytes(6).toString("hex")}`;
    const c = client(B, { ip: ipOf(), headers: { origin: FRONTEND } });
    const reg = await c.call("/auth/register", { method: "POST", body: { tenant_name: `Org ${name}`, email, password } });
    seen.push(reg.text);
    check(`org ${name}: sign-up accepted`, reg.status === 201 || reg.status === 200, `${reg.status} ${reg.text.slice(0, 200)}`);
    const mail = await until(async () => smtp.messages.find((m) => m.to.some((t) => t.includes(email))), 20_000);
    check(`org ${name}: confirmation email delivered over SMTP`, Boolean(mail));
    const token = mail && /verify-email\?token=([A-Za-z0-9_-]+)/.exec(decodeQP(mail.data))?.[1];
    const early = await c.call("/auth/login", { method: "POST", body: { username: email, password } });
    check(`org ${name}: cannot sign in before confirming`, early.status === 403, String(early.status));
    const ver = await c.call("/auth/verify-email", { method: "POST", body: { token } });
    check(`org ${name}: link confirms`, ver.status === 200, `${ver.status} ${ver.text}`);
    const again = await c.call("/auth/verify-email", { method: "POST", body: { token } });
    check(`org ${name}: the link works once`, again.status >= 400);
    const login = await c.call("/auth/login", { method: "POST", body: { username: email, password } });
    seen.push(login.text);
    c.setToken(login.body.access_token);
    orgs[name] = { email, password, c, cookies: login.setCookies };
    const me = await c.call("/auth/me");
    orgs[name].tenant = me.body.tenant_id; orgs[name].userId = me.body.id;
  }
  const A = orgs.A, Bo = orgs.B;
  const tokenCookie = A.cookies.find((c) => c.startsWith("legion_token="));
  const refreshCookie = A.cookies.find((c) => c.startsWith("legion_refresh="));
  check("session cookie: HttpOnly, Secure, SameSite", /HttpOnly/i.test(tokenCookie) && /Secure/i.test(tokenCookie) && /SameSite=(Lax|Strict)/i.test(tokenCookie), tokenCookie);
  check("refresh cookie: HttpOnly, Secure, SameSite=Strict, narrow path", /HttpOnly/i.test(refreshCookie) && /Secure/i.test(refreshCookie) && /SameSite=Strict/i.test(refreshCookie) && /Path=\/auth/i.test(refreshCookie), refreshCookie);
  const payload = JSON.parse(Buffer.from(A.c.token.split(".")[1], "base64url").toString());
  check("access token lifetime ≤ 15 minutes", payload.exp - payload.iat <= 15 * 60, `${payload.exp - payload.iat}s`);
  check("access token is bound to issuer/audience", Boolean(payload.iss && payload.aud), JSON.stringify(payload));
  const wrong = await client(B, { ip: ipOf() }).call("/auth/login", { method: "POST", body: { username: A.email, password: "Wrong-password-123" } });
  const nobody = await client(B, { ip: ipOf() }).call("/auth/login", { method: "POST", body: { username: "nobody@example.com", password: "Wrong-password-123" } });
  check("wrong password and unknown account are indistinguishable", wrong.status === 401 && nobody.status === 401 && wrong.body.detail === nobody.body.detail);
  const [hd, pl] = A.c.token.split(".");
  const forged = `${hd}.${Buffer.from(JSON.stringify({ ...payload, role: "admin", tenant_id: Bo.tenant })).toString("base64url")}.${A.c.token.split(".")[2]}`;
  const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${pl}.`;
  const otherKey = `${hd}.${pl}.${createHmac("sha256", "guess").update(`${hd}.${pl}`).digest("base64url")}`;
  for (const [label, tok] of [["payload-tampered", forged], ["alg=none", none], ["signed with another key", otherKey]]) {
    const r = await A.c.call("/auth/me", { tokenOverride: tok });
    check(`forged token (${label}) refused`, r.status === 401, String(r.status));
  }

  // ---------------------------------------------------------------------------
  section("MFA");
  const setup = await A.c.call("/auth/mfa/setup", { method: "POST", body: {} });
  check("MFA setup returns a secret once, not cacheable", setup.status === 200 && setup.headers.get("cache-control")?.includes("no-store"), setup.text);
  const enableCode = totp(setup.body.secret);
  const enable = await A.c.call("/auth/mfa/enable", { method: "POST", body: { code: enableCode } });
  check("MFA enabled with a valid code; recovery codes issued", enable.status === 200 && enable.body.recovery_codes?.length >= 8, enable.text);
  const oldToken = A.c.token;
  check("enabling MFA ends the old session", (await A.c.call("/auth/me", { tokenOverride: oldToken })).status === 401);
  const mc = client(B, { ip: ipOf() });
  const chal = await mc.call("/auth/login", { method: "POST", body: { username: A.email, password: A.password } });
  check("password alone yields a challenge, not a session", chal.body.mfa_required === true && !chal.body.access_token);
  check("the challenge token is not a session", (await mc.call("/auth/me", { tokenOverride: chal.body.mfa_token })).status === 401);
  const wrongCode = await mc.call("/auth/mfa/verify", { method: "POST", body: { mfa_token: chal.body.mfa_token, code: "000000" } });
  check("a wrong code is refused", wrongCode.status === 401 || wrongCode.status === 400, String(wrongCode.status));
  const reusedEnrol = await mc.call("/auth/mfa/verify", { method: "POST", body: { mfa_token: chal.body.mfa_token, code: enableCode } });
  check("the code used to enrol cannot be reused to sign in", reusedEnrol.status !== 200, String(reusedEnrol.status));
  // A fresh code needs the next 30-second window.
  await until(async () => totp(setup.body.secret) !== enableCode, 35_000, 500);
  const code = totp(setup.body.secret);
  const ok = await mc.call("/auth/mfa/verify", { method: "POST", body: { mfa_token: chal.body.mfa_token, code } });
  check("the right code completes sign-in", ok.status === 200 && Boolean(ok.body.access_token), `${ok.status} ${ok.text}`);
  A.c.setToken(ok.body.access_token);
  const chal2 = await mc.call("/auth/login", { method: "POST", body: { username: A.email, password: A.password } });
  const replay = await mc.call("/auth/mfa/verify", { method: "POST", body: { mfa_token: chal2.body.mfa_token, code } });
  check("a code that already worked cannot be replayed", replay.status !== 200, String(replay.status));
  let mfaLimited = false;
  for (let i = 0; i < 8 && !mfaLimited; i++) {
    const r = await client(B, { ip: ipOf() }).call("/auth/mfa/verify", { method: "POST", body: { mfa_token: chal2.body.mfa_token, code: String(100000 + i) } });
    mfaLimited = r.status === 429;
  }
  check("guessing codes is cut off per account, whatever the address", mfaLimited);

  // ---------------------------------------------------------------------------
  section("RBAC");
  const inv = await A.c.call("/users/invite", { method: "POST", body: { email: `viewer-${randomBytes(3).toString("hex")}@example.com`, role: "viewer" } });
  check("admin invites a viewer (link is not in the response in production)", inv.status === 201 && !inv.body.invite_url, inv.text);
  const invMail = await until(async () => smtp.messages.find((m) => /accept-invite\?token=/.test(decodeQP(m.data)) && m.to.some((t) => t.includes(inv.body.email))));
  const invToken = invMail && /accept-invite\?token=([A-Za-z0-9_-]+)/.exec(decodeQP(invMail.data))?.[1];
  const vc = client(B, { ip: ipOf() });
  await vc.call("/auth/accept-invite", { method: "POST", body: { token: invToken, password: "Viewer-password-123!" } });
  const vlogin = await vc.call("/auth/login", { method: "POST", body: { username: inv.body.email, password: "Viewer-password-123!" } });
  vc.setToken(vlogin.body.access_token);
  check("viewer signed in via the emailed invitation", Boolean(vc.token));
  for (const [what, path, method, body] of [
    ["create a sensor key", "/security-events/credentials", "POST", { label: "x" }],
    ["invite people", "/users/invite", "POST", { email: "x@example.com", role: "admin" }],
    ["read the audit log", "/audit", "GET"],
    ["create an AI agent", "/agents", "POST", { name: "x", permissions: ["alerts:read"] }],
    ["change workspace settings", "/workspace/settings", "PATCH", { timezone: "UTC" }],
    ["promote itself to admin", `/users/${(await vc.call("/auth/me")).body.id}/role`, "PATCH", { role: "admin" }],
  ]) {
    const r = await vc.call(path, { method, body });
    check(`viewer cannot ${what}`, r.status === 403, `${r.status} ${r.text.slice(0, 120)}`);
  }

  // ---------------------------------------------------------------------------
  section("webhook forgery and replay");
  const credA = await A.c.call("/security-events/credentials", { method: "POST", body: { label: "probe" } });
  const credB = await Bo.c.call("/security-events/credentials", { method: "POST", body: { label: "probe-b" } });
  seen.push(JSON.stringify((await A.c.call("/security-events/credentials")).body));
  const sensorIp = ipOf();
  const send = (keyId, secret, body, opts = {}) => signedWebhook(B, keyId, secret, body, { ip: sensorIp, ...opts })();
  const good = await send(credA.body.id, credA.body.secret, webhookBody(wazuhAlert(1)));
  check("a correctly signed event is accepted", good.status === 202, String(good.status));
  const body2 = webhookBody(wazuhAlert(2));
  const attackerIp = ipOf();
  const cases = [
    ["no signature headers", () => fetch(`${B}/security-events/webhook`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": attackerIp }, body: body2 })],
    ["wrong secret", () => send(credA.body.id, `whs_${"0".repeat(43)}`, body2, { ip: attackerIp })],
    ["unknown key id", () => send(`whk_${"A".repeat(22)}`, credA.body.secret, body2, { ip: attackerIp })],
    ["timestamp 10 minutes old", () => send(credA.body.id, credA.body.secret, body2, { ts: Math.floor(Date.now() / 1000) - 600, ip: attackerIp })],
    ["timestamp 10 minutes ahead", () => send(credA.body.id, credA.body.secret, body2, { ts: Math.floor(Date.now() / 1000) + 600, ip: attackerIp })],
    ["another org's secret with this org's key id", () => send(credA.body.id, credB.body.secret, body2, { ip: attackerIp })],
  ];
  for (const [label, fn] of cases) check(`forged webhook refused: ${label}`, (await fn()).status === 401);
  const ts = Math.floor(Date.now() / 1000), nonce = randomBytes(16).toString("base64url");
  const sig = "v2=" + createHmac("sha256", credA.body.secret).update(`v2.${ts}.${nonce}.`).update(body2).digest("hex");
  const tampered = await fetch(`${B}/security-events/webhook`, { method: "POST", headers: { "content-type": "application/json", "x-legion-key-id": credA.body.id, "x-legion-timestamp": String(ts), "x-legion-nonce": nonce, "x-legion-signature": sig, "x-forwarded-for": attackerIp }, body: body2.replace("web-01", "web-02") });
  check("forged webhook refused: body changed after signing", tampered.status === 401);
  const replayable = signedWebhook(B, credA.body.id, credA.body.secret, webhookBody(wazuhAlert(3)), { ip: sensorIp });
  const r1 = await replayable(), r2 = await replayable();
  check("a byte-for-byte replay is refused", r1.status === 202 && r2.status === 401, `${r1.status} ${r2.status}`);
  const huge = await send(credA.body.id, credA.body.secret, JSON.stringify({ provider: "wazuh", event: { ...wazuhAlert(4), full_log: "x".repeat(2_000_000) } }));
  check("an oversized body is refused before parsing", huge.status === 413, String(huge.status));
  const crossPayload = await send(credA.body.id, credA.body.secret, JSON.stringify({ provider: "wazuh", tenant_id: Bo.tenant, event: { ...wazuhAlert(5), tenant_id: Bo.tenant } }));
  const landedInB = await sql(ADMIN, db.db, "SELECT count(*)::int AS n FROM alerts WHERE tenant_id = $1", [Bo.tenant]);
  check("a tenant id inside the payload cannot steer the event into another org", crossPayload.status === 202 && landedInB[0].n === 0);
  let limited = false;
  const floodIp = ipOf();
  for (let i = 0; i < 80 && !limited; i++) limited = (await send(credA.body.id, "whs_wrong", body2, { ip: floodIp })).status === 429;
  check("repeated failed webhook authentication from one address is throttled", limited);
  check("…while the real sensor (another address) keeps working", (await send(credA.body.id, credA.body.secret, webhookBody(wazuhAlert(6)))).status === 202);

  // ---------------------------------------------------------------------------
  section("tenant isolation / IDOR (org A attacking org B)");
  await signedWebhook(B, credB.body.id, credB.body.secret, webhookBody(wazuhAlert(7, { agent: "b-secret-host" })), { ip: ipOf() })();
  const bAlert = (await Bo.c.call("/alerts")).body[0];
  const bAgent = await Bo.c.call("/agents", { method: "POST", body: { name: "b-agent", permissions: ["alerts:read"] } });
  seen.push(bAgent.text.replace(bAgent.body.credential?.secret ?? "∅", ""));
  const bAgentId = bAgent.body.identity?.id;
  const aList = (await A.c.call("/alerts")).body;
  check("org A's alert list has none of org B's alerts", Array.isArray(aList) && !aList.some((a) => a.id === bAlert.id || a.target === "b-secret-host"));
  const idor = [
    ["read B's alert", `/alerts/${bAlert.id}`, "GET"],
    ["change B's alert status", `/alerts/${bAlert.id}/status`, "PATCH", { status: "resolved" }],
    ["explain B's alert", `/alerts/${bAlert.id}/explain`, "POST", {}],
    ["revoke B's sensor key", `/security-events/credentials/${credB.body.id}`, "DELETE"],
    ["rotate B's sensor key", `/security-events/credentials/${credB.body.id}/rotate`, "POST", {}],
    ["read B's agent", `/agents/${bAgentId}`, "GET"],
    ["change B's agent permissions", `/agents/${bAgentId}`, "PATCH", { permissions: ["alerts:read", "alerts:update_status"] }],
    ["pause B's agent", `/agents/${bAgentId}/suspend`, "POST", {}],
    ["kill B's agent", `/kill-switch/agents/${bAgentId}`, "POST", { reason: "probe attempting cross-org kill", compromise: "confirmed" }],
    ["read B's agent activity", `/agents/${bAgentId}/activity`, "GET"],
    ["change B's owner's role", `/users/${Bo.userId}/role`, "PATCH", { role: "viewer" }],
    ["delete B's owner", `/users/${Bo.userId}`, "DELETE"],
    ["switch into B's workspace", "/workspaces/switch", "POST", { workspace_id: Bo.tenant }],
  ];
  for (const [what, path, method, body] of idor) {
    const r = await A.c.call(path, { method, body });
    check(`A cannot ${what}`, [403, 404].includes(r.status), `${r.status} ${r.text.slice(0, 160)}`);
  }
  const dec = await A.c.call(`/firewall/decisions?principalId=${bAgentId}`);
  check("A sees none of B's agent decisions", Array.isArray(dec.body.decisions) && dec.body.decisions.length === 0);
  const stillB = await Bo.c.call(`/alerts/${bAlert.id}`);
  check("B's alert is untouched after the attempts", stillB.body.status === "open");
  const stillAgent = await Bo.c.call(`/agents/${bAgentId}`);
  check("B's agent is untouched after the attempts", stillAgent.body.identity?.status === "active" && stillAgent.body.identity.permissions.length === 1);

  // ---------------------------------------------------------------------------
  section("WebSocket");
  const cookieOf = (cookies) => cookies.map((c) => c.split(";")[0]).join("; ");
  const aLogin = await client(B, { ip: ipOf() }).call("/auth/login", { method: "POST", body: { username: Bo.email, password: Bo.password } });
  const bCookie = cookieOf(aLogin.setCookies);
  const evil = await realtime(B, bCookie, "https://evil.example");
  check("cross-site WebSocket hijack refused (foreign Origin)", !evil.ok && evil.status === 403, String(evil.status));
  const noOrigin = await realtime(B, bCookie, undefined);
  check("WebSocket without Origin refused", !noOrigin.ok, String(noOrigin.status));
  const noCookie = await realtime(B, "", FRONTEND);
  check("WebSocket without a session refused", !noCookie.ok && noCookie.status === 401, String(noCookie.status));
  const bWs = await realtime(B, bCookie, FRONTEND);
  check("WebSocket with the dashboard Origin and a session opens", bWs.ok);
  // A's event must not reach B's socket.
  await signedWebhook(B, credA.body.id, credA.body.secret, webhookBody(wazuhAlert(8, { agent: "a-only-host" })), { ip: sensorIp })();
  await signedWebhook(B, credB.body.id, credB.body.secret, webhookBody(wazuhAlert(9, { agent: "b-live-host" })), { ip: ipOf() })();
  await until(async () => bWs.frames.some((f) => JSON.stringify(f).includes("b-live-host")), 15_000);
  check("B's socket receives B's live alert", bWs.frames.some((f) => JSON.stringify(f).includes("b-live-host")));
  check("…and never A's", !bWs.frames.some((f) => JSON.stringify(f).includes("a-only-host")));
  bWs.ws?.close();

  // ---------------------------------------------------------------------------
  section("sessions");
  const sc = client(B, { ip: ipOf() });
  const s1 = await sc.call("/auth/login", { method: "POST", body: { username: Bo.email, password: Bo.password } });
  const access1 = s1.body.access_token;
  const refreshOld = sc.jar.get("legion_refresh");
  const rotated = await sc.call("/auth/refresh", { method: "POST", h: { origin: FRONTEND } });
  check("refresh rotates the refresh token", rotated.status === 200 && sc.jar.get("legion_refresh") !== refreshOld, String(rotated.status));
  await sc.call("/auth/logout", { method: "POST", h: { origin: FRONTEND } });
  const afterLogout = await client(B, { ip: ipOf() }).call("/auth/refresh", { method: "POST", h: { origin: FRONTEND, cookie: `legion_refresh=${refreshOld}` } });
  check("after logout, the old refresh token is dead", afterLogout.status === 401, String(afterLogout.status));
  const pw = await client(B, { ip: ipOf(), token: access1 }).call("/auth/change-password", { method: "POST", body: { current_password: Bo.password, new_password: `${Bo.password}-2` } });
  check("password change succeeds", pw.status === 200, `${pw.status} ${pw.text}`);
  check("…and every older access token stops working", (await client(B, { ip: ipOf(), token: Bo.c.token }).call("/auth/me")).status === 401);
  Bo.password = `${Bo.password}-2`;

  // ---------------------------------------------------------------------------
  section("rate limiting");
  const rl = client(B, { ip: ipOf() });
  let r429 = null;
  for (let i = 0; i < 15 && !r429; i++) {
    const r = await rl.call("/auth/login", { method: "POST", body: { username: `x${i}@example.com`, password: "nope-nope-nope" } });
    if (r.status === 429) r429 = r;
  }
  check("sign-in attempts per address are limited (429 + Retry-After)", r429 && r429.headers.get("retry-after"), "never limited");
  let acct = null;
  for (let i = 0; i < 25 && !acct; i++) {
    const r = await client(B, { ip: ipOf() }).call("/auth/login", { method: "POST", body: { username: A.email, password: `wrong-${i}-xxxxxxxx` } });
    if (r.status === 429) acct = i;
  }
  check("failed sign-ins per ACCOUNT are limited across many addresses", acct !== null, "never limited");
  // A peer that is not a trusted proxy cannot choose its address with X-Forwarded-For.
  const lan = Object.values(networkInterfaces()).flat().find((a) => a && a.family === "IPv4" && !a.internal)?.address;
  if (lan) {
    const lanPort = await freePort();
    api2 = await startApi({ ...env, LEGION_BIND_ADDRESS: "0.0.0.0" }, { port: lanPort });
    let spoofLimited = false;
    for (let i = 0; i < 15 && !spoofLimited; i++) {
      const r = await fetch(`http://${lan}:${lanPort}/auth/login`, { method: "POST", headers: { "content-type": "application/json", "x-forwarded-for": `203.0.113.${i}` }, body: JSON.stringify({ username: `y${i}@example.com`, password: "nope-nope-nope" }) });
      spoofLimited = r.status === 429;
    }
    check("X-Forwarded-For from an untrusted peer does not evade the address limit", spoofLimited);
    await api2.stop();
  } else note("untrusted-peer spoofing", "no non-loopback interface; skipped");

  // ---------------------------------------------------------------------------
  section("secret leakage");
  const log = api.log();
  const issued = [credA.body.secret, credB.body.secret, bAgent.body.credential?.secret, setup.body.secret, A.password, Bo.password, SECRETS.JWT_SECRET, SECRETS.ENC, SECRETS.METRICS].filter(Boolean);
  check("no secret, password or key appears in the server log", issued.every((s) => !log.includes(s)), issued.filter((s) => log.includes(s)).map((s) => s.slice(0, 6) + "…").join(","));
  check("no secret appears in any non-issuing response", issued.every((s) => !seen.join("\n").includes(s)));
  const credRow = await sql(ADMIN, db.db, "SELECT row_to_json(c)::text AS r FROM webhook_credentials c WHERE key_id = $1", [credA.body.id]);
  check("sensor secrets are not stored in plaintext", !credRow[0].r.includes(credA.body.secret.replace(/^whs_/, "")));
  const userRow = await sql(ADMIN, db.db, "SELECT row_to_json(u)::text AS r FROM users u WHERE email = $1", [A.email]);
  check("TOTP seed and password are not stored in plaintext", !userRow[0].r.includes(setup.body.secret) && !userRow[0].r.includes(A.password));
  const agentRows = await sql(ADMIN, db.db, "SELECT string_agg(row_to_json(c)::text, '') AS r FROM machine_credentials c");
  check("agent secrets are not stored in plaintext", !String(agentRows[0].r ?? "").includes(String(bAgent.body.credential?.secret ?? "∅").split("_").pop()));
  const mails = smtp.messages.map((m) => m.data).join("\n");
  check("no email carries a password or secret", issued.every((s) => !mails.includes(s)));
  check("no 5xx was logged as an unhandled error during the probe", !/Unhandled|TypeError|ReferenceError/.test(log), (log.match(/.*(Unhandled|TypeError|ReferenceError).*/) ?? [""])[0]);
}

try {
  await main();
} catch (err) {
  check("probe ran to completion", false, err instanceof Error ? err.stack : String(err));
} finally {
  await api2?.stop().catch(() => {});
  await api?.stop().catch(() => {});
  await smtp?.stop().catch(() => {});
  await db?.drop();
  const failed = R.summary();
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(R.results, null, 2));
  process.exit(failed ? 1 : 0);
}
