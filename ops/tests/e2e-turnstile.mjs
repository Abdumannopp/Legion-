#!/usr/bin/env node
/**
 * Cloudflare Turnstile in a real browser: the dashboard built WITH a site key,
 * the built API WITH a secret key, and every hop between them real — except
 * Cloudflare itself, which this machine cannot reach. Its widget script is
 * replaced (Playwright route) by a stand-in that renders a "verify" button and
 * hands out single-use tokens, and its siteverify API by a local server that
 * accepts each token exactly once. What is tested is Legion's side: the
 * widget appears, the forms wait for it, the token travels with the request,
 * a used token is never reused, the server refuses without one, the CSP admits
 * the widget, and a blocked widget is explained instead of failing silently.
 *
 *   npm --prefix server run build
 *   E2E_ADMIN_DATABASE_URL=postgresql://…/postgres node ops/tests/e2e-turnstile.mjs
 *
 * Builds the dashboard into frontend/.next-turnstile-e2e (removed afterwards;
 * the normal .next is untouched) — about a minute.
 */
import { spawn, spawnSync, execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import { join } from "node:path";
import { REPO, freePort, freshDatabase, reporter, startApi, until } from "./lib/harness.mjs";

const ADMIN = process.env.E2E_ADMIN_DATABASE_URL;
if (!ADMIN) { console.error("Set E2E_ADMIN_DATABASE_URL"); process.exit(2); }
const R = reporter("Turnstile in the browser");
const { check, section, note } = R;

function loadPlaywright() {
  for (const base of [join(REPO, "frontend"), REPO, execSync("npm root -g").toString().trim()]) {
    try { return createRequire(join(base, "noop.js"))("playwright"); } catch { /* next */ }
  }
  console.error("Playwright is not installed (npm i -g playwright)."); process.exit(2);
}
const { chromium } = loadPlaywright();

// Cloudflare's published always-pass TEST site key. Never a real one.
const SITE_KEY = "1x00000000000000000000AA";
const SECRET = "0x4AAAAAAA-e2e-test-secret";

/** Stand-in for https://challenges.cloudflare.com/turnstile/v0/api.js — the same API surface Legion uses. */
const FAKE_WIDGET = `
(() => {
  let n = 0;
  const widgets = {};
  function draw(id) {
    const w = widgets[id];
    w.el.innerHTML = "";
    const b = document.createElement("button");
    b.type = "button"; b.textContent = "Verify you are human"; b.setAttribute("data-testid", "turnstile-verify");
    b.onclick = () => { w.el.innerHTML = '<span data-testid="turnstile-done">Verified</span>'; w.opts.callback("fake-ok-" + Math.random().toString(36).slice(2)); };
    w.el.appendChild(b);
  }
  window.turnstile = {
    render(el, opts) { const id = "w" + (++n); widgets[id] = { el, opts }; window.__turnstileRenders = (window.__turnstileRenders || []).concat([{ sitekey: opts.sitekey, action: opts.action }]); draw(id); return id; },
    reset(id) { if (widgets[id]) draw(id); },
    remove(id) { if (widgets[id]) { widgets[id].el.innerHTML = ""; delete widgets[id]; } },
  };
})();
`;

/** siteverify: each token is good exactly once (Cloudflare's rule). */
function startSiteverify() {
  const used = new Set();
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => { raw += d; });
    req.on("end", () => {
      const f = new URLSearchParams(raw);
      const token = f.get("response") ?? "";
      seen.push(token);
      const ok = f.get("secret") === SECRET && token.startsWith("fake-ok-") && !used.has(token);
      used.add(token);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(ok ? { success: true, "error-codes": [] } : { success: false, "error-codes": [used.has(token) && token.startsWith("fake-ok-") ? "timeout-or-duplicate" : "invalid-input-response"] }));
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, seen, url: `http://127.0.0.1:${server.address().port}/siteverify` })));
}

let api, web, db, browser, verify, work;
// `next build` rewrites these to point at the build directory it used; put them back afterwards.
const restore = [];
try {
  const apiPort = await freePort(), webPort = await freePort();
  const API = `http://localhost:${apiPort}`, WEB = `http://localhost:${webPort}`;

  section("build the dashboard with a Turnstile site key (separate output dir; .next is untouched)");
  const fe = join(REPO, "frontend");
  const DIST = ".next-turnstile-e2e";
  const nextBin = createRequire(join(fe, "package.json")).resolve("next/dist/bin/next");
  const env = { ...process.env, NEXT_DIST_DIR: DIST, NEXT_PUBLIC_API_URL: API, NEXT_PUBLIC_TURNSTILE_SITE_KEY: SITE_KEY, NEXT_TELEMETRY_DISABLED: "1" };
  work = join(fe, DIST);
  for (const f of ["next-env.d.ts", "tsconfig.json"]) { const path = join(fe, f); if (existsSync(path)) restore.push([path, readFileSync(path)]); }
  const build = spawnSync("node", [nextBin, "build"], { cwd: fe, env, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  check("dashboard builds with NEXT_PUBLIC_TURNSTILE_SITE_KEY", build.status === 0, (build.stderr || build.stdout).slice(-1500));
  if (build.status !== 0) throw new Error("build failed");

  verify = await startSiteverify();
  db = await freshDatabase(ADMIN, "legion_captcha");
  api = await startApi({
    NODE_ENV: "development", DEPLOYMENT_MODE: "self-hosted", DATABASE_URL: db.url, JWT_SECRET: randomBytes(48).toString("hex"),
    LEGION_ENCRYPTION_KEYS: `cap:${randomBytes(32).toString("hex")}`, FRONTEND_URL: WEB, COOKIE_SECURE: "false",
    TURNSTILE_SECRET_KEY: SECRET, TURNSTILE_VERIFY_URL: verify.url,
  }, { port: apiPort });
  check("API up with TURNSTILE_SECRET_KEY", api.up, api.log().slice(-500));
  web = spawn("node", [nextBin, "start", "-H", "localhost", "-p", String(webPort)], { cwd: fe, env, stdio: "ignore" });
  const webUp = await until(() => fetch(`${WEB}/login`).then((r) => r.ok), 60_000);
  check("dashboard up", Boolean(webUp));

  const csp = (await fetch(`${WEB}/login`)).headers.get("content-security-policy") ?? "";
  check("the CSP admits the widget (script and frame) and nothing more", /script-src[^;]*https:\/\/challenges\.cloudflare\.com/.test(csp) && /frame-src[^;]*https:\/\/challenges\.cloudflare\.com/.test(csp) && !/connect-src[^;]*cloudflare/.test(csp), csp);
  check("/auth/setup-status tells the dashboard Turnstile is on", (await (await fetch(`${API}/auth/setup-status`)).json()).captcha === true);

  browser = await chromium.launch();
  const newPage = async ({ blockWidget = false } = {}) => {
    const context = await browser.newContext({ locale: "en-US" });
    await context.route("https://challenges.cloudflare.com/**", (route) => (blockWidget ? route.abort() : route.fulfill({ status: 200, contentType: "text/javascript", body: FAKE_WIDGET })));
    const page = await context.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error" && /Content Security Policy/i.test(m.text())) errors.push(m.text()); });
    return { context, page, errors };
  };
  const submitDisabled = (page) => page.locator('button[type="submit"]').isDisabled();
  const solve = async (page) => { await page.getByTestId("turnstile-verify").click(); await page.getByTestId("turnstile-done").waitFor({ timeout: 5000 }); };

  section("first-run setup with the widget");
  const setupToken = /(lst_[A-Za-z0-9_-]+)/.exec(api.log())?.[1];
  const { page, context, errors } = await newPage();
  await page.goto(`${WEB}/setup`);
  await page.getByTestId("turnstile-verify").waitFor({ timeout: 15000 });
  check("the widget is shown, rendered with our site key and the 'setup' action", (await page.evaluate(() => window.__turnstileRenders))?.some((r) => r.sitekey === SITE_KEY && r.action === "setup"));
  await page.fill('input[placeholder="lst_…"]', setupToken);
  const inputs = page.locator("form input");
  await inputs.nth(1).fill("Captcha Co");
  await inputs.nth(2).fill("owner@example.com");
  await inputs.nth(3).fill("Correct-horse-1234");
  check("submit waits for the challenge", await submitDisabled(page));
  await solve(page);
  check("… and is enabled once it is solved", !(await submitDisabled(page)));
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/login/, { timeout: 15000 });
  check("setup succeeded and sends the person to sign in (the used token cannot sign them in too)", page.url().includes("/login"));

  section("sign-in with the widget");
  await page.getByTestId("turnstile-verify").waitFor({ timeout: 15000 });
  await page.fill('input[type="email"]', "owner@example.com");
  await page.fill('input[type="password"]', "wrong-password-123");
  check("sign-in waits for the challenge", await submitDisabled(page));
  await solve(page);
  await page.click('button[type="submit"]');
  await page.getByText("Invalid email or password").waitFor({ timeout: 10000 });
  check("a wrong password is reported as usual", true);
  await page.getByTestId("turnstile-verify").waitFor({ timeout: 5000 });
  check("after an attempt the widget asks again (a token is single-use)", await submitDisabled(page));
  await page.fill('input[type="password"]', "Correct-horse-1234");
  await solve(page);
  await page.click('button[type="submit"]');
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 15000 });
  check("the right password with a fresh token signs in", !page.url().includes("/login"), page.url());
  const tokens = verify.seen.filter((t) => t.startsWith("fake-ok-"));
  check("every request carried its own token; none was sent twice", tokens.length >= 3 && new Set(tokens).size === tokens.length, JSON.stringify(tokens));
  check("the browser keeps a known-device cookie for the flood priority lane", (await context.cookies()).some((c) => c.name === "legion_device" && c.httpOnly));
  check("no CSP violations or page errors", errors.length === 0, errors.join(" | "));
  await context.close();

  section("password reset with the widget");
  const r = await newPage();
  await r.page.goto(`${WEB}/forgot-password`);
  await r.page.getByTestId("turnstile-verify").waitFor({ timeout: 15000 });
  await r.page.fill('input[type="email"]', "owner@example.com");
  check("reset waits for the challenge", await submitDisabled(r.page));
  await solve(r.page);
  await r.page.click('button[type="submit"]');
  await r.page.getByText("owner@example.com").waitFor({ timeout: 10000 });
  check("the reset request goes through with a solved challenge", true);
  await r.context.close();

  section("the widget cannot load (blocked by an extension or the network)");
  const b = await newPage({ blockWidget: true });
  await b.page.goto(`${WEB}/login`);
  await b.page.getByText("The security check could not load").waitFor({ timeout: 15000 });
  check("the page says why, instead of a silent dead button", true);
  check("… and sign-in stays disabled", await submitDisabled(b.page));
  await b.context.close();

  section("the API refuses without the widget, whatever the dashboard does");
  const raw = await fetch(`${API}/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: "owner@example.com", password: "Correct-horse-1234" }) });
  check("a direct sign-in without a token is refused (400 captcha_required)", raw.status === 400 && (await raw.json()).code === "captcha_required");
  const replay = await fetch(`${API}/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: "owner@example.com", password: "Correct-horse-1234", turnstile_token: tokens[0] }) });
  check("a used token cannot be replayed (400 captcha_failed)", replay.status === 400 && (await replay.json()).code === "captcha_failed");
  note("siteverify calls", verify.seen.length);
} catch (e) {
  check("ran to completion", false, e?.stack ?? String(e));
} finally {
  await browser?.close().catch(() => {});
  web?.kill();
  await api?.stop().catch(() => {});
  verify?.server.close();
  await db?.drop().catch(() => {});
  if (work && existsSync(work)) rmSync(work, { recursive: true, force: true });
  for (const [path, content] of restore) writeFileSync(path, content);
  process.exit(R.summary() ? 1 : 0);
}
