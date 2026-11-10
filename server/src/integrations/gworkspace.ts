/**
 * Google Workspace — sign-in security events from the Admin SDK Reports API (pull, read only): suspicious sign-ins,
 * accounts Google disabled (hijacked, leaked password), government-backed attack warnings, failed sign-ins, and
 * blocked risky actions.
 *
 * A service account with domain-wide delegation for the single scope
 * https://www.googleapis.com/auth/admin.reports.audit.readonly, acting as one administrator (admin_email). Legion
 * signs a short JWT (RS256, node:crypto) with the key you give it; the key is sealed per connection. Hosts:
 * oauth2.googleapis.com and admin.googleapis.com only. Cursor: the newest event time. An event is stored once, by
 * its time + uniqueQualifier + name. Legion never changes users or settings in Workspace.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { signJwt } from "./gcp.js";
import { cleanText, cursorSince, parseTime, pickIp } from "./shared.js";
import type { Severity } from "../types.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 10;
const WINDOW_MS = 6 * 3600_000;
const SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly";

/** The login events that matter for security, and how serious each is. Everything else (ordinary logins, logouts) is skipped. */
const EVENTS: Record<string, { severity: Severity; text: string; mitre: string[] }> = {
  gov_attack_warning: { severity: "critical", text: "Google warned of a government-backed attack on this account", mitre: ["T1078"] },
  account_disabled_hijacked: { severity: "high", text: "Google disabled the account: it looked hijacked", mitre: ["T1078"] },
  account_disabled_password_leak: { severity: "high", text: "Google disabled the account: its password leaked", mitre: ["T1078"] },
  account_disabled_spamming: { severity: "medium", text: "Google disabled the account for sending spam", mitre: [] },
  account_disabled_spamming_through_relay: { severity: "medium", text: "Google disabled the account for spam through relay", mitre: [] },
  account_disabled_generic: { severity: "medium", text: "Google disabled the account", mitre: [] },
  suspicious_login: { severity: "high", text: "Suspicious sign-in blocked or flagged by Google", mitre: ["T1078"] },
  suspicious_login_less_secure_app: { severity: "high", text: "Suspicious sign-in from a less secure app", mitre: ["T1078"] },
  suspicious_programmatic_login: { severity: "high", text: "Suspicious programmatic sign-in", mitre: ["T1078"] },
  risky_sensitive_action_blocked: { severity: "medium", text: "Google blocked a risky sensitive action", mitre: [] },
  login_failure: { severity: "low", text: "Failed sign-in", mitre: ["T1110"] },
};

function param(event: Obj, name: string): string {
  for (const p of Array.isArray(event.parameters) ? event.parameters : []) {
    if (!isObj(p) || p.name !== name) continue;
    if (typeof p.value === "string") return cleanText(p.value, 200);
    if (Array.isArray(p.multiValue)) return p.multiValue.map((x) => cleanText(x, 60)).filter(Boolean).slice(0, 5).join(", ");
    if (typeof p.boolValue === "boolean") return String(p.boolValue);
  }
  return "";
}

export function findingsFromWorkspaceActivity(a: Obj): Finding[] {
  const id = isObj(a.id) ? a.id : {};
  const time = parseTime(id.time);
  const uq = cleanText(id.uniqueQualifier, 40);
  const actor = isObj(a.actor) ? a.actor : {};
  const out: Finding[] = [];
  for (const e of Array.isArray(a.events) ? a.events : []) {
    if (!isObj(e)) continue;
    const name = cleanText(e.name, 80);
    const kind = EVENTS[name];
    if (!kind || !time) continue;
    const user = cleanText(param(e, "affected_email_address") || actor.email, 200);
    const loginType = param(e, "login_type");
    const challenge = param(e, "login_challenge_method");
    out.push({
      externalId: `${time}:${uq}:${name}`,
      title: cleanText(`Google Workspace: ${kind.text}${user ? ` — ${user}` : ""}`, 300),
      severity: kind.severity,
      summary: [kind.text + ".", user ? `Account: ${user}` : "", loginType ? `Sign-in type: ${loginType}` : "", challenge ? `Challenge: ${challenge}` : "", param(e, "login_failure_type") ? `Failure: ${param(e, "login_failure_type")}` : ""].filter(Boolean).join("\n"),
      occurredAt: time,
      sourceIp: pickIp(a.ipAddress),
      target: user || null,
      mitre: kind.mitre,
      confidence: kind.severity === "low" ? 50 : 80,
      asset: null,
    });
  }
  return out;
}

export const gworkspaceAdapter: PullAdapter = {
  manifest: {
    kind: "gworkspace", displayName: "Google Workspace (sign-ins)", vendor: "Google", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["oauth2.googleapis.com", "admin.googleapis.com"],
    summary: "Suspicious and failed sign-ins, accounts Google disabled, and government-backed attack warnings from the Workspace login audit, polled by time. Read only.",
    auth: "Service account with domain-wide delegation for admin.reports.audit.readonly only, acting as one administrator; the JSON key is sealed per connection.",
  },
  configSchema: z.strictObject({ admin_email: z.string().email("An administrator's address in your domain").max(200) }),
  secretFields: ["service_account_json"],
  async poll(conn, cursor, signal) {
    let key: { client_email?: unknown; private_key?: unknown };
    try { key = JSON.parse(conn.secrets.service_account_json ?? ""); } catch { throw new Error("The service account key is not valid JSON"); }
    if (typeof key.client_email !== "string" || typeof key.private_key !== "string") throw new Error("The service account key has no client_email or private_key");
    const m = gworkspaceAdapter.manifest;
    const tokenRes = await adapterFetch(m, "https://oauth2.googleapis.com/token", {
      method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: signJwt(key.client_email, key.private_key, undefined, { scope: SCOPE, sub: String(conn.config.admin_email) }) }).toString(),
    });
    if (tokenRes.status !== 200) throw new Error(`Google sign-in failed (${tokenRes.status}); check the key, the domain-wide delegation for ${SCOPE} and the administrator address`);
    let token = "";
    try { token = String((JSON.parse(tokenRes.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
    if (!token) throw new Error("Google sign-in returned no token");
    const since = cursorSince(cursor);
    // Google returns the newest events first. A long gap (first run, an outage) is therefore read in windows of
    // six hours, oldest window first, so a page limit can never drop the older part of a backlog.
    const windowEnd = Date.parse(since) + WINDOW_MS;
    const catchingUp = windowEnd < Date.now() - 60_000;
    const findings: Finding[] = [];
    let newest = since;
    let pageToken = "";
    for (let page = 0; page < MAX_PAGES; page++) {
      const q = new URLSearchParams({ startTime: since, maxResults: "1000", ...(catchingUp ? { endTime: new Date(windowEnd).toISOString() } : {}), ...(pageToken ? { pageToken } : {}) });
      const res = await adapterFetch(m, `https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?${q}`, {
        method: "GET", signal, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024, headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`Google Workspace answered ${res.status}; will retry`);
      if (res.status !== 200) throw new Error(`Google Workspace refused the request (${res.status}); the administrator must be allowed to read the audit reports`);
      let body: { items?: unknown; nextPageToken?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Google Workspace returned invalid JSON"); }
      for (const a of Array.isArray(body.items) ? body.items : []) {
        if (!isObj(a)) continue;
        findings.push(...findingsFromWorkspaceActivity(a));
        const t = parseTime(isObj(a.id) ? a.id.time : null);
        if (t && t > newest) newest = t;
      }
      pageToken = typeof body.nextPageToken === "string" && body.nextPageToken.length <= 2000 ? body.nextPageToken : "";
      if (!pageToken) break;
    }
    if (catchingUp) newest = new Date(windowEnd).toISOString();
    return { findings, cursor: { since: newest } };
  },
};
