/**
 * Google Cloud — Security Command Center findings of one organisation (pull, read only).
 *
 * Service account with the role "Security Center Findings Viewer". Legion signs a short JWT (RS256, node:crypto)
 * with the key you give it and exchanges it at oauth2.googleapis.com for a one-hour token; the key is sealed per
 * connection and never returned. Hosts: oauth2.googleapis.com and securitycenter.googleapis.com only.
 * Cursor: the newest finding eventTime (epoch ms). A finding is stored once, by its resource name.
 */
import { createSign } from "node:crypto";
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, mitreIn, parseTime, pickIp, severityOf } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const b64 = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const MAX_PAGES = 10;

export function signJwt(email: string, privateKey: string, now = Math.floor(Date.now() / 1000), opts: { scope?: string; sub?: string } = {}): string {
  const head = b64(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64(JSON.stringify({ iss: email, scope: opts.scope ?? "https://www.googleapis.com/auth/cloud-platform", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600, ...(opts.sub ? { sub: opts.sub } : {}) }));
  const sig = createSign("RSA-SHA256").update(`${head}.${claim}`).sign(privateKey);
  return `${head}.${claim}.${b64(sig)}`;
}

export function findingFromScc(item: Obj): Finding | null {
  const f = isObj(item.finding) ? item.finding : item;
  const id = cleanText(f.name, 300);
  const title = cleanText(f.category, 300);
  if (!id || !title) return null;
  const sp = isObj(f.sourceProperties) ? f.sourceProperties : {};
  const resource = cleanText(f.resourceName, 255);
  return {
    externalId: id,
    title: title.replace(/_/g, " "),
    severity: severityOf(String(f.severity ?? "").toLowerCase()),
    summary: [cleanText(f.description, 3000), resource ? `Resource: ${resource}` : "", f.state ? `State: ${cleanText(f.state, 20)}` : "", f.externalUri ? `Link: ${cleanText(f.externalUri, 300)}` : ""].filter(Boolean).join("\n") || title,
    occurredAt: parseTime(f.eventTime),
    sourceIp: pickIp(sp.callerIp, sp.sourceIp, isObj(sp.properties) ? sp.properties.ip : undefined),
    target: resource ? resource.split("/").slice(-2).join("/") : null,
    mitre: mitreIn(JSON.stringify(isObj(f.mitreAttack) ? f.mitreAttack : {}), title),
    confidence: 70,
    asset: null,
  };
}

export const gcpAdapter: PullAdapter = {
  manifest: {
    kind: "gcp", displayName: "Google Cloud (Security Command Center)", vendor: "Google", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["oauth2.googleapis.com", "securitycenter.googleapis.com"],
    summary: "Security Command Center findings of one organisation, polled by event time. Read only.",
    auth: "Service account with Security Center Findings Viewer; its JSON key is sealed per connection.",
  },
  configSchema: z.strictObject({ organization_id: z.string().regex(/^\d{4,20}$/, "Numeric organisation id") }),
  secretFields: ["service_account_json"],
  async poll(conn, cursor, signal) {
    let key: { client_email?: unknown; private_key?: unknown };
    try { key = JSON.parse(conn.secrets.service_account_json ?? ""); } catch { throw new Error("The service account key is not valid JSON"); }
    if (typeof key.client_email !== "string" || typeof key.private_key !== "string") throw new Error("The service account key has no client_email or private_key");
    const tokenRes = await adapterFetch(gcpAdapter.manifest, "https://oauth2.googleapis.com/token", {
      method: "POST", signal, timeoutMs: 20_000, maxBytes: 64 * 1024, headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: signJwt(key.client_email, key.private_key) }).toString(),
    });
    if (tokenRes.status !== 200) throw new Error(`Google sign-in failed (${tokenRes.status}); check the service account key`);
    let token = "";
    try { token = String((JSON.parse(tokenRes.body) as { access_token?: unknown }).access_token ?? ""); } catch { /* below */ }
    if (!token) throw new Error("Google sign-in returned no token");
    const sinceMs = typeof (cursor as { since?: unknown } | null)?.since === "number" ? (cursor as { since: number }).since : Date.now() - 24 * 3600_000;
    const findings: Finding[] = [];
    let newest = sinceMs;
    let pageToken = "";
    for (let page = 0; page < MAX_PAGES; page++) {
      const q = new URLSearchParams({ filter: `state="ACTIVE" AND event_time>${sinceMs}`, orderBy: "event_time", pageSize: "100", ...(pageToken ? { pageToken } : {}) });
      const res = await adapterFetch(gcpAdapter.manifest, `https://securitycenter.googleapis.com/v1/organizations/${encodeURIComponent(String(conn.config.organization_id))}/sources/-/findings?${q}`, {
        method: "GET", signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`Security Command Center answered ${res.status}; will retry`);
      if (res.status !== 200) throw new Error(`Security Command Center refused the request (${res.status}); check the role and the organisation id`);
      let body: { listFindingsResults?: unknown; nextPageToken?: unknown } = {};
      try { body = JSON.parse(res.body); } catch { throw new Error("Security Command Center returned invalid JSON"); }
      for (const item of Array.isArray(body.listFindingsResults) ? body.listFindingsResults : []) {
        if (!isObj(item)) continue;
        const f = findingFromScc(item);
        if (f) findings.push(f);
        const t = Date.parse(String((isObj(item.finding) ? item.finding : {}).eventTime ?? ""));
        if (Number.isFinite(t) && t > newest && t <= Date.now() + 300_000) newest = t;
      }
      pageToken = typeof body.nextPageToken === "string" ? body.nextPageToken : "";
      if (!pageToken) break;
    }
    return { findings, cursor: { since: newest } };
  },
};
