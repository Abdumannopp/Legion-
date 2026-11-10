/**
 * Okta — System Log events that matter for security (pull, read only): warnings and errors (failed and
 * suspicious sign-ins, MFA failures, account lockouts, policy changes). The API token needs the read-only
 * administrator role. The org is chosen by name (acme.okta.com), never by URL; only *.okta.com,
 * *.oktapreview.com and *.okta-emea.com are reachable. The paging link (Link: rel="next") is followed only on
 * the same host. Cursor: newest `published` time. An event is stored once, by its uuid.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, parseTime, pickIp, severityOf } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 10;
const DOMAIN = /^[a-z0-9][a-z0-9-]{0,62}\.(?:okta|oktapreview|okta-emea)\.com$/;

export function findingFromOkta(e: Obj): Finding | null {
  const id = cleanText(e.uuid, 100);
  const msg = cleanText(e.displayMessage, 250);
  if (!id || !msg) return null;
  const actor = isObj(e.actor) ? e.actor : {};
  const client = isObj(e.client) ? e.client : {};
  const outcome = isObj(e.outcome) ? e.outcome : {};
  const account = cleanText(actor.alternateId ?? actor.displayName, 120);
  const sev = String(e.severity ?? "").toUpperCase();
  return {
    externalId: id,
    title: cleanText(`Okta: ${msg}${outcome.result === "FAILURE" ? " (failed)" : ""}`, 300),
    severity: severityOf(sev === "ERROR" ? "high" : sev === "WARN" ? "medium" : "low"),
    summary: [`${cleanText(e.eventType, 100)}${outcome.reason ? ` — ${cleanText(outcome.reason, 200)}` : ""}`, account ? `Account: ${account}` : "", isObj(client.geographicalContext) && client.geographicalContext.country ? `Country: ${cleanText(client.geographicalContext.country, 60)}` : ""].filter(Boolean).join("\n"),
    occurredAt: parseTime(e.published),
    sourceIp: pickIp(client.ipAddress),
    target: account || null,
    mitre: [],
    confidence: 65,
    asset: null,
  };
}

export const oktaAdapter: PullAdapter = {
  manifest: {
    kind: "okta", displayName: "Okta (identity)", vendor: "Okta", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["*.okta.com", "*.oktapreview.com", "*.okta-emea.com"],
    summary: "Okta System Log warnings and errors (failed or suspicious sign-ins, MFA failures, lockouts), polled by time. Read only.",
    auth: "Okta API token of a read-only administrator, sealed per connection.",
  },
  configSchema: z.strictObject({ domain: z.string().regex(DOMAIN, "Your Okta domain, for example acme.okta.com") }),
  secretFields: ["api_token"],
  async poll(conn, cursor, signal) {
    const domain = String(conn.config.domain);
    const since = typeof (cursor as { since?: unknown } | null)?.since === "string" ? (cursor as { since: string }).since : new Date(Date.now() - 24 * 3600_000).toISOString();
    const q = new URLSearchParams({ since, limit: "100", sortOrder: "ASCENDING", filter: 'severity eq "WARN" or severity eq "ERROR"' });
    let url: string | null = `https://${domain}/api/v1/logs?${q}`;
    const findings: Finding[] = [];
    let newest = since;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res = await adapterFetch(oktaAdapter.manifest, url, { method: "GET", signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, headers: { authorization: `SSWS ${conn.secrets.api_token ?? ""}`, accept: "application/json" } });
      if (res.status === 429 || res.status >= 500) throw new Error(`Okta answered ${res.status}; will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`Okta refused the token (${res.status}); check the API token and its administrator role`);
      if (res.status !== 200) throw new Error(`Okta answered ${res.status}`);
      let events: unknown;
      try { events = JSON.parse(res.body); } catch { throw new Error("Okta returned invalid JSON"); }
      for (const e of Array.isArray(events) ? events : []) {
        if (!isObj(e)) continue;
        const f = findingFromOkta(e);
        if (f) findings.push(f);
        const t = parseTime(e.published);
        if (t && t > newest) newest = t;
      }
      const link = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get("link") ?? "")?.[1];
      url = link && new URL(link).hostname === domain ? link : null;
    }
    return { findings, cursor: { since: newest } };
  },
};
