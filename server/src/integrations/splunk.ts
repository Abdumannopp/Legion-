/**
 * Splunk Cloud — notable events (Splunk Enterprise Security) or any index you name, read through the REST search
 * export endpoint (pull, read only).
 *
 * A Splunk authentication token of a user that can search that index, sealed per connection and sent as
 * "Authorization: Bearer …". The stack is chosen by name (acme → acme.splunkcloud.com, REST port 8089); only
 * *.splunkcloud.com is reachable. Splunk Cloud only accepts REST calls from addresses on its allow list: add the
 * Legion server's outbound address there. Self-managed Splunk: use the generic JSON webhook (a Splunk alert action),
 * because Legion never calls an address a customer typed.
 *
 * Cursor: index time. Each poll asks for events indexed in [cursor, now), so an event that arrives late at its
 * source is still read once. At most 1 000 events per poll. An event is stored once, by its event_id (Enterprise
 * Security) or a hash of its identity. Legion never changes anything in Splunk; the search is fixed, not user text.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, cursorSince, mitreIn, parseTime, pickIp, severityOf, sha } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_RESULTS = 1000;
const first = (v: unknown) => (Array.isArray(v) ? v[0] : v);

export function findingFromSplunk(r: Obj): Finding | null {
  const name = cleanText(first(r.rule_name ?? r.search_name ?? r.source), 250);
  if (!name) return null;
  const id = cleanText(first(r.event_id), 200) || sha(`${first(r._cd) ?? ""}|${first(r._time) ?? ""}|${first(r._raw) ?? ""}|${name}`).slice(0, 40);
  const dest = cleanText(first(r.dest ?? r.dest_host ?? r.host), 255);
  const user = cleanText(first(r.user ?? r.src_user), 120);
  const sev = first(r.urgency ?? r.severity);
  return {
    externalId: id,
    title: cleanText(`Splunk: ${cleanText(first(r.rule_title), 200) || name}${dest ? ` on ${dest}` : ""}`, 300),
    severity: severityOf(typeof sev === "string" && sev.toLowerCase() === "informational" ? "low" : sev),
    summary: [
      cleanText(first(r.rule_description ?? r.description), 2000),
      user ? `User: ${user}` : "",
      r.status_label ? `Splunk status: ${cleanText(first(r.status_label), 40)}` : "",
      !r.rule_description && !r.description && r._raw ? cleanText(first(r._raw), 1500) : "",
    ].filter(Boolean).join("\n") || name,
    occurredAt: parseTime(first(r._time)),
    sourceIp: pickIp(first(r.src), first(r.src_ip)),
    target: dest || user || null,
    mitre: mitreIn(first(r["annotations.mitre_attack"]), r["annotations.mitre_attack.mitre_technique_id"], first(r.rule_description)),
    confidence: 70,
    asset: dest ? { name: dest, ip: pickIp(first(r.dest_ip)), os: null } : null,
  };
}

export const splunkAdapter: PullAdapter = {
  manifest: {
    kind: "splunk", displayName: "Splunk Cloud", vendor: "Splunk (Cisco)", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: ["*.splunkcloud.com"],
    summary: "Splunk Enterprise Security notable events (or another index you name) from Splunk Cloud, polled by index time. Read only. (Self-managed Splunk: use the generic JSON webhook.)",
    auth: "Splunk authentication token of a user allowed to search the index, sealed per connection. Add Legion's address to Splunk Cloud's REST allow list.",
  },
  configSchema: z.strictObject({
    stack: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Your stack name: acme for acme.splunkcloud.com"),
    index: z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$/, "Index name").default("notable"),
  }),
  secretFields: ["token"],
  async poll(conn, cursor, signal) {
    const host = `${String(conn.config.stack)}.splunkcloud.com`;
    const index = String(conn.config.index ?? "notable");
    const since = cursorSince(cursor);
    const until = new Date().toISOString();
    const body = new URLSearchParams({
      search: `search index=${index} | eval legion_indextime=_indextime | sort 0 legion_indextime | head ${MAX_RESULTS}`,
      output_mode: "json",
      index_earliest: String(Date.parse(since) / 1000),
      index_latest: String(Date.parse(until) / 1000),
      earliest_time: String(Math.floor(Date.parse(since) / 1000) - 7 * 24 * 3600),
      latest_time: "now",
    });
    const res = await adapterFetch(splunkAdapter.manifest, `https://${host}:8089/services/search/v2/jobs/export`, {
      method: "POST", signal, timeoutMs: 60_000, maxBytes: 32 * 1024 * 1024, body: body.toString(),
      headers: { authorization: `Bearer ${conn.secrets.token ?? ""}`, "content-type": "application/x-www-form-urlencoded" },
    });
    if (res.status === 429 || res.status === 503 || res.status >= 500) throw new Error(`Splunk answered ${res.status}; will retry`);
    if (res.status === 401 || res.status === 403) throw new Error(`Splunk refused the token (${res.status}); check the token and that the user may search index ${index}`);
    if (res.status !== 200) throw new Error(`Splunk answered ${res.status}`);
    const findings: Finding[] = [];
    let lastIndexed = 0;
    for (const line of res.body.split("\n")) {
      if (!line.trim()) continue;
      let row: unknown;
      try { row = JSON.parse(line); } catch { continue; }
      if (!isObj(row) || row.preview === true || !isObj(row.result)) continue;
      const f = findingFromSplunk(row.result);
      if (f) findings.push(f);
      const it = Number(first(row.result.legion_indextime));
      if (Number.isFinite(it) && it > lastIndexed) lastIndexed = it;
      if (findings.length >= MAX_RESULTS) break;
    }
    // A full page means more may be waiting: resume from the last index time read (that second comes again and is
    // dropped as duplicates), so nothing beyond the page is skipped. Otherwise everything up to `until` was read.
    let resume = findings.length >= MAX_RESULTS && lastIndexed > 0 ? new Date(lastIndexed * 1000).toISOString() : until;
    // Over 1 000 events in one second: move on rather than read that second forever.
    if (resume <= since) resume = until;
    return { findings, cursor: { since: resume } };
  },
};
