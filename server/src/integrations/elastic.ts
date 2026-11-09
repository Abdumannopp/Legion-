/**
 * Elastic Security (SIEM) on Elastic Cloud — open detection alerts, read through Kibana's detection engine API
 * (pull, read only).
 *
 * An Elastic API key with read access to the security alerts index (the built-in "viewer" role is enough); it is
 * sealed per connection and sent as "Authorization: ApiKey …". Only Elastic Cloud Kibana hosts are reachable
 * (…kb.<region>.<provider>.elastic-cloud.com / .cloud.es.io / .elastic.cloud): a self-managed Kibana is not polled,
 * because Legion never calls an address a customer typed — self-managed Elastic sends alerts to the generic JSON
 * webhook instead (a Kibana webhook connector), which needs no inbound access to the customer.
 *
 * Cursor: the newest @timestamp. Only alerts whose workflow status is "open" are read. An alert is stored once, by
 * its document id. Legion never acknowledges, closes or changes alerts in Elastic.
 */
import { z } from "zod";
import { adapterFetch, hostAllowed } from "./fetch.js";
import { cleanText, cursorSince, mitreIn, parseTime, pickIp, severityOf } from "./shared.js";
import type { Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 5;
const EGRESS = ["*.kb.*.*.elastic-cloud.com", "*.kb.*.*.cloud.es.io", "*.kb.*.*.elastic.cloud"];

/** A field from an alert document, written either flat ("kibana.alert.rule.name") or nested. */
export function field(src: Obj, path: string): unknown {
  if (path in src) return src[path];
  let cur: unknown = src;
  for (const part of path.split(".")) {
    if (!isObj(cur)) return undefined;
    cur = cur[part];
  }
  return cur;
}
const first = (v: unknown) => (Array.isArray(v) ? v[0] : v);

export function findingFromElasticAlert(id: string, src: Obj): Finding | null {
  const rule = cleanText(field(src, "kibana.alert.rule.name") ?? field(src, "signal.rule.name"), 250);
  if (!id || !rule) return null;
  const host = cleanText(first(field(src, "host.name")), 255);
  const user = cleanText(first(field(src, "user.name")), 120);
  const sev = field(src, "kibana.alert.severity") ?? field(src, "signal.rule.severity");
  const risk = field(src, "kibana.alert.risk_score") ?? field(src, "signal.rule.risk_score");
  const threat = field(src, "kibana.alert.rule.threat");
  const ids: string[] = [];
  for (const t of Array.isArray(threat) ? threat : []) {
    if (!isObj(t)) continue;
    for (const tech of Array.isArray(t.technique) ? t.technique : []) {
      if (!isObj(tech)) continue;
      ids.push(String(tech.id ?? ""));
      for (const sub of Array.isArray(tech.subtechnique) ? tech.subtechnique : []) if (isObj(sub)) ids.push(String(sub.id ?? ""));
    }
  }
  return {
    externalId: id,
    title: cleanText(`Elastic: ${rule}${host ? ` on ${host}` : ""}`, 300),
    severity: typeof sev === "string" && sev ? severityOf(sev) : severityOf(risk, "hundred"),
    summary: [
      cleanText(field(src, "kibana.alert.reason") ?? field(src, "kibana.alert.rule.description"), 3000),
      user ? `User: ${user}` : "",
      field(src, "process.command_line") ? `Command line: ${cleanText(first(field(src, "process.command_line")), 1000)}` : "",
    ].filter(Boolean).join("\n") || rule,
    occurredAt: parseTime(field(src, "kibana.alert.original_time") ?? field(src, "@timestamp")),
    sourceIp: pickIp(first(field(src, "source.ip")), first(field(src, "client.ip"))),
    target: host || user || null,
    mitre: mitreIn(ids),
    confidence: typeof risk === "number" && risk >= 0 && risk <= 100 ? Math.round(risk) : 70,
    asset: host ? { name: host, ip: pickIp(first(field(src, "host.ip"))), os: cleanText(first(field(src, "host.os.name")), 60) || null } : null,
  };
}

export const elasticAdapter: PullAdapter = {
  manifest: {
    kind: "elastic", displayName: "Elastic Security (Elastic Cloud)", vendor: "Elastic", status: "available", plane: "data", inbound: "pull", outbound: [],
    egressHosts: EGRESS,
    summary: "Open Elastic Security detection alerts from a Kibana on Elastic Cloud, polled by time. Read only. (Self-managed Elastic: use the generic JSON webhook.)",
    auth: "Elastic API key with read access to the security alerts (viewer role is enough), sealed per connection.",
  },
  configSchema: z.strictObject({
    kibana_host: z.string().toLowerCase().refine((h) => hostAllowed({ egressHosts: EGRESS }, h), "The Kibana host of your Elastic Cloud deployment, e.g. my-deploy.kb.us-central1.gcp.cloud.es.io"),
    space: z.string().regex(/^[a-z0-9_-]{1,100}$/).default("default"),
  }),
  secretFields: ["api_key"],
  async poll(conn, cursor, signal) {
    const host = String(conn.config.kibana_host);
    const space = String(conn.config.space ?? "default");
    const prefix = space === "default" ? "" : `/s/${space}`;
    const since = cursorSince(cursor);
    const findings: Finding[] = [];
    let newest = since;
    let after: unknown[] | null = null;
    for (let page = 0; page < MAX_PAGES; page++) {
      const body = {
        size: 100,
        sort: [{ "@timestamp": "asc" }, { "kibana.alert.uuid": "asc" }],
        query: { bool: { filter: [{ range: { "@timestamp": { gte: since } } }, { term: { "kibana.alert.workflow_status": "open" } }] } },
        ...(after ? { search_after: after } : {}),
      };
      const res = await adapterFetch(elasticAdapter.manifest, `https://${host}${prefix}/api/detection_engine/signals/search`, {
        method: "POST", signal, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024, body: JSON.stringify(body),
        headers: { authorization: `ApiKey ${conn.secrets.api_key ?? ""}`, "content-type": "application/json", "kbn-xsrf": "legion", accept: "application/json" },
      });
      if (res.status === 429 || res.status >= 500) throw new Error(`Elastic answered ${res.status}; will retry`);
      if (res.status === 401 || res.status === 403) throw new Error(`Elastic refused the API key (${res.status}); it needs read access to the security alerts`);
      if (res.status !== 200) throw new Error(`Elastic answered ${res.status}`);
      let hits: unknown[] = [];
      try { const j = JSON.parse(res.body) as { hits?: { hits?: unknown } }; hits = Array.isArray(j.hits?.hits) ? j.hits!.hits as unknown[] : []; } catch { throw new Error("Elastic returned invalid JSON"); }
      for (const h of hits) {
        if (!isObj(h) || !isObj(h._source)) continue;
        const f = findingFromElasticAlert(cleanText(h._id, 200), h._source);
        if (f) findings.push(f);
        const t = parseTime(field(h._source, "@timestamp"));
        if (t && t > newest) newest = t;
      }
      const last = hits[hits.length - 1];
      after = isObj(last) && Array.isArray(last.sort) && last.sort.length <= 4 ? last.sort : null;
      if (hits.length < 100 || !after) break;
    }
    return { findings, cursor: { since: newest } };
  },
};
