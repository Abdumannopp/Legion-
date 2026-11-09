/**
 * ServiceNow — opens one incident per alert (Table API). Outbound, ticket only.
 *
 * One incident per alert and connection: the incident carries correlation_id "legion-<alert id>", and before
 * creating, Legion looks it up by that field. The Table API reads the database directly (no search index), so a
 * retry after a lost answer finds the first incident instead of opening a second; the new number is also stored
 * on the message at once (as for Jira, audit A-6). The instance is chosen by name (acme → acme.service-now.com),
 * never by URL; only *.service-now.com is reachable. The integration user needs the itil role (create incidents)
 * and nothing more; its password is sealed per connection. Legion creates incidents only; it never updates or
 * closes them, and never touches other tables.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { severityAtLeast } from "./notify-filter.js";
import { PermanentDeliveryError, type ConnectionContext, type OutboundAdapter, type OutboundMessage } from "./types.js";

const INSTANCE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const SYS_ID = /^[a-f0-9]{32}$/;
const NUMBER = /^[A-Z]{2,8}\d{4,12}$/;
// ServiceNow: 1 = high, 3 = low. Impact and urgency together give the priority.
const LEVEL = { critical: { impact: "1", urgency: "1" }, high: { impact: "2", urgency: "1" }, medium: { impact: "2", urgency: "2" }, low: { impact: "3", urgency: "3" } } as const;
const clean = (s: string, max: number) => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f‪-‮]/g, "").slice(0, max);

const base = (conn: ConnectionContext) => `https://${String(conn.config.instance)}.service-now.com`;
const linkFor = (conn: ConnectionContext, sysId: string) => `${base(conn)}/nav_to.do?uri=incident.do%3Fsys_id%3D${sysId}`;
function headers(conn: ConnectionContext): Record<string, string> {
  const basic = Buffer.from(`${conn.secrets.username ?? ""}:${conn.secrets.password ?? ""}`).toString("base64");
  return { authorization: `Basic ${basic}`, accept: "application/json", "content-type": "application/json" };
}
function check(status: number, what: string): void {
  if (status >= 200 && status < 300) return;
  if (status === 429 || status === 408 || status >= 500) throw new Error(`ServiceNow answered ${status} (${what})`);
  throw new PermanentDeliveryError(`ServiceNow refused the request (${status}, ${what}); check the instance, the user and its itil role`);
}
function ref(conn: ConnectionContext, body: string): { key: string; url: string } | null {
  try {
    const j = JSON.parse(body) as { result?: unknown };
    const r = Array.isArray(j.result) ? j.result[0] : j.result;
    if (!r || typeof r !== "object") return null;
    const { number, sys_id } = r as { number?: unknown; sys_id?: unknown };
    if (typeof number !== "string" || !NUMBER.test(number) || typeof sys_id !== "string" || !SYS_ID.test(sys_id)) return null;
    return { key: number, url: linkFor(conn, sys_id) };
  } catch { return null; }
}

export const servicenowAdapter: OutboundAdapter = {
  manifest: {
    kind: "servicenow", displayName: "ServiceNow", vendor: "ServiceNow", status: "available", plane: "tool", inbound: null, outbound: ["ticket"],
    egressHosts: ["*.service-now.com"],
    summary: "Opens one ServiceNow incident per alert (no duplicates on retry), delivered through the notification outbox. Creates incidents only; changes nothing else.",
    auth: "ServiceNow user with the itil role (create incidents), basic authentication; the password is sealed per connection.",
  },
  configSchema: z.strictObject({
    instance: z.string().regex(INSTANCE, "Instance name only: acme for acme.service-now.com"),
    assignment_group: z.string().regex(/^[a-f0-9]{32}$/, "sys_id of the assignment group (32 hex characters)").optional(),
    min_severity: z.enum(["low", "medium", "high", "critical"]).default("high"),
  }),
  secretFields: ["username", "password"],
  async deliver(conn, msg: OutboundMessage, signal, remember) {
    if (!severityAtLeast(msg.severity, String(conn.config.min_severity ?? "high"))) return {};
    const correlation = `legion-${msg.alertId.replace(/[^A-Za-z0-9-]/g, "")}`.slice(0, 100);
    // 1. Already opened? (a retry, or a crash after creation) — the Table API reads the database, not an index.
    const q = new URLSearchParams({ sysparm_query: `correlation_id=${correlation}`, sysparm_fields: "number,sys_id", sysparm_limit: "1" });
    const found = await adapterFetch(servicenowAdapter.manifest, `${base(conn)}/api/now/table/incident?${q}`, { method: "GET", headers: headers(conn), signal, timeoutMs: 15_000, maxBytes: 64 * 1024 });
    check(found.status, "look-up");
    const existing = ref(conn, found.body);
    if (existing) return { ref: existing };
    // 2. Create it.
    const level = LEVEL[msg.severity];
    const description = [msg.summary, msg.target ? `Host: ${msg.target}` : "", msg.sourceIp ? `Source address: ${msg.sourceIp}` : "", `Open in Legion: ${msg.link}`].filter(Boolean).map((t) => clean(t, 3000)).join("\n\n");
    const res = await adapterFetch(servicenowAdapter.manifest, `${base(conn)}/api/now/table/incident?sysparm_fields=number,sys_id`, {
      method: "POST", headers: headers(conn), signal, timeoutMs: 20_000, maxBytes: 64 * 1024,
      body: JSON.stringify({
        short_description: clean(`[${msg.severity.toUpperCase()}] ${msg.title}`, 160),
        description, correlation_id: correlation, correlation_display: "Legion",
        impact: level.impact, urgency: level.urgency, category: "security",
        ...(conn.config.assignment_group ? { assignment_group: String(conn.config.assignment_group) } : {}),
      }),
    });
    check(res.status, "create");
    const created = ref(conn, res.body);
    if (!created) throw new Error("ServiceNow created an incident but did not return its number");
    await remember?.({ ticket: created });
    return { ref: created };
  },
};
