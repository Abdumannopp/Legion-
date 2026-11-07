/**
 * Jira Cloud — opens a ticket for an alert.
 *
 * One ticket per alert and connection: before creating, Legion looks for an issue labelled
 * "legion-<alert id>" in the project, so a retry after a timeout (or a crash after the ticket was created)
 * finds the first ticket instead of opening a second. The site is chosen by name (acme → acme.atlassian.net),
 * never by URL; the only hosts Legion calls are *.atlassian.net. The API token is sealed per connection.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { severityAtLeast } from "./notify-filter.js";
import { PermanentDeliveryError, type ConnectionContext, type OutboundAdapter } from "./types.js";

const label = (alertId: string) => `legion-${alertId.toLowerCase().replace(/[^a-z0-9-]/g, "")}`.slice(0, 60);
const clean = (s: string, max: number) => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f‪-‮]/g, "").slice(0, max);

function base(conn: ConnectionContext): string {
  return `https://${String(conn.config.site)}.atlassian.net`;
}
function headers(conn: ConnectionContext): Record<string, string> {
  const token = Buffer.from(`${conn.secrets.email}:${conn.secrets.api_token}`).toString("base64");
  return { authorization: `Basic ${token}`, accept: "application/json", "content-type": "application/json" };
}
function check(status: number, what: string): void {
  if (status >= 200 && status < 300) return;
  if (status === 429 || status === 408 || status >= 500) throw new Error(`Jira answered ${status} (${what})`);
  throw new PermanentDeliveryError(`Jira refused the request (${status}, ${what}); check the site, project and credentials`);
}

export const jiraAdapter: OutboundAdapter = {
  manifest: {
    kind: "jira", displayName: "Jira Cloud", vendor: "Atlassian", status: "available", plane: "tool", inbound: null, outbound: ["ticket"],
    egressHosts: ["*.atlassian.net"],
    summary: "Opens one Jira ticket per alert (no duplicates on retry), delivered through the notification outbox. Creates tickets only; changes nothing else.",
    auth: "Atlassian account e-mail + API token with permission to create issues in one project; sealed per connection.",
  },
  configSchema: z.strictObject({
    site: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/, "Site name only, e.g. acme for acme.atlassian.net"),
    project_key: z.string().regex(/^[A-Z][A-Z0-9_]{1,9}$/, "Project key such as SEC"),
    issue_type: z.string().min(1).max(60).default("Task"),
    min_severity: z.enum(["low", "medium", "high", "critical"]).default("high"),
  }),
  secretFields: ["email", "api_token"],
  async deliver(conn, msg, signal) {
    if (!severityAtLeast(msg.severity, String(conn.config.min_severity ?? "high"))) return {};
    const key = String(conn.config.project_key);
    const lab = label(msg.alertId);
    // 1. Already ticketed? (a retry, or a crash after creation)
    const q = new URLSearchParams({ jql: `project = "${key}" AND labels = "${lab}"`, fields: "key", maxResults: "1" });
    const found = await adapterFetch(jiraAdapter.manifest, `${base(conn)}/rest/api/3/search/jql?${q}`, { method: "GET", headers: headers(conn), signal, timeoutMs: 15_000, maxBytes: 256 * 1024 });
    check(found.status, "search");
    let existing: string | undefined;
    try { existing = (JSON.parse(found.body) as { issues?: Array<{ key?: string }> }).issues?.[0]?.key; } catch { /* treated as not found */ }
    if (existing) return { ref: { key: existing, url: `${base(conn)}/browse/${existing}` } };
    // 2. Create it.
    const lines = [msg.summary, msg.target ? `Host: ${msg.target}` : "", msg.sourceIp ? `Source address: ${msg.sourceIp}` : "", `Open in Legion: ${msg.link}`].filter(Boolean).map((t) => clean(t, 3000));
    const res = await adapterFetch(jiraAdapter.manifest, `${base(conn)}/rest/api/3/issue`, {
      method: "POST", headers: headers(conn), signal, timeoutMs: 20_000, maxBytes: 256 * 1024,
      body: JSON.stringify({
        fields: {
          project: { key }, issuetype: { name: String(conn.config.issue_type ?? "Task") },
          summary: clean(`[${msg.severity.toUpperCase()}] ${msg.title}`, 250),
          labels: ["legion", lab, `severity-${msg.severity}`],
          description: { type: "doc", version: 1, content: lines.map((t) => ({ type: "paragraph", content: [{ type: "text", text: t }] })) },
        },
      }),
    });
    check(res.status, "create");
    let created: string | undefined;
    try { created = (JSON.parse(res.body) as { key?: string }).key; } catch { /* below */ }
    if (!created || !/^[A-Z][A-Z0-9_]+-\d+$/.test(created)) throw new Error("Jira created an issue but did not return its key");
    return { ref: { key: created, url: `${base(conn)}/browse/${created}` } };
  },
};
