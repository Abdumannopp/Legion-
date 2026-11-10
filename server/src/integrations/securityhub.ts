/**
 * AWS Security Hub — findings in ASFF from every AWS security service the account has turned on (Inspector,
 * Macie, Config, IAM Access Analyzer, Firewall Manager, partner products…), per region (pull, read only).
 *
 * Same credentials model as the GuardDuty connection: an IAM key limited to securityhub:GetFindings, or — better —
 * only sts:AssumeRole on a read-only role in the customer's account, with an external id. Hosts:
 * securityhub.<region>.amazonaws.com and sts.amazonaws.com only. Requests are signed with SigV4 (no SDK).
 *
 * Cursor: the newest UpdatedAt. Only ACTIVE findings whose workflow status is NEW or NOTIFIED are read; an updated
 * finding comes again — a duplicate, or a raised severity (audit A-9). GuardDuty's own findings are skipped unless
 * include_guardduty is set, so a workspace with both connections does not get every GuardDuty finding twice.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { credentialsFor, REGION, type AwsCreds } from "./guardduty.js";
import { cleanText, cursorSince, mitreIn, parseTime, pickIp, severityOf } from "./shared.js";
import { signV4 } from "./sigv4.js";
import type { ConnectionContext, Finding, PullAdapter } from "./types.js";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const MAX_PAGES = 5;

export function findingFromAsff(f: Obj): Finding | null {
  const id = cleanText(f.Id, 512);
  const title = cleanText(f.Title, 250);
  if (!id || !title) return null;
  const sev = isObj(f.Severity) ? f.Severity : {};
  const label = String(sev.Label ?? "").toLowerCase();
  const product = cleanText(f.ProductName ?? (isObj(f.ProductFields) ? f.ProductFields["aws/securityhub/ProductName"] : ""), 60);
  const resources = (Array.isArray(f.Resources) ? f.Resources : []).filter(isObj);
  const r0 = resources[0] ?? {};
  const resource = cleanText(r0.Id, 255);
  const net = isObj(f.Network) ? f.Network : {};
  const types = Array.isArray(f.Types) ? f.Types.map((t) => cleanText(t, 120)).filter(Boolean).slice(0, 3) : [];
  const instance = String(r0.Type ?? "") === "AwsEc2Instance" ? resource.split("/").pop() ?? "" : "";
  return {
    externalId: id,
    title: cleanText(`${product ? `${product}: ` : "AWS: "}${title}`, 300),
    severity: label ? severityOf(label === "informational" ? "low" : label) : severityOf(sev.Normalized, "hundred"),
    summary: [
      cleanText(f.Description, 3000),
      types.length ? `Type: ${types.join(", ")}` : "",
      resource ? `Resource: ${cleanText(r0.Type, 60)} ${resource}` : "",
      f.AwsAccountId ? `Account: ${cleanText(f.AwsAccountId, 20)}` : "",
      f.Region ? `Region: ${cleanText(f.Region, 30)}` : "",
      isObj(f.Remediation) && isObj(f.Remediation.Recommendation) ? `Fix: ${cleanText(f.Remediation.Recommendation.Text, 500)}` : "",
    ].filter(Boolean).join("\n") || title,
    occurredAt: parseTime(f.LastObservedAt ?? f.FirstObservedAt ?? f.CreatedAt),
    sourceIp: pickIp(net.SourceIpV4, net.SourceIpV6),
    target: resource || null,
    mitre: mitreIn(f.Types, f.Description),
    confidence: typeof f.Confidence === "number" && f.Confidence >= 0 && f.Confidence <= 100 ? f.Confidence : 70,
    asset: instance ? { name: instance, ip: null, os: null } : null,
  };
}

const manifest = {
  kind: "securityhub", displayName: "AWS Security Hub", vendor: "Amazon Web Services", status: "available" as const, plane: "data" as const, inbound: "pull" as const, outbound: [] as [],
  egressHosts: ["securityhub.*.amazonaws.com", "sts.amazonaws.com"],
  summary: "Security Hub findings (Inspector, Macie, Config, Access Analyzer and partner products) from the regions you list, polled by update time. Read only.",
  auth: "IAM key limited to securityhub:GetFindings — or, with role_arn, only sts:AssumeRole on a read-only role in the customer account (external id). Sealed per connection.",
};

async function getFindings(creds: AwsCreds, region: string, body: unknown, signal: AbortSignal): Promise<Obj> {
  const host = `securityhub.${region}.amazonaws.com`;
  const payload = JSON.stringify(body);
  const signed = signV4({ method: "POST", host, path: "/findings", body: payload, region, service: "securityhub", ...creds });
  const res = await adapterFetch(manifest, `https://${host}/findings`, {
    method: "POST", signal, timeoutMs: 30_000, maxBytes: 16 * 1024 * 1024, body: payload, headers: { ...signed, "content-type": "application/json" },
  });
  if (res.status === 429 || res.status >= 500) throw new Error(`Security Hub (${region}) answered ${res.status}; will retry`);
  if (res.status === 401 || res.status === 403) throw new Error(`Security Hub (${region}) refused the credentials (${res.status}); check the IAM policy, and that Security Hub is enabled in this region`);
  if (res.status !== 200) throw new Error(`Security Hub (${region}) answered ${res.status}`);
  try { const j = JSON.parse(res.body); return isObj(j) ? j : {}; } catch { throw new Error(`Security Hub (${region}) returned invalid JSON`); }
}

export const securityhubAdapter: PullAdapter = {
  manifest,
  configSchema: z.strictObject({
    regions: z.array(z.string().regex(REGION, "An AWS region such as eu-west-1")).min(1).max(5),
    role_arn: z.string().regex(/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,128}$/, "An IAM role ARN").optional(),
    external_id: z.string().regex(/^[A-Za-z0-9+=,.@:\/-]{2,1224}$/).optional(),
    include_guardduty: z.boolean().default(false),
  }),
  secretFields: ["access_key_id", "secret_access_key"],
  async poll(conn: ConnectionContext, cursor, signal) {
    const since = cursorSince(cursor);
    const creds = await credentialsFor(conn, signal, manifest, "legion-securityhub");
    const findings: Finding[] = [];
    let newest = since;
    const filters: Obj = {
      UpdatedAt: [{ Start: since, End: new Date(Date.now() + 60_000).toISOString() }],
      RecordState: [{ Value: "ACTIVE", Comparison: "EQUALS" }],
      WorkflowStatus: [{ Value: "NEW", Comparison: "EQUALS" }, { Value: "NOTIFIED", Comparison: "EQUALS" }],
      ...(conn.config.include_guardduty ? {} : { ProductName: [{ Value: "GuardDuty", Comparison: "NOT_EQUALS" }] }),
    };
    for (const region of conn.config.regions as string[]) {
      let next: string | undefined;
      for (let page = 0; page < MAX_PAGES; page++) {
        const out = await getFindings(creds, region, { Filters: filters, SortCriteria: [{ Field: "UpdatedAt", SortOrder: "asc" }], MaxResults: 100, ...(next ? { NextToken: next } : {}) }, signal);
        for (const f of Array.isArray(out.Findings) ? out.Findings : []) {
          if (!isObj(f)) continue;
          const x = findingFromAsff(f);
          if (x) findings.push(x);
          const u = parseTime(f.UpdatedAt);
          if (u && u > newest) newest = u;
        }
        next = typeof out.NextToken === "string" && out.NextToken && out.NextToken.length <= 4096 ? out.NextToken : undefined;
        if (!next) break;
      }
    }
    return { findings, cursor: { since: newest } };
  },
};
