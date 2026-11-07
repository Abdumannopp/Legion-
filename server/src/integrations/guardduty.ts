/**
 * AWS GuardDuty — a pull integration (GuardDuty API, SigV4, no SDK).
 *
 * Authentication: an IAM user's access key limited to guardduty:ListDetectors, ListFindings and GetFindings
 * (read only; the policy is in INTEGRATIONS.md). The secret key is sealed per connection. The only hosts
 * reachable are guardduty.<region>.amazonaws.com and sts.amazonaws.com (for the optional cross-account role).
 *
 * Cursor: the newest finding updatedAt (epoch ms). The filter is ">=", the boundary finding repeats and is
 * dropped as a duplicate. A finding is stored once, by its id.
 */
import { z } from "zod";
import { adapterFetch } from "./fetch.js";
import { cleanText, parseTime, pickIp, severityOf } from "./shared.js";
import { signV4 } from "./sigv4.js";
import type { ConnectionContext, Finding, PullAdapter } from "./types.js";

const REGION = /^[a-z]{2}(?:-[a-z]+)+-\d$/;
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const get = (o: unknown, path: string[]): unknown => path.reduce<unknown>((c, k) => (isObj(c) ? c[k] : undefined), o);

export function findingFromGuardDuty(f: Obj): Finding | null {
  const id = cleanText(f.Id, 200);
  const title = cleanText(f.Title, 300) || cleanText(f.Type, 300);
  if (!id || !title) return null;
  const action = get(f, ["Service", "Action"]);
  const ip = pickIp(
    get(action, ["NetworkConnectionAction", "RemoteIpDetails", "IpAddressV4"]),
    get(action, ["AwsApiCallAction", "RemoteIpDetails", "IpAddressV4"]),
    get(action, ["KubernetesApiCallAction", "RemoteIpDetails", "IpAddressV4"]),
    get(action, ["RdsLoginAttemptAction", "RemoteIpDetails", "IpAddressV4"]),
    Array.isArray(get(action, ["PortProbeAction", "PortProbeDetails"])) ? get((get(action, ["PortProbeAction", "PortProbeDetails"]) as unknown[])[0], ["RemoteIpDetails", "IpAddressV4"]) : null,
  );
  const instance = cleanText(get(f, ["Resource", "InstanceDetails", "InstanceId"]), 100);
  const user = cleanText(get(f, ["Resource", "AccessKeyDetails", "UserName"]), 100);
  const sev = typeof f.Severity === "number" ? f.Severity : Number(f.Severity);
  return {
    externalId: id,
    title,
    severity: severityOf(Number.isFinite(sev) ? sev : "medium", "ten"),
    summary: [cleanText(f.Description, 3000), f.Type ? `Type: ${cleanText(f.Type, 120)}` : "", f.Region ? `Region: ${cleanText(f.Region, 30)}` : "", f.AccountId ? `Account: ${cleanText(f.AccountId, 20)}` : ""].filter(Boolean).join("\n") || title,
    occurredAt: parseTime(get(f, ["Service", "EventLastSeen"]) ?? f.UpdatedAt),
    sourceIp: ip,
    target: instance || user || null,
    mitre: [],
    confidence: 70,
    asset: instance ? { name: instance, ip: pickIp(get(Array.isArray(get(f, ["Resource", "InstanceDetails", "NetworkInterfaces"])) ? (get(f, ["Resource", "InstanceDetails", "NetworkInterfaces"]) as unknown[])[0] : null, ["PrivateIpAddress"])), os: null } : null,
  };
}

interface AwsCreds { accessKeyId: string; secretAccessKey: string; sessionToken?: string }

/**
 * Optional cross-account role: with config.role_arn, the stored key only needs sts:AssumeRole on that one role
 * (with the external id the customer set in the role's trust policy); GuardDuty is then read with short-lived
 * credentials (15 minutes). Without role_arn the stored key reads GuardDuty directly.
 */
export async function credentialsFor(conn: ConnectionContext, signal: AbortSignal): Promise<AwsCreds> {
  const base: AwsCreds = { accessKeyId: conn.secrets.access_key_id ?? "", secretAccessKey: conn.secrets.secret_access_key ?? "" };
  const roleArn = typeof conn.config.role_arn === "string" ? conn.config.role_arn : "";
  if (!roleArn) return base;
  const query: Record<string, string> = { Action: "AssumeRole", Version: "2011-06-15", RoleArn: roleArn, RoleSessionName: "legion-guardduty", DurationSeconds: "900" };
  if (typeof conn.config.external_id === "string" && conn.config.external_id) query.ExternalId = conn.config.external_id;
  const signed = signV4({ method: "GET", host: "sts.amazonaws.com", path: "/", query, region: "us-east-1", service: "sts", ...base });
  const qs = Object.entries(query).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
  const res = await adapterFetch(guarddutyManifest, `https://sts.amazonaws.com/?${qs}`, { method: "GET", signal, timeoutMs: 15_000, maxBytes: 64 * 1024, headers: signed });
  if (res.status === 429 || res.status >= 500) throw new Error(`AWS STS answered ${res.status}; will retry`);
  if (res.status !== 200) throw new Error(`AWS STS refused to assume the role (${res.status}); check the role's trust policy and external id`);
  const pick = (tag: string) => new RegExp(`<${tag}>([^<]{1,2048})</${tag}>`).exec(res.body)?.[1];
  const accessKeyId = pick("AccessKeyId"), secretAccessKey = pick("SecretAccessKey"), sessionToken = pick("SessionToken");
  if (!accessKeyId || !secretAccessKey || !sessionToken) throw new Error("AWS STS returned no credentials");
  return { accessKeyId, secretAccessKey, sessionToken };
}

async function call(conn: ConnectionContext, creds: AwsCreds, region: string, method: "GET" | "POST", path: string, body: unknown, signal: AbortSignal): Promise<Obj> {
  const host = `guardduty.${region}.amazonaws.com`;
  const payload = body === undefined ? "" : JSON.stringify(body);
  const signed = signV4({ method, host, path, body: payload, region, service: "guardduty", ...creds });
  const res = await adapterFetch(guarddutyManifest, `https://${host}${path}`, {
    method, signal, timeoutMs: 30_000, maxBytes: 8 * 1024 * 1024, body: payload || undefined,
    headers: { ...signed, ...(payload ? { "content-type": "application/json" } : {}) },
  });
  if (res.status === 429 || res.status >= 500) throw new Error(`GuardDuty (${region}) answered ${res.status}; will retry`);
  if (res.status === 403 || res.status === 401) throw new Error(`GuardDuty (${region}) refused the credentials (${res.status}); check the IAM policy and keys`);
  if (res.status !== 200) throw new Error(`GuardDuty (${region}) answered ${res.status}`);
  try { const j = JSON.parse(res.body); return isObj(j) ? j : {}; } catch { throw new Error(`GuardDuty (${region}) returned invalid JSON`); }
}

const guarddutyManifest = {
  kind: "guardduty", displayName: "AWS GuardDuty", vendor: "Amazon Web Services", status: "available" as const, plane: "data" as const, inbound: "pull" as const, outbound: [] as [],
  egressHosts: ["guardduty.*.amazonaws.com", "sts.amazonaws.com"],
  summary: "GuardDuty findings from the regions you list, polled by update time. Read only.",
  auth: "IAM access key limited to guardduty:ListDetectors, ListFindings, GetFindings — or, with role_arn, only to sts:AssumeRole on a read-only role in the customer account (external id). Sealed per connection.",
};

export const guarddutyAdapter: PullAdapter = {
  manifest: guarddutyManifest,
  configSchema: z.strictObject({
    regions: z.array(z.string().regex(REGION, "An AWS region such as eu-west-1")).min(1).max(5),
    role_arn: z.string().regex(/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,128}$/, "An IAM role ARN").optional(),
    external_id: z.string().regex(/^[A-Za-z0-9+=,.@:\/-]{2,1224}$/).optional(),
  }),
  secretFields: ["access_key_id", "secret_access_key"],
  async poll(conn, cursor, signal) {
    const sinceMs = typeof (cursor as { since?: unknown } | null)?.since === "number" ? (cursor as { since: number }).since : Date.now() - 24 * 3600_000;
    const findings: Finding[] = [];
    let newest = sinceMs;
    const creds = await credentialsFor(conn, signal);
    for (const region of conn.config.regions as string[]) {
      const detectors = await call(conn, creds, region, "GET", "/detector", undefined, signal);
      for (const detectorId of (Array.isArray(detectors.detectorIds) ? detectors.detectorIds : []).filter((d): d is string => typeof d === "string" && /^[a-z0-9]{1,64}$/.test(d)).slice(0, 5)) {
        let nextToken: string | undefined;
        for (let page = 0; page < 5; page++) {
          const list = await call(conn, creds, region, "POST", `/detector/${detectorId}/findings`, {
            findingCriteria: { criterion: { updatedAt: { greaterThanOrEqual: sinceMs } } },
            sortCriteria: { attributeName: "updatedAt", orderBy: "ASC" }, maxResults: 50, ...(nextToken ? { nextToken } : {}),
          }, signal);
          const ids = (Array.isArray(list.findingIds) ? list.findingIds : []).filter((x): x is string => typeof x === "string").slice(0, 50);
          if (ids.length) {
            const got = await call(conn, creds, region, "POST", `/detector/${detectorId}/findings/get`, { findingIds: ids }, signal);
            for (const f of Array.isArray(got.findings) ? got.findings : []) {
              if (!isObj(f)) continue;
              const x = findingFromGuardDuty(f);
              if (x) findings.push(x);
              const u = Date.parse(String(f.UpdatedAt ?? ""));
              if (Number.isFinite(u) && u > newest && u <= Date.now() + 300_000) newest = u;
            }
          }
          nextToken = typeof list.nextToken === "string" && list.nextToken ? list.nextToken : undefined;
          if (!nextToken) break;
        }
      }
    }
    return { findings, cursor: { since: newest } };
  },
};
