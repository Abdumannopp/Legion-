import { BlockList, isIP } from "node:net";

/*
 * Where is this action going? Deterministic classification of URLs and IP
 * addresses — the SSRF defence. Nothing here resolves DNS; the executor
 * (guardedRequest) re-checks every resolved address at connect time, so a
 * hostname that later resolves to an internal address is still refused.
 */

export interface IpAddr {
  address: string;
  family: "ipv4" | "ipv6";
}

const nonPublic = new BlockList();
// IPv4
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) nonPublic.addSubnet(net, bits, "ipv4");
// IPv6
for (const [net, bits] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32],
  ["100::", 64], ["2001::", 23],
] as const) nonPublic.addSubnet(net, bits, "ipv6");

/** Pulls the IPv4 address out of IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96) forms. */
function embeddedIpv4(v6: string): string | null {
  const lower = v6.toLowerCase();
  const dotted = /^(?:::ffff:|64:ff9b::)(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (dotted) return dotted[1]!;
  const hex = /^(?:::ffff:|64:ff9b::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

export function parseIpLiteral(host: string): IpAddr | null {
  const h = host.replace(/^\[|\]$/g, "");
  const v = isIP(h);
  if (v === 4) return { address: h, family: "ipv4" };
  if (v === 6) return { address: h, family: "ipv6" };
  return null;
}

/** Loopback, private, link-local (cloud metadata lives at 169.254.169.254), CGNAT, multicast, reserved. */
export function isNonPublicIp(ip: IpAddr): boolean {
  if (ip.family === "ipv6") {
    const v4 = embeddedIpv4(ip.address);
    if (v4) return nonPublic.check(v4, "ipv4");
  }
  return nonPublic.check(ip.address, ip.family);
}

/** Names that always mean "inside": never a legitimate external destination. */
export function isBlockedHostName(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".lan") ||
    h.endsWith(".home.arpa") ||
    h === "metadata" ||
    h === "instance-data" ||
    !h.includes(".") // bare names resolve via the local search domain
  );
}

export function hostAllowed(host: string, patterns: readonly string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return patterns.some((p) => (p.startsWith("*.") ? h.endsWith(p.slice(1)) && h.length > p.length - 1 : h === p));
}

export type DestinationVerdict =
  | { ok: true; normalized: string; host: string; port: number }
  | { ok: false; hard: boolean; rule: string; reason: string; normalized: string | null };

/**
 * Static checks on a URL. `allowedHosts`/`allowedPorts` come from the tenant
 * policy; everything else is fixed.
 */
export function classifyUrl(raw: string, allowedHosts: readonly string[], allowedPorts: readonly number[]): DestinationVerdict {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, hard: true, rule: "egress.malformed_url", reason: "Not a valid absolute URL.", normalized: null };
  }
  // WHATWG parsing already normalised tricks like http://2130706433/ → 127.0.0.1.
  const normalized = `${url.protocol}//${url.host}${url.pathname}`;
  if (url.protocol !== "https:") {
    return { ok: false, hard: true, rule: "egress.scheme", reason: `Only https is allowed, not ${url.protocol}`, normalized };
  }
  if (url.username || url.password) {
    return { ok: false, hard: true, rule: "egress.credentials_in_url", reason: "Credentials embedded in the URL.", normalized };
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const ip = parseIpLiteral(host);
  if (ip && isNonPublicIp(ip)) {
    return { ok: false, hard: true, rule: "egress.internal_address", reason: `${host} is an internal or reserved address.`, normalized };
  }
  if (!ip && isBlockedHostName(host)) {
    return { ok: false, hard: true, rule: "egress.internal_name", reason: `${host} names an internal host.`, normalized };
  }
  const port = url.port ? Number(url.port) : 443;
  if (!allowedPorts.includes(port)) {
    return { ok: false, hard: false, rule: "egress.port", reason: `Port ${port} is not allowed.`, normalized };
  }
  if (!hostAllowed(host, allowedHosts)) {
    return { ok: false, hard: false, rule: "egress.not_allowlisted", reason: `${host} is not on this organisation's egress allowlist.`, normalized };
  }
  return { ok: true, normalized, host, port };
}
