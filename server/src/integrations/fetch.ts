/**
 * The only way an adapter reaches a vendor.
 *
 * HTTPS only, to a host its manifest declares (a leading "*." matches one
 * label: "securityhub.*.amazonaws.com" allows securityhub.eu-west-1.amazonaws.com),
 * with a timeout and a response-size cap. An adapter never fetches a URL a
 * customer typed: a connection's configuration chooses among the vendor's
 * hosts, it cannot point Legion at an internal address.
 */
import type { IntegrationManifest } from "./types.js";

export class EgressRefused extends Error {}

export function hostAllowed(manifest: Pick<IntegrationManifest, "egressHosts">, host: string): boolean {
  const h = host.toLowerCase();
  return manifest.egressHosts.some((pattern) => {
    const re = new RegExp(`^${pattern.toLowerCase().split(".").map((p) => (p === "*" ? "[a-z0-9-]+" : p.replace(/[^a-z0-9-]/g, "\\$&"))).join("\\.")}$`);
    return re.test(h);
  });
}

export async function adapterFetch(
  manifest: Pick<IntegrationManifest, "egressHosts">, url: string,
  init: RequestInit & { timeoutMs?: number; maxBytes?: number } = {},
): Promise<{ status: number; body: string; headers: Headers }> {
  const u = new URL(url);
  if (u.protocol !== "https:" || u.username || u.password || !hostAllowed(manifest, u.hostname)) {
    throw new EgressRefused(`refused egress to ${u.protocol}//${u.hostname}`);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), init.timeoutMs ?? 15_000);
  init.signal?.addEventListener("abort", () => controller.abort(), { once: true });
  try {
    const res = await fetch(u, { ...init, redirect: "error", signal: controller.signal });
    const max = init.maxBytes ?? 10 * 1024 * 1024;
    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      if (!reader) break;
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > max) { controller.abort(); throw new EgressRefused(`response exceeds ${max} bytes`); }
      chunks.push(value);
    }
    return { status: res.status, body: Buffer.concat(chunks).toString("utf8"), headers: res.headers };
  } finally {
    clearTimeout(timer);
  }
}
