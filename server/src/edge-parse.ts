/**
 * Parsing of the settings that decide who Legion believes on the network:
 * which proxies may speak for a client's address, and which web origins may
 * talk to the API. No imports, so config.ts can refuse to boot on a bad value
 * without a circular dependency on the runtime code in edge.ts.
 *
 * Both are allow-lists with no "everything" form. `*`, `true` and `0.0.0.0/0`
 * are rejected on purpose: "trust every proxy" and "allow every origin" are the
 * two settings whose whole effect is to switch a protection off.
 */
import { isIP } from "node:net";

/** What Express's `trust proxy` accepts: a hop count, or a list of addresses/ranges/keywords. */
export type TrustSetting = false | number | string[];

export interface ParsedTrust {
  setting: TrustSetting;
  /** One line for the boot log: what is actually being trusted. */
  description: string;
  /** Trusting by position (a hop count) rather than by address. */
  byHopCount: boolean;
}

const KEYWORDS = new Set(["loopback", "linklocal", "uniquelocal"]);

function validCidrOrIp(entry: string): boolean {
  const slash = entry.indexOf("/");
  const ip = slash === -1 ? entry : entry.slice(0, slash);
  const family = isIP(ip);
  if (family === 0) return false;
  if (slash === -1) return true;
  const prefix = entry.slice(slash + 1);
  if (!/^\d{1,3}$/.test(prefix)) return false;
  const bits = Number(prefix);
  // /0 is "every address": the same as trusting everyone.
  return bits >= 1 && bits <= (family === 4 ? 32 : 128);
}

/**
 * TRUSTED_PROXIES:
 *   (unset)             loopback only — nginx/Caddy on the same host, which is how Legion
 *                       is deployed (it listens on 127.0.0.1 by default)
 *   none                trust nobody: the client is whoever opened the TCP connection
 *   2                   trust the last N hops BY POSITION (cloud load balancers whose
 *                       addresses change). Only safe if nothing but the proxy can reach the port.
 *   10.0.0.0/8,loopback trust these addresses/ranges/keywords (loopback, linklocal, uniquelocal)
 */
export function parseTrustedProxies(spec: string): { ok: true; trust: ParsedTrust } | { ok: false; error: string } {
  const raw = spec.trim();
  if (raw === "") {
    return { ok: true, trust: { setting: ["loopback"], byHopCount: false, description: "loopback only (default)" } };
  }
  if (/^(none|false|0|off)$/i.test(raw)) {
    return { ok: true, trust: { setting: false, byHopCount: false, description: "no proxy is trusted; the client address is the TCP peer" } };
  }
  if (/^\d+$/.test(raw)) {
    const hops = Number(raw);
    if (hops < 1 || hops > 10) return { ok: false, error: "TRUSTED_PROXIES: a hop count must be between 1 and 10" };
    return { ok: true, trust: { setting: hops, byHopCount: true, description: `the last ${hops} hop(s), by position` } };
  }
  const entries = raw.split(",").map((s) => s.trim()).filter(Boolean);
  for (const entry of entries) {
    if (/^(true|\*|all|any)$/i.test(entry)) {
      return { ok: false, error: `TRUSTED_PROXIES: "${entry}" would trust every client's X-Forwarded-For. List the proxy addresses instead.` };
    }
    if (!KEYWORDS.has(entry.toLowerCase()) && !validCidrOrIp(entry)) {
      return { ok: false, error: `TRUSTED_PROXIES: "${entry.slice(0, 60)}" is not an IP address, a CIDR range (not /0) or one of loopback, linklocal, uniquelocal` };
    }
  }
  return { ok: true, trust: { setting: entries, byHopCount: false, description: entries.join(", ") } };
}

/** The origin ("https://host[:port]") of a URL, or null if it is not an http(s) URL. */
export function originOf(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * CORS_ORIGINS: extra web origins allowed to call the API with credentials, in
 * addition to FRONTEND_URL's. Exact origins only; no wildcards, no "null".
 */
export function parseOrigins(spec: string): { ok: true; origins: string[] } | { ok: false; error: string } {
  const out: string[] = [];
  for (const entry of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    if (entry === "*" || entry.toLowerCase() === "null" || entry.includes("*")) {
      return { ok: false, error: `CORS_ORIGINS: "${entry.slice(0, 60)}" is not allowed — list exact origins such as https://app.example.com` };
    }
    const origin = originOf(entry);
    if (!origin) return { ok: false, error: `CORS_ORIGINS: "${entry.slice(0, 60)}" is not an http(s) origin` };
    out.push(origin);
  }
  return { ok: true, origins: [...new Set(out)] };
}
