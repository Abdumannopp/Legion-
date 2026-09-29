/**
 * The network edge: who the client is, which web origins may talk to the API,
 * and what the browser is told to do with our responses.
 *
 * Three rules run through this file:
 *  1. A forwarded header is believed only when the TCP peer that sent it is a
 *     proxy the operator NAMED (TRUSTED_PROXIES). Nothing is trusted by default
 *     beyond loopback.
 *  2. Origins are exact-match allow-lists. There is no wildcard form.
 *  3. Requests with no Origin (curl, sensors, server-to-server) are not browsers
 *     and are not what CORS/CSRF defences are about, so they are never blocked
 *     merely for lacking one — except a WebSocket, which is cookie-authenticated
 *     and therefore the classic cross-site-hijack target.
 */
import type { Application, NextFunction, Request, RequestHandler, Response } from "express";
import type { IncomingMessage } from "node:http";
import cors from "cors";
import helmet from "helmet";
import { config } from "./config.js";
import { originOf, parseOrigins, parseTrustedProxies, type ParsedTrust } from "./edge-parse.js";
import { BoundedCounter } from "./bounded-counter.js";

// --- Trusted proxies ----------------------------------------------------------

export function resolveTrust(spec: string = config.trustedProxies): ParsedTrust {
  const parsed = parseTrustedProxies(spec);
  if (!parsed.ok) throw new Error(parsed.error);
  return parsed.trust;
}

/** Applies TRUSTED_PROXIES to Express, which then derives `req.ip` from it. */
export function applyTrustedProxies(app: Application, spec: string = config.trustedProxies): ParsedTrust {
  const trust = resolveTrust(spec);
  app.set("trust proxy", trust.setting);
  return trust;
}

function stripMapped(address: string): string {
  return address.startsWith("::ffff:") && address.includes(".") ? address.slice(7) : address;
}

/**
 * The client address for a request Express never routed — a WebSocket upgrade.
 * Same rule as `req.ip`: walk the chain from the TCP peer outward and stop at
 * the first address that is not a trusted proxy. Reuses the compiled trust
 * function Express built from the same setting, so the two can never disagree.
 */
export function clientAddress(app: Application, req: IncomingMessage): string {
  const peer = stripMapped(req.socket.remoteAddress ?? "");
  const trust = app.get("trust proxy fn") as ((addr: string, i: number) => boolean) | undefined;
  const header = req.headers["x-forwarded-for"];
  const forwarded = (Array.isArray(header) ? header.join(",") : header ?? "")
    .split(",").map((s) => stripMapped(s.trim())).filter(Boolean);
  const chain: string[] = [peer, ...forwarded.reverse()];
  if (!trust) return peer || "unknown";
  let i = 0;
  for (; i < chain.length - 1; i++) if (!trust(chain[i]!, i)) break;
  return chain[i] || "unknown";
}

// --- Origins ------------------------------------------------------------------

/** Every origin allowed to call the API from a browser. */
export function allowedOrigins(): Set<string> {
  const out = new Set<string>();
  const front = originOf(config.frontendUrl);
  if (front) out.add(front);
  const extra = parseOrigins(config.corsOrigins);
  if (extra.ok) for (const o of extra.origins) out.add(o);
  if (!config.isProduction) {
    // `localhost` and `127.0.0.1` are the same dashboard to a developer.
    for (const o of [...out]) {
      out.add(o.replace("//localhost", "//127.0.0.1"));
      out.add(o.replace("//127.0.0.1", "//localhost"));
    }
  }
  return out;
}

const cache = { key: "", set: new Set<string>() };
function allowed(): Set<string> {
  const key = `${config.frontendUrl}|${config.corsOrigins}`;
  if (cache.key !== key) { cache.key = key; cache.set = allowedOrigins(); }
  return cache.set;
}

/** Strict CORS: allow-listed origins only, credentials on, no wildcard, no echo. */
export function corsMiddleware(): RequestHandler {
  return cors({
    origin: (origin, callback) => {
      // No Origin header: not a cross-origin browser request. No CORS headers needed.
      if (!origin) return callback(null, false);
      // A disallowed origin gets NO Access-Control-* headers, so the browser
      // refuses to expose the response. (Not an error: erroring would 500.)
      return callback(null, allowed().has(origin));
    },
    credentials: true,
    methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "Accept", "Accept-Language"],
    exposedHeaders: ["Retry-After", "RateLimit", "RateLimit-Policy"],
    maxAge: 600,
    optionsSuccessStatus: 204,
  });
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Cookie-authenticated requests that change state must come from us.
 *
 * SameSite already blocks the common cross-site case; this closes the rest
 * (a sibling subdomain, an older browser) with the one signal browsers cannot
 * forge: the Origin header. Requests without an Origin are not browsers and
 * carry their own credentials, so they pass. `exempt` are machine endpoints
 * authenticated by signature.
 */
export function originGuard(exempt: RegExp): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;
    if (origin === undefined || SAFE_METHODS.has(req.method) || exempt.test(req.path)) return next();
    if (allowed().has(origin)) return next();
    return res.status(403).json({ detail: "Cross-origin request refused" });
  };
}

// --- Response headers ---------------------------------------------------------

export function hstsEnabled(): boolean {
  return config.isProduction && config.cookieSecure && config.frontendUrl.startsWith("https://");
}

/**
 * Headers for an API that only ever returns JSON: nothing in a response from
 * here should be rendered, framed, or cached, so the policy says exactly that.
 */
export function securityHeaders(): RequestHandler[] {
  const helmetMw = helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
      },
    },
    // Only sent over HTTPS in production. Over plain HTTP the browser ignores
    // it, and on a self-hosted http:// install it must not be sent at all.
    strictTransportSecurity: hstsEnabled()
      ? { maxAge: config.hstsMaxAgeSeconds, includeSubDomains: true, preload: config.hstsPreload }
      : false,
    xFrameOptions: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
    // Same-site, not same-origin: the dashboard on app.example.com must still read api.example.com.
    crossOriginResourcePolicy: { policy: "same-site" },
    crossOriginOpenerPolicy: { policy: "same-origin" },
    xPermittedCrossDomainPolicies: { permittedPolicies: "none" },
  });
  const extra: RequestHandler = (_req, res, next) => {
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
    // Responses carry per-user data; a shared cache must never keep them.
    // Handlers that set their own Cache-Control keep it.
    if (!res.getHeader("Cache-Control")) res.setHeader("Cache-Control", "no-store");
    next();
  };
  return [helmetMw, extra];
}

// --- WebSocket ----------------------------------------------------------------

export type WsOriginVerdict = "ok" | "missing" | "denied";

/**
 * Browsers send cookies on cross-site WebSocket handshakes and the same-origin
 * policy does not apply to them, so without this check any web page a logged-in
 * user visits could open an authenticated socket (cross-site WebSocket hijacking).
 */
export function checkWebSocketOrigin(origin: string | undefined): WsOriginVerdict {
  if (origin === undefined || origin === "") return config.wsAllowMissingOrigin ? "ok" : "missing";
  return allowed().has(origin) ? "ok" : "denied";
}

/** Handshakes per address per minute. Cheap, in-process, bounded. */
const upgradeAttempts = new BoundedCounter(60_000, config.rateLimitMaxKeys);
export const UPGRADE_LIMIT_PER_MINUTE = 60;

export function upgradeRateLimited(address: string): boolean {
  return upgradeAttempts.increment(address).totalHits > UPGRADE_LIMIT_PER_MINUTE;
}

/** Tests only. */
export function resetUpgradeLimiter(): void {
  upgradeAttempts.clear();
}
