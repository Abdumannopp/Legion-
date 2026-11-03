/**
 * The dashboard's Content-Security-Policy, built per request.
 *
 * Scripts: a fresh nonce for every page plus 'strict-dynamic' — only scripts
 * Next.js itself rendered with that nonce run, and the scripts THEY load
 * (Paddle.js, injected by @paddle/paddle-js) inherit the trust. An injected
 * <script> or inline event handler has no nonce and does not run. This
 * replaces script-src 'unsafe-inline', which let any HTML injection execute.
 *
 * Styles keep 'unsafe-inline': React's style={{…}} attributes cannot carry a
 * nonce, and style injection is not script execution.
 *
 * Pure and dependency-free so it can be unit-tested and used from proxy.ts.
 */
export interface CspInput {
  nonce: string;
  apiUrl: string;
  wsUrl?: string;
  isDev: boolean;
  /** Cloudflare Turnstile widget on the sign-in forms (NEXT_PUBLIC_TURNSTILE_SITE_KEY). */
  turnstile?: boolean;
}

const PADDLE = ["https://cdn.paddle.com", "https://*.paddle.com"];
// Allowed only when the widget is configured: its script, and the iframe it runs the challenge in.
const TURNSTILE = "https://challenges.cloudflare.com";

function originOf(u: string): string {
  try { return new URL(u).origin; } catch { return ""; }
}

export function buildCsp({ nonce, apiUrl, wsUrl, isDev, turnstile = false }: CspInput): string {
  if (!/^[A-Za-z0-9+/=_-]{16,}$/.test(nonce)) throw new Error("CSP nonce must be at least 16 base64 characters");
  const api = originOf(apiUrl);
  const ws = originOf((wsUrl || apiUrl.replace(/^http/, "ws")).replace(/^ws/, "http")).replace(/^http/, "ws");
  const challenge = turnstile ? ` ${TURNSTILE}` : "";
  return [
    "default-src 'self'",
    // 'self' and the Paddle hosts are ignored by browsers that understand
    // 'strict-dynamic'; they are the fallback for the few that do not.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""} ${PADDLE.join(" ")}${challenge}`,
    "script-src-attr 'none'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https://*.paddle.com",
    "font-src 'self' data:",
    `connect-src 'self' ${[api, ws].filter(Boolean).join(" ")} ${PADDLE.join(" ")}${isDev ? " ws://localhost:* ws://127.0.0.1:*" : ""}`,
    `frame-src ${PADDLE.join(" ")}${challenge}`,
    "frame-ancestors 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    ...(api.startsWith("https://") && !isDev ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
}

/** 128 random bits, base64 — unguessable and unique per response. */
export function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
