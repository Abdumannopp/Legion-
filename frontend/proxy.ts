/**
 * Next.js Proxy (formerly "middleware"): a fresh CSP nonce for every page.
 *
 * Next.js reads the nonce from the Content-Security-Policy REQUEST header and
 * stamps it on every script it renders. Pages are dynamically rendered (the
 * root layout reads cookies), which is what makes a per-request nonce possible.
 */
import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, newNonce } from "./lib/csp";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const WS_URL = process.env.NEXT_PUBLIC_WS_URL;

export function proxy(request: NextRequest) {
  const nonce = newNonce();
  const csp = buildCsp({ nonce, apiUrl: API_URL, wsUrl: WS_URL, isDev: process.env.NODE_ENV !== "production", turnstile: Boolean(process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY) });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      // Pages only: static assets carry no script and need no nonce.
      source: "/((?!_next/static|_next/image|favicon.ico|icon.svg|icon.png|apple-icon.png|brand/).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
