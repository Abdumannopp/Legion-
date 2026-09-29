// Security headers for the dashboard.
//
// The CSP is built from NEXT_PUBLIC_API_URL / NEXT_PUBLIC_WS_URL because those
// are the only places the browser may talk to besides itself (and Paddle, for
// checkout). 'unsafe-inline' for scripts/styles is what Next.js's own inline
// bootstrap requires without per-request nonces; everything else is closed:
// no objects, no framing of us, no base-tag or form hijacking, no foreign
// script hosts.
const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const wsUrl = process.env.NEXT_PUBLIC_WS_URL || apiUrl.replace(/^http/, "ws");
const isDev = process.env.NODE_ENV !== "production";

const originOf = (u) => { try { return new URL(u).origin; } catch { return ""; } };
const apiOrigin = originOf(apiUrl);
const wsOrigin = originOf(wsUrl.replace(/^ws/, "http")).replace(/^http/, "ws");

const paddle = ["https://cdn.paddle.com", "https://*.paddle.com"];

const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""} ${paddle.join(" ")}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https://*.paddle.com",
  "font-src 'self' data:",
  `connect-src 'self' ${[apiOrigin, wsOrigin].filter(Boolean).join(" ")} ${paddle.join(" ")}${isDev ? " ws://localhost:* ws://127.0.0.1:*" : ""}`,
  `frame-src ${paddle.join(" ")}`,
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join("; ");

const headers = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), usb=(), interest-cohort=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
];
// Only over HTTPS: on a plain-http install the browser ignores it, and it must
// never be advertised there.
if (apiUrl.startsWith("https://") && !isDev) {
  headers.push({ key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" });
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers }];
  },
};

export default nextConfig;
