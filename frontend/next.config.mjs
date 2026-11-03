// Security headers for the dashboard.
//
// The Content-Security-Policy is NOT set here: it carries a fresh nonce per
// page, so proxy.ts builds it for every request (lib/csp.ts). A second, static
// policy here would be intersected with it by the browser and would only make
// maintenance harder. Everything else is static and set below.
const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const isDev = process.env.NODE_ENV !== "production";

const headers = [
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
  // A second build next to the normal one (ops/tests/e2e-turnstile.mjs builds
  // with a Turnstile site key without touching .next). Default unchanged.
  distDir: process.env.NEXT_DIST_DIR || ".next",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers }];
  },
};

export default nextConfig;
