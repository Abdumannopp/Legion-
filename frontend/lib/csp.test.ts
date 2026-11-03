import { describe, expect, it } from "vitest";
import { buildCsp, newNonce } from "./csp";

const directive = (csp: string, name: string) => csp.split("; ").find((d) => d.startsWith(`${name} `)) ?? "";

describe("dashboard CSP", () => {
  const nonce = newNonce();
  const prod = buildCsp({ nonce, apiUrl: "https://legion.example.com/api", isDev: false });

  it("scripts run only with this response's nonce: no 'unsafe-inline', no 'unsafe-eval' in production", () => {
    const script = directive(prod, "script-src");
    expect(script).toContain(`'nonce-${nonce}'`);
    expect(script).toContain("'strict-dynamic'");
    expect(script).not.toContain("'unsafe-inline'");
    expect(script).not.toContain("'unsafe-eval'");
    expect(directive(prod, "script-src-attr")).toBe("script-src-attr 'none'");
  });

  it("keeps framing, plugins, base-tag and form hijacking closed", () => {
    expect(prod).toContain("frame-ancestors 'none'");
    expect(prod).toContain("object-src 'none'");
    expect(prod).toContain("base-uri 'self'");
    expect(prod).toContain("form-action 'self'");
    expect(prod).toContain("upgrade-insecure-requests");
  });

  it("the browser may talk only to itself, the API (and its WebSocket) and Paddle", () => {
    const connect = directive(prod, "connect-src");
    expect(connect).toContain("https://legion.example.com");
    expect(connect).toContain("wss://legion.example.com");
    expect(connect).not.toMatch(/\*(?!\.paddle\.com)/);
  });

  it("nonces are unique and unguessable (128 bits)", () => {
    const seen = new Set(Array.from({ length: 1000 }, () => newNonce()));
    expect(seen.size).toBe(1000);
    expect(Buffer.from(newNonce(), "base64")).toHaveLength(16);
  });

  it("refuses a nonce that is too short to be a secret", () => {
    expect(() => buildCsp({ nonce: "abc", apiUrl: "https://x.example", isDev: false })).toThrow();
  });

  it("development adds only what React's dev tooling needs", () => {
    const dev = buildCsp({ nonce, apiUrl: "http://localhost:8000", isDev: true });
    expect(directive(dev, "script-src")).toContain("'unsafe-eval'");
    expect(dev).not.toContain("upgrade-insecure-requests");
  });

  it("Cloudflare Turnstile is allowed only when the widget is configured", () => {
    expect(prod).not.toContain("challenges.cloudflare.com");
    const withWidget = buildCsp({ nonce, apiUrl: "https://legion.example.com/api", isDev: false, turnstile: true });
    expect(directive(withWidget, "script-src")).toContain("https://challenges.cloudflare.com");
    expect(directive(withWidget, "frame-src")).toContain("https://challenges.cloudflare.com");
    // Nothing else widens: still no inline script, and no other directive mentions it.
    expect(directive(withWidget, "script-src")).not.toContain("'unsafe-inline'");
    expect(directive(withWidget, "connect-src")).not.toContain("cloudflare");
  });
});
