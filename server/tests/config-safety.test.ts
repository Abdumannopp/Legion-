/**
 * Configuration combinations that must never start a server.
 *
 * These exist because the same mistake has now happened three times in this
 * codebase: a safety check keyed on NODE_ENV=production, which a self-hosted
 * customer never sets. Each case here is a state with no valid interpretation
 * in any deployment mode.
 */
import { describe, it, expect } from "vitest";
import { unsafeConfigProblems, type SafetyInputs } from "../src/config.js";

const safe: SafetyInputs = {
  frontendUrl: "http://localhost:3000",
  cookieSecure: false,
  dbSslInsecure: false,
  databaseUrl: "postgresql://legion:pw@localhost:5432/legion",
};

const check = (overrides: Partial<SafetyInputs>) =>
  unsafeConfigProblems({ ...safe, ...overrides });

describe("HTTPS without a Secure cookie", () => {
  it("is refused", () => {
    const problems = check({ frontendUrl: "https://legion.example.com", cookieSecure: false });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/COOKIE_SECURE/);
  });

  it("is accepted once the cookie is marked Secure", () => {
    expect(check({ frontendUrl: "https://legion.example.com", cookieSecure: true })).toEqual([]);
  });

  it("leaves plain-HTTP installs alone", () => {
    // Many on-prem installs run on an internal network over HTTP. Forcing the
    // Secure flag there would send the cookie nowhere and lock everyone out.
    expect(check({ frontendUrl: "http://legion.internal", cookieSecure: false })).toEqual([]);
  });

  it("leaves local evaluation alone", () => {
    // `npm run try` is a supported way to run Legion and must keep working.
    expect(check({ frontendUrl: "http://localhost:3000", cookieSecure: false })).toEqual([]);
  });
});

describe("unverified TLS to the database", () => {
  it("is refused when the database is remote", () => {
    const problems = check({
      dbSslInsecure: true,
      databaseUrl: "postgresql://legion:pw@db.example.com:5432/legion",
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/DB_SSL_INSECURE/);
    expect(problems[0]).toContain("db.example.com");
  });

  it("is allowed against a database on this machine", () => {
    // Nothing sits between the app and a socket on the same host, so the
    // escape hatch stays usable for local experiments.
    for (const host of ["localhost", "127.0.0.1"]) {
      expect(check({
        dbSslInsecure: true,
        databaseUrl: `postgresql://legion:pw@${host}:5432/legion`,
      })).toEqual([]);
    }
  });

  it("is silent when certificate verification is on", () => {
    expect(check({
      dbSslInsecure: false,
      databaseUrl: "postgresql://legion:pw@db.example.com:5432/legion",
    })).toEqual([]);
  });

  it("treats an unparseable database URL as local rather than crashing", () => {
    expect(check({ dbSslInsecure: true, databaseUrl: "not a url" })).toEqual([]);
  });
});

describe("combinations", () => {
  it("reports every problem at once, not just the first", () => {
    const problems = check({
      frontendUrl: "https://legion.example.com",
      cookieSecure: false,
      dbSslInsecure: true,
      databaseUrl: "postgresql://legion:pw@db.example.com:5432/legion",
    });
    expect(problems).toHaveLength(2);
  });

  it("passes a correctly configured deployment", () => {
    expect(check({
      frontendUrl: "https://legion.example.com",
      cookieSecure: true,
      dbSslInsecure: false,
      databaseUrl: "postgresql://legion:pw@db.example.com:5432/legion",
    })).toEqual([]);
  });
});

describe("hosted-service warnings", () => {
  const base = { deploymentMode: "saas" as const, paddleApiKey: "pdl_live_x", paddleWebhookSecret: "ntf_x", paddleEnvironment: "production" as const, smtpHost: "smtp.resend.com" };

  it("say nothing on a fully configured hosted service, or on a self-hosted install", async () => {
    const { saasWarnings } = await import("../src/config.js");
    expect(saasWarnings(base)).toEqual([]);
    expect(saasWarnings({ ...base, deploymentMode: "self-hosted", paddleApiKey: "", smtpHost: "" })).toEqual([]);
  });

  it("flag a hosted service where trials cannot be paid for, or sign-ups cannot be confirmed", async () => {
    const { saasWarnings } = await import("../src/config.js");
    expect(saasWarnings({ ...base, paddleWebhookSecret: "" }).join()).toMatch(/no way to subscribe/);
    expect(saasWarnings({ ...base, paddleEnvironment: "sandbox" }).join()).toMatch(/SANDBOX/);
    expect(saasWarnings({ ...base, smtpHost: "" }).join()).toMatch(/confirmation email/);
  });
});
