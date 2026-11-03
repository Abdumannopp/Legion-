/**
 * `npm run setup` must be safe to re-run: it may refresh what it owns, but
 * never throw away what the operator configured (SMTP, AI keys, their
 * public address). Pure helpers from scripts/env-file.mjs; no database.
 */
import { describe, it, expect } from "vitest";
// @ts-expect-error — plain .mjs helper without type declarations
import { mergeEnv, parseDomain, parseEnv, parseSaas, setEnvValue } from "../scripts/env-file.mjs";

const template = [
  "# header",
  "FRONTEND_URL=http://localhost:3000",
  "JWT_SECRET=new-secret",
  "COOKIE_SECURE=false",
  "SMTP_HOST=",
  "OPENROUTER_API_KEY=",
  "",
].join("\n");

describe("re-running setup keeps the operator's settings", () => {
  const previous = [
    "FRONTEND_URL=https://legion.example.com",
    "JWT_SECRET=old-secret",
    "COOKIE_SECURE=true",
    "SMTP_HOST=smtp.example.com",
    "OPENROUTER_API_KEY=sk-or-123",
    "MY_OWN_SETTING=keep-me",
  ].join("\n");

  it("keeps SMTP, AI keys and the public address", () => {
    const env = parseEnv(mergeEnv(template, previous));
    expect(env.get("SMTP_HOST")).toBe("smtp.example.com");
    expect(env.get("OPENROUTER_API_KEY")).toBe("sk-or-123");
    expect(env.get("FRONTEND_URL")).toBe("https://legion.example.com");
    expect(env.get("COOKIE_SECURE")).toBe("true");
  });

  it("keeps settings the template doesn't know about", () => {
    expect(parseEnv(mergeEnv(template, previous)).get("MY_OWN_SETTING")).toBe("keep-me");
  });

  it("takes setup's value for the keys it is told to own", () => {
    const env = parseEnv(mergeEnv(template, previous, new Set(["JWT_SECRET"])));
    expect(env.get("JWT_SECRET")).toBe("new-secret");
    expect(env.get("SMTP_HOST")).toBe("smtp.example.com");
  });

  it("a first run is just the template", () => {
    expect(mergeEnv(template, "")).toBe(template);
  });

  it("an empty old value takes the template's default instead", () => {
    const env = parseEnv(mergeEnv("SMTP_HOST=smtp.resend.com\nSMTP_PORT=465\n", "SMTP_HOST=\nSMTP_PORT=2525\n"));
    expect(env.get("SMTP_HOST")).toBe("smtp.resend.com");
    expect(env.get("SMTP_PORT")).toBe("2525");
  });

  it("a value containing '=' survives intact", () => {
    const env = parseEnv(mergeEnv(template, "SMTP_HOST=a=b=c"));
    expect(env.get("SMTP_HOST")).toBe("a=b=c");
  });
});

describe("--domain", () => {
  it("accepts a plain hostname, either spelling", () => {
    expect(parseDomain(["--domain", "legion.example.com"])).toBe("legion.example.com");
    expect(parseDomain(["--domain=Legion.Example.COM"])).toBe("legion.example.com");
    expect(parseDomain([], { LEGION_DOMAIN: "soc.acme.uz" })).toBe("soc.acme.uz");
  });

  it("is optional", () => {
    expect(parseDomain([])).toBeNull();
  });

  it.each(["https://legion.example.com", "legion.example.com/", "legion.example.com:443", "localhost", "", "legion example.com"])(
    "refuses %j instead of writing a broken FRONTEND_URL",
    (bad) => {
      expect(() => parseDomain(["--domain", bad])).toThrow(/not a domain name/);
    },
  );
});

describe("setEnvValue (frontend/.env.local)", () => {
  it("replaces only the one key", () => {
    const before = "NEXT_PUBLIC_API_URL=http://localhost:8000\nNEXT_PUBLIC_OPERATOR_NAME=Acme\n";
    const after = setEnvValue(before, "NEXT_PUBLIC_API_URL", "https://x.example.com/api");
    expect(after).toBe("NEXT_PUBLIC_API_URL=https://x.example.com/api\nNEXT_PUBLIC_OPERATOR_NAME=Acme\n");
  });

  it("adds the key when missing", () => {
    expect(setEnvValue("A=1", "B", "2")).toBe("A=1\nB=2\n");
  });
});

describe("--saas", () => {
  it("is off unless asked for", () => {
    expect(parseSaas(["--domain", "x.example.com"])).toBe(false);
    expect(parseSaas(["--saas"])).toBe(true);
    expect(parseSaas([], { LEGION_SAAS: "1" })).toBe(true);
  });
});
