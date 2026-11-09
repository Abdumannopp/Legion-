/** Audit A-8: an error stored on a connection says nothing about its credentials, in any form a provider echoes. */
import { describe, expect, it } from "vitest";
import { scrubError } from "../src/integrations/scrub.js";

const secrets = { email: "bot@acme.io", api_token: "jira-token-very-secret", webhook_url: "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX" };
const b64 = (s: string) => Buffer.from(s).toString("base64");

describe("scrubError", () => {
  it("removes the exact value, its base64 / url-encoded / JSON-escaped forms and the Basic header's email:token", () => {
    const basic = b64("bot@acme.io:jira-token-very-secret");
    for (const echoed of [
      "bad credentials jira-token-very-secret",
      `request failed: Authorization: Basic ${basic}`,
      `raw ${basic} in the middle`,
      `body {"token":"${JSON.stringify("jira-token-very-secret").slice(1, -1)}"}`,
      `GET /x?key=${encodeURIComponent("jira-token-very-secret")}`,
      `base64url ${Buffer.from("jira-token-very-secret").toString("base64url")}`,
    ]) {
      const out = scrubError(echoed, secrets);
      expect(out, echoed).not.toContain("jira-token-very-secret");
      expect(out, echoed).not.toContain(basic);
      expect(out, echoed).not.toContain(Buffer.from("jira-token-very-secret").toString("base64url"));
    }
  });
  it("removes webhook URLs of the hosts we deliver to, and the query string of any URL", () => {
    const out = scrubError("POST https://hooks.slack.com/services/T1/B2/abc failed; https://acme.logic.azure.com/workflows/x?sig=SECRETSIG; https://example.com/a?token=zzz&b=1", {});
    expect(out).not.toMatch(/T1\/B2|SECRETSIG|zzz/);
    expect(out).toContain("https://example.com/a?[redacted]");
  });
  it("catches credentials Legion never stored (JWT, AWS key, password field, Bearer header, URL credentials)", () => {
    const out = scrubError("Bearer abcdefghijklmnop1234 AKIAABCDEFGHIJKLMNOP password=hunter2xyz https://user:pa55w0rd@host.io/x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk", {});
    expect(out).not.toMatch(/abcdefghijklmnop1234|AKIAABCDEFGHIJKLMNOP|hunter2xyz|pa55w0rd|eyJhbGci/);
  });
  it("does not shred ordinary words when a secret is short, keeps useful text, and is capped", () => {
    expect(scrubError("Jira answered 503 (search) for project SEC", { pin: "SEC" })).toBe("Jira answered 503 (search) for project SEC");
    expect(scrubError("x".repeat(1000), {}).length).toBe(300);
    expect(scrubError("a\n\n b\t c", {})).toBe("a b c");
  });
});
