/** Skill definitions and the shared, deterministic knowledge they use. No database. */
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { maskSecrets } from "../src/firewall/scan.js";
import { PERMISSION_TIERS } from "../src/permissions.js";
import { BUILTIN_SKILLS, createBuiltinRegistry } from "../src/skills/builtin/index.js";
import { mdSafe } from "../src/skills/builtin/common.js";
import { extractIndicators, normalizeIndicator, primaryStage, readEvent } from "../src/skills/knowledge.js";
import { SkillRegistry, validateDefinition } from "../src/skills/registry.js";
import { ALL_SKILL_CAPABILITIES, capabilityPermission, MAX_SKILL_PERMISSION_TIER, securityEventSchema, type SkillDefinition } from "../src/skills/types.js";

const valid = (): SkillDefinition => ({
  name: "ok_skill", title: "OK", description: "d", version: "1.0.0",
  input: z.strictObject({ a: z.number().default(1) }), output: z.strictObject({}), capabilities: ["read:assets"],
  auditEvents: ["skill.invoke"], example: {}, limitations: [], handler: async () => ({}),
});

describe("registry", () => {
  it("registers every built-in skill, each valid, strict and read-only", () => {
    const r = createBuiltinRegistry();
    expect(r.names()).toHaveLength(8);
    for (const s of BUILTIN_SKILLS) {
      expect(validateDefinition(s as SkillDefinition)).toEqual([]);
      expect(s.limitations.length).toBeGreaterThan(0);
      for (const c of s.capabilities) expect(PERMISSION_TIERS[capabilityPermission(c)]).toBeLessThanOrEqual(MAX_SKILL_PERMISSION_TIER);
    }
  });

  it("no capability maps to a state-changing permission", () => {
    for (const c of ALL_SKILL_CAPABILITIES) expect(PERMISSION_TIERS[capabilityPermission(c)]).toBeLessThan(2);
  });

  it.each([
    ["a bad name", { name: "Bad-Name" }, /snake_case/],
    ["a bad version", { version: "1" }, /semantic/],
    ["an unknown capability", { capabilities: ["write:alerts"] }, /unknown capability/],
    ["no capability", { capabilities: [] }, /at least one/],
    ["a non-strict input", { input: z.object({ a: z.number().default(1) }) }, /strict/],
    ["an example that does not validate", { example: { a: "x" } }, /example/],
    ["no audit events", { auditEvents: [] }, /audit/],
  ])("refuses %s", (_n, patch, msg) => {
    expect(validateDefinition({ ...valid(), ...patch } as SkillDefinition).join("; ")).toMatch(msg);
  });

  it("refuses a duplicate name and unknown lookups", () => {
    const r = new SkillRegistry().register(valid());
    expect(() => r.register(valid())).toThrow(/already registered/);
    expect(r.get("../ok_skill")).toBeUndefined();
    expect(r.get("missing_skill")).toBeUndefined();
  });
});

describe("knowledge", () => {
  it("extracts indicators from log text without mistaking file names for domains", () => {
    const got = extractIndicators(
      "Connection from 45.155.205.12 to https://evil.example.net/x.php; file /etc/nginx/nginx.conf changed; " +
      "hash 44d88612fea8a8f36de82e1278abb02f; see CVE-2021-44228; mail admin@corp.example; resolved c2.bad-domain.io",
    );
    const keys = got.map((i) => `${i.type}:${i.value}`);
    expect(keys).toEqual(expect.arrayContaining([
      "ip:45.155.205.12", "url:https://evil.example.net/x.php", "hash:44d88612fea8a8f36de82e1278abb02f",
      "cve:CVE-2021-44228", "email:admin@corp.example", "domain:c2.bad-domain.io",
    ]));
    expect(keys).not.toContain("domain:nginx.conf");
  });

  it("normalises and rejects indicators strictly", () => {
    expect(normalizeIndicator("CVE-2021-44228".toLowerCase())).toEqual({ type: "cve", value: "CVE-2021-44228" });
    expect(normalizeIndicator("999.1.1.1", "ip")).toBeNull();
    expect(normalizeIndicator("javascript:alert(1)", "url")).toBeNull();
    expect(normalizeIndicator("a b.com")).toBeNull();
  });

  it("MITRE ids outrank wording when placing an event in the attack order", () => {
    const e = securityEventSchema.parse({ id: "x", tenantId: "t", title: "Failed password; suspicious process", severity: "low", createdAt: new Date().toISOString(), mitreTechniques: ["T1078"] });
    expect(primaryStage(readEvent(e))).toBe("initial_access");
  });

  it("Markdown from untrusted text cannot form links, images or headings", () => {
    const s = mdSafe("# Title ![x](https://evil.example/?d=1) [click](http://evil.example)");
    expect(s).not.toMatch(/https?:\/\//);
    expect(s).not.toMatch(/(?<!\\)[[\]()!#]/);
  });

  it("maskSecrets keeps the text and removes whole private keys", () => {
    const out = maskSecrets(`key AKIA${"ABCDEFGHIJKLMNOP"} and\n-----BEGIN PRIVATE KEY-----\nMIIsecret\n-----END PRIVATE KEY-----\ndone`);
    expect(out).toBe("key [REDACTED:aws_access_key] and\n[REDACTED:private_key]\ndone");
  });
});
