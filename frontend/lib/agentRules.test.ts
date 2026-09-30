import { describe, expect, it } from "vitest";
import { primaryRule, ruleGroup } from "./agentRules";
import { translations } from "./i18n/translations";

describe("plain-language rule explanations", () => {
  it("explains the default quarantine and kill rules by what they protect", () => {
    expect(ruleGroup("sql.foreign_tenant")).toBe("otherWorkspace");
    expect(ruleGroup("tenant.mismatch")).toBe("otherWorkspace");
    expect(ruleGroup("a2a.cross_tenant")).toBe("otherWorkspace");
    expect(ruleGroup("egress.secret_in_payload")).toBe("secret");
    expect(ruleGroup("http.legion_secret")).toBe("secret");
    expect(ruleGroup("a2a.injection_payload")).toBe("injection");
    expect(ruleGroup("a2a.laundering")).toBe("injection");
    expect(ruleGroup("content.untrusted_hold")).toBe("injection");
  });

  it("groups the rest by family and falls back to a generic policy explanation", () => {
    expect(ruleGroup("egress.not_allowlisted")).toBe("destination");
    expect(ruleGroup("sql.multiple_statements")).toBe("database");
    expect(ruleGroup("shell.denied_command")).toBe("command");
    expect(ruleGroup("files.recursive_delete")).toBe("files");
    expect(ruleGroup("mcp.poisoned_definition")).toBe("toolDefinition");
    expect(ruleGroup("permission.not_granted")).toBe("notPermitted");
    expect(ruleGroup("confirm.permission")).toBe("needsApproval");
    expect(ruleGroup("risk.score_block")).toBe("unusual");
    expect(ruleGroup("identity.not_active")).toBe("notActive");
    expect(ruleGroup("a2a.fan_out")).toBe("agentToAgent");
    expect(ruleGroup("something.new")).toBe("policy");
  });

  it("has an explanation for every group in every language", () => {
    const groups = ["otherWorkspace", "secret", "injection", "toolDefinition", "destination", "database", "command",
      "files", "notPermitted", "needsApproval", "unusual", "notActive", "agentToAgent", "unknownTool", "policy"] as const;
    for (const locale of ["en", "ru", "uz"] as const) {
      for (const g of groups) {
        expect(translations[locale].agents.rules[g].what.length).toBeGreaterThan(10);
        expect(translations[locale].agents.rules[g].next.length).toBeGreaterThan(10);
      }
    }
  });

  it("picks the rule that refused over one that only warned", () => {
    expect(primaryRule([{ id: "risk.score_warn", effect: "WARN" }, { id: "sql.foreign_tenant", effect: "QUARANTINE" }])).toBe("sql.foreign_tenant");
    expect(primaryRule([{ id: "risk.score_warn", effect: "WARN" }])).toBe("risk.score_warn");
    expect(primaryRule([])).toBeNull();
  });
});

describe("permission names", () => {
  it("names every permission an agent can be granted, in every language", async () => {
    // The package's list is the source of truth; a new permission without a
    // plain-language name would show as a raw id.
    const { PERMISSION_TIERS } = await import("../../packages/agent-identity/src/permissions");
    for (const locale of ["en", "ru", "uz"] as const) {
      for (const id of Object.keys(PERMISSION_TIERS)) {
        expect(translations[locale].agents.permissions[id], `${locale} ${id}`).toBeTruthy();
      }
    }
  });
});
