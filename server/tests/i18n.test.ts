/**
 * Legion is English only. The server must answer in English whatever the
 * browser asks for, and its own texts (emails, no-AI explanation, Copilot
 * fallback) must be English.
 */
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../src/index.js";
import { LOCALES, copilotFallback, localExplanation, localeFrom, suggestedActions, actionText, translate, validationMessage } from "../src/i18n.js";
import { alertEmail, inviteEmail, passwordResetEmail, testNotificationEmail, verifyEmailEmail } from "../src/mailer.js";
import type { Alert } from "../src/types.js";

const alert = (over: Partial<Alert> = {}): Alert => ({
  id: "A-1", tenant_id: "t", status: "open", severity: "critical", title: "Brute force on web-01", summary: "Many failed logins",
  confidence: 91, source_ip: "203.0.113.9", target: "web-01", source: "wazuh", mitre_technique: "T1110", ...over,
} as Alert);

describe("English only", () => {
  it("there is exactly one language", () => {
    expect([...LOCALES]).toEqual(["en"]);
  });

  it("Accept-Language is ignored", () => {
    for (const h of ["ru", "uz-Latn-UZ,en;q=0.8", "de", "", undefined]) expect(localeFrom(h)).toBe("en");
    expect(translate("Authentication required", "en")).toBe("Authentication required");
  });

  it("the API answers in English whatever the browser asks for", async () => {
    for (const lang of ["ru", "uz", "en"]) {
      const r = await request(app).get("/alerts").set("Accept-Language", lang);
      expect(r.status).toBe(401);
      expect(r.body.detail).toBe("Authentication required");
    }
  });

  it("validation messages are English", () => {
    expect(validationMessage({ path: ["email"] })).toBe("Enter a valid email address");
    expect(validationMessage(undefined)).toBe("Invalid request");
  });

  it("the no-AI explanation and Copilot fallback keep the alert's data, in English", () => {
    const a = alert();
    const text = localExplanation(a, "en");
    expect(text).toContain("CRITICAL priority");
    expect(text).toContain("203.0.113.9");
    expect(copilotFallback([a], a, "en")).toContain("unresolved alert");
    expect(copilotFallback([], undefined, "en")).toBe("There are no unresolved alerts in your tenant right now.");
  });

  it("suggested next steps are English text", () => {
    const steps = suggestedActions(alert());
    expect(steps.map((s) => actionText(s, "en")).join(" ")).toContain("Block or investigate source IP 203.0.113.9");
  });

  it("emails are English, with the link intact", () => {
    const url = "https://app.example/x?token=abc";
    const mails = [passwordResetEmail(url), verifyEmailEmail(url, 24), inviteEmail({ inviteUrl: url, tenantName: "Acme", invitedBy: "a@b.io", role: "analyst", expiresDays: 7 }), testNotificationEmail()];
    for (const m of mails) {
      expect(m.subject).not.toMatch(/[а-яёА-ЯЁ]/);
      expect(m.text).not.toMatch(/[а-яёА-ЯЁ]/);
    }
    expect(mails[0]!.text).toContain(url);
    expect(inviteEmail({ inviteUrl: url, tenantName: "Acme", invitedBy: "a@b.io", role: "analyst", expiresDays: 7 }).text).toContain("7 days");
    const am = alertEmail(alert());
    expect(am.subject).toContain("Brute force on web-01");
  });
});
