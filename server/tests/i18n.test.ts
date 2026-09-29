/**
 * Three languages (English, Russian, Uzbek) on the server side.
 *
 * The dashboard sends its language in Accept-Language; everything the server
 * writes for a person — errors, confirmations, emails, the no-AI explanation,
 * Copilot's fallback answer — must come back in it. The first block also
 * guards the future: a route that adds a new English message without a
 * translation fails here.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach, vi } from "vitest";
import request from "supertest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { app } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as outbox from "../src/outbox.js";
import {
  CATALOG, LOCALES, copilotFallback, localExplanation, localeFrom, suggestedActions, actionText, translate, validationMessage,
} from "../src/i18n.js";
import { alertEmail, inviteEmail, passwordResetEmail, testNotificationEmail, verifyEmailEmail } from "../src/mailer.js";
import type { Alert } from "../src/types.js";

const src = (name: string) => readFileSync(join(fileURLToPath(import.meta.url), "..", "..", "src", name), "utf8");

describe("every message the API writes has a Russian and an Uzbek translation", () => {
  // Strings that are data, not messages: an audit-log detail value.
  const NOT_MESSAGES = new Set(["recovery"]);

  const literals = ["index.ts", "paddle.ts", "ratelimit.ts"].flatMap((file) =>
    [...src(file).matchAll(/\b(?:detail|message):\s*"((?:[^"\\]|\\.)+)"/g)].map((m) => ({ file, text: m[1]! }))
  ).filter(({ text }) => !NOT_MESSAGES.has(text));

  it("finds the messages (sanity check of the scan itself)", () => {
    expect(literals.length).toBeGreaterThan(40);
  });

  it.each(literals.map((l) => [l.file, l.text]))("%s: %s", (_file, text) => {
    expect(CATALOG[text], `add "${text}" to CATALOG in src/i18n.ts`).toBeDefined();
  });

  it("covers the access-state messages (written as a ternary, so listed here)", () => {
    for (const text of [
      "Your subscription payment is past due. Legion is read-only until it is settled.",
      "This workspace does not have an active Legion subscription.",
    ]) {
      expect(CATALOG[text]).toBeDefined();
    }
  });

  it("covers the messages with a variable part", () => {
    for (const [text, ru] of [
      ["SMTP connection failed: ECONNREFUSED", "Не удалось подключиться к SMTP-серверу: ECONNREFUSED"],
      ["Could not send: 550 rejected", "Не удалось отправить: 550 rejected"],
      ["Could not reach Paddle: timeout", "Нет связи с Paddle: timeout"],
      ["Test email sent to soc@acme.example", "Тестовое письмо отправлено на soc@acme.example"],
    ]) {
      expect(translate(text!, "ru")).toBe(ru);
      expect(translate(text!, "uz")).not.toBe(text);
    }
  });

  it("no translation is empty or left in English", () => {
    for (const [en, t] of Object.entries(CATALOG)) {
      expect(t.ru.trim(), en).not.toBe("");
      expect(t.uz.trim(), en).not.toBe("");
      expect(t.ru, en).not.toBe(en);
      expect(t.uz, en).not.toBe(en);
      expect(t.ru, `${en} (ru should be Cyrillic)`).toMatch(/[а-яё]/i);
    }
  });

  it("every validation message is translatable", () => {
    const paths = [["email"], ["password"], ["new_password"], ["tenant_name"], ["code"], ["whatever"]];
    for (const path of paths) expect(CATALOG[validationMessage({ path })]).toBeDefined();
    expect(CATALOG[validationMessage(undefined)]).toBeDefined();
  });
});

describe("reading the language from Accept-Language", () => {
  it.each([
    [undefined, "en"],
    ["", "en"],
    ["ru", "ru"],
    ["uz", "uz"],
    ["uz-Latn-UZ", "uz"],
    ["RU-ru", "ru"],
    ["de-DE,de;q=0.9", "en"],
    ["de-DE,ru;q=0.8,en;q=0.5", "ru"],
    ["en;q=0.4,uz;q=0.9", "uz"],
    ["ru;q=0", "en"],
    ["*", "en"],
  ])("%s → %s", (header, expected) => {
    expect(localeFrom(header as string | undefined)).toBe(expected);
  });
});

const sample: Alert = {
  id: "LGN-TEST1", tenant_id: "t", title: "SSH brute force on web-01", severity: "critical", agent: "Sentinel",
  status: "open", summary: "sshd: 40 failed logins", confidence: 91.6, created_at: new Date().toISOString(),
  ai_explanation: null, ai_explanation_locale: null, explained_at: null, source_ip: "198.51.100.4",
  target: "web-01", mitre_technique: "T1110", source: "wazuh",
};

describe("texts the server composes itself", () => {
  it("the no-AI explanation, per language, keeps the alert's own data", () => {
    const en = localExplanation(sample, "en");
    const ru = localExplanation(sample, "ru");
    const uz = localExplanation(sample, "uz");
    expect(en).toMatch(/^CRITICAL priority/);
    expect(ru).toMatch(/^Приоритет КРИТИЧЕСКИЙ/);
    expect(uz).toMatch(/^KRITIK ustuvorlik/);
    for (const text of [en, ru, uz]) {
      expect(text).toContain("SSH brute force on web-01");
      expect(text).toContain("198.51.100.4");
      expect(text).toContain("92%");
    }
  });

  it("suggested next steps go out as codes plus English text", () => {
    const codes = suggestedActions(sample);
    expect(codes.map((a) => a.code)).toEqual(["review_timeline", "validate_ownership", "block_source_ip", "reset_credentials", "escalate"]);
    for (const locale of LOCALES) {
      for (const a of codes) expect(actionText(a, locale).length).toBeGreaterThan(5);
    }
    expect(actionText({ code: "block_source_ip", ip: "10.0.0.9" }, "ru")).toContain("10.0.0.9");
  });

  it("Copilot's fallback answer, per language", () => {
    expect(copilotFallback([], undefined, "ru")).toMatch(/нет нерешённых оповещений/);
    expect(copilotFallback([sample], sample, "uz")).toMatch(/^Hal qilinmagan ogohlantirishlar: 1 ta/);
    expect(copilotFallback([sample], sample, "en")).toMatch(/^You have 1 unresolved alert/);
  });
});

describe("emails", () => {
  const all = (locale: "en" | "ru" | "uz") => [
    passwordResetEmail("https://legion.test/reset-password?token=abc", locale),
    verifyEmailEmail("https://legion.test/verify-email?token=abc", 24, locale),
    inviteEmail({ inviteUrl: "https://legion.test/accept-invite?token=abc", tenantName: "Acme", invitedBy: "boss@acme.example", role: "analyst", expiresDays: 7, locale }),
    alertEmail(sample, locale),
    { ...testNotificationEmail(locale), html: "" },
  ];

  it("each email exists in all three languages, with the link intact", () => {
    const en = all("en");
    for (const locale of ["ru", "uz"] as const) {
      all(locale).forEach((mail, i) => {
        expect(mail.subject).not.toBe(en[i]!.subject);
        expect(mail.text).not.toBe(en[i]!.text);
        for (const url of mail.text.match(/https?:\/\/\S+/g) ?? []) expect(mail.html || mail.text).toContain(url.replace(/&/g, "&amp;"));
      });
    }
  });

  it("Russian emails are in Russian, with correct plural forms", () => {
    const [reset, verify, invite, alert] = all("ru");
    expect(reset!.subject).toBe("Сброс пароля Legion");
    expect(verify!.text).toContain("действует 24 часа");
    expect(invite!.text).toContain("Роль: аналитик");
    expect(invite!.text).toContain("действует 7 дней");
    expect(alert!.subject).toBe("[Legion КРИТИЧЕСКИЙ] SSH brute force on web-01");
    expect(alert!.html).toContain('lang="ru"');
  });

  it("Uzbek emails are in Uzbek", () => {
    const [reset, verify, invite] = all("uz");
    expect(reset!.subject).toBe("Legion parolini tiklash");
    expect(verify!.text).toContain("24 soat amal qiladi");
    expect(invite!.text).toContain("Rolingiz: tahlilchi");
  });

  it("the alert's own title and summary are never translated", () => {
    for (const locale of LOCALES) {
      const mail = alertEmail(sample, locale);
      expect(mail.text).toContain("SSH brute force on web-01");
      expect(mail.text).toContain("sshd: 40 failed logins");
    }
  });
});

describe("the API answers in the requested language", () => {
  const PASSWORD = "a-good-password";
  let savedMode: typeof config.deploymentMode;

  beforeAll(async () => { await migrate(); savedMode = config.deploymentMode; config.deploymentMode = "saas"; });
  afterAll(async () => { config.deploymentMode = savedMode; await closePool(); });
  beforeEach(async () => { await truncateAll(); });
  afterEach(() => { vi.restoreAllMocks(); });

  /** Signs up in `locale`, confirms, signs in; returns the session cookie. */
  async function account(email: string, locale: string) {
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    const res = await request(app).post("/auth/register").set("Accept-Language", locale)
      .send({ email, password: PASSWORD, tenant_name: "Acme SOC" }).expect(201);
    const line = info.mock.calls.map((c) => String(c[0])).find((l) => l.includes("/verify-email?token="))!;
    info.mockRestore();
    const token = new URL(line.slice(line.indexOf("http"))).searchParams.get("token");
    await request(app).post("/auth/verify-email").send({ token }).expect(200);
    const login = await request(app).post("/auth/login").send({ username: email, password: PASSWORD }).expect(200);
    return { tenantId: res.body.tenant_id as string, cookie: login.headers["set-cookie"] as unknown as string[] };
  }

  it("error messages", async () => {
    const wrong = { username: "nobody@acme.example", password: "wrong-password" };
    expect((await request(app).post("/auth/login").send(wrong)).body.detail).toBe("Invalid email or password");
    expect((await request(app).post("/auth/login").set("Accept-Language", "ru").send(wrong)).body.detail).toBe("Неверный адрес эл. почты или пароль");
    expect((await request(app).post("/auth/login").set("Accept-Language", "uz").send(wrong)).body.detail).toBe("Email yoki parol noto'g'ri");
    expect((await request(app).get("/no-such-route").set("Accept-Language", "uz")).body.detail).toBe("Topilmadi");
  });

  it("form validation errors", async () => {
    const res = await request(app).post("/auth/register").set("Accept-Language", "ru")
      .send({ email: "not-an-email", password: PASSWORD, tenant_name: "Acme" }).expect(422);
    expect(res.body.detail).toBe("Введите корректный адрес эл. почты");
  });

  it("machine-readable fields stay as they are", async () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    await request(app).post("/auth/register").send({ email: "wait@acme.example", password: PASSWORD, tenant_name: "Acme" }).expect(201);
    info.mockRestore();
    const res = await request(app).post("/auth/login").set("Accept-Language", "uz").send({ username: "wait@acme.example", password: PASSWORD }).expect(403);
    expect(res.body.code).toBe("email_unverified");
    expect(res.body.detail).toMatch(/emailingizni tasdiqlang/);
  });

  it("the verification email goes out in the sign-up language, and alert emails default to it", async () => {
    const sent: string[] = [];
    const info = vi.spyOn(console, "info").mockImplementation((line: unknown) => { sent.push(String(line)); });
    const res = await request(app).post("/auth/register").set("Accept-Language", "uz")
      .send({ email: "uz@acme.example", password: PASSWORD, tenant_name: "Toshkent SOC" }).expect(201);
    info.mockRestore();
    expect(sent.some((l) => l.includes("/verify-email?token="))).toBe(true);
    expect((await store.getTenant(res.body.tenant_id))!.notification_locale).toBe("uz");
  });

  it("the no-AI explanation is written in the reader's language and redone for another one", async () => {
    const { tenantId, cookie } = await account("analyst@acme.example", "en");
    await outbox.insertAlertAndNotify({ ...sample, tenant_id: tenantId, ai_explanation: null, explained_at: null });

    const ru = await request(app).post(`/alerts/${sample.id}/explain`).set("Cookie", cookie).set("Accept-Language", "ru").expect(200);
    expect(ru.body.ai_explanation).toMatch(/^Приоритет КРИТИЧЕСКИЙ/);
    expect(ru.body.ai_explanation_locale).toBe("ru");
    expect(ru.body.suggested_action_codes.map((a: { code: string }) => a.code)).toContain("block_source_ip");
    expect(ru.body.suggested_actions[0]).toBe("Review event timeline");

    // Same language again: the stored one is reused, not regenerated.
    const again = await request(app).post(`/alerts/${sample.id}/explain`).set("Cookie", cookie).set("Accept-Language", "ru").expect(200);
    expect(again.body.explained_at).toBe(ru.body.explained_at);

    const uz = await request(app).post(`/alerts/${sample.id}/explain`).set("Cookie", cookie).set("Accept-Language", "uz").expect(200);
    expect(uz.body.ai_explanation).toMatch(/^KRITIK ustuvorlik/);
    expect(uz.body.ai_explanation_locale).toBe("uz");
  });

  it("Copilot answers in the reader's language when no AI is configured", async () => {
    const { cookie } = await account("copilot@acme.example", "en");
    const res = await request(app).post("/copilot/chat").set("Cookie", cookie).set("Accept-Language", "ru")
      .send({ message: "Что происходит?" }).expect(200);
    expect(res.body.source).toBe("local");
    expect(res.body.reply).toMatch(/нет нерешённых оповещений/);
  });

  it("alert emails use the organisation's chosen language", async () => {
    const saved = { host: config.smtpHost, min: config.alertEmailMinSeverity };
    config.smtpHost = "smtp.test.invalid";
    config.alertEmailMinSeverity = "high";
    try {
      const { tenantId, cookie } = await account("admin@acme.example", "en");
      const set = await request(app).patch("/notifications/settings").set("Cookie", cookie)
        .send({ notification_email: "soc@acme.example", notification_locale: "ru" }).expect(200);
      expect(set.body.notification_locale).toBe("ru");
      expect((await request(app).get("/notifications/settings").set("Cookie", cookie)).body.notification_locale).toBe("ru");
      // A new address is only pending until its owner confirms it (see
      // notification-confirmation.test.ts); this test is about the language.
      await query("UPDATE tenants SET notification_email = 'soc@acme.example' WHERE id = $1", [tenantId]);

      await outbox.insertAlertAndNotify({ ...sample, id: "LGN-MAIL1", tenant_id: tenantId, ai_explanation: null, explained_at: null });
      const row = (await query("SELECT payload FROM notification_outbox WHERE tenant_id = $1", [tenantId])).rows[0];
      expect(row.payload.subject).toBe("[Legion КРИТИЧЕСКИЙ] SSH brute force on web-01");

      await request(app).patch("/notifications/settings").set("Cookie", cookie)
        .send({ notification_email: "soc@acme.example", notification_locale: "fr" }).expect(422);
    } finally {
      config.smtpHost = saved.host;
      config.alertEmailMinSeverity = saved.min;
    }
  });
});
