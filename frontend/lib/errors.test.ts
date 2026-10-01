import { describe, expect, it } from "vitest";
import { ApiError } from "./api";
import { describeError } from "./errors";
import { formatMoney } from "./i18n/format";
import { translations } from "./i18n/translations";

const en = translations.en;

describe("every important error says what happened, why, and what to do next", () => {
  const cases: [string, unknown, string][] = [
    ["network", new ApiError("offline", 0, "network"), en.errors.network.title],
    ["session", new ApiError("Not authenticated", 401), en.errors.session.title],
    ["plan", new ApiError("No active subscription", 402, "subscription_inactive"), en.errors.plan.title],
    ["past due", new ApiError("Past due", 402, "subscription_past_due"), en.errors.pastDue.title],
    ["region", new ApiError("Hosted elsewhere", 421, "wrong_region", { region_url: "https://eu.example.com" }), en.errors.region.title],
    ["forbidden", new ApiError("Admins only", 403), en.errors.forbidden.title],
    ["not found", new ApiError("No such identity.", 404), en.errors.notFound.title],
    ["conflict", new ApiError("Already revoked", 409), en.errors.conflict.title],
    ["invalid", new ApiError("say why", 400), en.errors.invalid.title],
    ["rate limited", new ApiError("Slow down", 429), en.errors.rateLimited.title],
    ["server", new ApiError("boom", 503), en.errors.server.title],
    ["unknown", new TypeError("x is undefined"), en.errors.unknown.title],
  ];
  for (const [name, err, title] of cases) {
    it(name, () => {
      const x = describeError(err, en);
      expect(x.title).toBe(title);
      expect(x.why.length).toBeGreaterThan(10);
      expect(x.next.length).toBeGreaterThan(10);
    });
  }

  it("keeps the server's own words as the detail", () => {
    expect(describeError(new ApiError("No such identity.", 404), en).detail).toBe("No such identity.");
  });

  it("offers the one action that helps", () => {
    expect(describeError(new ApiError("x", 401), en).action?.href).toBe("/login");
    expect(describeError(new ApiError("x", 402, "subscription_inactive"), en, { isAdmin: true }).action?.href).toBe("/billing");
    // A member can't pay; they are told who can.
    const member = describeError(new ApiError("x", 402, "subscription_inactive"), en, { isAdmin: false });
    expect(member.action).toBeUndefined();
    expect(member.next).toBe(en.errors.plan.nextMember);
    expect(describeError(new ApiError("x", 421, "wrong_region", { region_url: "https://eu.example.com" }), en).action?.href).toBe("https://eu.example.com");
  });

  it("a busy sign-in (503 auth_busy) is a short wait, not 'something went wrong'", () => {
    const x = describeError(new ApiError("busy", 503, "auth_busy", undefined, 2), en);
    expect(x.title).toBe(en.errors.rateLimited.title);
    expect(x.next).toBe(en.errors.rateLimited.nextSeconds(2));
    expect(x.retryable).toBe(true);
  });

  it("says how long to wait when the server said", () => {
    expect(describeError(new ApiError("x", 429, undefined, undefined, 30), en).next).toBe(en.errors.rateLimited.nextSeconds(30));
  });

  it("marks only the failures a retry can fix as retryable", () => {
    expect(describeError(new ApiError("x", 0, "network"), en).retryable).toBe(true);
    expect(describeError(new ApiError("x", 503), en).retryable).toBe(true);
    expect(describeError(new ApiError("x", 403), en).retryable).toBe(false);
    expect(describeError(new ApiError("x", 400), en).retryable).toBe(false);
  });

  it("explains in every language", () => {
    for (const locale of ["ru", "uz"] as const) {
      const x = describeError(new ApiError("x", 403), translations[locale]);
      expect(x.title).toBe(translations[locale].errors.forbidden.title);
      expect(x.title).not.toBe(en.errors.forbidden.title);
    }
  });
});

describe("money in the viewer's language", () => {
  it("formats minor units with the currency's own decimals", () => {
    expect(formatMoney(2900, "USD", "en")).toBe("$29.00");
    expect(formatMoney(2900, "eur", "en")).toBe("€29.00");
    // Yen has no minor unit.
    expect(formatMoney(2900, "JPY", "en")).toBe("¥2,900");
  });

  it("follows the language's conventions", () => {
    const ru = formatMoney(2900, "USD", "ru");
    expect(ru).toMatch(/29,00/);
    expect(ru).toMatch(/\$/);
  });

  it("falls back to number and code for an unknown currency", () => {
    expect(formatMoney(2900, "ZZ", "en")).toBe("29 ZZ");
  });
});
