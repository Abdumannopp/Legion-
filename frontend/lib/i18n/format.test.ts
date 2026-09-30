import { afterEach, describe, expect, it } from "vitest";
import { formatDate, formatDateTime, formatTime, setDisplaySettings } from "./format";

const moment = "2026-09-30T22:15:00Z";

afterEach(() => setDisplaySettings({ timeZone: undefined, dateFormat: "locale", timeFormat: "locale" }));

describe("presentation settings", () => {
  it("a chosen time zone moves the calendar day and the clock", () => {
    setDisplaySettings({ timeZone: "Asia/Tashkent", dateFormat: "YYYY-MM-DD", timeFormat: "24h" });
    expect(formatDate(moment, "en")).toBe("2026-10-01");
    expect(formatTime(moment, "en")).toBe("03:15");
    setDisplaySettings({ timeZone: "America/New_York" });
    expect(formatDateTime(moment, "en")).toBe("2026-09-30, 18:15");
  });

  it("fixed date formats, in any language", () => {
    setDisplaySettings({ timeZone: "UTC" });
    for (const [f, want] of [["DD.MM.YYYY", "30.09.2026"], ["DD/MM/YYYY", "30/09/2026"], ["MM/DD/YYYY", "09/30/2026"]] as const) {
      setDisplaySettings({ dateFormat: f });
      expect(formatDate(moment, "ru")).toBe(want);
      expect(formatDate(moment, "uz")).toBe(want);
    }
  });

  it("12-hour time when chosen; the language's own style by default", () => {
    setDisplaySettings({ timeZone: "UTC", timeFormat: "12h" });
    expect(formatTime(moment, "en")).toMatch(/^10:15\sPM$/);
    setDisplaySettings({ timeFormat: "locale" });
    expect(formatDate(moment, "en")).toBe("Sep 30, 2026");
    expect(formatDate(moment, "uz")).toBe("2026-yil 30-sentabr");
  });
});
