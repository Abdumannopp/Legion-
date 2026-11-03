import { describe, expect, it } from "vitest";
import { compareAlerts, sortAlerts, upsertAlert } from "./alert-feed";

const a = (id: string, seq: number, created_at: string, extra: object = {}) => ({ id, seq, created_at, ...extra });

describe("order: newest first by created_at, arrival order among equals", () => {
  it("sorts by time, newest first", () => {
    const list = sortAlerts([a("old", 1, "2026-09-29T10:00:00.000Z"), a("new", 2, "2026-09-29T12:00:00.000Z"), a("mid", 3, "2026-09-29T11:00:00.000Z")]);
    expect(list.map((x) => x.id)).toEqual(["new", "mid", "old"]);
  });

  it("breaks a tie by seq, so two alerts in the same millisecond order the same on every client", () => {
    const t = "2026-09-29T10:00:00.000Z";
    expect(sortAlerts([a("first", 5, t), a("second", 6, t)]).map((x) => x.id)).toEqual(["second", "first"]);
    expect(compareAlerts(a("x", 6, t), a("y", 5, t))).toBeLessThan(0);
  });

  it("does not throw on a malformed date", () => {
    expect(() => sortAlerts([a("x", 1, "not a date"), a("y", 2, "2026-09-29T10:00:00.000Z")])).not.toThrow();
  });
});

describe("upsertAlert", () => {
  const base = sortAlerts([a("c", 3, "2026-09-29T12:00:03.000Z"), a("b", 2, "2026-09-29T12:00:02.000Z"), a("a", 1, "2026-09-29T12:00:01.000Z")]);

  it("inserts an unknown alert where it belongs, whatever order things arrive in", () => {
    const out = upsertAlert(base, a("d", 4, "2026-09-29T12:00:04.000Z"));
    expect(out.map((x) => x.id)).toEqual(["d", "c", "b", "a"]);
    // late arrival of an alert created between two others
    const mid = upsertAlert(base, a("bc", 9, "2026-09-29T12:00:02.500Z"));
    expect(mid.map((x) => x.id)).toEqual(["c", "bc", "b", "a"]);
  });

  it("replaces a known alert with a newer version, in place", () => {
    const out = upsertAlert(base, a("b", 7, "2026-09-29T12:00:02.000Z", { status: "resolved" }));
    expect(out.map((x) => x.id)).toEqual(["c", "b", "a"]);
    expect((out[1] as { status?: string }).status).toBe("resolved");
  });

  it("ignores a duplicate or an older version, returning the very same list", () => {
    expect(upsertAlert(base, a("b", 2, "2026-09-29T12:00:02.000Z"))).toBe(base);
    expect(upsertAlert(base, a("b", 1, "2026-09-29T12:00:02.000Z", { status: "resolved" }))).toBe(base);
  });

  it("never adds an alert the list does not have when told not to (an update to something filtered out)", () => {
    expect(upsertAlert(base, a("zzz", 50, "2026-09-29T13:00:00.000Z"), { insert: false })).toBe(base);
  });

  it("does not mutate its input", () => {
    const copy = JSON.stringify(base);
    upsertAlert(base, a("d", 4, "2026-09-29T12:00:04.000Z"));
    upsertAlert(base, a("b", 9, "2026-09-29T12:00:02.000Z"));
    expect(JSON.stringify(base)).toBe(copy);
  });
});
