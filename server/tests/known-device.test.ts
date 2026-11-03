/**
 * The known-device priority budget (known-device.ts): a cookie — stolen, or
 * minted by an attacker for their own account — buys at most a few priority
 * sign-ins a minute for the account it names, then nothing.
 */
import { describe, expect, it } from "vitest";
import { PRIORITY_PER_MINUTE, issueDeviceToken, knownDevicePriority } from "../src/known-device.js";
import { signToken } from "../src/auth-jwt.js";

describe("known-device priority", () => {
  it("holds for the named account only, up to the per-minute budget", () => {
    const token = issueDeviceToken("user-a");
    expect(knownDevicePriority(token, "user-b")).toBe(false);
    const granted = Array.from({ length: PRIORITY_PER_MINUTE + 5 }, () => knownDevicePriority(token, "user-a")).filter(Boolean).length;
    expect(granted).toBe(PRIORITY_PER_MINUTE);
  });

  it("is not granted by a token minted for another purpose, or by garbage", () => {
    const access = signToken("access", { sub: "user-c" }, "15m");
    const mfa = signToken("mfa", { sub: "user-c", purpose: "mfa" }, "5m");
    for (const raw of [access, mfa, "", "x", undefined, 42, `${issueDeviceToken("user-c")}x`]) {
      expect(knownDevicePriority(raw, "user-c")).toBe(false);
    }
    expect(knownDevicePriority(issueDeviceToken("user-c"), "user-c")).toBe(true);
  });
});
