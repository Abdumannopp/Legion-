/**
 * Known devices: who goes first when sign-in is flooded.
 *
 * A flood of sign-in guesses from many addresses can fill the password-hashing
 * queue (passwords.ts), and then every sign-in is refused with 503 — per-address
 * limits cannot tell a botnet from a crowd. A browser that has completed a
 * sign-in to an account (both factors) gets a signed cookie naming that
 * account; its next sign-in TO THE SAME ACCOUNT is served from the priority
 * lane, which the flood cannot fill.
 *
 * The cookie grants nothing else: it is not a session, skips no check, and the
 * password is still verified in full. It survives logout on purpose (it means
 * "this browser has signed in here before"). A stolen or self-made cookie only
 * speeds up sign-ins to its own account, at most PRIORITY_PER_MINUTE of them
 * per account and instance; past that, they queue like everyone else.
 */
import { signToken, verifyTokenOf } from "./auth-jwt.js";
import { BoundedCounter } from "./bounded-counter.js";
import { config } from "./config.js";

export const DEVICE_COOKIE = "legion_device";
const DEVICE_DAYS = 90;
export const DEVICE_MAX_AGE_MS = DEVICE_DAYS * 86_400_000;
export const PRIORITY_PER_MINUTE = 10;

const used = new BoundedCounter(60_000, config.rateLimitMaxKeys);

export function issueDeviceToken(userId: string): string {
  return signToken("device", { sub: userId }, `${DEVICE_DAYS}d`);
}

/** True when `raw` is a valid device token for `userId` and the account's priority budget is not spent. */
export function knownDevicePriority(raw: unknown, userId: string): boolean {
  const claims = typeof raw === "string" ? verifyTokenOf("device", raw) : null;
  if (!claims || claims.sub !== userId) return false;
  return used.increment(userId).totalHits <= PRIORITY_PER_MINUTE;
}
