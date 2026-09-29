/**
 * Throttling for the sensor webhook's UNAUTHENTICATED side.
 *
 * The webhook is exempt from the general API limiter on purpose: a busy SOC
 * sends more events per minute than any dashboard limit would allow, and
 * throttling signed telemetry would drop it. But that exemption used to apply
 * before authentication too, so anyone could make every request cost a JSON
 * parse, a database lookup and an HMAC — an unmetered way to exhaust the
 * database pool for every tenant.
 *
 * Only FAILED attempts are counted, per client address. The check happens
 * before the body is even read, so a refused client costs nothing but a map
 * lookup. A sender whose requests are correctly signed never accumulates a
 * count, however many it sends. In-process (bounded, see bounded-counter.ts):
 * the point is to protect each instance's own pool.
 */
import type { NextFunction, Request, Response } from "express";
import { BoundedCounter } from "./bounded-counter.js";
import { config } from "./config.js";

const WINDOW_MS = 60_000;
const failures = new BoundedCounter(WINDOW_MS, config.rateLimitMaxKeys);

/** Responses that count as a failed attempt: refused credentials, bad bodies, oversize. */
const FAILURE = new Set([400, 401, 413, 415]);

/** Same convention as ratelimit.ts: off under NODE_ENV=test unless a test of the limiter turns it on. */
const bypassed = () => process.env.NODE_ENV === "test" && process.env.LEGION_ENFORCE_RATE_LIMITS !== "1";

export function webhookFailureGate(req: Request, res: Response, next: NextFunction): void {
  if (bypassed()) return next();
  const who = req.ip || req.socket.remoteAddress || "unknown";
  if (failures.peek(who) >= config.webhookFailedAuthPerMinute) {
    res.setHeader("Retry-After", String(Math.ceil(WINDOW_MS / 1000)));
    // Drain nothing: the connection is closed after this short answer, so an
    // attacker cannot make the server read a large body it will not use.
    res.setHeader("Connection", "close");
    res.status(429).json({ detail: "Too many failed webhook authentications from this address. Try again later." });
    return;
  }
  res.on("finish", () => {
    if (FAILURE.has(res.statusCode)) failures.increment(who);
  });
  next();
}

/** Tests only. */
export function resetWebhookFailures(): void {
  failures.clear();
}
