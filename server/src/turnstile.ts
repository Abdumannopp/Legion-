/**
 * Cloudflare Turnstile: "is this a person?" before the endpoints a botnet
 * would flood — sign-in (each attempt costs a password hash), sign-up, password
 * reset and resend-verification (each may send an email).
 *
 * Off unless TURNSTILE_SECRET_KEY is set. When on, a request must carry the
 * token the widget produced (`turnstile_token` in the JSON body, or the
 * `cf-turnstile-response` header), and Cloudflare must confirm it
 * (https://developers.cloudflare.com/turnstile/get-started/server-side-validation/).
 * A token is single-use, so the dashboard asks for a fresh one per attempt.
 *
 * Fails closed: if Cloudflare cannot be asked, the request is refused (503),
 * never waved through — the check exists for the moment someone is attacking.
 * The rest of the API is unaffected, and per-address / per-account limits run
 * before this check, so it is never the only control.
 *
 * Bounded: at most MAX_IN_FLIGHT verifications wait on Cloudflare at once and
 * each gives up after TIMEOUT_MS, so a flood of forged tokens costs a bounded
 * number of outbound requests, not an unbounded queue.
 */
import type { NextFunction, Request, Response } from "express";
import { config } from "./config.js";

const MAX_IN_FLIGHT = 256;
const TIMEOUT_MS = 5_000;
/** Turnstile tokens are at most 2048 characters. */
const MAX_TOKEN = 2048;
let inFlight = 0;
let lastWarning = 0;

export type Verdict = "ok" | "missing" | "failed" | "unavailable";

export function captchaEnabled(): boolean {
  return Boolean(config.turnstileSecretKey);
}

function warn(reason: string): void {
  const now = Date.now();
  if (now - lastWarning < 60_000) return;
  lastWarning = now;
  console.warn(`Legion: Turnstile verification unavailable (${reason}); sign-in and sign-up are refused until it recovers`);
}

/** Asks Cloudflare whether `token` is a valid, unused challenge solution. */
export async function verifyTurnstile(token: unknown, remoteIp?: string): Promise<Verdict> {
  if (typeof token !== "string" || token.length === 0) return "missing";
  if (token.length > MAX_TOKEN) return "failed";
  if (inFlight >= MAX_IN_FLIGHT) { warn("too many verifications in flight"); return "unavailable"; }
  inFlight++;
  try {
    const body = new URLSearchParams({ secret: config.turnstileSecretKey, response: token });
    if (remoteIp) body.set("remoteip", remoteIp);
    // A redirect is never followed: the secret key must only ever reach the configured URL.
    const res = await fetch(config.turnstileVerifyUrl, { method: "POST", body, redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MS) });
    if (!res.ok) { warn(`HTTP ${res.status}`); return "unavailable"; }
    const data = (await res.json()) as { success?: unknown; "error-codes"?: unknown };
    if (data.success === true) return "ok";
    const codes = Array.isArray(data["error-codes"]) ? data["error-codes"].map(String) : [];
    // Our own configuration, or Cloudflare's: not the visitor's fault, and not fixable by them.
    if (codes.some((c) => c === "missing-input-secret" || c === "invalid-input-secret" || c === "internal-error")) {
      warn(codes.join(","));
      return "unavailable";
    }
    return "failed";
  } catch (error) {
    warn(error instanceof Error ? error.name : "network error");
    return "unavailable";
  } finally {
    inFlight--;
  }
}

/** Express middleware for the endpoints above. A no-op while Turnstile is off. */
export async function requireHuman(req: Request, res: Response, next: NextFunction): Promise<void> {
  if (!captchaEnabled()) return next();
  const token = (req.body as { turnstile_token?: unknown } | undefined)?.turnstile_token ?? req.header("cf-turnstile-response");
  const verdict = await verifyTurnstile(token, req.ip);
  if (verdict === "ok") return next();
  if (verdict === "unavailable") {
    res.setHeader("Retry-After", "5");
    res.status(503).json({ detail: "The security check is temporarily unavailable. Try again in a moment.", code: "captcha_unavailable" });
    return;
  }
  res.status(400).json(verdict === "missing"
    ? { detail: "Complete the security check and try again.", code: "captcha_required" }
    : { detail: "The security check failed or expired. Complete it again.", code: "captcha_failed" });
}
