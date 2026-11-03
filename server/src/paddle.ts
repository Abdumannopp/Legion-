import { createHmac, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";

/**
 * Verifies a Paddle Billing webhook.
 *
 * Paddle signs `${ts}:${rawBody}` with HMAC-SHA256 using the notification
 * destination's secret. The RAW bytes matter — re-serialising the parsed JSON
 * produces different bytes and the signature will never match.
 *
 * Header format: `ts=1671552777;h1=<64 hex chars>`
 */
export function verifyPaddleSignature(
  header: string | undefined,
  rawBody: Buffer | undefined,
  secret: string,
  maxAgeSeconds = 300
): { ok: true } | { ok: false; reason: string } {
  if (!secret) return { ok: false, reason: "Paddle webhook secret is not configured" };
  if (!header) return { ok: false, reason: "Missing Paddle-Signature header" };
  if (!rawBody) return { ok: false, reason: "Raw request body unavailable" };

  const parts = new Map<string, string>();
  for (const segment of header.split(";")) {
    const index = segment.indexOf("=");
    if (index > 0) parts.set(segment.slice(0, index).trim(), segment.slice(index + 1).trim());
  }

  const ts = parts.get("ts");
  const h1 = parts.get("h1");
  if (!ts || !h1) return { ok: false, reason: "Malformed Paddle-Signature header" };

  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!Number.isFinite(age) || age > maxAgeSeconds) {
    return { ok: false, reason: "Signature timestamp outside tolerance" };
  }

  const expected = createHmac("sha256", secret)
    .update(`${ts}:${rawBody.toString("utf8")}`)
    .digest("hex");

  // Length check first: timingSafeEqual throws on mismatched lengths.
  if (h1.length !== expected.length) return { ok: false, reason: "Invalid signature" };
  if (!timingSafeEqual(Buffer.from(h1), Buffer.from(expected))) {
    return { ok: false, reason: "Invalid signature" };
  }
  return { ok: true };
}

export function paddleConfigured(): boolean {
  return Boolean(config.paddleApiKey);
}

async function paddleRequest<T>(
  path: string,
  init: { method: string; body?: unknown }
): Promise<{ ok: true; data: T } | { ok: false; status: number; detail: string }> {
  if (!paddleConfigured()) {
    return { ok: false, status: 503, detail: "Paddle is not configured" };
  }
  try {
    const response = await fetch(`${config.paddleApiBase}${path}`, {
      method: init.method,
      headers: {
        Authorization: `Bearer ${config.paddleApiKey}`,
        "Content-Type": "application/json",
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      // The API key rides in the Authorization header: never follow a redirect
      // with it, and never wait on the billing API indefinitely.
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
    const payload = (await response.json().catch(() => ({}))) as {
      data?: T;
      error?: { detail?: string };
    };
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        detail: payload.error?.detail || `Paddle API returned ${response.status}`,
      };
    }
    return { ok: true, data: payload.data as T };
  } catch (error) {
    // Transport errors name hosts, addresses and TLS details: they go to the
    // server log, and the tenant administrator gets a fixed sentence.
    console.error("Legion: Paddle API request failed:", error instanceof Error ? error.name : "unknown error");
    return { ok: false, status: 502, detail: "Could not reach the billing provider. Try again later." };
  }
}

interface PortalSession {
  urls?: { general?: { overview?: string } };
}

/** Creates a short-lived authenticated link into Paddle's hosted portal.
 *  Sessions are single-use — never cache the URL. */
export async function createPortalSession(
  customerId: string,
  subscriptionIds: string[]
): Promise<{ ok: true; url: string } | { ok: false; status: number; detail: string }> {
  const result = await paddleRequest<PortalSession>(
    `/customers/${encodeURIComponent(customerId)}/portal-sessions`,
    { method: "POST", body: subscriptionIds.length ? { subscription_ids: subscriptionIds } : {} }
  );
  if (!result.ok) return result;
  const url = result.data?.urls?.general?.overview;
  if (!url) {
    return { ok: false, status: 502, detail: "Paddle did not return a portal URL" };
  }
  return { ok: true, url };
}
