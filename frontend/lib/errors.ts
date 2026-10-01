/**
 * Turns any failure into what a person needs: what happened, why, and what
 * they can do next — in their language. The server's own message (already
 * translated) is kept as the detail; the explanation comes from the status
 * and code, so it is right even for messages the dashboard has never seen.
 */
import { ApiError } from "@/lib/api";
import type { translations } from "@/lib/i18n/translations";

type T = (typeof translations)["en"];

export interface Explained {
  title: string;
  /** The server's own words, when it said something more specific. */
  detail: string | null;
  why: string;
  next: string;
  action?: { label: string; href: string };
  /** Whether trying again can help (network, rate limit, server trouble). */
  retryable: boolean;
}

export function describeError(err: unknown, t: T, opts: { isAdmin?: boolean } = {}): Explained {
  const e = t.errors;
  if (!(err instanceof ApiError)) {
    // A failure the dashboard itself described (already in the reader's language).
    const detail = err instanceof Error && err.message ? err.message : null;
    return { title: e.unknown.title, detail, why: e.unknown.why, next: e.unknown.next, retryable: true };
  }
  const detail = err.message && err.status !== 0 ? err.message : null;
  const base = (k: { title: string; why: string; next: string }, retryable = false): Explained => ({ title: k.title, detail, why: k.why, next: k.next, retryable });

  if (err.status === 0 || err.code === "network") return { ...base(e.network, true), detail: null };
  if (err.status === 401) return { ...base(e.session), action: { label: e.session.action, href: "/login" } };
  if (err.status === 402) {
    const k = err.code === "subscription_past_due" || err.data?.access_state === "readonly" ? e.pastDue : e.plan;
    return {
      title: k.title, detail, why: k.why, next: opts.isAdmin ? k.nextAdmin : k.nextMember, retryable: false,
      ...(opts.isAdmin ? { action: { label: k.action, href: "/billing" } } : {}),
    };
  }
  if (err.status === 421 || err.code === "wrong_region") {
    const url = typeof err.data?.region_url === "string" ? err.data.region_url : null;
    return { ...base(e.region), ...(url ? { action: { label: e.region.action, href: url } } : {}) };
  }
  if (err.status === 403) return base(e.forbidden);
  if (err.status === 404) return base(e.notFound);
  if (err.status === 409) return base(e.conflict);
  if (err.status === 400 || err.status === 422) return base(e.invalid);
  // Sign-in is busy (password hashing saturated on the server): a short wait, not a fault.
  if (err.status === 429 || err.code === "auth_busy") {
    return { ...base(e.rateLimited, true), next: err.retryAfter ? e.rateLimited.nextSeconds(err.retryAfter) : e.rateLimited.next };
  }
  if (err.status >= 500) return base(e.server, true);
  return base(e.unknown, true);
}
