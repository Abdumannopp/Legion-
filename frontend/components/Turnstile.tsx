"use client";

/**
 * Cloudflare Turnstile on the sign-in, sign-up, setup and password-reset forms.
 *
 * Shown only when the dashboard was built with NEXT_PUBLIC_TURNSTILE_SITE_KEY;
 * the API must then have the matching TURNSTILE_SECRET_KEY (server/src/turnstile.ts).
 * The CSP allows challenges.cloudflare.com only in that case (lib/csp.ts).
 *
 * A token is single-use: call `reset()` after every request that sent one,
 * successful or not, and the widget produces a fresh one (usually without the
 * person doing anything).
 */
import { useCallback, useEffect, useState } from "react";
import { useLanguage } from "@/lib/i18n/LanguageContext";

const SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || "";
const SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

interface TurnstileApi {
  render(el: HTMLElement, opts: Record<string, unknown>): string;
  reset(id?: string): void;
  remove(id: string): void;
}
declare global {
  interface Window { turnstile?: TurnstileApi }
}

let loading: Promise<TurnstileApi> | null = null;
function loadTurnstile(): Promise<TurnstileApi> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  loading ??= new Promise<TurnstileApi>((resolve, reject) => {
    // Inserted by our own (nonce-trusted) code, so 'strict-dynamic' lets it run.
    const s = document.createElement("script");
    s.src = SCRIPT;
    s.async = true;
    s.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error("turnstile")));
    s.onerror = () => { loading = null; reject(new Error("turnstile")); };
    document.head.appendChild(s);
  });
  return loading;
}

export interface Captcha {
  /** False when the dashboard has no site key: forms behave exactly as before. */
  enabled: boolean;
  /** The current token, or null while the challenge is unsolved / used up. */
  token: string | null;
  /** True when a request may be sent (solved, or Turnstile not in use). */
  ready: boolean;
  /** The widget could not load or errored (blocked script, no network). */
  failed: boolean;
  /** Discards the used token and asks the widget for a new one. */
  reset: () => void;
  /** Place this where the widget should appear (null when disabled). */
  element: React.ReactNode;
}

export function useTurnstile(action: "login" | "signup" | "setup" | "reset" | "resend"): Captcha {
  const { locale } = useLanguage();
  const [container, setContainer] = useState<HTMLDivElement | null>(null);
  const [widgetId, setWidgetId] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!SITE_KEY || !container) return;
    let id: string | null = null;
    let cancelled = false;
    loadTurnstile()
      .then((ts) => {
        if (cancelled) return;
        id = ts.render(container, {
          sitekey: SITE_KEY,
          action,
          language: locale,
          theme: "auto",
          callback: (t: string) => { setToken(t); setFailed(false); },
          "expired-callback": () => setToken(null),
          "error-callback": () => { setToken(null); setFailed(true); },
        });
        setWidgetId(id);
      })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => {
      cancelled = true;
      setToken(null);
      if (id && window.turnstile) window.turnstile.remove(id);
    };
  }, [container, action, locale]);

  const reset = useCallback(() => {
    setToken(null);
    if (widgetId && window.turnstile) window.turnstile.reset(widgetId);
  }, [widgetId]);

  return {
    enabled: Boolean(SITE_KEY),
    token,
    ready: !SITE_KEY || Boolean(token),
    failed,
    reset,
    element: SITE_KEY ? <div ref={setContainer} className="flex justify-center min-h-[65px]" /> : null,
  };
}
