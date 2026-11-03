// frontend/hooks/useRealtimeAlerts.ts
"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, WS_URL, getAlertSync } from "@/lib/api";
import { AlertSyncClient, type FeedEvent, type SocketLike, type SyncState } from "@/lib/realtime/alert-sync";
import { useLanguage } from "@/lib/i18n/LanguageContext";

export type RealtimeEvent = FeedEvent<Alert>;

/** Desktop notifications for missed alerts: a few individually, then one summary. */
const MAX_INDIVIDUAL_NOTIFICATIONS = 3;

/** Fires a desktop notification, but never lets a Notification failure
 *  escape into the socket's message handler. */
function notify(title: string, body: string, tag: string): void {
  try {
    if (typeof Notification === "undefined") return;
    if (Notification.permission !== "granted") return;
    // `tag` makes several open tabs show one notification per alert, not one each.
    new Notification(title, { body, icon: "/icon.png", tag });
  } catch {
    // Notifications are best-effort; a failure here must not break realtime.
  }
}

/**
 * The live alert feed.
 *
 * The WebSocket only says "something changed" (and carries a copy of it); the
 * database is the source of truth, and the client keeps a cursor into it and
 * asks for whatever it is missing — on connect, on reconnect, after a Redis or
 * server restart, when the tab returns to the foreground, and on a timer. All of
 * that lives in lib/realtime/alert-sync.ts, which has no React in it so it can be
 * tested on its own; this hook only connects it to the page.
 *
 * Usage: load the list with getAlertFeed(), show it, and pass the cursor that came
 * with it to `setBaseline`. Events then arrive through `onEvent`, already
 * de-duplicated, in order of version, and only for changes the list does not
 * already contain. `onReset` is called if the client has fallen so far behind
 * that it must reload the list (and call `setBaseline` again).
 *
 * Authentication: exactly one method — the httpOnly `legion_token` cookie,
 * which the browser attaches to the upgrade request automatically because the
 * API is same-site. We deliberately do NOT append a `?token=` query param: the
 * JWT would then land in access logs, proxy logs and browser history.
 */
export function useRealtimeAlerts(
  onEvent?: (event: RealtimeEvent) => void,
  onReset?: () => void | Promise<void>
) {
  const { t } = useLanguage();
  const [newAlerts, setNewAlerts] = useState<Alert[]>([]);
  const [state, setState] = useState<SyncState>({ connected: false, syncing: false, cursor: 0, ready: false, lastSyncAt: null, lastError: null });

  // Kept in refs so a caller passing inline callbacks doesn't tear down and
  // re-open the socket on every render.
  const onEventRef = useRef(onEvent);
  const onResetRef = useRef(onReset);
  useEffect(() => {
    onEventRef.current = onEvent;
    onResetRef.current = onReset;
  }, [onEvent, onReset]);

  const clientRef = useRef<AlertSyncClient<Alert> | null>(null);
  /** A baseline set before the client exists (the list can load first). */
  const pendingBaseline = useRef<number | null>(null);

  useEffect(() => {
    const client = new AlertSyncClient<Alert>({
      connect: () => new WebSocket(`${WS_URL}/ws/alerts`) as unknown as SocketLike,
      fetchSync: (after, signal) => getAlertSync(after, signal),
      onEvent: (event) => {
        if (event.type === "new_alert") {
          const alert = event.alert;
          // Newest change first. The client already drops duplicates; this guard
          // covers the same alert being re-listed after a dismiss.
          setNewAlerts((prev) => (prev.some((a) => a.id === alert.id) ? prev : [alert, ...prev].sort((a, b) => b.seq - a.seq)));
        }
        onEventRef.current?.(event);
      },
      onReset: () => onResetRef.current?.(),
      onState: setState,
      isVisible: () => typeof document === "undefined" || document.visibilityState === "visible",
      subscribeVisibility: (cb) => {
        document.addEventListener("visibilitychange", cb);
        return () => document.removeEventListener("visibilitychange", cb);
      },
      subscribeOnline: (cb) => {
        window.addEventListener("online", cb);
        return () => window.removeEventListener("online", cb);
      },
    });
    clientRef.current = client;
    client.start();
    if (pendingBaseline.current !== null) client.setBaseline(pendingBaseline.current);
    return () => {
      client.stop();
      clientRef.current = null;
    };
  }, []);

  // Desktop notifications, once per alert however it arrived (live, or caught up
  // after being away), and never a flood after a long absence.
  const notified = useRef(new Set<string>());
  useEffect(() => {
    const fresh = newAlerts.filter((a) => !notified.current.has(a.id));
    if (fresh.length === 0) return;
    fresh.forEach((a) => notified.current.add(a.id));
    if (fresh.length <= MAX_INDIVIDUAL_NOTIFICATIONS) {
      fresh.forEach((a) => notify("🚨 Legion Alert", `${a.severity.toUpperCase()}: ${a.title}`, a.id));
    } else {
      notify("🚨 Legion Alert", t.ai.newAlertsNotice(fresh.length), "legion-alert-batch");
    }
  }, [newAlerts, t]);

  /** Install the list's cursor (from getAlertFeed) — see the hook's doc. */
  const setBaseline = useCallback((cursor: number) => {
    pendingBaseline.current = cursor;
    clientRef.current?.setBaseline(cursor);
  }, []);
  const syncNow = useCallback(() => clientRef.current?.syncNow("manual"), []);
  const dismissAll = useCallback(() => setNewAlerts([]), []);
  const dismissOne = useCallback((id: string) => {
    setNewAlerts((prev) => prev.filter((a) => a.id !== id));
  }, []);

  return { newAlerts, isConnected: state.connected, syncing: state.syncing, lastSyncAt: state.lastSyncAt, dismissAll, dismissOne, setBaseline, syncNow };
}
