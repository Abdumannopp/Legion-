import { defineMessages } from "../core";

/**
 * Every important error answers three questions: what happened, why, and
 * what to do next (lib/errors.ts picks the entry; ErrorNotice shows it).
 * The server's own message, already in the reader's language, is shown as
 * the detail of "what happened".
 */
export const errors = defineMessages({
  en: {
    whyLabel: "Why",
    nextLabel: "What you can do",
    retry: "Try again",
    network: { title: "Legion can't be reached", why: "Your connection dropped, or the Legion service is restarting.", next: "Check your internet connection, then try again in a moment." },
    session: { title: "You've been signed out", why: "Your session ended — it expired, or you signed out in another tab.", next: "Sign in again. Nothing you saved was lost.", action: "Sign in" },
    plan: { title: "This workspace's plan isn't active", why: "The free trial has ended or the subscription was cancelled. Your data is safe, and Legion keeps recording your sensors' events.", nextAdmin: "Choose a plan on the Billing page to continue.", nextMember: "Ask a workspace admin to renew the plan.", action: "Open Billing" },
    pastDue: { title: "Payment is overdue", why: "The last payment didn't go through, so the workspace is read-only for now.", nextAdmin: "Update the payment method on the Billing page.", nextMember: "Ask a workspace admin to update the payment method.", action: "Open Billing" },
    forbidden: { title: "You don't have permission to do this", why: "Your role in this workspace doesn't include this action.", next: "Ask a workspace admin to do it, or to change your role." },
    notFound: { title: "We couldn't find that", why: "It may have been removed, or it belongs to a different workspace.", next: "Check that you're in the right workspace (see the switcher in the sidebar)." },
    conflict: { title: "That can't be done right now", why: "Something changed since the page loaded, or the item is in a state that doesn't allow this.", next: "Refresh the page and try again." },
    invalid: { title: "Some information isn't right", why: "Legion checked what you entered and couldn't accept it.", next: "Correct the highlighted details and try again." },
    rateLimited: { title: "Too many attempts", why: "Legion slows down repeated attempts to protect your account and workspace.", next: "Wait a moment and try again.", nextSeconds: (s: number) => `Wait ${s} seconds and try again.` },
    region: { title: "This workspace is in another region", why: "Its data is stored in a different region, which this address doesn't serve.", next: "Open the workspace from its own region.", action: "Go there" },
    server: { title: "Something went wrong on our side", why: "Legion hit a temporary problem. Nothing you did caused it.", next: "Try again in a minute. If it keeps happening, contact support." },
    unknown: { title: "That didn't work", why: "Legion couldn't complete the request.", next: "Try again. If it keeps happening, contact support." },
  },
});
