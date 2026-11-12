import { defineMessages, plural } from "../core";

/**
 * Words used on many screens. Page-specific text belongs in that page's own
 * namespace file; only put something here when a second screen needs it.
 */
export const common = defineMessages({
  en: {
    appTagline: "Cybersecurity Intelligence",
    loading: "Loading…",
    save: "Save",
    saving: "Saving…",
    saved: "Saved",
    cancel: "Cancel",
    close: "Close",
    back: "Back",
    retry: "Try again",
    refresh: "Refresh",
    search: "Search",
    copy: "Copy",
    copied: "Copied",
    edit: "Edit",
    remove: "Remove",
    confirm: "Confirm",
    continue: "Continue",
    signIn: "Sign in",
    signOut: "Sign out",
    email: "Email",
    password: "Password",
    none: "None",
    unknown: "Unknown",
    all: "All",
    yes: "Yes",
    no: "No",
    genericError: "Something went wrong. Please try again.",
    captchaUnavailable: "The security check could not load. Check your connection or turn off content blockers for this site, then reload the page.",
    networkError: "Can't reach the Legion server. Check your connection and try again.",
    reopenReasonPrompt: "Why is this resolved alert being reopened? (kept in the audit log)",
    severity: {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
    },
    status: {
      open: "Open",
      investigating: "Investigating",
      resolved: "Resolved",
    },
    role: {
      admin: "Admin",
      analyst: "Analyst",
      viewer: "Viewer",
    },
    userStatus: {
      active: "Active",
      invited: "Invited",
      disabled: "Deactivated",
    },
    subscription: {
      trialing: "Trialing",
      active: "Active",
      past_due: "Past due",
      paused: "Paused",
      canceled: "Canceled",
    },
    risk: {
      critical: "Critical",
      high: "High",
      medium: "Medium",
      low: "Low",
    },
    /** Next steps the server suggests for an alert (see suggested_action_codes). */
    actions: {
      review_timeline: "Review event timeline",
      validate_ownership: "Validate affected asset ownership",
      block_source_ip: (ip: string) => `Block or investigate source IP ${ip}`,
      reset_credentials: "Reset affected credentials and enforce MFA",
      escalate: "Escalate to incident response immediately",
    },
    time: {
      justNow: "just now",
      minutesAgo: (n: number) => `${n}m ago`,
      hoursAgo: (n: number) => `${n}h ago`,
      daysAgo: (n: number) => `${n}d ago`,
    },
    count: {
      alerts: (n: number) => plural("en", n, { one: `${n} alert`, other: `${n} alerts` }),
      days: (n: number) => plural("en", n, { one: `${n} day`, other: `${n} days` }),
      hours: (n: number) => plural("en", n, { one: `${n} hour`, other: `${n} hours` }),
    },
  },
});
