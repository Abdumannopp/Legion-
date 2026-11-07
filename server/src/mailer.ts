import nodemailer, { type Transporter } from "nodemailer";
import { config } from "./config.js";
import type { Locale } from "./i18n.js";

let transport: Transporter | null = null;

/** SMTP is optional. Without a host, Legion keeps working and every send is
 *  reported as skipped rather than failing the request that triggered it. */
export function mailEnabled(): boolean {
  return Boolean(config.smtpHost);
}

function getTransport(): Transporter | null {
  if (!mailEnabled()) return null;
  if (!transport) {
    transport = nodemailer.createTransport({
      host: config.smtpHost,
      port: config.smtpPort,
      secure: config.smtpSecure,
      // nodemailer's defaults (2 min to connect, 10 min idle socket) are
      // longer than the outbox lease, so a hung server could let a second
      // worker reclaim — and resend — a row that is still being sent.
      connectionTimeout: 15_000,
      greetingTimeout: 15_000,
      socketTimeout: 45_000,
      auth: config.smtpUser
        ? { user: config.smtpUser, pass: config.smtpPassword }
        : undefined,
    });
  }
  return transport;
}

export type MailResult =
  | { sent: true }
  | { sent: false; reason: "not_configured" | "send_failed"; detail?: string };

export async function sendMail(message: {
  to: string;
  subject: string;
  text: string;
  html?: string;
  /** Stable across retries of the same notification, so a mail system that
   *  receives it twice can recognise the duplicate. */
  messageId?: string;
}): Promise<MailResult> {
  const mailer = getTransport();
  if (!mailer) return { sent: false, reason: "not_configured" };
  try {
    await mailer.sendMail({ from: config.smtpFrom, ...message });
    return { sent: true };
  } catch (error) {
    // Never surface SMTP internals (credentials can appear in errors) and
    // never let a mail failure break the caller's request.
    const detail = error instanceof Error ? error.message : "unknown error";
    console.error("SMTP send failed:", detail);
    return { sent: false, reason: "send_failed", detail };
  }
}

/** Verifies the SMTP connection without sending anything. */
export async function verifyMail(): Promise<MailResult> {
  const mailer = getTransport();
  if (!mailer) return { sent: false, reason: "not_configured" };
  try {
    await mailer.verify();
    return { sent: true };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown error";
    return { sent: false, reason: "send_failed", detail };
  }
}

const escape = (value: string) =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

function layout(title: string, bodyHtml: string, locale: Locale): string {
  return `<!doctype html><html lang="${locale}"><body style="margin:0;background:#08060F;padding:24px;font-family:Segoe UI,Helvetica,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px;background:#140F24;border:1px solid #251C3D;border-radius:12px;padding:28px">
<tr><td style="padding-bottom:18px"><span style="color:#F6F4FB;font-size:15px;letter-spacing:6px;text-transform:uppercase">Legion</span><br><span style="color:#A78BFA;font-size:9px;letter-spacing:4px;text-transform:uppercase">Cyber Intelligence</span></td></tr>
<tr><td style="color:#F6F4FB;font-size:19px;font-weight:600;padding-bottom:14px">${escape(title)}</td></tr>
<tr><td style="color:#B1A9CC;font-size:14px;line-height:1.6">${bodyHtml}</td></tr>
</table></td></tr></table></body></html>`;
}

const button = (url: string, label: string) =>
  `<p style="margin:0 0 18px"><a href="${escape(url)}" style="display:inline-block;background:#7C3AED;color:#fff;text-decoration:none;padding:11px 20px;border-radius:8px;font-size:14px">${escape(label)}</a></p>`;
const para = (text: string) => `<p style="margin:0 0 18px">${text}</p>`;
const small = (text: string) => `<p style="margin:0;color:#857CA8;font-size:12px">${escape(text)}</p>`;
const strong = (text: string) => `<strong style="color:#F6F4FB">${escape(text)}</strong>`;

const ROLE: Record<Locale, Record<string, string>> = {
  en: { admin: "admin", analyst: "analyst", viewer: "viewer" },
};

export function passwordResetEmail(resetUrl: string, locale: Locale = "en") {
  const t = {
    en: {
      subject: "Reset your Legion password",
      title: "Reset your password",
      intro: "A password reset was requested for your Legion account.",
      valid: "Open this link to choose a new password (valid for 1 hour):",
      validHtml: "The link below is valid for one hour.",
      button: "Choose a new password",
      ignore: "If you didn't request this, ignore this email — your password stays unchanged.",
    },
  }[locale];
  return {
    subject: t.subject,
    text: `${t.intro}\n\n${t.valid}\n${resetUrl}\n\n${t.ignore}`,
    html: layout(t.title, `${para(`${escape(t.intro)} ${escape(t.validHtml)}`)}\n${button(resetUrl, t.button)}\n${small(t.ignore)}`, locale),
  };
}

export function verifyEmailEmail(verifyUrl: string, hours: number, locale: Locale = "en") {
  const t = {
    en: {
      subject: "Confirm your email for Legion",
      title: "Confirm your email address",
      welcome: "Welcome to Legion.",
      body: `Confirm your email address to finish creating your account. The link is valid for ${hours} hours.`,
      textBody: `Confirm your email address to finish creating your account (link valid for ${hours} hours):`,
      button: "Confirm email",
      ignore: "If you didn't sign up for Legion, ignore this email — no account is activated without this step.",
    },
  }[locale];
  return {
    subject: t.subject,
    text: `${t.welcome}\n\n${t.textBody}\n${verifyUrl}\n\n${t.ignore}`,
    html: layout(t.title, `${para(`${escape(t.welcome)} ${escape(t.body)}`)}\n${button(verifyUrl, t.button)}\n${small(t.ignore)}`, locale),
  };
}

export function inviteEmail(params: {
  inviteUrl: string;
  tenantName: string;
  invitedBy: string;
  role: string;
  expiresDays: number;
  locale?: Locale;
}) {
  const { inviteUrl, tenantName, invitedBy, expiresDays } = params;
  const locale = params.locale ?? "en";
  const role = ROLE[locale][params.role] ?? params.role;
  const days = `${expiresDays} ${expiresDays === 1 ? "day" : "days"}`;
  const t = {
    en: {
      subject: `${invitedBy} invited you to ${tenantName} on Legion`,
      title: `You've been invited to ${tenantName}`,
      text: `${invitedBy} has invited you to join "${tenantName}" on Legion as ${role}.`,
      html: `${escape(invitedBy)} has invited you to join ${strong(tenantName)} on Legion as ${strong(role)}.`,
      set: `Set your password and get started (link valid for ${days}):`,
      button: "Set your password",
      valid: `This link is valid for ${days}. If you weren't expecting it, ignore this email — no account is created until you set a password.`,
      ignore: "If you weren't expecting this invitation you can ignore this email — no account is created until you set a password.",
    },
  }[locale];
  return {
    subject: t.subject,
    text: `${t.text}\n\n${t.set}\n${inviteUrl}\n\n${t.ignore}`,
    html: layout(t.title, `${para(t.html)}\n${button(inviteUrl, t.button)}\n${small(t.valid)}`, locale),
  };
}

const ALERT_LABELS: Record<Locale, { alert: string; severity: string; confidence: string; sourceIp: string; target: string; view: string; open: string; sev: Record<string, string> }> = {
  en: { alert: "Alert", severity: "Severity", confidence: "Confidence", sourceIp: "Source IP", target: "Target", view: "View in Legion", open: "Open in Legion", sev: { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" } },
};

/** Alert notification. The title and summary come from the monitored system
 *  and stay as they are; only Legion's own labels are translated. */
export function alertEmail(alert: {
  id: string;
  title: string;
  severity: string;
  summary: string;
  source_ip: string | null;
  target: string | null;
  confidence: number;
}, locale: Locale = "en") {
  const l = ALERT_LABELS[locale];
  const sev = l.sev[alert.severity] ?? alert.severity.toUpperCase();
  const url = `${config.frontendUrl}/incident/${encodeURIComponent(alert.id)}`;
  const rows: Array<[string, string]> = [
    [l.alert, alert.id],
    [l.severity, sev],
    [l.confidence, `${Math.round(alert.confidence)}%`],
    [l.sourceIp, alert.source_ip || "—"],
    [l.target, alert.target || "—"],
  ];
  return {
    subject: `[Legion ${sev}] ${alert.title}`,
    text: `${alert.title}

${rows.map(([k, v]) => `${k}: ${v}`).join("\n")}

${alert.summary}

${l.view}: ${url}`,
    html: layout(
      alert.title,
      `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;font-size:13px;margin-bottom:16px">
${rows
  .map(
    ([k, v]) =>
      `<tr><td style="color:#857CA8;padding:3px 12px 3px 0">${escape(k)}</td><td style="color:#F6F4FB">${escape(v)}</td></tr>`
  )
  .join("")}
</table>
<p style="margin:0 0 18px">${escape(alert.summary)}</p>
<p style="margin:0"><a href="${escape(url)}" style="display:inline-block;background:#7C3AED;color:#fff;text-decoration:none;padding:11px 20px;border-radius:8px;font-size:14px">${escape(l.open)}</a></p>`,
      locale
    ),
  };
}

/**
 * What Legion did on its own (or needs a person to decide), for the workspace's administrators. Built from
 * fixed templates plus a few short facts; every value is shown as text. The link goes to the dashboard
 * only (no one-click action: a copy of this mail must not be a way to approve anything).
 */
export function protectionEmail(params: {
  kind: "acted" | "failed" | "approval" | "notice";
  title: string;
  facts: Array<[string, string]>;
  path: string;
  locale?: Locale;
}) {
  const locale = params.locale ?? "en";
  const t = {
    en: {
      subject: { acted: "Legion acted on its own", failed: "Legion tried to act and could not", approval: "Legion needs your decision", notice: "Message from Legion" },
      footer: {
        acted: "You allowed Legion to do this in Protection settings. Review it and undo it from the dashboard if it was wrong; you can switch to manual mode or press the emergency stop at any time.",
        failed: "Nothing more was done. Check the action in the dashboard before trying again.",
        approval: "Legion will not do this until a signed-in administrator approves it in the dashboard.",
        notice: "",
      },
      open: "Open in Legion",
    },
  }[locale];
  const url = `${config.frontendUrl}${params.path}`;
  const rows = params.facts.map(([k, v]) => `<tr><td style="color:#857CA8;padding:3px 12px 3px 0">${escape(k)}</td><td style="color:#F6F4FB">${escape(v)}</td></tr>`).join("");
  const footer = t.footer[params.kind];
  return {
    subject: `[Legion] ${t.subject[params.kind]}: ${params.title}`.slice(0, 200),
    text: `${params.title}\n\n${params.facts.map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${footer}\n\n${t.open}: ${url}`,
    html: layout(params.title, `<table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;font-size:13px;margin-bottom:16px">${rows}</table>${footer ? para(escape(footer)) : ""}${button(url, t.open)}`, locale),
  };
}

/**
 * Sent to an address an administrator asked to receive alert emails. Nothing is
 * sent to it until its owner confirms — the recipient may never have heard of
 * this organisation, so the wording says so and the default is "ignore".
 */
export function notificationConfirmEmail(params: { url: string; tenantName: string; requestedBy: string; hours: number; locale?: Locale }) {
  const locale = params.locale ?? "en";
  const t = {
    en: {
      subject: "Confirm Legion security alert emails to this address",
      title: "Confirm alert emails",
      body: `${params.requestedBy} asked Legion to send security alert emails for the organisation "${params.tenantName}" to this address.`,
      action: `If you expect these alerts, confirm within ${params.hours} hours:`,
      button: "Confirm this address",
      ignore: "If you don't know this organisation or didn't expect this, ignore this email. Nothing will be sent to you.",
    },
  }[locale];
  return {
    subject: t.subject,
    text: `${t.body}\n\n${t.action}\n${params.url}\n\n${t.ignore}`,
    html: layout(t.title, `${para(escape(t.body))}\n${para(escape(t.action))}\n${button(params.url, t.button)}\n${small(t.ignore)}`, locale),
  };
}

/** Settings → Notifications → "Send test email". */
export function testNotificationEmail(locale: Locale = "en") {
  const t = {
    en: { subject: "Legion test notification", body: "This is a test notification from Legion. If you received it, alert emails are working.", open: "Open Legion" },
  }[locale];
  return { subject: t.subject, text: `${t.body}\n\n${t.open}: ${config.frontendUrl}` };
}

export type SecurityNoticeKind = "password_changed" | "mfa_enabled" | "mfa_disabled" | "recovery_codes_regenerated" | "new_device_login";

/**
 * Tells the account owner that something security-relevant just happened to
 * their account. The point is the case where it was NOT them: each notice says
 * what to do then. Carries no link that acts on the account (a phished copy of
 * this mail must not be a way in) and no secret; `detail` is shown as text.
 */
export function securityNoticeEmail(kind: SecurityNoticeKind, params: { when: string; detail?: string; locale?: Locale }) {
  const locale = params.locale ?? "en";
  const what: Record<Locale, Record<SecurityNoticeKind, string>> = {
    en: {
      password_changed: "The password of your Legion account was changed.",
      mfa_enabled: "Two-factor authentication was turned on for your Legion account. Every other session was signed out.",
      mfa_disabled: "Two-factor authentication was turned OFF for your Legion account. Every other session was signed out.",
      recovery_codes_regenerated: "New two-factor recovery codes were generated for your Legion account. The previous codes no longer work.",
      new_device_login: "Your Legion account was signed in to from a device or browser it has not been used from before.",
    },
  };
  const t = {
    en: { subject: "Security notice for your Legion account", title: "Security notice", when: "When", details: "Details", notYou: "If this was you, no action is needed. If it was not, reset your password from the sign-in page right away and tell your Legion administrator." },
  }[locale];
  const lines = [what[locale][kind], `${t.when}: ${params.when}`, ...(params.detail ? [`${t.details}: ${params.detail}`] : [])];
  return {
    subject: t.subject,
    text: `${lines.join("\n")}\n\n${t.notYou}`,
    html: layout(t.title, `${lines.map((l) => para(escape(l))).join("\n")}\n${small(t.notYou)}`, locale),
  };
}

/**
 * Warns a workspace's administrators that it will be erased on a given date unless
 * it is brought back into use. Links go to the dashboard only (no one-click action),
 * and the workspace name is shown as text.
 */
export function workspaceDeletionNoticeEmail(params: { workspace: string; deleteOn: string; billingUrl: string; exportUrl: string; locale?: Locale }) {
  const locale = params.locale ?? "en";
  const t = {
    en: {
      subject: `Your Legion workspace "${params.workspace}" will be deleted on ${params.deleteOn}`,
      title: "Your workspace will be deleted",
      body: `The Legion workspace "${params.workspace}" has been locked for a long time. On ${params.deleteOn} it will be permanently erased: its alerts, agents, audit history, payment checks and accounts. This cannot be undone.`,
      keep: "To keep it, subscribe again before that date. The deletion is then cancelled automatically.",
      subscribe: "Open billing",
      exportNote: "To keep a copy of your data, an administrator can download it any time before then (Settings → Data export). Export works while the workspace is locked.",
      exportButton: "Open settings",
      ignore: "If you no longer need this workspace, you do not have to do anything.",
    },
  }[locale];
  return {
    subject: t.subject,
    text: `${t.body}\n\n${t.keep}\n${params.billingUrl}\n\n${t.exportNote}\n${params.exportUrl}\n\n${t.ignore}`,
    html: layout(t.title, `${para(escape(t.body))}\n${para(escape(t.keep))}\n${button(params.billingUrl, t.subscribe)}\n${para(escape(t.exportNote))}\n${button(params.exportUrl, t.exportButton)}\n${small(t.ignore)}`, locale),
  };
}
