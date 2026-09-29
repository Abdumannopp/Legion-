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

/** Russian noun forms after a number: 1 час, 2 часа, 5 часов. */
function ru(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return `${n} ${one}`;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return `${n} ${few}`;
  return `${n} ${many}`;
}

const ROLE: Record<Locale, Record<string, string>> = {
  en: { admin: "admin", analyst: "analyst", viewer: "viewer" },
  ru: { admin: "администратор", analyst: "аналитик", viewer: "наблюдатель" },
  uz: { admin: "administrator", analyst: "tahlilchi", viewer: "kuzatuvchi" },
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
    ru: {
      subject: "Сброс пароля Legion",
      title: "Сброс пароля",
      intro: "Для вашей учётной записи Legion запрошен сброс пароля.",
      valid: "Откройте ссылку, чтобы задать новый пароль (действует 1 час):",
      validHtml: "Ссылка ниже действует один час.",
      button: "Задать новый пароль",
      ignore: "Если вы этого не запрашивали, просто проигнорируйте письмо — пароль не изменится.",
    },
    uz: {
      subject: "Legion parolini tiklash",
      title: "Parolni tiklash",
      intro: "Legion hisobingiz uchun parolni tiklash so'raldi.",
      valid: "Yangi parol o'rnatish uchun havolani oching (1 soat amal qiladi):",
      validHtml: "Quyidagi havola bir soat amal qiladi.",
      button: "Yangi parol o'rnatish",
      ignore: "Agar buni siz so'ramagan bo'lsangiz, xatga e'tibor bermang — parolingiz o'zgarmaydi.",
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
    ru: {
      subject: "Подтвердите адрес эл. почты для Legion",
      title: "Подтвердите адрес эл. почты",
      welcome: "Добро пожаловать в Legion.",
      body: `Подтвердите адрес, чтобы завершить создание учётной записи. Ссылка действует ${ru(hours, "час", "часа", "часов")}.`,
      textBody: `Подтвердите адрес, чтобы завершить создание учётной записи (ссылка действует ${ru(hours, "час", "часа", "часов")}):`,
      button: "Подтвердить адрес",
      ignore: "Если вы не регистрировались в Legion, проигнорируйте это письмо — без подтверждения учётная запись не активируется.",
    },
    uz: {
      subject: "Legion uchun emailingizni tasdiqlang",
      title: "Email manzilingizni tasdiqlang",
      welcome: "Legion'ga xush kelibsiz.",
      body: `Hisob yaratishni yakunlash uchun emailingizni tasdiqlang. Havola ${hours} soat amal qiladi.`,
      textBody: `Hisob yaratishni yakunlash uchun emailingizni tasdiqlang (havola ${hours} soat amal qiladi):`,
      button: "Emailni tasdiqlash",
      ignore: "Agar Legion'da ro'yxatdan o'tmagan bo'lsangiz, xatga e'tibor bermang — bu qadamsiz hech qanday hisob faollashmaydi.",
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
  const days = locale === "ru" ? ru(expiresDays, "день", "дня", "дней") : locale === "uz" ? `${expiresDays} kun` : `${expiresDays} days`;
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
    ru: {
      subject: `${invitedBy} приглашает вас в «${tenantName}» в Legion`,
      title: `Приглашение в «${tenantName}»`,
      text: `${invitedBy} приглашает вас присоединиться к «${tenantName}» в Legion. Роль: ${role}.`,
      html: `${escape(invitedBy)} приглашает вас присоединиться к ${strong(tenantName)} в Legion. Роль: ${strong(role)}.`,
      set: `Задайте пароль, чтобы начать работу (ссылка действует ${days}):`,
      button: "Задать пароль",
      valid: `Ссылка действует ${days}. Если вы не ждали этого письма, просто проигнорируйте его — учётная запись не создаётся, пока вы не зададите пароль.`,
      ignore: "Если вы не ждали приглашения, проигнорируйте это письмо — учётная запись не создаётся, пока вы не зададите пароль.",
    },
    uz: {
      subject: `${invitedBy} sizni Legion'dagi "${tenantName}" ga taklif qildi`,
      title: `"${tenantName}" ga taklif`,
      text: `${invitedBy} sizni Legion'dagi "${tenantName}" ga qo'shilishga taklif qildi. Rolingiz: ${role}.`,
      html: `${escape(invitedBy)} sizni Legion'dagi ${strong(tenantName)} ga qo'shilishga taklif qildi. Rolingiz: ${strong(role)}.`,
      set: `Parol o'rnating va ishni boshlang (havola ${days} amal qiladi):`,
      button: "Parol o'rnatish",
      valid: `Havola ${days} amal qiladi. Agar bu taklifni kutmagan bo'lsangiz, xatga e'tibor bermang — parol o'rnatmaguningizcha hisob yaratilmaydi.`,
      ignore: "Agar bu taklifni kutmagan bo'lsangiz, xatga e'tibor bermang — parol o'rnatmaguningizcha hisob yaratilmaydi.",
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
  ru: { alert: "Оповещение", severity: "Критичность", confidence: "Уверенность", sourceIp: "IP-адрес источника", target: "Цель", view: "Открыть в Legion", open: "Открыть в Legion", sev: { critical: "КРИТИЧЕСКИЙ", high: "ВЫСОКИЙ", medium: "СРЕДНИЙ", low: "НИЗКИЙ" } },
  uz: { alert: "Ogohlantirish", severity: "Jiddiylik darajasi", confidence: "Ishonchlilik", sourceIp: "Manba IP manzili", target: "Nishon", view: "Legion'da ko'rish", open: "Legion'da ochish", sev: { critical: "KRITIK", high: "YUQORI", medium: "O'RTA", low: "PAST" } },
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
    ru: {
      subject: "Подтвердите получение оповещений Legion на этот адрес",
      title: "Подтвердите оповещения",
      body: `${params.requestedBy} попросил(а) Legion отправлять на этот адрес оповещения безопасности организации «${params.tenantName}».`,
      action: `Если вы ждёте эти оповещения, подтвердите в течение ${ru(params.hours, "часа", "часов", "часов")}:`,
      button: "Подтвердить адрес",
      ignore: "Если вы не знаете эту организацию или не ожидали этого письма, просто проигнорируйте его. Ничего отправлено не будет.",
    },
    uz: {
      subject: "Legion xavfsizlik ogohlantirishlarini shu manzilga yuborishni tasdiqlang",
      title: "Ogohlantirishlarni tasdiqlang",
      body: `${params.requestedBy} Legion'dan "${params.tenantName}" tashkilotining xavfsizlik ogohlantirishlarini shu manzilga yuborishni so'radi.`,
      action: `Agar bu ogohlantirishlarni kutayotgan bo'lsangiz, ${params.hours} soat ichida tasdiqlang:`,
      button: "Manzilni tasdiqlash",
      ignore: "Agar bu tashkilotni tanimasangiz yoki buni kutmagan bo'lsangiz, xatga e'tibor bermang. Sizga hech narsa yuborilmaydi.",
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
    ru: { subject: "Тестовое уведомление Legion", body: "Это тестовое уведомление от Legion. Если вы его получили, оповещения по эл. почте работают.", open: "Открыть Legion" },
    uz: { subject: "Legion sinov bildirishnomasi", body: "Bu Legion'dan sinov bildirishnomasi. Agar uni olgan bo'lsangiz, ogohlantirish xatlari ishlayapti.", open: "Legion'ni ochish" },
  }[locale];
  return { subject: t.subject, text: `${t.body}\n\n${t.open}: ${config.frontendUrl}` };
}
