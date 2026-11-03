import { isIP } from "node:net";
/**
 * Server-side language support.
 *
 * The dashboard sends the interface language in `Accept-Language` on every
 * request. Everything a person reads that the server writes — error messages,
 * confirmations, emails, AI explanations, Copilot answers — is then produced
 * in that language (English).
 *
 * Route code keeps writing English messages; `localizeResponses` translates
 * the `detail` and `message` fields of every JSON response on the way out,
 * using the catalogue below. tests/i18n.test.ts fails the build when a route
 * adds a message the catalogue does not have.
 */
import type { NextFunction, Request, Response } from "express";
import type { Alert } from "./types.js";

/** Legion is English only (built for the global market); the type stays so a language can be added later. */
export type Locale = "en";
export const LOCALES: readonly Locale[] = ["en"];

export function isLocale(value: unknown): value is Locale {
  return value === "en";
}

/** Always English. */
export function localeFrom(_header: string | undefined | null): Locale {
  return "en";
}

export function requestLocale(_req: Request): Locale {
  return "en";
}

/** Messages the API may return verbatim from a validation schema. */
const KNOWN_MESSAGES = new Set<string>([
  "Authentication required",
  "This account is not active",
  "Insufficient permissions",
  "Invalid email or password",
  "Finish setting up your account from the invitation email first",
  "This account has been deactivated",
  "This account is no longer active",
  "Confirm your email address first — we sent you a link when you signed up.",
  "This confirmation link is invalid or has expired. Request a new one from the sign-in page.",
  "Email confirmed. You can sign in now.",
  "If that account is waiting for confirmation, a new link has been sent.",
  "Email is already registered",
  "This Legion installation is already set up. Ask an administrator to invite you.",
  "A valid setup token is required. It is printed in the Legion server's console on startup.",
  "This sign-in attempt has expired. Please log in again.",
  "A code is required",
  "That code is not valid",
  "That recovery code is not valid",
  "Two-factor authentication is already enabled",
  "Start setup first",
  "That code is not valid — check your authenticator app's clock",
  "Two-factor authentication is not enabled",
  "Password is incorrect",
  "A valid authentication or recovery code is required",
  "No session to refresh",
  "Session reuse detected. Please log in again.",
  "Session expired. Please log in again.",
  "If that email is registered, a reset link has been generated.",
  "Token is invalid or has expired",
  "Password updated. Please log in again.",
  "Current password is incorrect",
  "This invitation is invalid or has expired",
  "Your account is ready. Please log in.",
  "Alert ID already exists",
  "Alert not found",
  "That email address is already in use",
  "User not found",
  "That user has already accepted their invitation",
  "A tenant must keep at least one admin",
  "You cannot deactivate your own account",
  "Set a notification email address first",
  "SMTP is not configured (set SMTP_HOST)",
  "Billing is not available on a self-hosted installation",
  "No subscription on file for this tenant yet",
  "Paddle is not configured",
  "No Paddle customer on file for this tenant yet",
  "Paddle did not return a portal URL",
  "Your subscription payment is past due. Legion is read-only until it is settled.",
  "This workspace does not have an active Legion subscription.",
  "Unknown tenant",
  "Security event webhook is disabled",
  "Not found",
  "No such payment on hold",
  "That address is not blocked",
  "Not an IP address",
  "A block lasts between 5 minutes and 7 days",
  "At most 200 allowlist entries",
  "Webhook credential not found",
  "This webhook credential is revoked or expired",
  "This webhook credential is already being rotated",
  "Two-factor sign-in is temporarily unavailable. Use a recovery code, or contact your administrator.",
  "Service unavailable",
  "Internal server error",
  "Too many attempts. Wait a minute and try again.",
  "Too many failed sign-in attempts for this account. Try again later.",
  "Delivery not found",
  "No failed delivery with that id",
  "Service temporarily unavailable. Try again shortly.",
  "Could not reach the billing provider. Try again later.",
  "Too many incorrect attempts. Wait a few minutes and try again.",
  "Too many emails requested for this address. Try again later.",
  "Too many failed webhook authentications from this address. Try again later.",
  "Too many incorrect codes. Sign in again in a few minutes.",
  "Cross-origin request refused",
  "Too many confirmation emails. Try again later.",
  "This confirmation link is invalid or has expired.",
  "Address confirmed. Security alerts will be sent here.",
  "Too many test emails. Try again later.",
  "The mail server could not be reached. Your administrator can see the details in the server log.",
  "The test email could not be sent. Your administrator can see the details in the server log.",
  "Too many invitations. Try again later.",
  "Invalid request",
  "Enter a valid email address",
  "Password must be 8 to 128 characters",
  "Organisation name must be 2 to 100 characters",
  "Enter the 6-digit code",
  "A value in the request is missing or invalid",
  "You are no longer a member of this workspace",
  "The billing currency cannot change while a subscription is active",
  "Choose a period of at most a year, with from before to",
  "Only administrators can create workspaces on this installation",
  "Confirm your email address first",
  "Workspace not found",
  "This invitation is invalid, has expired, or was sent to another account",
  "This is the workspace your account belongs to; it cannot be left",
  "A workspace must keep at least one admin",
  "You already have a Legion account. Sign in to accept this invitation.",
  "That person is already a member of this workspace",
  "Integration not found.",
  "This workspace is hosted in another region.",
  "Test alert: Legion is working",
  "This is a test alert you sent from the Connect page. It shows what a real alert looks like and that live updates and notifications reach you. It is safe to resolve.",
  "Complete the security check and try again.",
  "The security check failed or expired. Complete it again.",
  "The security check is temporarily unavailable. Try again in a moment.",
  "Too many sign-ins are being processed right now. Try again in a few seconds.",
  "Too many test alerts. Try again later.",
  "That integration is not available.",
]);


/** Text is already English. Kept so callers need no change. */
export function translate(text: string, _locale: Locale = "en"): string {
  return text;
}

/** Records the (only) language on the response. */
export function localizeResponses(_req: Request, res: Response, next: NextFunction): void {
  res.locals.locale = "en";
  next();
}

/**
 * English message for the first problem in a request body. Field-specific
 * wording where a person could have caused it from a form; a generic line
 * otherwise (the dashboard validates the same rules before sending).
 */
export function validationMessage(issue: { message?: string; path?: PropertyKey[] } | undefined): string {
  if (!issue) return "Invalid request";
  if (issue.message && KNOWN_MESSAGES.has(issue.message)) return issue.message;
  const field = String(issue.path?.[issue.path.length - 1] ?? "");
  if (/email/.test(field)) return "Enter a valid email address";
  if (/password/.test(field)) return "Password must be 8 to 128 characters";
  if (field === "tenant_name") return "Organisation name must be 2 to 100 characters";
  if (field === "code") return "Enter the 6-digit code";
  return "A value in the request is missing or invalid";
}

// --- Alerts: suggested next steps and the no-AI explanation ------------------

export type SuggestedAction =
  | { code: "review_timeline" | "validate_ownership" | "reset_credentials" | "escalate" }
  | { code: "block_source_ip"; ip: string };

/** The next steps for an alert, as codes the dashboard renders in any language. */
export function suggestedActions(alert: Alert): SuggestedAction[] {
  const result: SuggestedAction[] = [{ code: "review_timeline" }, { code: "validate_ownership" }];
  // Only a real IP address becomes an instruction to block something: this text is
  // shown to an analyst, and the field is written by whoever can make a log line.
  if (alert.source_ip && isIP(alert.source_ip) !== 0) result.push({ code: "block_source_ip", ip: alert.source_ip });
  if (/auth|login|credential|brute/i.test(`${alert.title} ${alert.summary}`)) result.push({ code: "reset_credentials" });
  if (alert.severity === "critical") result.push({ code: "escalate" });
  return result;
}

const ACTION_TEXT = (a: SuggestedAction): string => ({
  review_timeline: "Review event timeline",
  validate_ownership: "Validate affected asset ownership",
  block_source_ip: `Block or investigate source IP ${"ip" in a ? a.ip : ""}`,
  reset_credentials: "Reset affected credentials and enforce MFA",
  escalate: "Escalate to incident response immediately",
})[a.code];

export function actionText(action: SuggestedAction, _locale: Locale = "en"): string {
  return ACTION_TEXT(action);
}

const SEVERITY: Record<Alert["severity"], string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };

export function severityLabel(severity: Alert["severity"], _locale: Locale = "en"): string {
  return SEVERITY[severity];
}

/** Deterministic explanation used when no AI key is configured, and as the
 *  fallback whenever the model is unreachable. */
export function localExplanation(alert: Alert, locale: Locale): string {
  const sev = severityLabel(alert.severity, locale);
  const conf = Math.round(alert.confidence);
  const critical = alert.severity === "critical";
  return `${sev} priority: ${alert.title}. The signal has ${conf}% confidence${alert.source_ip ? ` and originated from ${alert.source_ip}` : ""}. First validate the activity on ${alert.target || "the affected asset"}, preserve relevant logs, then ${critical ? "isolate the asset and escalate immediately" : "investigate before closing the incident"}.`;
}

/** Copilot's answer when no AI provider is configured or it is unreachable. */
export function copilotFallback(open: Alert[], urgent: Alert | undefined, locale: Locale): string {
  if (!urgent) {
    return "There are no unresolved alerts in your tenant right now.";
  }
  const steps = suggestedActions(urgent);
  const next = actionText(steps[steps.length - 1] ?? { code: "review_timeline" }, locale);
  const conf = Math.round(urgent.confidence);
  const sev = severityLabel(urgent.severity, locale).toLowerCase();
  return `You have ${open.length} unresolved alert(s). The highest priority is ${urgent.id}: “${urgent.title}” (${sev}, ${conf}% confidence). Recommended next step: ${next}.`;
}

/** Appended to the AI system prompts so the answer is in the reader's language. */
export function answerLanguageInstruction(_locale: Locale = "en"): string {
  return "Write your answer in English.";
}
