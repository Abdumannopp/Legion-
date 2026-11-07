import type { Locale } from "./i18n/core";
import type { AddonId, Entitlements, PlanId } from "./plans";
import { translations } from "./i18n/translations";
import { createRefresher, type LockManagerLike } from "./session-refresh";
import { setDisplaySettings, type DateFormat, type TimeFormat } from "./i18n/format";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// WebSocket base. Defaults to NEXT_PUBLIC_API_URL with the http(s) scheme
// swapped for ws(s), so the socket always follows the API host (:8000) and
// never the page host (:3000) — that mismatch was the original bug.
const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL || API_URL.replace(/^http/, "ws");

export { API_URL, WS_URL };

// The interface language, sent with every request so the API answers in it
// (error messages, emails it sends, AI explanations). Set by LanguageProvider.
let apiLocale: Locale = "en";
export function setApiLocale(locale: Locale) {
  apiLocale = locale;
}

/** fetch with the language header, and a readable error when the server is
 *  unreachable instead of the browser's "Failed to fetch". */
async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Accept-Language", apiLocale);
  try {
    return await fetch(url, { ...init, headers });
  } catch {
    throw new ApiError(translations[apiLocale].common.networkError, 0, "network");
  }
}

const failed = () => translations[apiLocale].common.genericError;

export interface Alert {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  agent: "Sentinel" | "Hunter" | "Guardian" | "Oracle" | "Vanguard";
  status: "open" | "investigating" | "resolved";
  summary: string;
  confidence: number;
  created_at: string;
  ai_explanation: string | null;
  explained_at: string | null;
  source_ip: string | null;
  target: string | null;
  mitre_technique: string | null;
  /** Where the alert came from: "wazuh", an integration kind, or Legion itself ("legion-test", "legion-monitor", …). */
  source?: string | null;
  /** When the event happened at its source (the sensor's own timestamp); created_at is when Legion stored it. */
  occurred_at?: string | null;
  /** English text of the suggested next steps (kept for API clients). */
  suggested_actions: string[];
  /** The same steps as codes, so the dashboard can show them in any language:
   *  render with `t.common.actions[code]` (block_source_ip takes `ip`). */
  suggested_action_codes: SuggestedAction[];
  /** Language the stored ai_explanation was written in. */
  ai_explanation_locale: Locale | null;
  /** Who wrote ai_explanation: a model ("ai") or Legion's built-in rules ("local"). */
  ai_explanation_source?: "ai" | "local" | null;
  /** True only when a model wrote the stored explanation — show it as a suggestion. */
  ai_generated?: boolean;
  /** This alert's version. Per-tenant, bumped by every change, assigned in commit
   *  order: the basis of live-feed ordering, de-duplication and catch-up. */
  seq: number;
  /** The seq the alert was created with. */
  created_seq: number;
}

export type SuggestedAction =
  | { code: "review_timeline" | "validate_ownership" | "reset_credentials" | "escalate" }
  | { code: "block_source_ip"; ip: string };

export interface AlertStats {
  total: number;
  open: number;
  investigating: number;
  resolved: number;
  by_severity: Record<string, number>;
}

class ApiError extends Error {
  status: number;
  /** Machine-readable reason when the API gives one, e.g. "email_unverified". */
  code?: string;
  /** The rest of the error body (e.g. region_url, access_state, approval) for explaining it. */
  data?: Record<string, unknown>;
  /** Seconds the server asked us to wait (Retry-After), when it said. */
  retryAfter?: number;
  constructor(message: string, status: number, code?: string, data?: Record<string, unknown>, retryAfter?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.data = data;
    this.retryAfter = retryAfter;
  }
}

// The real JWT lives in an httpOnly cookie set by the backend (see
// POST /auth/login) — client JS never sees or stores it, so an XSS bug
// elsewhere in the app can't exfiltrate it via localStorage. This
// non-sensitive companion cookie just tells the frontend "you're logged
// in" so it can decide whether to redirect to /login; it isn't used for
// authentication server-side.
const SESSION_FLAG_COOKIE = "legion_session";

function hasSessionFlag(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie
    .split("; ")
    .some((c) => c.startsWith(`${SESSION_FLAG_COOKIE}=`));
}

/**
 * Refreshes the session: one attempt per tab at a time, and serialised across
 * tabs (see session-refresh.ts) so two tabs never present the same spent
 * refresh token — which the server rightly treats as theft.
 */
const refreshSession = createRefresher({
  refresh: () => apiFetch(`${API_URL}/auth/refresh`, { method: "POST", credentials: "include" }).then((res) => res.ok),
  locks: typeof navigator !== "undefined" && "locks" in navigator ? (navigator.locks as unknown as LockManagerLike) : null,
  storage: (() => { try { return typeof window !== "undefined" ? window.localStorage : null; } catch { return null; } })(),
});

async function send(path: string, options: RequestInit): Promise<Response> {
  return apiFetch(`${API_URL}${path}`, {
    ...options,
    credentials: "include", // send/receive the httpOnly auth cookie
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
  });
}

/*
 * Dangerous actions answer 403 { code: "reauth_required" } unless the person confirmed their password
 * in the last 10 minutes (server: recentAuth). The dialog (components/ReauthDialog.tsx) registers here;
 * the request is sent again once, after a successful confirmation. Cancelling leaves the 403 as it was.
 */
type ReauthHandler = () => Promise<boolean>;
let reauthHandler: ReauthHandler | null = null;
export function setReauthHandler(handler: ReauthHandler | null): void { reauthHandler = handler; }

async function confirmedAfterReauth(res: Response): Promise<boolean> {
  if (res.status !== 403 || !reauthHandler) return false;
  let code: unknown;
  try { code = (await res.clone().json())?.code; } catch { return false; }
  return code === "reauth_required" && (await reauthHandler());
}

/** Re-confirm identity (password; and the authenticator code when MFA is on). */
export function stepUp(password: string, code?: string): Promise<{ access_token: string; valid_for_seconds: number }> {
  return request("/auth/step-up", { method: "POST", body: JSON.stringify(code ? { password, code } : { password }) });
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let res = await send(path, options);

  // The access token is short-lived by design. A 401 usually just means it
  // expired, so try once to renew and replay the request — the user should
  // never be bounced to the login screen mid-shift for that.
  if (res.status === 401 && !path.startsWith("/auth/refresh")) {
    if (await refreshSession()) {
      res = await send(path, options);
    }
  }
  if (await confirmedAfterReauth(res)) res = await send(path, options);

  if (!res.ok) {
    let detail = res.statusText;
    let code: string | undefined;
    let data: Record<string, unknown> | undefined;
    try {
      // Two shapes: { detail, code } (dashboard API) and { error: { code, message } } (agent layer).
      const body = await res.json();
      data = body && typeof body === "object" ? body : undefined;
      detail = body.detail || body.error?.message || body.message || detail;
      code = body.code || body.error?.code;
    } catch {
      // response wasn't JSON, keep statusText
    }
    const retry = Number(res.headers.get("retry-after"));
    throw new ApiError(detail, res.status, code, data, Number.isFinite(retry) && retry > 0 ? retry : undefined);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

/** The workspace's data as a JSON file (administrators). Returned as a Blob so a large workspace is not parsed in memory. */
export async function downloadWorkspaceExport(): Promise<{ blob: Blob; filename: string }> {
  let res = await send("/workspace/export", {});
  if (res.status === 401 && (await refreshSession())) res = await send("/workspace/export", {});
  if (await confirmedAfterReauth(res)) res = await send("/workspace/export", {});
  if (!res.ok) {
    let detail = res.statusText;
    try { const body = await res.json(); detail = body.detail || detail; } catch { /* not JSON */ }
    const retry = Number(res.headers.get("retry-after"));
    throw new ApiError(detail, res.status, undefined, undefined, Number.isFinite(retry) && retry > 0 ? retry : undefined);
  }
  const named = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "");
  return { blob: await res.blob(), filename: named?.[1] ?? "legion-workspace.json" };
}

export type DeploymentMode = "self-hosted" | "saas";

/** `setup_required`: a self-hosted install with no administrator yet.
 *  `deployment_mode`: "saas" means anyone may sign up (hosted service). */
export async function getSetupStatus(): Promise<{ setup_required: boolean; deployment_mode?: DeploymentMode; trial_days?: number | null; captcha?: boolean }> {
  const res = await apiFetch(`${API_URL}/auth/setup-status`, { credentials: "include" });
  if (!res.ok) return { setup_required: false };
  return res.json();
}

async function postJson(path: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await apiFetch(`${API_URL}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = typeof data.detail === "string" ? data.detail : failed();
    throw new ApiError(detail, res.status, typeof data.code === "string" ? data.code : undefined);
  }
  return data;
}

/** Hosted sign-up: creates a workspace and emails a confirmation link.
 *  No session is started until the address is confirmed. */
export async function signUp(input: { company: string; email: string; password: string }, captchaToken?: string | null): Promise<void> {
  await postJson("/auth/register", { tenant_name: input.company, email: input.email, password: input.password, ...captcha(captchaToken) });
}

/** The Turnstile token, when the form has one (components/Turnstile.tsx). */
function captcha(token?: string | null): { turnstile_token?: string } {
  return token ? { turnstile_token: token } : {};
}

export async function verifyEmail(token: string): Promise<void> {
  await postJson("/auth/verify-email", { token });
}

export async function resendVerification(email: string, captchaToken?: string | null): Promise<void> {
  await postJson("/auth/resend-verification", { email, ...captcha(captchaToken) });
}

/** Creates the first administrator. Requires the one-time token the server
 *  prints on its console at startup. Does not sign in; the caller does that. */
export async function completeSetup(input: {
  setupToken: string;
  organisation: string;
  email: string;
  password: string;
}, captchaToken?: string | null): Promise<void> {
  const res = await apiFetch(`${API_URL}/auth/register`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      setup_token: input.setupToken.trim(),
      tenant_name: input.organisation,
      email: input.email,
      password: input.password,
      ...captcha(captchaToken),
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.detail || failed(), res.status, data.code);
}

/** Either the session started, or a second factor is required. */
export type LoginResult =
  | { mfaRequired: false }
  | { mfaRequired: true; mfaToken: string };

export async function login(email: string, password: string, captchaToken?: string | null): Promise<LoginResult> {
  const body = new URLSearchParams();
  body.set("username", email);
  body.set("password", password);
  if (captchaToken) body.set("turnstile_token", captchaToken);

  const res = await apiFetch(`${API_URL}/auth/login`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.detail || failed(), res.status, data.code);

  // The password was right but it is only the first factor. No session cookie
  // has been set; the caller must complete verifyMfa() below.
  if (data.mfa_required) return { mfaRequired: true, mfaToken: data.mfa_token };

  // The response body also includes an access_token for non-browser API
  // clients, but the dashboard ignores it — the httpOnly cookie the
  // response just set is what authenticates subsequent requests.
  return { mfaRequired: false };
}

export interface MfaVerifyResult {
  used_recovery_code: boolean;
  recovery_codes_remaining: number | null;
}

/** Second step of login. `code` is a TOTP code; `recoveryCode` is one of the
 *  single-use backup codes. */
export async function verifyMfa(
  mfaToken: string,
  value: string,
  kind: "code" | "recovery" = "code"
): Promise<MfaVerifyResult> {
  const res = await apiFetch(`${API_URL}/auth/mfa/verify`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      mfa_token: mfaToken,
      ...(kind === "code" ? { code: value } : { recovery_code: value }),
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(data.detail || failed(), res.status, data.code);
  return data;
}

// ---------- MFA management (signed in) ----------

export interface MfaStatus {
  enabled: boolean;
  enrolled_at: string | null;
  recovery_codes_remaining: number;
}

export function getMfaStatus(): Promise<MfaStatus> {
  return request<MfaStatus>("/auth/mfa");
}

export function startMfaSetup(): Promise<{ secret: string; otpauth_uri: string }> {
  return request<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup", { method: "POST" });
}

/** Confirms enrolment. The returned recovery codes are shown once and never
 *  retrievable again — only hashes are stored server-side. */
export function enableMfa(code: string): Promise<{ enabled: boolean; recovery_codes: string[] }> {
  return request<{ enabled: boolean; recovery_codes: string[] }>("/auth/mfa/enable", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export function disableMfa(password: string, code: string): Promise<{ enabled: boolean }> {
  return request<{ enabled: boolean }>("/auth/mfa/disable", {
    method: "POST",
    body: JSON.stringify({ password, code }),
  });
}

export function regenerateRecoveryCodes(password: string): Promise<{ recovery_codes: string[] }> {
  return request<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export async function logout(): Promise<void> {
  try {
    await apiFetch(`${API_URL}/auth/logout`, { method: "POST", credentials: "include" });
  } catch {
    // Best-effort — the cookie will simply expire on its own otherwise.
  }
}

export function isLoggedIn(): boolean {
  return hasSessionFlag();
}

/** Mirrors the backend's AccessState: what this workspace's subscription
 *  currently permits. */
export type AccessState = "ok" | "readonly" | "blocked";

export interface CurrentUser {
  id: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  status: "active" | "invited" | "disabled";
  tenant_id: string;
  tenant_name: string | null;
  trial_ends_at: string | null;
  access_state: AccessState;
  /** The workspace this session acts in (a person can belong to several). */
  workspace?: { id: string; name: string; role: Role; region: string; currency: string } | null;
  home_workspace_id?: string;
  /** Effective regional settings (the person's, else the workspace's). */
  settings?: RegionalSettings | null;
  /** The person's own choices only; null = not chosen. */
  preferences?: Partial<Record<keyof RegionalSettings, string | null>>;
}

type Role = "admin" | "analyst" | "viewer";
export interface RegionalSettings { timezone: string; locale: string; date_format: DateFormat; time_format: TimeFormat }

export async function getMe(): Promise<CurrentUser> {
  const me = await request<CurrentUser>("/auth/me");
  // Present times the way this person chose; the browser's zone unless they picked one.
  if (me.settings) {
    setDisplaySettings({
      timeZone: me.preferences?.timezone ?? undefined,
      dateFormat: me.settings.date_format, timeFormat: me.settings.time_format,
    });
  }
  return me;
}

// ---------- Workspaces ----------

export interface WorkspaceSummary { id: string; name: string; role: Role; status: "active" | "invited"; home: boolean; region: string }

export function getWorkspaces(): Promise<{ current: string; default: string | null; workspaces: WorkspaceSummary[] }> {
  return request("/workspaces");
}

/** Starts a session in another workspace (new cookies); the page should reload. */
export function switchWorkspace(workspaceId: string): Promise<{ workspace: { id: string; name: string; role: Role } }> {
  return request("/workspaces/switch", { method: "POST", body: JSON.stringify({ workspace_id: workspaceId }) });
}

export function createWorkspace(input: { name: string; currency?: string; timezone?: string }): Promise<{ id: string; name: string }> {
  return request("/workspaces", { method: "POST", body: JSON.stringify(input) });
}

export function leaveWorkspace(workspaceId: string): Promise<{ status: string }> {
  return request("/workspaces/leave", { method: "POST", body: JSON.stringify({ workspace_id: workspaceId }) });
}

/** Accepts an invitation to another workspace while signed in (existing accounts). */
export function acceptWorkspaceInvite(token: string): Promise<{ workspace_id: string; role: Role }> {
  return request("/workspaces/invitations/accept", { method: "POST", body: JSON.stringify({ token }) });
}

export interface WorkspaceSettings {
  id: string; name: string; region: string; timezone: string; locale: string; currency: string;
  date_format: DateFormat; time_format: TimeFormat;
  options: { currencies: string[]; locales: string[]; date_formats: DateFormat[]; time_formats: TimeFormat[] };
}
export function getWorkspaceSettings(): Promise<WorkspaceSettings> {
  return request("/workspace/settings");
}
export function updateWorkspaceSettings(patch: Partial<Pick<WorkspaceSettings, "name" | "timezone" | "currency" | "date_format" | "time_format">>): Promise<WorkspaceSettings> {
  return request("/workspace/settings", { method: "PATCH", body: JSON.stringify(patch) });
}
export function updatePreferences(patch: Partial<Record<"timezone" | "date_format" | "time_format", string | null>>): Promise<{ settings: RegionalSettings }> {
  return request("/auth/me/preferences", { method: "PATCH", body: JSON.stringify(patch) });
}

/** Emails a reset link if the address has an account; the answer is the same either way. */
export async function forgotPassword(email: string, captchaToken?: string | null): Promise<void> {
  await postJson("/auth/forgot-password", { email, ...captcha(captchaToken) });
}

export function resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
  return request<{ message: string }>("/auth/reset-password", {
    method: "POST",
    body: JSON.stringify({ token, new_password: newPassword }),
  });
}

export function changePassword(
  currentPassword: string,
  newPassword: string
): Promise<{ message: string }> {
  return request<{ message: string }>("/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

// ---------- Team invitations ----------

export interface InvitePreview {
  email: string;
  role: "admin" | "analyst" | "viewer";
  tenant_name: string | null;
  /** The address already has a Legion account: accept by signing in, not by choosing a password. */
  existing_account?: boolean;
}

/** Public: reads an invitation so the accept page can show who it's for. */
/** POST with the token in the body — never in a URL, where proxies log it. */
export function getInvite(token: string): Promise<InvitePreview> {
  return request<InvitePreview>("/auth/invite/preview", { method: "POST", body: JSON.stringify({ token }) });
}

export function acceptInvite(token: string, password: string): Promise<{ message: string }> {
  return request<{ message: string }>("/auth/accept-invite", {
    method: "POST",
    body: JSON.stringify({ token, password }),
  });
}

export function getAlerts(filters?: {
  severity?: string;
  status?: string;
  q?: string;
}): Promise<Alert[]> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.status) params.set("status", filters.status);
  if (filters?.q) params.set("q", filters.q);
  const qs = params.toString();
  return request<Alert[]>(`/alerts${qs ? `?${qs}` : ""}`);
}

/**
 * The alert list together with the cursor it corresponds to, read from one
 * database snapshot. The live feed needs both: the cursor says exactly which
 * later changes it is responsible for.
 */
export function getAlertFeed(filters?: {
  severity?: string;
  status?: string;
  q?: string;
}, signal?: AbortSignal): Promise<{ alerts: Alert[]; cursor: number }> {
  const params = new URLSearchParams();
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.status) params.set("status", filters.status);
  if (filters?.q) params.set("q", filters.q);
  const qs = params.toString();
  return request<{ alerts: Alert[]; cursor: number }>(`/alerts/feed${qs ? `?${qs}` : ""}`, { signal, cache: "no-store" });
}

/** Everything that changed after `after`, oldest first (see the server's /alerts/sync). */
export function getAlertSync(after: number, signal?: AbortSignal): Promise<{ alerts: Alert[]; cursor: number; has_more: boolean; reset: boolean }> {
  return request(`/alerts/sync?after=${encodeURIComponent(String(after))}&limit=200`, { signal, cache: "no-store" });
}

export function getAlert(id: string): Promise<Alert> {
  return request<Alert>(`/alerts/${id}`);
}

export function getStats(): Promise<AlertStats> {
  return request<AlertStats>("/alerts/stats");
}

/** Reopening a resolved alert needs a reason (recorded in the audit log). */
export function updateAlertStatus(
  id: string,
  status: Alert["status"],
  reason?: string
): Promise<Alert> {
  return request<Alert>(`/alerts/${id}/status`, {
    method: "PATCH",
    body: JSON.stringify(reason ? { status, reason } : { status }),
  });
}

/** Asks why a resolved alert is being reopened. Null: the person cancelled (nothing is changed). */
export function reopenReason(from: Alert["status"] | undefined, to: Alert["status"]): string | null | undefined {
  if (from !== "resolved" || to === "resolved") return undefined;
  const r = typeof window === "undefined" ? null : window.prompt(translations[apiLocale].common.reopenReasonPrompt);
  return r && r.trim() ? r.trim().slice(0, 500) : null;
}

export function explainAlert(id: string, force = false): Promise<Alert> {
  return request<Alert>(`/alerts/${id}/explain${force ? "?force=true" : ""}`, {
    method: "POST",
  });
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface CopilotReply {
  reply: string;
  /** "ai" when a model answered, "local" when Legion's built-in analysis did. */
  source: "ai" | "local";
  ai_generated: boolean;
  /** Always true: nothing in a reply is acted on. */
  advisory: true;
}

export function askCopilot(
  message: string,
  history: ChatMessage[]
): Promise<CopilotReply> {
  return request<CopilotReply>("/copilot/chat", {
    method: "POST",
    body: JSON.stringify({ message, history }),
  });
}

export interface AiSettings {
  enabled: boolean;
  /** The organisation's own choice; null = the server default applies. */
  tenant_setting: boolean | null;
  default_enabled: boolean;
  provider_configured: boolean;
  provider: string | null;
  data_mode: "standard" | "strict";
  /** True when nobody chose the mode: the deployment's starting setting applies. */
  data_mode_is_default: boolean;
  circuit: "closed" | "open";
  advisory: true;
}

export function getAiSettings(): Promise<AiSettings> {
  return request<AiSettings>("/ai/settings");
}

export function updateAiSettings(patch: { enabled?: boolean | null; data_mode?: "standard" | "strict" }): Promise<AiSettings> {
  return request<AiSettings>("/ai/settings", { method: "PATCH", body: JSON.stringify(patch) });
}

export interface Asset {
  id: string;
  name: string;
  os: string;
  ip_address: string | null;
  risk: "critical" | "high" | "medium" | "low";
  online: boolean;
  last_seen: string;
}

export function getAssets(filters?: {
  risk?: string;
  online?: boolean;
  q?: string;
}): Promise<Asset[]> {
  const params = new URLSearchParams();
  if (filters?.risk) params.set("risk", filters.risk);
  if (filters?.online !== undefined) params.set("online", String(filters.online));
  if (filters?.q) params.set("q", filters.q);
  const qs = params.toString();
  return request<Asset[]>(`/assets${qs ? `?${qs}` : ""}`);
}

// ---------- Billing (Paddle) ----------

export interface Subscription {
  status: "trialing" | "active" | "past_due" | "paused" | "canceled";
  paddle_price_id: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  access_state: AccessState;
  trial_ends_at: string | null;
}

/** Returns null (rather than throwing) when the tenant has no
 * subscription on file yet — that's the expected state for a brand new
 * tenant, not an error the caller needs to handle specially. */
export async function getSubscription(): Promise<Subscription | null> {
  try {
    return await request<Subscription>("/billing/subscription");
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export function openBillingPortal(): Promise<{ url: string }> {
  return request<{ url: string }>("/billing/portal", { method: "POST" });
}

/** What the server enforces for this workspace: its plan, add-ons and how much of each limit is used. */
export interface PlanEntitlements extends Entitlements {
  plan: PlanId;
  addons: AddonId[];
  source: "self-hosted" | "override" | "subscription" | "legacy" | "trial";
  usage: {
    endpoints: { used: number; limit: number | null; over: boolean };
    admins: { used: number; limit: number | null; over: boolean };
  };
}

export function getEntitlements(): Promise<PlanEntitlements> {
  return request<PlanEntitlements>("/billing/entitlements");
}

/** The price list as the server has it, with which plans and add-ons can be bought online. */
export interface PlanCatalog {
  plans: Array<{ id: PlanId; buy: { month: boolean; year: boolean } }>;
  addons: Array<{ id: AddonId; buy: boolean }>;
}

export function getPlans(): Promise<PlanCatalog> {
  return request<PlanCatalog>("/billing/plans");
}

export interface CheckoutContext {
  checkout_token: string;
  currency?: string;
  /** Without a plan: the workspace's single price (the old call). */
  price_id?: string | null;
  /** With a plan: what to put in the checkout. */
  items?: Array<{ priceId: string; quantity: number }>;
}

/** The server maps a plan (and add-ons) to Paddle prices; the browser never names one. */
export function getCheckoutContext(choice?: { plan: PlanId; interval: "month" | "year"; addons?: AddonId[] }): Promise<CheckoutContext> {
  return request<CheckoutContext>("/billing/checkout-context", { method: "POST", body: choice ? JSON.stringify(choice) : undefined });
}

// ---------- Users / RBAC ----------

export interface TeamUser {
  id: string;
  email: string;
  role: "admin" | "analyst" | "viewer";
  status: "active" | "invited" | "disabled";
  tenant_id: string;
  created_at: string;
}

export function getUsers(): Promise<TeamUser[]> {
  return request<TeamUser[]>("/users");
}

/** `invite_url` is only returned when SMTP isn't configured (local setup) —
 *  production refuses to boot without it, so it can never appear from a
 *  live server. */
export interface InviteResult extends TeamUser {
  email_sent: boolean;
  invite_url?: string;
}

export function inviteUser(
  email: string,
  role: TeamUser["role"]
): Promise<InviteResult> {
  return request<InviteResult>("/users/invite", {
    method: "POST",
    body: JSON.stringify({ email, role }),
  });
}

export function resendInvite(
  userId: string
): Promise<{ email_sent: boolean; invite_url?: string }> {
  return request<{ email_sent: boolean; invite_url?: string }>(
    `/users/${userId}/resend-invite`,
    { method: "POST" }
  );
}

/** Deactivates rather than deletes — audit rows must keep resolving to a
 *  real identity. */
export function deactivateUser(userId: string): Promise<TeamUser> {
  return request<TeamUser>(`/users/${userId}`, { method: "DELETE" });
}

export function updateUserRole(
  userId: string,
  role: TeamUser["role"]
): Promise<TeamUser> {
  return request<TeamUser>(`/users/${userId}/role`, {
    method: "PATCH",
    body: JSON.stringify({ role }),
  });
}

// ---------- Audit log ----------

export interface AuditLogEntry {
  id: string;
  user_email: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  detail: string | null;
  ip_address: string | null;
  created_at: string;
}

export function getAuditLogs(filters?: {
  action?: string;
  resource_id?: string;
  limit?: number;
}): Promise<AuditLogEntry[]> {
  const params = new URLSearchParams();
  if (filters?.action) params.set("action", filters.action);
  if (filters?.resource_id) params.set("resource_id", filters.resource_id);
  if (filters?.limit) params.set("limit", String(filters.limit));
  const qs = params.toString();
  return request<AuditLogEntry[]>(`/audit${qs ? `?${qs}` : ""}`);
}

// ---------- Notification settings ----------

export interface NotificationSettings {
  /** The confirmed address alert emails go to. */
  notification_email: string | null;
  /** A requested address waiting for its owner to confirm it; receives nothing yet. */
  pending_notification_email?: string | null;
  /** Whether a confirmation email went out on this save. */
  confirmation_sent?: boolean;
  /** Language alert emails are written in. */
  notification_locale: Locale;
}

export function getNotificationSettings(): Promise<NotificationSettings> {
  return request<NotificationSettings>("/notifications/settings");
}

export function updateNotificationSettings(
  notification_email: string | null,
  notification_locale: Locale
): Promise<NotificationSettings> {
  return request<NotificationSettings>("/notifications/settings", {
    method: "PATCH",
    body: JSON.stringify({ notification_email, notification_locale }),
  });
}

/** The recipient of a confirmation email confirms the address (public page). */
export async function confirmNotificationEmail(token: string): Promise<void> {
  await postJson("/notifications/confirm", { token });
}

/** `message` is a human-readable result in the interface language. */
export function sendTestNotification(): Promise<{ status: string; message?: string }> {
  return request<{ status: string; message?: string }>("/notifications/test", { method: "POST" });
}

export { ApiError };


// ---------- Overview and onboarding ----------

export type ProtectionStatus = "not_connected" | "waiting_for_data" | "attention" | "protected";
export type SourceHealth = "receiving" | "waiting" | "silent" | "error" | "paused";
export type OnboardingStepId = "connect" | "first_event" | "notifications" | "team" | "agent";
export type FirewallDecisionName = "ALLOW" | "WARN" | "CONFIRM" | "BLOCK" | "QUARANTINE" | "KILL";

export interface Overview {
  status: ProtectionStatus;
  reasons: string[];
  protected: {
    sources: { kind: string; name: string; health: SourceHealth; last_event_at: string | null }[];
    assets: number;
    assets_online: number;
    agents: { total: number; active: number; stopped: number };
  };
  threats: {
    open: { critical: number; high: number; medium: number; low: number };
    open_total: number;
    new_last_24h: number;
    top: { id: string; title: string; severity: Alert["severity"]; created_at: string }[];
  };
  blocked: {
    window_days: number;
    refused: number;
    contained: number;
    approvals_pending: number;
    recent: { decision_id: string; at: string; agent_id: string; agent_name: string | null; action: string; decision: FirewallDecisionName; rules: string[]; reason: string | null }[];
  };
  onboarding: { steps: { id: OnboardingStepId; done: boolean; optional: boolean }[]; complete: boolean };
}

export function getOverview(): Promise<Overview> {
  return request("/overview");
}

// ---------- Connect (sensor keys, integrations) ----------

export interface SensorKey {
  id: string;
  label: string;
  status: "active" | "rotating" | "expired" | "revoked";
  created_at: string;
  last_used_at: string | null;
}
export interface IssuedSensorKey extends SensorKey { secret: string; api_key: string }

export function getSensorKeys(): Promise<{ credentials: SensorKey[] }> {
  return request("/security-events/credentials");
}
export function createSensorKey(label: string): Promise<IssuedSensorKey> {
  return request("/security-events/credentials", { method: "POST", body: JSON.stringify({ label }) });
}
export function revokeSensorKey(id: string): Promise<{ status: string }> {
  return request(`/security-events/credentials/${encodeURIComponent(id)}`, { method: "DELETE" });
}
export function sendTestAlert(): Promise<{ alert_id: string }> {
  return request("/security-events/test", { method: "POST" });
}

export interface IntegrationInfo {
  kind: string;
  displayName: string;
  vendor: string;
  status: "available" | "planned";
  plane: "data" | "tool";
  inbound: "push" | "pull" | null;
  outbound: string[];
  summary: string;
  auth: string;
}
export function getIntegrationCatalogue(): Promise<{ integrations: IntegrationInfo[] }> {
  return request("/integrations/catalogue");
}

export interface ConnectionInfo {
  id: string; kind: string; name: string; status: "active" | "paused" | "error" | "disabled";
  config: Record<string, unknown>; has_secrets: boolean; last_success_at: string | null; last_error: string | null; failures: number; created_at: string;
}
export function listConnections(): Promise<{ connections: ConnectionInfo[] }> {
  return request("/integrations");
}
export function createConnection(body: { kind: string; name: string; config: Record<string, unknown>; secrets: Record<string, string> }): Promise<ConnectionInfo> {
  return request("/integrations", { method: "POST", body: JSON.stringify(body) });
}
export function setConnectionStatus(id: string, action: "pause" | "resume"): Promise<ConnectionInfo> {
  return request(`/integrations/${encodeURIComponent(id)}/${action}`, { method: "POST" });
}
export function removeConnection(id: string): Promise<{ status: string }> {
  return request(`/integrations/${encodeURIComponent(id)}`, { method: "DELETE" });
}

function absoluteApi(path: string): string {
  const base = API_URL.startsWith("http") ? API_URL : `${typeof window !== "undefined" ? window.location.origin : ""}${API_URL}`;
  return `${base.replace(/\/+$/, "")}${path}`;
}
/** Where sensors send events: this API's webhook, as an absolute URL. */
export function webhookUrl(): string {
  return absoluteApi("/security-events/webhook");
}
/** Where an AI agent exchanges its ID and secret for a short-lived token. */
export function agentTokenUrl(): string {
  return absoluteApi("/agent/v1/token");
}

// ---------- AI agents ----------

export interface AgentPermissionInfo { id: string; tier: 0 | 1 | 2; asks_first: boolean }
export function getAgentPermissions(): Promise<{ permissions: AgentPermissionInfo[]; never: string[] }> {
  return request("/agent-permissions");
}

export interface AgentSummary {
  id: string;
  name: string;
  description: string;
  owner: { userId: string; active: boolean };
  status: string;
  statusReason: string | null;
  canActNow: boolean;
  blockedBecause: string | null;
  createdAt: string;
  permissions: { granted: string[]; effective: string[] };
  tools: { families: string[]; skills: string[]; used: { action: string; calls: number; lastAt: string }[] };
  connectedSystems: { destinations: string[]; mcpServers: string[]; agents: string[] };
  risk: { level: string; overall: "low" | "medium" | "high" | "critical"; refusalsInWindow: number; containmentsInWindow: number; pendingApprovals: number; behavior: { level: string; score: number } | null };
  activity: { lastActivityAt: string | null; decisionsInWindow: number; activeCredentials: number };
}
export function getAgents(): Promise<{ agents: AgentSummary[] }> {
  return request("/agents/registry");
}
export function createAgent(input: { name: string; description?: string; permissions: string[] }): Promise<{ identity: { id: string; name: string }; credential: { id: string; secret: string } }> {
  return request("/agents", { method: "POST", body: JSON.stringify(input) });
}
export function updateAgentPermissions(id: string, permissions: string[]): Promise<{ identity: { id: string; permissions: string[] } }> {
  return request(`/agents/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ permissions }) });
}
export function pauseAgent(id: string, reason?: string): Promise<unknown> {
  return request(`/agents/${encodeURIComponent(id)}/suspend`, { method: "POST", body: JSON.stringify(reason ? { reason } : {}) });
}
export function resumeAgent(id: string): Promise<unknown> {
  return request(`/agents/${encodeURIComponent(id)}/resume`, { method: "POST", body: JSON.stringify({}) });
}
export function emergencyStopAgent(id: string, reason: string, compromise: "suspected" | "confirmed"): Promise<unknown> {
  return request(`/kill-switch/agents/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify({ reason, compromise }) });
}

export interface AgentDecision {
  decisionId: string;
  occurredAt: string;
  principalId: string;
  action: string;
  permission: string | null;
  decision: FirewallDecisionName;
  destination: string | null;
  ruleHits: { id: string; effect: string; reason: string }[];
}
export function getAgentDecisions(agentId: string): Promise<{ decisions: AgentDecision[] }> {
  return request(`/firewall/decisions?principalId=${encodeURIComponent(agentId)}&limit=50`);
}

export interface ApprovalRequest {
  id: string;
  identityId: string;
  action: string;
  permission: string | null;
  resourceType: string | null;
  resourceId: string | null;
  preview: unknown;
  riskScore: number;
  ruleIds: string[];
  status: "pending" | "approved" | "denied" | "consumed" | "expired" | "cancelled";
  requestedAt: string;
  expiresAt: string;
}
export function getApprovals(status: ApprovalRequest["status"] = "pending"): Promise<{ approvals: ApprovalRequest[] }> {
  return request(`/firewall/approvals?status=${status}`);
}
export function answerApproval(id: string, answer: "approve" | "deny", reason?: string): Promise<{ approval: ApprovalRequest }> {
  return request(`/firewall/approvals/${encodeURIComponent(id)}/${answer}`, { method: "POST", body: JSON.stringify(reason ? { reason } : {}) });
}

// --- Defense: attack campaigns and automatic response ------------------------

export interface AttackCampaign {
  id: string;
  rule: "rapid_chain" | "wide_sweep" | "swarm" | "velocity" | "ai_manipulation";
  subject: string;
  status: "active" | "closed";
  first_seen: string;
  last_seen: string;
  alert_count: number;
  sources: string[];
  targets: string[];
  techniques: string[];
  alert_id: string | null;
}

export interface IpBlock {
  id: string;
  ip: string;
  reason: string;
  campaign_id: string | null;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  automatic: boolean;
  active: boolean;
}

export interface AutoResponseSettings { mode: "off" | "auto"; minutes: number; allowlist: string; acknowledged: boolean }

export async function getCampaigns(): Promise<AttackCampaign[]> {
  return (await request<{ campaigns: AttackCampaign[] }>("/security/campaigns")).campaigns;
}

export async function getBlocks(activeOnly = true): Promise<IpBlock[]> {
  return (await request<{ blocks: IpBlock[] }>(`/security/blocks${activeOnly ? "?active=true" : ""}`)).blocks;
}

export async function blockAddress(ip: string, reason?: string, minutes?: number): Promise<IpBlock> {
  return (await request<{ block: IpBlock }>("/security/blocks", {
    method: "POST", body: JSON.stringify({ ip: ip.trim(), ...(reason?.trim() ? { reason: reason.trim() } : {}), ...(minutes ? { minutes } : {}) }),
  })).block;
}

export async function unblockAddress(ip: string): Promise<void> {
  await request(`/security/blocks/${encodeURIComponent(ip)}`, { method: "DELETE" });
}

export function getAutoResponse(): Promise<AutoResponseSettings> {
  return request<AutoResponseSettings>("/security/auto-response");
}

export function updateAutoResponse(patch: Partial<Omit<AutoResponseSettings, "acknowledged">> & { acknowledge?: boolean }): Promise<AutoResponseSettings> {
  return request<AutoResponseSettings>("/security/auto-response", { method: "PATCH", body: JSON.stringify(patch) });
}


// ---- Legion's five agents and their skills ---------------------------------
export type LegionAgentName = "Sentinel" | "Hunter" | "Guardian" | "Oracle" | "Vanguard";
export interface SkillInfo {
  name: string;
  agent: LegionAgentName;
  title: string;
  description: string;
  requiredPermissions: string[];
}
export function getSkills(): Promise<{ skills: SkillInfo[] }> {
  return request("/skills");
}
export interface SkillAssignmentResult { missingPermissions: string[]; requiredPermissions: string[] }
export function getSkillAssignments(identityId: string): Promise<{ assignments: { skill: string }[] }> {
  return request(`/skills/assignments?identityId=${encodeURIComponent(identityId)}`);
}
export function assignSkill(identityId: string, skill: string): Promise<SkillAssignmentResult> {
  return request("/skills/assignments", { method: "POST", body: JSON.stringify({ identityId, skill }) });
}
export function unassignSkill(identityId: string, skill: string): Promise<unknown> {
  return request(`/skills/assignments/${encodeURIComponent(identityId)}/${encodeURIComponent(skill)}`, { method: "DELETE" });
}

// ---- The seven most dangerous attack types: what Legion sees -----------------
export type ThreatName = "ransomware" | "bec" | "phishing" | "ddos" | "ai_deception" | "espionage" | "supply_chain";
export interface ThreatCoverage {
  threat: ThreatName;
  status: "detected" | "watching" | "blind" | "partial";
  detections: number;
  lastSeen: string | null;
  eventIds: string[];
}
export function getCoverage(): Promise<{ windowDays: number; eventsAnalyzed: number; threats: ThreatCoverage[] }> {
  return request("/security/coverage");
}

// ---- Payment check: payments held until a person confirms them ----------------
export type PaymentHoldReason = "new_beneficiary" | "account_under_attack" | "mailbox_takeover_active" | "rejected_before";
export interface PaymentCheck {
  id: string;
  created_at: string;
  beneficiary_hint: string;
  beneficiary_name: string | null;
  amount: string;
  currency: string;
  requested_by: string | null;
  reference: string | null;
  decision: "allow" | "hold";
  reasons: PaymentHoldReason[];
  resolution: "released" | "rejected" | null;
  resolved_at: string | null;
}
export interface PaymentConsent {
  /** Hosted workspaces only. */
  applicable: boolean;
  acknowledged: boolean;
  /** The payment check refuses to answer until an administrator confirms (a new workspace). */
  required: boolean;
  notice_version: string;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}

export function getPaymentConsent(): Promise<PaymentConsent> {
  return request<PaymentConsent>("/security/payments/consent");
}

export function acknowledgePaymentNotice(): Promise<PaymentConsent> {
  return request<PaymentConsent>("/security/payments/consent", { method: "POST", body: JSON.stringify({ acknowledge: true }) });
}

export function getHeldPayments(): Promise<{ payments: PaymentCheck[] }> {
  return request("/security/payments?held=true");
}
export function releasePayment(id: string): Promise<{ payment: PaymentCheck }> {
  return request(`/security/payments/${encodeURIComponent(id)}/release`, { method: "POST" });
}
export function rejectPayment(id: string): Promise<{ payment: PaymentCheck }> {
  return request(`/security/payments/${encodeURIComponent(id)}/reject`, { method: "POST" });
}

// --- Protection modes: how much Legion may do on its own, because a person said so (SOC core) ---

export type ProtectionMode = "manual" | "hybrid" | "automatic";
export interface ProtectionSettings {
  mode: ProtectionMode; auto_actions: string[]; acknowledged: boolean;
  acknowledged_at: string | null; acknowledged_by: string | null; effective_mode: ProtectionMode;
}
export interface LiveActionInfo { id: string; class: string; summary: string; reversible: boolean }
export interface ProtectionState {
  protection: ProtectionSettings;
  notice: { version: string; lines: string[] };
  live_actions: LiveActionInfo[];
  live_per_hour: number;
  plan_allows: boolean;
  paused: boolean;
}
export interface ProtectionReport {
  days: number;
  totals: { automatic: number; approved_by_person: number; by_person: number; awaiting_approval: number; failed: number; refused_or_cancelled: number };
  recent: Array<{ id: string; action_id: string; target: string | null; status: string; by: string; did: string | null; error: string | null; at: string }>;
  changes: Array<{ at: string; by: string | null; detail: string | null }>;
}
export interface SocApproval {
  id: string; action_id: string; risk_class: string; summary: string; action_digest: string; require_mfa: boolean;
  required_approvals: number; approvals: number; status: string; expires_at: string; created_at: string;
  requested_by: { kind: string; agent?: string };
}

export const getProtection = () => request<ProtectionState>("/soc/protection");
export const getProtectionReport = (days = 7) => request<ProtectionReport>(`/soc/protection/report?days=${days}`);
export function updateProtection(patch: { mode?: ProtectionMode; auto_actions?: string[]; acknowledge?: boolean }): Promise<{ protection: ProtectionSettings }> {
  return request("/soc/protection", { method: "PUT", body: JSON.stringify(patch) });
}
/** The emergency stop: refuses new actions and holds queued ones until lifted. */
export const setActionsPaused = (paused: boolean, reason?: string) =>
  request<{ paused: boolean }>("/actions/controls", { method: "POST", body: JSON.stringify(reason ? { paused, reason } : { paused }) });
export const getSocApprovals = () => request<{ approvals: SocApproval[] }>("/approvals?status=pending");
export function decideSocApproval(a: SocApproval, decision: "approve" | "reject", opts: { reason?: string; mfa_code?: string } = {}) {
  return request(`/approvals/${encodeURIComponent(a.id)}/decision`, {
    method: "POST", body: JSON.stringify({ decision, action_digest: a.action_digest, ...opts }),
  });
}
