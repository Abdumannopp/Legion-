import type { Locale } from "./i18n.js";

export type Role = "admin" | "analyst" | "viewer";
export type Severity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "open" | "investigating" | "resolved";
export type Agent = "Sentinel" | "Hunter" | "Guardian" | "Oracle" | "Executor";

/** `invited` users have no usable password yet and cannot authenticate.
 *  `disabled` users are kept for audit-log integrity but are locked out. */
export type UserStatus = "active" | "invited" | "disabled";

/** What a tenant is currently allowed to do, derived from its subscription.
 *  `readonly` is the past_due grace state: existing data stays visible so an
 *  unpaid invoice never hides a live security incident. */
export type AccessState = "ok" | "readonly" | "blocked";

export interface Tenant {
  id: string;
  name: string;
  notification_email: string | null;
  /** Requested but not yet confirmed by its owner; receives nothing until then. */
  notification_email_pending: string | null;
  /** Language of this organisation's alert emails. */
  notification_locale: Locale;
  /** End of the self-serve trial. Sales can extend this without touching code. */
  trial_ends_at: string | null;
  created_at: string;
  /** This organisation's own choice about AI analysis. Null = never chosen:
   *  the deployment default applies (ai-policy.ts). */
  ai_enabled: boolean | null;
  /** "strict" swaps IPs, e-mail addresses and hostnames for placeholders
   *  before anything reaches the provider. */
  ai_data_mode: "standard" | "strict";
  /** Where this workspace's data lives (null: created before regions — this deployment's). */
  region: string | null;
  timezone: string;
  locale: string;
  /** ISO 4217; what the workspace is billed in. */
  currency: string;
  date_format: string;
  time_format: string;
}

export interface User {
  id: string;
  email: string;
  password_hash: string;
  tenant_id: string;
  role: Role;
  status: UserStatus;
  token_version: number;
  /** SHA-256 of the emailed reset token. The token itself is never stored. */
  reset_token_hash: string | null;
  reset_expires: string | null;
  /** SHA-256 of the emailed invitation token. */
  invite_token_hash: string | null;
  invite_expires: string | null;
  invited_by: string | null;
  created_at: string;
  mfa_enabled: boolean;
  /** The TOTP seed, sealed with AES-256-GCM (secret-box.ts). Present once setup
   *  has started, even before the user has confirmed a first code and switched
   *  `mfa_enabled` on. Read it with mfa.secretFor(), never directly. */
  mfa_secret_enc: string | null;
  /** A seed still in PLAINTEXT, from before encryption at rest. Converted at
   *  boot (secrets-migration.ts) or on first use; nothing writes it any more. */
  mfa_secret_legacy: string | null;
  mfa_enrolled_at: string | null;
  /** Null until the owner of the address follows the emailed link (hosted
   *  sign-up only; invited and first-run accounts are verified on creation). */
  email_verified_at: string | null;
  /** The workspace that created this account (users.tenant_id). `tenant_id`
   *  and `role` are the ACTIVE workspace's once the request is authenticated
   *  (workspaces.ts); for a user loaded straight from the table they are the
   *  home workspace's. */
  home_tenant_id?: string;
  /** The workspace a sign-in lands in; null = home. */
  default_workspace_id?: string | null;
  timezone?: string | null;
  locale?: string | null;
  date_format?: string | null;
  time_format?: string | null;
}

export interface Alert { id: string; tenant_id: string; title: string; severity: Severity; agent: Agent; status: AlertStatus; summary: string; confidence: number; created_at: string; ai_explanation: string | null; ai_explanation_locale: Locale | null; /** Written by a model, or by Legion's deterministic fallback. Null: predates this field. */ ai_explanation_source: "ai" | "local" | null; explained_at: string | null; /** This alert's version: per-tenant, bumped by every change, assigned in commit order. */ seq: number; /** The seq it was created with; a change with created_seq above a client's baseline is an alert that client has not seen. */ created_seq: number; source_ip: string | null; target: string | null; mitre_technique: string | null; source: string; /** When the event happened at its source (the sensor's own timestamp), if it said; created_at is when Legion stored it. They differ when a sensor re-sends after an outage. */ occurred_at: string | null }
export interface Asset { id: string; tenant_id: string; name: string; os: string; ip_address: string | null; risk: Severity; online: boolean; last_seen: string }
export interface AuditLog { id: string; tenant_id: string; user_id: string | null; user_email: string | null; action: string; resource_type: string | null; resource_id: string | null; detail: string | null; ip_address: string | null; created_at: string }
export interface Subscription { tenant_id: string; status: "trialing" | "active" | "past_due" | "paused" | "canceled"; paddle_customer_id: string; paddle_subscription_id: string | null; paddle_price_id: string | null; current_period_end: string | null; cancel_at_period_end: boolean; last_event_at: string | null }
export interface Database { tenants: Tenant[]; users: User[]; alerts: Alert[]; assets: Asset[]; audit: AuditLog[]; subscriptions: Subscription[] }
