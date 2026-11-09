/**
 * The integration contract.
 *
 * Legion is a platform that security data flows INTO (findings) and that
 * people and agents act THROUGH. Wazuh is one integration among many; nothing
 * outside src/integrations knows any vendor's payload shape.
 *
 *   data plane   findings into Legion      push (the vendor calls us) or pull (we poll the vendor)
 *   tool plane   actions out of Legion     notify (Slack, Teams, …) or respond (agent tools, MCP, A2A)
 *
 * Every adapter turns vendor data into the same Finding; one ingestion path
 * (ingest.ts) stores it — idempotently, in one transaction with its
 * notifications — so durability, dedupe, realtime, email, SOC alerting and
 * tenant isolation are written once, not per vendor.
 */
import type { z } from "zod";
import type { Severity } from "../types.js";

/** A security finding in Legion's vocabulary, whatever produced it. */
export interface Finding {
  /** Stable id at the source. Together with the source and workspace it makes the alert id, so a re-sent finding is a duplicate, never a second alert. */
  externalId: string;
  title: string;
  severity: Severity;
  /** Human-readable detail (the vendor's text is kept; it is untrusted content). */
  summary: string;
  /** When it happened at the source (ISO), if known and plausible. */
  occurredAt: string | null;
  sourceIp: string | null;
  /** The affected host, account or resource, as the source names it. */
  target: string | null;
  mitre: string[];
  /** 0–100: how sure the source is. */
  confidence: number;
  /** The asset to upsert in the inventory, if the source identifies one. */
  asset?: { name: string; ip: string | null; os: string | null } | null;
}

export type Plane = "data" | "tool";
export type Availability = "available" | "planned";

export interface IntegrationManifest {
  /** Stable id: [a-z][a-z0-9_]* (also the connection's `kind`). */
  kind: string;
  displayName: string;
  vendor: string;
  status: Availability;
  plane: Plane;
  inbound: "push" | "pull" | null;
  outbound: ("notify" | "ticket" | "respond")[];
  /** Hosts a pull/outbound adapter may call (adapterFetch refuses anything else). */
  egressHosts: string[];
  /** What it brings in or does, for the catalogue. */
  summary: string;
  /** How it authenticates to or from the vendor. */
  auth: string;
}

/** A configured connection as an adapter sees it: its settings and opened secrets. */
export interface ConnectionContext {
  id: string;
  tenantId: string;
  config: Record<string, unknown>;
  secrets: Record<string, string>;
}

export type NormalizeResult = { skipped: true; reason: string } | { skipped: false; source: string; findings: Finding[] };

/** A vendor that calls Legion (webhook). Authentication happens before normalize() is called. */
export interface PushAdapter {
  manifest: IntegrationManifest & { inbound: "push" };
  /** Pure: bytes already authenticated and parsed → findings. Must not throw on hostile input. */
  normalize(payload: unknown): NormalizeResult;
}

/** A vendor Legion polls. Runs on whichever instance claims the connection. */
export interface PullAdapter {
  manifest: IntegrationManifest & { inbound: "pull" };
  /** Validates the connection's non-secret settings. */
  configSchema: z.ZodType<Record<string, unknown>>;
  /** Names of the secrets the connection needs (stored sealed, never returned). */
  secretFields: string[];
  /**
   * Findings since `cursor` (null on the first run), and where to resume.
   * At-least-once: a crash after ingest and before the cursor is saved
   * re-delivers the same findings, which ingestion drops as duplicates.
   */
  poll(conn: ConnectionContext, cursor: unknown, signal: AbortSignal): Promise<{ findings: Finding[]; cursor: unknown }>;
}

/** What Legion sends to an outbound connector for one alert. Plain data; the adapter formats it. */
export interface OutboundMessage {
  type: "notify" | "ticket";
  alertId: string;
  title: string;
  severity: Severity;
  summary: string;
  sourceIp: string | null;
  target: string | null;
  /** Link back to the alert in the dashboard. */
  link: string;
  /** Set by the delivery layer on a retry: a ticket an earlier attempt already created (audit A-6). */
  ticket?: { key?: string; url?: string };
  /** Set by the delivery layer: when an earlier attempt started creating a ticket whose outcome is unknown (ISO time). */
  createAttemptedAt?: string;
}

/** Lets an adapter record, durably and at once, what it has done so far, so a retry can pick up from there. */
export type RememberFn = (patch: Record<string, unknown>) => Promise<void>;

export interface DeliveryResult {
  /** The external object that was created (a ticket), if any. */
  ref?: { key: string; url: string };
}

/** Thrown by an adapter when retrying cannot help (bad credentials, unknown project): the job is dead-lettered at once. */
export class PermanentDeliveryError extends Error {}

/**
 * Thrown by an adapter that is deliberately waiting (not failing): the message is retried later, but the wait is
 * not counted against the connection's health, so a healthy connection is never stopped for being careful.
 */
export class DeferredDelivery extends Error {}

/**
 * A connector Legion sends INTO (chat notification, ticket). It can tell a person or open a ticket; it
 * can never change anything in the customer's environment: `outbound` is "notify" or "ticket" only, and a
 * test fails if an outbound adapter claims "respond" or reaches the blocklist/action code.
 */
export interface OutboundAdapter {
  manifest: IntegrationManifest & { inbound: null; plane: "tool" };
  configSchema: z.ZodType<Record<string, unknown>>;
  secretFields: string[];
  /** Rejects secrets that cannot be right (a Slack URL on another host) when the connection is saved. */
  validateSecrets?(secrets: Record<string, string>): string | null;
  /** At-least-once: must be idempotent per message.alertId where the vendor allows it (tickets look the alert up first). */
  deliver(conn: ConnectionContext, message: OutboundMessage, signal: AbortSignal, remember?: RememberFn): Promise<DeliveryResult>;
}

export type Adapter = PushAdapter | PullAdapter | OutboundAdapter;
