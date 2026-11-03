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
  outbound: ("notify" | "respond")[];
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

export type Adapter = PushAdapter | PullAdapter;
