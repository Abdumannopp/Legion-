/**
 * The closed catalog of actions the SOC core knows. An action that is not here
 * does not exist: the policy engine denies it and the action engine refuses it.
 *
 * Risk class, which agents may propose it and the shape of its input are
 * defined here, in code — never by a policy document and never by a model.
 */
import { isIP } from "node:net";
import { z } from "zod";
import type { Agent } from "../types.js";
import type { RiskClass } from "./types.js";

export const CATALOG_VERSION = "2026-11-04.1";

const noControl = (s: string) => !/[\u0000-\u001f\u007f]/.test(s);
const text = (max: number) => z.string().trim().min(1).max(max).refine(noControl, "Text must not contain control characters");
const ip = z.string().trim().min(2).max(45).refine((v) => isIP(v) !== 0, "Not an IP address");
const alertId = z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_.:-]+$/, "Not an alert id");
const paymentId = z.string().regex(/^PAY-[0-9A-F]{16}$/, "Not a payment id");
const reason = text(500).optional();

export interface CatalogEntry {
  id: string;
  class: RiskClass;
  /** read: changes nothing. write: changes Legion's or a customer system's state. */
  effect: "read" | "write";
  /** Which agents may propose it. Humans are governed by RBAC on the route. */
  agents: readonly Agent[];
  reversible: boolean;
  summary: string;
  input: z.ZodType<Record<string, unknown>>;
  /** The thing the action is about, for records and approvals (never a secret). */
  targetOf: (input: Record<string, unknown>) => string | null;
}

const entries: CatalogEntry[] = [
  {
    id: "alert.explain", class: "R0", effect: "read", agents: ["Oracle"], reversible: true,
    summary: "Explain an alert in plain words",
    input: z.strictObject({ alert_id: alertId }), targetOf: (i) => String(i.alert_id),
  },
  {
    id: "alert.triage", class: "R0", effect: "read", agents: ["Oracle", "Sentinel", "Hunter"], reversible: true,
    summary: "Score an alert's urgency with its reasons",
    input: z.strictObject({ alert_id: alertId }), targetOf: (i) => String(i.alert_id),
  },
  {
    id: "alert.set_status", class: "R1", effect: "write", agents: ["Oracle"], reversible: true,
    summary: "Change an alert's status",
    input: z.strictObject({ alert_id: alertId, status: z.enum(["open", "investigating", "resolved"]) }), targetOf: (i) => String(i.alert_id),
  },
  {
    id: "notify.admins", class: "R1", effect: "write", agents: ["Sentinel", "Oracle", "Vanguard"], reversible: false,
    summary: "E-mail the workspace administrators",
    input: z.strictObject({ subject: text(200), alert_id: alertId.optional() }), targetOf: () => "administrators",
  },
  {
    id: "ip.unblock", class: "R2", effect: "write", agents: ["Vanguard"], reversible: true,
    summary: "Remove an address from the blocklist",
    input: z.strictObject({ ip }), targetOf: (i) => String(i.ip),
  },
  {
    id: "ip.block", class: "R3", effect: "write", agents: ["Vanguard"], reversible: true,
    summary: "Block an address for a limited time",
    input: z.strictObject({ ip, minutes: z.number().int().min(5).max(10_080), reason, campaign_id: z.string().max(64).optional() }),
    targetOf: (i) => String(i.ip),
  },
  {
    id: "payment.reject", class: "R3", effect: "write", agents: ["Vanguard"], reversible: false,
    summary: "Reject a payment that is on hold",
    input: z.strictObject({ payment_id: paymentId, reason }), targetOf: (i) => String(i.payment_id),
  },
  {
    id: "payment.release", class: "R4", effect: "write", agents: ["Vanguard"], reversible: false,
    summary: "Release a payment that is on hold (money leaves)",
    input: z.strictObject({ payment_id: paymentId, reason }), targetOf: (i) => String(i.payment_id),
  },
  {
    id: "account.disable", class: "R4", effect: "write", agents: ["Vanguard"], reversible: true,
    summary: "Disable a user account in a connected identity system",
    input: z.strictObject({ account: text(200), system: z.enum(["entra", "okta", "google"]), reason }), targetOf: (i) => `${String(i.system)}:${String(i.account)}`,
  },
  {
    id: "host.isolate", class: "R4", effect: "write", agents: ["Vanguard"], reversible: true,
    summary: "Isolate a host from the network through an EDR",
    input: z.strictObject({ host: text(200), reason }), targetOf: (i) => String(i.host),
  },
];

const byId = new Map(entries.map((e) => [e.id, Object.freeze(e)]));

export function catalogEntry(id: string): CatalogEntry | null {
  return byId.get(id) ?? null;
}

export function catalogList(): Array<Pick<CatalogEntry, "id" | "class" | "effect" | "agents" | "reversible" | "summary">> {
  return entries.map(({ id, class: c, effect, agents, reversible, summary }) => ({ id, class: c, effect, agents, reversible, summary }));
}

export const ACTION_IDS: readonly string[] = entries.map((e) => e.id);
