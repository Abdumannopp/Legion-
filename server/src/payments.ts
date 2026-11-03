/**
 * Payment check: stopping financial fraud before the money leaves.
 *
 * Business email compromise, deepfake "CEO" calls and stolen accounts all end
 * the same way: a payment to an account the attacker controls. Legion is not
 * in the payment path, so the customer's payment software (ERP, bank
 * connector, treasury tool) asks Legion first, with the sensor credential it
 * already has:
 *
 *   POST /security-events/payment-check   (signed, like the blocklist)
 *   { "action": "payment-check", "beneficiary": { "account": "...", "name": "..." },
 *     "amount": 12500, "currency": "USD", "requestedBy": "dana@acme.example" }
 *
 * Legion answers "allow" or "hold", with reasons. A hold stays until a person
 * confirms the payment by calling a number they already had (never one from
 * the email or the call) and releases it in the dashboard; the payment
 * software asks again and gets "allow".
 *
 * Held when:
 *   new_beneficiary          the account has never been confirmed for this
 *                            organisation (the classic "our bank details changed").
 *   account_under_attack     the person asking is the subject of an active
 *                            mailbox takeover or broken-into-account campaign.
 *   mailbox_takeover_active  any mailbox in the organisation shows takeover
 *                            signs in the last 48 hours.
 *   rejected_before          a person rejected this same payment.
 *
 * The account number itself is never stored: only a keyed hash (to recognise
 * it again) and its last four characters (for a person to recognise it).
 */
import { createHmac, randomBytes } from "node:crypto";
import { z } from "zod";
import { clip } from "./ai-safety.js";
import { config } from "./config.js";
import { queryAll, queryOne } from "./db/pool.js";
import * as outbox from "./outbox.js";
import * as store from "./store.js";

export const PAYMENT_CHECK_PATH = "/security-events/payment-check";
export const PAYMENT_SOURCE = "legion-payments";
export const ATTACK_WINDOW_DAYS = 7;
export const MAILBOX_WINDOW_HOURS = 48;
export const RELEASE_VALID_DAYS = 7;

// A payment is money: odd text is refused, never silently changed (an account
// with a hidden character would otherwise be recognised as a different account).
const text = (min: number, max: number) => z.string().refine((s) => !s.includes("\u0000"), "Text must not contain control characters").pipe(z.string().trim().min(min).max(max));

export const paymentCheckSchema = z.strictObject({
  action: z.literal("payment-check"),
  beneficiary: z.strictObject({
    account: text(4, 64),
    name: text(0, 200).optional(),
  }),
  amount: z.number().finite().nonnegative().max(1e13),
  currency: z.string().trim().regex(/^[A-Za-z0-9]{2,10}$/),
  requestedBy: text(1, 200).optional(),
  reference: text(0, 200).optional(),
});
export type PaymentCheckInput = z.infer<typeof paymentCheckSchema>;

export const HOLD_REASONS = ["new_beneficiary", "account_under_attack", "mailbox_takeover_active", "rejected_before"] as const;
export type HoldReason = (typeof HOLD_REASONS)[number];

const REASON_TEXT: Record<HoldReason, string> = {
  new_beneficiary: "This account has never been confirmed for your organisation. Changed bank details are how most payment fraud starts.",
  account_under_attack: "The person asking for this payment is the subject of an active account or mailbox takeover.",
  mailbox_takeover_active: "A mailbox in your organisation shows takeover signs in the last 48 hours.",
  rejected_before: "A person in your organisation rejected this same payment.",
};

export const VERIFY_ADVICE = "Confirm the payment by calling the supplier or colleague on a phone number you already had — never one from the email, the invoice or the call itself; a familiar voice or video can be synthetic. Then release it in Legion (Defense → Payments on hold).";

export function normaliseAccount(account: string): string {
  return account.replace(/[\s.-]/g, "").toUpperCase();
}

/** Recognises the account again without storing it. */
export function beneficiaryHash(tenantId: string, account: string): string {
  return createHmac("sha256", config.webhookSecret || "legion-payments").update(`${tenantId}:${normaliseAccount(account)}`).digest("hex");
}

export function accountHint(account: string): string {
  return `…${normaliseAccount(account).slice(-4)}`;
}

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
  reasons: HoldReason[];
  resolution: "released" | "rejected" | null;
  resolved_at: string | null;
}

const COLUMNS = "id, created_at, beneficiary_hint, beneficiary_name, amount::text AS amount, currency, requested_by, reference, decision, reasons, resolution, resolved_at";

const money = (amount: number, currency: string) => `${amount.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${currency}`;

/** Per organisation, so a stolen sensor key used from many addresses cannot flood the table and the alert list. */
export const CHECKS_PER_MINUTE = 120;
export const ALERTS_PER_HOUR = 20;
export class PaymentRateLimited extends Error {
  constructor() { super("Too many payment checks"); this.name = "PaymentRateLimited"; }
}

export async function checkPayment(tenantId: string, input: PaymentCheckInput): Promise<{ check: PaymentCheck; reasons: { code: HoldReason; message: string }[]; verify: string | null }> {
  const hash = beneficiaryHash(tenantId, input.beneficiary.account);
  const currency = input.currency.toUpperCase();
  const amount = Math.round(input.amount * 100) / 100;
  const requester = input.requestedBy?.toLowerCase() ?? null;

  const recent = await queryOne<{ minute: number; holds: number }>(
    `SELECT count(*) FILTER (WHERE created_at > now() - interval '1 minute')::int AS minute,
            count(*) FILTER (WHERE decision = 'hold' AND created_at > now() - interval '1 hour')::int AS holds
       FROM payment_checks WHERE tenant_id = $1 AND created_at > now() - interval '1 hour'`,
    [tenantId],
  );
  if ((recent?.minute ?? 0) >= CHECKS_PER_MINUTE) throw new PaymentRateLimited();
  const quietAlerts = (recent?.holds ?? 0) >= ALERTS_PER_HOUR;

  const ben = await queryOne<{ verified_at: Date | null }>(
    `INSERT INTO payment_beneficiaries (tenant_id, beneficiary_hash) VALUES ($1, $2)
     ON CONFLICT (tenant_id, beneficiary_hash) DO UPDATE SET last_seen = now()
     RETURNING verified_at`,
    [tenantId, hash],
  );
  // The same payment, already decided by a person.
  const earlier = await queryOne<{ resolution: "released" | "rejected" }>(
    `SELECT resolution FROM payment_checks
      WHERE tenant_id = $1 AND beneficiary_hash = $2 AND amount = $3 AND currency = $4 AND resolution IS NOT NULL
        AND resolved_at > now() - make_interval(days => $5)
      ORDER BY resolved_at DESC LIMIT 1`,
    [tenantId, hash, amount, currency, RELEASE_VALID_DAYS],
  );

  const reasons: HoldReason[] = [];
  if (earlier?.resolution === "rejected") reasons.push("rejected_before");
  if (earlier?.resolution !== "released") {
    if (!ben?.verified_at) reasons.push("new_beneficiary");
    if (requester) {
      const local = requester.split("@")[0]!;
      const attacked = await queryOne<{ n: number }>(
        `SELECT count(*)::int AS n FROM attack_campaigns
          WHERE tenant_id = $1 AND rule IN ('mailbox_takeover', 'account_compromise')
            AND last_seen > now() - make_interval(days => $2)
            AND (lower(subject) = $3 OR lower(subject) = $4)`,
        [tenantId, ATTACK_WINDOW_DAYS, requester, local],
      );
      if ((attacked?.n ?? 0) > 0) reasons.push("account_under_attack");
    }
    if (!reasons.includes("account_under_attack")) {
      const mailbox = await queryOne<{ n: number }>(
        `SELECT count(*)::int AS n FROM attack_campaigns
          WHERE tenant_id = $1 AND rule = 'mailbox_takeover' AND last_seen > now() - make_interval(hours => $2)`,
        [tenantId, MAILBOX_WINDOW_HOURS],
      );
      if ((mailbox?.n ?? 0) > 0) reasons.push("mailbox_takeover_active");
    }
  }
  const decision = reasons.length ? "hold" : "allow";

  const id = `PAY-${randomBytes(8).toString("hex").toUpperCase()}`;
  const check = await queryOne<PaymentCheck>(
    `INSERT INTO payment_checks (tenant_id, id, beneficiary_hash, beneficiary_hint, beneficiary_name, amount, currency, requested_by, reference, decision, reasons)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     RETURNING ${COLUMNS}`,
    [tenantId, id, hash, accountHint(input.beneficiary.account), input.beneficiary.name ? clip(input.beneficiary.name, 200) : null,
      amount, currency, input.requestedBy ? clip(input.requestedBy, 200) : null, input.reference ? clip(input.reference, 200) : null, decision, reasons],
  );

  if (decision === "hold" && !quietAlerts) {
    // One alert per payment per day, however often the payment software asks.
    const day = new Date().toISOString().slice(0, 10);
    const alertId = `PAY-${createHmac("sha256", config.webhookSecret || "legion-payments").update(`${tenantId}:${hash}:${amount}:${currency}:${day}`).digest("hex").slice(0, 16).toUpperCase()}`;
    const who = input.beneficiary.name ? ` (${clip(input.beneficiary.name, 80)})` : "";
    await outbox.insertAlertAndNotify({
      id: alertId, tenant_id: tenantId, status: "open", agent: "Executor",
      severity: reasons.includes("account_under_attack") || reasons.includes("rejected_before") ? "critical" : "high",
      title: clip(`Payment held: ${money(amount, currency)} to ${accountHint(input.beneficiary.account)}${who}`, 300),
      summary: clip(`${reasons.map((r) => REASON_TEXT[r]).join(" ")}${input.requestedBy ? ` Requested by ${clip(input.requestedBy, 120)}.` : ""} ${VERIFY_ADVICE}`, 4000),
      confidence: 90, ai_explanation: null, explained_at: null, source_ip: null, target: null,
      mitre_technique: "T1657", source: PAYMENT_SOURCE, occurred_at: null,
    }, {});
  }
  await store.audit({
    tenant_id: tenantId, user_id: null, user_email: null, action: decision === "hold" ? "security.payment_held" : "security.payment_allowed",
    resource_type: "payment", resource_id: id, detail: `${money(amount, currency)} to ${accountHint(input.beneficiary.account)}${reasons.length ? `: ${reasons.join(", ")}` : ""}`,
    ip_address: null,
  });
  return {
    check: check!,
    reasons: reasons.map((code) => ({ code, message: REASON_TEXT[code] })),
    verify: decision === "hold" ? VERIFY_ADVICE : null,
  };
}

export async function listPayments(tenantId: string, opts: { heldOnly?: boolean } = {}): Promise<PaymentCheck[]> {
  return queryAll<PaymentCheck>(
    `SELECT ${COLUMNS} FROM payment_checks
      WHERE tenant_id = $1 ${opts.heldOnly ? "AND decision = 'hold' AND resolution IS NULL" : ""}
      ORDER BY created_at DESC LIMIT 200`,
    [tenantId],
  );
}

/**
 * A person confirmed (or refused) a held payment. Releasing also confirms the
 * beneficiary, so later payments to the same account are not held for being
 * new. Returns null when there is no such unresolved hold in this tenant.
 */
export async function resolvePayment(tenantId: string, id: string, userId: string, resolution: "released" | "rejected"): Promise<PaymentCheck | null> {
  const row = await queryOne<PaymentCheck & { beneficiary_hash: string }>(
    `UPDATE payment_checks SET resolution = $4, resolved_at = now(), resolved_by = $3
      WHERE tenant_id = $1 AND id = $2 AND decision = 'hold' AND resolution IS NULL
      RETURNING ${COLUMNS}, beneficiary_hash`,
    [tenantId, id, userId, resolution],
  );
  if (!row) return null;
  if (resolution === "released") {
    await queryOne(
      "UPDATE payment_beneficiaries SET verified_at = now(), verified_by = $3 WHERE tenant_id = $1 AND beneficiary_hash = $2",
      [tenantId, row.beneficiary_hash, userId],
    );
  }
  const { beneficiary_hash: _hash, ...check } = row;
  return check;
}

/**
 * Payment checks for the security skills (src/agents.ts). Same data as the
 * dashboard, never an account number: only its last characters.
 */
export async function listPaymentsForSkills(tenantId: string, q: { since?: string; limit: number }) {
  const rows = await queryAll<{
    id: string; created_at: Date; beneficiary_hint: string; beneficiary_name: string | null; amount: string; currency: string;
    requested_by: string | null; decision: "allow" | "hold"; reasons: string[]; resolution: "released" | "rejected" | null; resolved_at: Date | null;
  }>(
    `SELECT id, created_at, beneficiary_hint, beneficiary_name, amount::text AS amount, currency, requested_by, decision, reasons, resolution, resolved_at
       FROM payment_checks
      WHERE tenant_id = $1 ${q.since ? "AND created_at >= $3::timestamptz" : ""}
      ORDER BY created_at DESC LIMIT $2`,
    q.since ? [tenantId, Math.min(Math.max(q.limit, 1), 500), q.since] : [tenantId, Math.min(Math.max(q.limit, 1), 500)],
  );
  return rows.map((r) => ({
    id: r.id, tenantId, createdAt: new Date(r.created_at).toISOString(), beneficiaryHint: r.beneficiary_hint, beneficiaryName: r.beneficiary_name,
    amount: Number(r.amount), currency: r.currency, requestedBy: r.requested_by, decision: r.decision, reasons: r.reasons,
    resolution: r.resolution, resolvedAt: r.resolved_at ? new Date(r.resolved_at).toISOString() : null,
  }));
}
