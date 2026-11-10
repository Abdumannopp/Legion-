import { z } from "zod";
import { proposedActionSchema, riskLevel, untrustedSummarySchema, type PaymentRecord, type SkillDefinition } from "../types.js";
import { assemblyOf, clip, HOUR_MS, isoMinusHours, propose } from "./common.js";

/*
 * Vanguard: what Legion's payment check has held, what is still waiting for
 * a person, and which patterns look like an attacker working through a
 * payment process. Reads the checks only; releasing or rejecting a payment is
 * a person's decision (Defense → Payments on hold).
 */

const STALE_HOURS = 24;
const REPEAT_HOLDS = 3;
const REQUESTER_NEW_ACCOUNTS = 3;

const input = z.strictObject({
  windowDays: z.number().int().min(1).max(90).default(30),
  limit: z.number().int().min(1).max(500).default(500),
});

const money = z.record(z.string(), z.number());

const output = z.strictObject({
  window: z.strictObject({ from: z.string(), to: z.string() }),
  checksAnalyzed: z.number().int(),
  summary: z.strictObject({
    allowed: z.number().int(),
    held: z.number().int(),
    waiting: z.number().int(),
    released: z.number().int(),
    rejected: z.number().int(),
    heldAmountByCurrency: money,
    waitingAmountByCurrency: money,
    oldestWaitingHours: z.number().nullable(),
  }),
  waiting: z.array(z.strictObject({
    id: z.string(),
    account: z.string(),
    name: z.string().nullable(),
    amount: z.number(),
    currency: z.string(),
    requestedBy: z.string().nullable(),
    waitingHours: z.number(),
    reasons: z.array(z.string()),
    stale: z.boolean(),
  })).max(50),
  patterns: z.array(z.strictObject({
    id: z.enum(["repeat_attempts", "requester_many_new_accounts", "retry_after_rejection", "released_to_new_account"]),
    riskLevel,
    subject: z.string(),
    reason: z.string(),
    checkIds: z.array(z.string()).max(20),
  })).max(20),
  overallRisk: riskLevel,
  proposedActions: z.array(proposedActionSchema).max(20),
  untrusted: untrustedSummarySchema,
  limitations: z.array(z.string()),
});

type Input = z.infer<typeof input>;
type Output = z.infer<typeof output>;

const add = (m: Record<string, number>, currency: string, amount: number) => { m[currency] = Math.round(((m[currency] ?? 0) + amount) * 100) / 100; };
const isHeld = (p: PaymentRecord) => p.decision === "hold";

export const paymentFraudReview: SkillDefinition<Input, Output> = {
  name: "payment_fraud_review",
  agent: "Vanguard",
  title: "Payment Fraud Review",
  description: "Reviews Legion's payment checks: how many payments were allowed or held, which are still waiting for a person to confirm by phone (and for how long), and patterns that look like fraud: repeated attempts to one account, one requester asking for several new accounts, a payment retried after a rejection, a large release to a new account. Never shows an account number.",
  version: "1.0.0",
  input,
  output,
  capabilities: ["read:payments"],
  auditEvents: ["skill.invoke"],
  example: { windowDays: 30 },
  limitations: [
    "It sees only payments your payment software asked Legion about. A payment made without asking is invisible.",
    "Accounts are shown by their last four characters only, so two different accounts can look alike. Names are typed by whoever raised the payment and can be wrong or false.",
    "It never releases, rejects or stops a payment. A person confirms by calling a number they already had, then decides in Defense → Payments on hold.",
    "Legion does not check the bank, the supplier's identity or the amount against an invoice.",
  ],
  async handler(ctx, q) {
    const to = ctx.now.toISOString();
    const from = isoMinusHours(ctx.now, q.windowDays * 24);
    const checks = await ctx.data.payments({ since: from, limit: q.limit });
    const held = checks.filter(isHeld);
    const waiting = held.filter((p) => !p.resolution);

    const heldAmount: Record<string, number> = {};
    const waitingAmount: Record<string, number> = {};
    for (const p of held) add(heldAmount, p.currency, p.amount);
    for (const p of waiting) add(waitingAmount, p.currency, p.amount);
    const hoursWaiting = (p: PaymentRecord) => Math.max(0, (ctx.now.getTime() - new Date(p.createdAt).getTime()) / HOUR_MS);
    const waitingRows = waiting.map((p) => ({
      id: p.id, account: p.beneficiaryHint, name: p.beneficiaryName ? clip(p.beneficiaryName, 120) : null, amount: p.amount, currency: p.currency,
      requestedBy: p.requestedBy ? clip(p.requestedBy, 120) : null, waitingHours: Math.round(hoursWaiting(p) * 10) / 10, reasons: p.reasons,
      stale: hoursWaiting(p) >= STALE_HOURS,
    })).sort((a, b) => b.waitingHours - a.waitingHours);

    // ---- patterns --------------------------------------------------------------------------
    const patterns: Output["patterns"] = [];
    const byAccount = new Map<string, PaymentRecord[]>();
    for (const p of checks) byAccount.set(p.beneficiaryHint, [...(byAccount.get(p.beneficiaryHint) ?? []), p]);
    for (const [hint, list] of byAccount) {
      const heldHere = list.filter(isHeld);
      if (heldHere.length >= REPEAT_HOLDS) {
        patterns.push({ id: "repeat_attempts", riskLevel: "high", subject: hint, checkIds: heldHere.map((p) => p.id).slice(0, 20),
          reason: `${heldHere.length} payments to account ${hint} were held. Someone keeps trying the same account.` });
      }
      const sorted = [...list].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      const rejected = sorted.find((p) => p.resolution === "rejected" && p.resolvedAt);
      const after = rejected && sorted.find((p) => p.id !== rejected.id && p.createdAt > rejected.resolvedAt!);
      if (rejected && after) {
        patterns.push({ id: "retry_after_rejection", riskLevel: "critical", subject: hint, checkIds: [rejected.id, after.id],
          reason: `A payment to account ${hint} was rejected, and the account was tried again afterwards.` });
      }
      const bigRelease = list.filter((p) => p.resolution === "released" && p.reasons.includes("new_beneficiary")).sort((a, b) => b.amount - a.amount)[0];
      if (bigRelease) {
        patterns.push({ id: "released_to_new_account", riskLevel: "medium", subject: hint, checkIds: [bigRelease.id],
          reason: `${bigRelease.amount} ${bigRelease.currency} was released to account ${hint}, which was new. Worth a second look at the call that confirmed it.` });
      }
    }
    const byRequester = new Map<string, Set<string>>();
    const requesterIds = new Map<string, string[]>();
    for (const p of held.filter((x) => x.reasons.includes("new_beneficiary") && x.requestedBy)) {
      const who = p.requestedBy!.toLowerCase();
      byRequester.set(who, (byRequester.get(who) ?? new Set()).add(p.beneficiaryHint));
      requesterIds.set(who, [...(requesterIds.get(who) ?? []), p.id]);
    }
    for (const [who, accounts] of byRequester) {
      if (accounts.size >= REQUESTER_NEW_ACCOUNTS) {
        patterns.push({ id: "requester_many_new_accounts", riskLevel: "high", subject: clip(who, 120), checkIds: requesterIds.get(who)!.slice(0, 20),
          reason: `${clip(who, 120)} asked for payments to ${accounts.size} different new accounts. Their account may be taken over.` });
      }
    }
    const order = { critical: 4, high: 3, medium: 2, low: 1 } as const;
    patterns.sort((a, b) => order[b.riskLevel] - order[a.riskLevel]);

    // ---- recommendations: never executed ---------------------------------------------------
    const assembly = assemblyOf([]);
    const proposedActions: Output["proposedActions"] = [
      ...waitingRows.slice(0, 10).map((w) => propose(assembly, {
        action: "confirm_by_phone", humanOnly: true, permission: null, destructive: false,
        description: `Call ${w.name ?? `the holder of account ${w.account}`} on a phone number you ALREADY had (never one from the email or the invoice), then release or reject ${w.amount} ${w.currency}${w.stale ? ` (waiting ${Math.round(w.waitingHours)} hours)` : ""} in Defense → Payments on hold.`,
      })),
      ...patterns.filter((p) => p.id === "requester_many_new_accounts").slice(0, 5).map((p) => propose(assembly, {
        action: "reset_credentials", humanOnly: true, permission: null, destructive: false,
        description: `Check whether ${p.subject}'s account or mailbox is taken over: reset the password, end its sessions, look for forwarding rules.`,
      })),
    ];

    const top = patterns.length ? patterns[0]!.riskLevel : waitingRows.some((w) => w.stale) ? "medium" : waiting.length ? "low" : "low";
    return {
      window: { from, to },
      checksAnalyzed: checks.length,
      summary: {
        allowed: checks.length - held.length, held: held.length, waiting: waiting.length,
        released: held.filter((p) => p.resolution === "released").length, rejected: held.filter((p) => p.resolution === "rejected").length,
        heldAmountByCurrency: heldAmount, waitingAmountByCurrency: waitingAmount,
        oldestWaitingHours: waitingRows.length ? waitingRows[0]!.waitingHours : null,
      },
      waiting: waitingRows.slice(0, 50),
      patterns: patterns.slice(0, 20),
      overallRisk: top,
      proposedActions,
      untrusted: ctx.untrusted(),
      limitations: [...paymentFraudReview.limitations],
    };
  },
};
