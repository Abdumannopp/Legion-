/**
 * Live executors: the actions Legion can really carry out, and the checks that run AT THE MOMENT it does.
 *
 * Reaching here already means the policy engine and the workspace's protection settings agreed. These
 * executors do not trust that: each one checks the facts again (plan, address, allowlist), because the
 * world may have changed between "queued" and "running" — and each is built so that doing it twice does
 * no more harm than doing it once, or is refused on the second try.
 *
 * Today there are two: block an address for a limited time (Wazuh and the dashboard read the same
 * blocklist) and e-mail the administrators. Anything else stays simulation-only (actions/simulate.ts).
 * LIVE_ACTION_IDS (policy/catalog.ts) and the CHECK on tenants.protection_auto_actions list the same two.
 */
import { LIVE_ACTION_IDS } from "../policy/catalog.js";
import * as blocklist from "../blocklist.js";
import { allows, resolvePlan } from "../plan-limits.js";
import { transaction } from "../db/pool.js";
import { enqueueProtectionNotice } from "../protection-notify.js";
import * as store from "../store.js";

/** The executor looked again and declined. The action ends `failed` with this reason; nothing was done. */
export class LiveRefused extends Error {
  constructor(readonly why: "plan" | "not_public" | "allowlisted" | "full" | "no_recipients", message: string) { super(message); }
}

export type LiveResult = Record<string, unknown> & { did: string };
type Executor = (tenantId: string, input: Record<string, unknown>, ctx: { actionId: string; reason: string | null }) => Promise<LiveResult>;

const EXECUTORS: Record<string, Executor> = {
  "ip.block": async (tenantId, input, ctx) => {
    const ip = String(input.ip);
    const minutes = Number(input.minutes);
    // Automatic protection is a plan feature; a workspace that moved to a smaller plan keeps detection only.
    if (!allows(await resolvePlan(tenantId), "autoBlocking")) throw new LiveRefused("plan", "The plan no longer includes automatic blocking");
    if (!blocklist.isPublicAddress(ip)) throw new LiveRefused("not_public", "Not a public internet address: it is never blocked");
    const settings = await blocklist.getSettings(tenantId);
    if (blocklist.isAllowlisted(settings.allowlist, ip)) throw new LiveRefused("allowlisted", "The address is on the workspace allowlist");
    try {
      const { block, created } = await blocklist.addBlock(tenantId, ip, {
        minutes, userId: null, campaignId: typeof input.campaign_id === "string" ? input.campaign_id : null,
        reason: `Protection (${ctx.actionId.slice(0, 8)}): ${String(input.reason ?? ctx.reason ?? "blocked").slice(0, 400)}`,
      });
      await store.audit({
        tenant_id: tenantId, user_id: null, user_email: null, action: "security.auto_block", resource_type: "ip", resource_id: ip,
        detail: `protection, action ${ctx.actionId}, ${minutes} min`, ip_address: null,
      });
      return { did: created ? "block" : "extend_block", ip, minutes, blocked_until: block.expires_at };
    } catch (e) {
      if (e instanceof blocklist.BlockError) throw new LiveRefused("full", e.message);
      throw e;
    }
  },

  "notify.admins": async (tenantId, input, ctx) => {
    const subject = String(input.subject);
    const queued = await transaction((client) => enqueueProtectionNotice(client, tenantId, `notify:${ctx.actionId}`, {
      kind: "notice", title: subject, facts: [["Alert", String(input.alert_id ?? "—")], ["Sent by", "Legion (protection)"]],
      path: input.alert_id ? `/incident/${encodeURIComponent(String(input.alert_id))}` : "/",
    }));
    // dedupe_key makes a repeat queue nothing, so "0" after a retry is fine; with no mail server it is not "sent".
    return { did: "email_administrators", queued };
  },
};

export const hasLiveExecutor = (actionId: string): boolean => actionId in EXECUTORS;

export async function executeLive(tenantId: string, actionId: string, input: Record<string, unknown>, ctx: { actionId: string; reason: string | null }): Promise<LiveResult> {
  const fn = EXECUTORS[actionId];
  if (!fn) throw new Error(`no live executor for ${actionId}`);
  return fn(tenantId, input, ctx);
}

// Kept in step with policy/catalog.ts and the database CHECK (protection.test.ts proves it).
export const EXECUTOR_IDS: readonly string[] = Object.keys(EXECUTORS);
if (EXECUTOR_IDS.length !== LIVE_ACTION_IDS.length || !EXECUTOR_IDS.every((id) => LIVE_ACTION_IDS.includes(id))) {
  throw new Error("LIVE_ACTION_IDS and the live executors disagree");
}
