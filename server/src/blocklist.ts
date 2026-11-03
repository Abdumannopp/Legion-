/**
 * Automatic response: the addresses a workspace's Wazuh manager should block.
 *
 * AI-driven attacks move faster than a person reads an alert, so a defence that
 * waits for a person loses the race. Legion keeps a per-workspace blocklist;
 * the Wazuh manager pulls it (integrations/custom-legion.py --sync-blocklist,
 * run by Wazuh's command wodle) and turns each entry into its own active
 * response (firewall-drop on every agent, undone after the configured timeout).
 * Nothing is pushed into the customer's network and Legion holds no Wazuh
 * credentials: the manager asks, signed with its existing sensor credential.
 *
 * Entries come from an administrator (any address, any time) or, when the
 * workspace switched it on, from a campaign (campaigns.ts). Automatic blocking
 * is where a defence can be turned against its owner — an attacker who can make
 * Legion block your partners, or exhaust the list — so it has hard limits:
 *
 *   - off unless an administrator turns it on ('auto'),
 *   - only campaigns that identify ONE attacking address (rapid_chain,
 *     wide_sweep, velocity); never swarm (the subject is your host) nor a
 *     single manipulation attempt (one event is not proof),
 *   - only public addresses, never one on the workspace's allowlist,
 *   - every block expires (auto_block_minutes), at most AUTO_PER_HOUR automatic
 *     blocks an hour and MAX_ACTIVE at once,
 *   - every block and unblock is audited, and an administrator can undo it.
 */
import { BlockList, isIP } from "node:net";
import { randomUUID } from "node:crypto";
import type { Campaign, CampaignRule } from "./campaigns.js";
import { queryAll, queryOne } from "./db/pool.js";
import * as store from "./store.js";

export const AUTO_RULES: ReadonlySet<CampaignRule> = new Set(["rapid_chain", "wide_sweep", "velocity", "credential_attack", "account_compromise"]);

/** The one attacking address a campaign is about, if it is about one. */
export function attackerOf(c: Pick<Campaign, "rule" | "subject" | "sources">): string | null {
  if (!AUTO_RULES.has(c.rule)) return null;
  // account_compromise is about the account; the address that broke in is its only source.
  if (c.rule === "account_compromise") return c.sources.length === 1 ? c.sources[0]! : null;
  return c.subject;
}
export const AUTO_PER_HOUR = 50;
export const MAX_ACTIVE = 1000;

export interface Block {
  id: string;
  ip: string;
  reason: string;
  campaign_id: string | null;
  created_by: string | null;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
  automatic: boolean;
  active: boolean;
}

export interface AutoResponseSettings { mode: "off" | "auto"; minutes: number; allowlist: string }

// --- which addresses may ever be blocked automatically ------------------------

const NON_PUBLIC = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) NON_PUBLIC.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32]] as const) {
  NON_PUBLIC.addSubnet(net, bits, "ipv6");
}

/** IPv4-mapped IPv6 ("::ffff:10.0.0.1") is judged as the IPv4 address it is. */
function unmap(ip: string): string {
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  return m ? m[1]! : ip;
}

/** A routable internet address: not private, loopback, link-local, shared, documentation or multicast. */
export function isPublicAddress(ip: string): boolean {
  const v = unmap(ip.trim());
  const family = isIP(v);
  if (family === 0) return false;
  return !NON_PUBLIC.check(v, family === 4 ? "ipv4" : "ipv6");
}

export type AllowlistResult = { ok: true; list: BlockList; entries: string[] } | { ok: false; error: string };

/** "203.0.113.5, 198.51.100.0/24, 2001:db8::/48" → a BlockList. Empty is valid. */
export function parseAllowlist(text: string): AllowlistResult {
  const list = new BlockList();
  const entries = String(text ?? "").split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  if (entries.length > 200) return { ok: false, error: "At most 200 allowlist entries" };
  for (const entry of entries) {
    const [addr, bitsText, extra] = entry.split("/");
    const family = isIP(addr ?? "");
    if (!addr || family === 0 || extra !== undefined) return { ok: false, error: `Not an IP address or range: ${entry.slice(0, 60)}` };
    const type = family === 4 ? "ipv4" : "ipv6";
    if (bitsText === undefined) { list.addAddress(addr, type); continue; }
    const bits = Number(bitsText);
    const max = family === 4 ? 32 : 128;
    if (!/^\d{1,3}$/.test(bitsText) || bits < (family === 4 ? 8 : 16) || bits > max) {
      return { ok: false, error: `Range too wide or invalid: ${entry.slice(0, 60)}` };
    }
    list.addSubnet(addr, bits, type);
  }
  return { ok: true, list, entries };
}

function allowlisted(allowlist: string, ip: string): boolean {
  const parsed = parseAllowlist(allowlist);
  if (!parsed.ok) return false;
  const v = unmap(ip);
  return parsed.list.check(v, isIP(v) === 4 ? "ipv4" : "ipv6");
}

// --- settings -----------------------------------------------------------------

export async function getSettings(tenantId: string): Promise<AutoResponseSettings> {
  const row = await queryOne<{ auto_block_mode: "off" | "auto"; auto_block_minutes: number; block_allowlist: string }>(
    "SELECT auto_block_mode, auto_block_minutes, block_allowlist FROM tenants WHERE id = $1", [tenantId],
  );
  return { mode: row?.auto_block_mode ?? "off", minutes: row?.auto_block_minutes ?? 60, allowlist: row?.block_allowlist ?? "" };
}

export async function updateSettings(tenantId: string, patch: Partial<AutoResponseSettings>): Promise<AutoResponseSettings> {
  if (patch.allowlist !== undefined) {
    const parsed = parseAllowlist(patch.allowlist);
    if (!parsed.ok) throw Object.assign(new Error(parsed.error), { status: 400, expose: true });
    patch.allowlist = parsed.entries.join(", ");
  }
  await queryOne(
    `UPDATE tenants SET
       auto_block_mode    = coalesce($2, auto_block_mode),
       auto_block_minutes = coalesce($3, auto_block_minutes),
       block_allowlist    = coalesce($4, block_allowlist)
     WHERE id = $1`,
    [tenantId, patch.mode ?? null, patch.minutes ?? null, patch.allowlist ?? null],
  );
  return getSettings(tenantId);
}

// --- the list -----------------------------------------------------------------

const COLUMNS = `id, ip, reason, campaign_id, created_by, created_at, expires_at, revoked_at,
  (created_by IS NULL) AS automatic, (revoked_at IS NULL AND expires_at > now()) AS active`;

export async function listBlocks(tenantId: string, opts: { activeOnly?: boolean; limit?: number } = {}): Promise<Block[]> {
  return queryAll<Block>(
    `SELECT ${COLUMNS} FROM ip_blocks
      WHERE tenant_id = $1 AND ($2::boolean IS NOT TRUE OR (revoked_at IS NULL AND expires_at > now()))
      ORDER BY created_at DESC LIMIT $3`,
    [tenantId, opts.activeOnly ?? false, Math.min(Math.max(1, opts.limit ?? 200), 1000)],
  );
}

/** What the Wazuh manager enforces right now. */
export async function activeEntries(tenantId: string): Promise<Array<{ ip: string; expires_at: string; reason: string; campaign_id: string | null }>> {
  return queryAll(
    `SELECT ip, expires_at, reason, campaign_id FROM ip_blocks
      WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now()
      ORDER BY created_at LIMIT $2`,
    [tenantId, MAX_ACTIVE],
  );
}

export class BlockError extends Error {
  readonly status = 400;
  readonly expose = true;
}

/**
 * Adds a block, or extends the active one for that address. `userId` null means
 * Legion decided (automatic). Returns the block, and whether it is new.
 */
export async function addBlock(
  tenantId: string, ipInput: string, opts: { minutes: number; reason: string; campaignId?: string | null; userId: string | null },
): Promise<{ block: Block; created: boolean }> {
  const ip = unmap(String(ipInput ?? "").trim());
  if (isIP(ip) === 0) throw new BlockError("Not an IP address");
  const minutes = Math.round(opts.minutes);
  if (!(minutes >= 5 && minutes <= 10_080)) throw new BlockError("A block lasts between 5 minutes and 7 days");
  const active = await queryOne<{ n: number }>(
    "SELECT count(*)::int AS n FROM ip_blocks WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > now()", [tenantId],
  );
  // An expired-but-unrevoked row would hold the unique slot: retire it first.
  await queryOne(
    "UPDATE ip_blocks SET revoked_at = expires_at WHERE tenant_id = $1 AND ip = $2 AND revoked_at IS NULL AND expires_at <= now()",
    [tenantId, ip],
  );
  const existing = await queryOne<Block>(
    `SELECT ${COLUMNS} FROM ip_blocks WHERE tenant_id = $1 AND ip = $2 AND revoked_at IS NULL`, [tenantId, ip],
  );
  if (!existing && (active?.n ?? 0) >= MAX_ACTIVE) throw new BlockError(`At most ${MAX_ACTIVE} addresses can be blocked at once`);
  const row = await queryOne<Block & { inserted: boolean }>(
    `INSERT INTO ip_blocks (tenant_id, id, ip, reason, campaign_id, created_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(mins => $7))
     ON CONFLICT (tenant_id, ip) WHERE revoked_at IS NULL DO UPDATE SET
       expires_at = GREATEST(ip_blocks.expires_at, EXCLUDED.expires_at)
     RETURNING ${COLUMNS}, (xmax = 0) AS inserted`,
    [tenantId, randomUUID(), ip, opts.reason.slice(0, 500) || "Blocked", opts.campaignId ?? null, opts.userId, minutes],
  );
  const { inserted, ...block } = row!;
  return { block, created: inserted };
}

export async function revokeBlock(tenantId: string, ipInput: string, userId: string): Promise<Block | null> {
  const ip = unmap(String(ipInput ?? "").trim());
  if (isIP(ip) === 0) throw new BlockError("Not an IP address");
  return queryOne<Block>(
    `UPDATE ip_blocks SET revoked_at = now(), revoked_by = $3
      WHERE tenant_id = $1 AND ip = $2 AND revoked_at IS NULL
      RETURNING ${COLUMNS}`,
    [tenantId, ip, userId],
  );
}

// --- the automatic part -------------------------------------------------------

export type AutoDecision =
  | { campaign: string; ip: string; action: "blocked" | "extended" }
  | { campaign: string; ip: string | null; action: "skipped"; why: "off" | "rule" | "not_public" | "allowlisted" | "rate_limited" | "full" };

/**
 * Decides, for campaigns that were just detected, which source addresses to
 * block. Every decision — including the reason for NOT blocking — is returned,
 * and each block is audited.
 */
export async function respondToCampaigns(tenantId: string, campaigns: Campaign[]): Promise<AutoDecision[]> {
  if (!campaigns.length) return [];
  const settings = await getSettings(tenantId);
  const decisions: AutoDecision[] = [];
  for (const c of campaigns) {
    const ip = attackerOf(c);
    if (settings.mode !== "auto") { decisions.push({ campaign: c.id, ip, action: "skipped", why: "off" }); continue; }
    if (!ip) { decisions.push({ campaign: c.id, ip: null, action: "skipped", why: "rule" }); continue; }
    if (!isPublicAddress(ip)) { decisions.push({ campaign: c.id, ip, action: "skipped", why: "not_public" }); continue; }
    if (allowlisted(settings.allowlist, ip)) { decisions.push({ campaign: c.id, ip, action: "skipped", why: "allowlisted" }); continue; }
    const recent = await queryOne<{ n: number }>(
      "SELECT count(*)::int AS n FROM ip_blocks WHERE tenant_id = $1 AND created_by IS NULL AND created_at > now() - interval '1 hour'",
      [tenantId],
    );
    if ((recent?.n ?? 0) >= AUTO_PER_HOUR) { decisions.push({ campaign: c.id, ip, action: "skipped", why: "rate_limited" }); continue; }
    try {
      const { created } = await addBlock(tenantId, ip, {
        minutes: settings.minutes, userId: null, campaignId: c.id,
        reason: `Automatic: campaign ${c.id} (${c.rule.replace("_", " ")})`,
      });
      decisions.push({ campaign: c.id, ip, action: created ? "blocked" : "extended" });
      await store.audit({
        tenant_id: tenantId, user_id: null, user_email: null, action: "security.auto_block", resource_type: "ip",
        resource_id: ip, detail: `campaign ${c.id} (${c.rule}), ${settings.minutes} min`, ip_address: null,
      });
    } catch (error) {
      if (error instanceof BlockError) { decisions.push({ campaign: c.id, ip, action: "skipped", why: "full" }); continue; }
      throw error;
    }
  }
  return decisions;
}
