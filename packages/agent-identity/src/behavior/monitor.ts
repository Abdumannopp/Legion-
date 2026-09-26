import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { AuditLog } from "../audit.js";
import { chainHash, GENESIS, lockChain } from "../chain.js";
import type { FirewallPolicy, PolicyStore } from "../firewall/policy.js";
import type { PromptInjectionGuard } from "../prompt-guard/guard.js";
import type { IdentityStore } from "../store.js";
import type { ExternalPrincipal, MachinePrincipal } from "../types.js";
import { assess } from "./assess.js";
import { buildProfile, windowEvents, windowFailures } from "./profile.js";
import { LEVEL_ORDER, type Assessment, type BehaviorLevel, type BehaviorProfile } from "./types.js";

/** What the firewall needs per request: the level, and what counts as "established" behaviour. */
export interface BehaviorState {
  level: BehaviorLevel;
  score: number;
  established: boolean;
  knownActions: ReadonlySet<string>;
  knownDestinations: ReadonlySet<string>;
  assessedAt: string;
}

export interface BehaviorChange {
  tenantId: string;
  identityId: string;
  identityName: string;
  from: BehaviorLevel;
  to: BehaviorLevel;
  assessment: Assessment;
  autoSuspended: boolean;
}

export interface BehaviorEventRow {
  seq: string;
  eventId: string;
  occurredAt: string;
  tenantId: string;
  identityId: string;
  identityName: string;
  kind: "level_change" | "acknowledged" | "auto_suspended";
  fromLevel: string;
  toLevel: string;
  score: number;
  signals: unknown;
  actor: string;
  reason: string | null;
}

const COLUMNS: [Exclude<keyof BehaviorEventRow, "seq">, string][] = [
  ["eventId", "event_id"], ["occurredAt", "occurred_at"], ["tenantId", "tenant_id"], ["identityId", "identity_id"],
  ["identityName", "identity_name"], ["kind", "kind"], ["fromLevel", "from_level"], ["toLevel", "to_level"],
  ["score", "score"], ["signals", "signals"], ["actor", "actor"], ["reason", "reason"],
];

const PROFILE_MAX_AGE_MS = 60 * 60_000;
const MONITOR: ExternalPrincipal = { type: "external_system", id: "legion-behavior-monitor", tenantId: null, displayName: "Legion behaviour monitor" };

export class BehaviorMonitor {
  private readonly cache = new Map<string, { at: number; state: BehaviorState }>();

  constructor(
    private readonly o: {
      pool: Pool;
      policies: PolicyStore;
      store: IdentityStore;
      audit: AuditLog;
      contentGuard: PromptInjectionGuard;
      log: (msg: string, err?: unknown) => void;
      onChange?: (change: BehaviorChange) => void | Promise<void>;
      /** How long a per-agent state is reused before it is reassessed. Default 30 s. */
      refreshSeconds?: number;
    },
  ) {}

  /** Cached state for the firewall. Reassessed at most every `refreshSeconds` per agent per instance. */
  async stateFor(p: MachinePrincipal): Promise<BehaviorState> {
    const hit = this.cache.get(p.id);
    if (hit && Date.now() - hit.at < (this.o.refreshSeconds ?? 30) * 1000) return hit.state;
    return (await this.refresh(p.tenantId, p.id, p.displayName)).state;
  }

  /** Reassess now: profile (reused for up to an hour), window, classification, transition. */
  async refresh(tenantId: string, identityId: string, name: string): Promise<{ state: BehaviorState; assessment: Assessment; profile: BehaviorProfile }> {
    const { policy } = await this.o.policies.get(tenantId);
    const cfg = policy.behavior;
    const now = new Date();
    const stored = await this.o.pool.query(
      "SELECT level, acknowledged_at, excluded_from, excluded_to FROM agent_behavior_state WHERE tenant_id = $1 AND identity_id = $2",
      [tenantId, identityId],
    );
    const prev = stored.rows[0];
    const windowStart = new Date(Math.max(now.getTime() - cfg.windowMinutes * 60_000, prev?.acknowledged_at ? new Date(prev.acknowledged_at).getTime() : 0));
    const excluded = prev?.excluded_from ? { from: new Date(prev.excluded_from), to: new Date(prev.excluded_to) } : null;

    const profile = await this.profile(tenantId, identityId, cfg, windowStart, excluded);
    const [events, failures, content] = await Promise.all([
      windowEvents(this.o.pool, tenantId, identityId, windowStart),
      windowFailures(this.o.pool, tenantId, identityId, windowStart),
      this.o.contentGuard.summary(tenantId, identityId, policy.promptInjection.suspiciousWindowSeconds).catch(() => undefined),
    ]);
    const assessment = assess({
      profile, events, windowStart, windowEnd: now, failures,
      content: content ? { malicious: content.unacknowledgedMalicious, suspicious: content.unacknowledgedSuspicious } : undefined,
    });

    await this.transition(tenantId, identityId, name, assessment, policy, windowStart);

    const state: BehaviorState = {
      level: assessment.level,
      score: assessment.score,
      established: profile.established,
      knownActions: new Set(Object.keys(profile.actions)),
      knownDestinations: new Set(Object.keys(profile.destinations)),
      assessedAt: now.toISOString(),
    };
    this.cache.set(identityId, { at: Date.now(), state });
    return { state, assessment, profile };
  }

  private async profile(tenantId: string, identityId: string, cfg: FirewallPolicy["behavior"], windowStart: Date, excluded: { from: Date; to: Date } | null): Promise<BehaviorProfile> {
    const row = (await this.o.pool.query(
      "SELECT computed_at, profile FROM agent_behavior_profiles WHERE tenant_id = $1 AND identity_id = $2",
      [tenantId, identityId],
    )).rows[0];
    // Reuse for an hour, unless the window moved past the stored baseline's end (after a review).
    if (row && Date.now() - new Date(row.computed_at).getTime() < PROFILE_MAX_AGE_MS && new Date(row.profile.until) <= windowStart) {
      return row.profile as BehaviorProfile;
    }
    const profile = await buildProfile(this.o.pool, {
      tenantId, identityId, from: new Date(windowStart.getTime() - cfg.baselineDays * 86_400_000), to: windowStart,
      excluded, minEvents: cfg.minBaselineEvents, minDays: cfg.minBaselineDays,
    });
    await this.o.pool.query(
      `INSERT INTO agent_behavior_profiles (tenant_id, identity_id, computed_at, events, profile) VALUES ($1,$2, now(), $3, $4)
       ON CONFLICT (tenant_id, identity_id) DO UPDATE SET computed_at = now(), events = EXCLUDED.events, profile = EXCLUDED.profile`,
      [tenantId, identityId, profile.events, JSON.stringify(profile)],
    );
    return profile;
  }

  /**
   * Stores the new classification. A level change is recorded once — the
   * conditional update makes exactly one instance win when several assess
   * the same agent at the same moment.
   */
  private async transition(tenantId: string, identityId: string, name: string, a: Assessment, policy: FirewallPolicy, windowStart: Date) {
    // One transaction: make sure the row exists, lock it, read the level it
    // had, write the new one and — if it changed — record the change. A
    // concurrent assessment waits on the lock, then sees the new level and
    // records nothing.
    const c = await this.o.pool.connect();
    let from: BehaviorLevel;
    try {
      await c.query("BEGIN");
      await c.query(
        `INSERT INTO agent_behavior_state (tenant_id, identity_id, level, score, signals, assessed_at)
         VALUES ($1,$2,'NORMAL',0,'[]', now()) ON CONFLICT (tenant_id, identity_id) DO NOTHING`,
        [tenantId, identityId],
      );
      from = (await c.query(
        "SELECT level FROM agent_behavior_state WHERE tenant_id = $1 AND identity_id = $2 FOR UPDATE",
        [tenantId, identityId],
      )).rows[0].level as BehaviorLevel;
      await c.query(
        `UPDATE agent_behavior_state SET level = $3, score = $4, signals = $5, assessed_at = now(), window_start = $6
          WHERE tenant_id = $1 AND identity_id = $2`,
        [tenantId, identityId, a.level, a.score, JSON.stringify(a.signals), windowStart],
      );
      if (a.level !== from) {
        await this.record({ tenantId, identityId, identityName: name, kind: "level_change", fromLevel: from, toLevel: a.level, score: a.score, signals: a.signals, actor: MONITOR.id, reason: null }, c);
      }
      await c.query("COMMIT");
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
    if (a.level === from) return;
    if (LEVEL_ORDER.indexOf(a.level) > LEVEL_ORDER.indexOf(from)) {
      this.o.log(`behaviour: ${name} (${identityId}) ${from} → ${a.level} score ${a.score}: ${a.signals.map((s) => s.id).join(", ")}`);
    }

    let autoSuspended = false;
    if (a.level === "CRITICAL" && policy.behavior.autoSuspendOnCritical) {
      autoSuspended = await this.suspend(tenantId, identityId, name, a);
    }
    if (this.o.onChange) {
      Promise.resolve(this.o.onChange({ tenantId, identityId, identityName: name, from, to: a.level, assessment: a, autoSuspended }))
        .catch((err) => this.o.log("onBehaviorChange hook failed", err));
    }
  }

  private async suspend(tenantId: string, identityId: string, name: string, a: Assessment): Promise<boolean> {
    try {
      const reason = `Behaviour CRITICAL (score ${a.score}): ${a.signals.map((s) => s.id).join(", ")}`.slice(0, 500);
      await this.o.store.tx(async (c) => {
        const current = await this.o.store.getForUpdate(c, tenantId, "ai_agent", identityId)
          ?? await this.o.store.getForUpdate(c, tenantId, "service_account", identityId);
        if (!current || current.status !== "active") return;
        await this.o.store.setStatus(c, identityId, "suspended", reason);
        await this.o.audit.record({ principal: { ...MONITOR, tenantId }, tenantId, action: "identity.suspended", outcome: "success", resourceType: current.kind, resourceId: identityId, reason }, c);
      });
      await this.record({ tenantId, identityId, identityName: name, kind: "auto_suspended", fromLevel: a.level, toLevel: a.level, score: a.score, signals: a.signals, actor: MONITOR.id, reason });
      return true;
    } catch (err) {
      this.o.log("automatic suspension failed", err);
      return false;
    }
  }

  /**
   * A person reviewed the behaviour. The window restarts now. With `learn`,
   * the reviewed activity becomes part of the baseline ("this is its role");
   * without, it is kept out of the baseline ("this was wrong").
   */
  async acknowledge(c: PoolClient, tenantId: string, identityId: string, name: string, by: string, reason: string, learn: boolean) {
    const prev = (await c.query(
      "SELECT level, score, signals, window_start FROM agent_behavior_state WHERE tenant_id = $1 AND identity_id = $2 FOR UPDATE",
      [tenantId, identityId],
    )).rows[0];
    const now = new Date();
    const windowStart = prev?.window_start ? new Date(prev.window_start) : now;
    await c.query(
      `INSERT INTO agent_behavior_state (tenant_id, identity_id, level, score, signals, assessed_at, window_start, acknowledged_at, acknowledged_by, excluded_from, excluded_to)
       VALUES ($1,$2,'NORMAL',0,'[]', $3, $3, $3, $4, $5, $6)
       ON CONFLICT (tenant_id, identity_id) DO UPDATE SET level = 'NORMAL', score = 0, signals = '[]', assessed_at = $3,
         window_start = $3, acknowledged_at = $3, acknowledged_by = $4, excluded_from = $5, excluded_to = $6`,
      [tenantId, identityId, now, by, learn ? null : windowStart, learn ? null : now],
    );
    await c.query("DELETE FROM agent_behavior_profiles WHERE tenant_id = $1 AND identity_id = $2", [tenantId, identityId]);
    await this.record({
      tenantId, identityId, identityName: name, kind: "acknowledged", fromLevel: prev?.level ?? "NORMAL", toLevel: "NORMAL",
      score: prev?.score ?? 0, signals: prev?.signals ?? [], actor: by, reason: `${learn ? "[learned] " : "[excluded] "}${reason}`,
    }, c);
    this.cache.delete(identityId);
  }

  /** Reassess every agent active in the tenant's window (run every minute or so, so alerts fire without traffic). */
  async sweep(tenantId: string): Promise<{ identityId: string; level: BehaviorLevel }[]> {
    const { policy } = await this.o.policies.get(tenantId);
    const active = await this.o.pool.query(
      `SELECT DISTINCT d.principal_id, i.name FROM firewall_decisions d JOIN machine_identities i ON i.id::text = d.principal_id
        WHERE d.tenant_id = $1 AND d.occurred_at > now() - make_interval(mins => $2)`,
      [tenantId, policy.behavior.windowMinutes],
    );
    const out = [];
    for (const r of active.rows) {
      const { state } = await this.refresh(tenantId, r.principal_id, r.name);
      out.push({ identityId: r.principal_id as string, level: state.level });
    }
    return out;
  }

  invalidate(identityId: string): void {
    this.cache.delete(identityId);
  }

  async listStates(tenantId: string) {
    const res = await this.o.pool.query(
      `SELECT s.*, i.name, i.kind, i.status FROM agent_behavior_state s
         JOIN machine_identities i ON i.id = s.identity_id AND i.tenant_id = s.tenant_id
        WHERE s.tenant_id = $1 ORDER BY array_position(ARRAY['CRITICAL','HIGH_RISK','SUSPICIOUS','NORMAL'], s.level), s.score DESC`,
      [tenantId],
    );
    return res.rows.map((r) => ({
      identityId: r.identity_id, name: r.name, kind: r.kind, status: r.status, level: r.level as BehaviorLevel, score: r.score,
      signals: r.signals, assessedAt: new Date(r.assessed_at).toISOString(),
      acknowledgedAt: r.acknowledged_at ? new Date(r.acknowledged_at).toISOString() : null, acknowledgedBy: r.acknowledged_by,
    }));
  }

  // ---- Append-only event log --------------------------------------------------

  private async record(e: Omit<BehaviorEventRow, "seq" | "eventId" | "occurredAt">, inTx?: PoolClient): Promise<void> {
    const row: Omit<BehaviorEventRow, "seq"> = { eventId: randomUUID(), occurredAt: new Date().toISOString(), ...e };
    const write = async (c: PoolClient) => {
      const prev = await lockChain(c, "agent_behavior_events", row.tenantId);
      await c.query(
        `INSERT INTO agent_behavior_events (chain_key, ${COLUMNS.map(([, col]) => col).join(", ")}, prev_hash, hash)
         VALUES ($1, ${COLUMNS.map((_, i) => `$${i + 2}`).join(", ")}, $${COLUMNS.length + 2}, $${COLUMNS.length + 3})`,
        [row.tenantId, ...COLUMNS.map(([k]) => (k === "signals" ? JSON.stringify(row[k]) : row[k])), prev, chainHash(prev, row)],
      );
    };
    if (inTx) return write(inTx);
    const c = await this.o.pool.connect();
    try {
      await c.query("BEGIN");
      await write(c);
      await c.query("COMMIT");
    } catch (err) {
      await c.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      c.release();
    }
  }

  async events(tenantId: string, f: { identityId?: string; before?: string; limit?: number } = {}) {
    const args: unknown[] = [tenantId];
    const where = ["tenant_id = $1"];
    if (f.identityId) { args.push(f.identityId); where.push(`identity_id = $${args.length}`); }
    if (f.before) { args.push(f.before); where.push(`seq < $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
    const res = await this.o.pool.query(`SELECT * FROM agent_behavior_events WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${args.length}`, args);
    return res.rows.map(toRow);
  }

  async verifyChain(tenantId: string): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.o.pool.query("SELECT * FROM agent_behavior_events WHERE chain_key = $1 ORDER BY seq", [tenantId]);
    let prev = GENESIS;
    let n = 0;
    for (const r of res.rows) {
      n++;
      const { seq, ...fields } = toRow(r);
      if (r.prev_hash !== prev || r.hash !== chainHash(prev, fields)) return { ok: false, brokenAtSeq: seq, rows: n };
      prev = r.hash;
    }
    return { ok: true, rows: n };
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toRow(r: any): BehaviorEventRow {
  const out = { seq: String(r.seq) } as BehaviorEventRow;
  for (const [k, c] of COLUMNS) (out as unknown as Record<string, unknown>)[k] = r[c];
  out.occurredAt = new Date(r.occurred_at).toISOString();
  return out;
}
