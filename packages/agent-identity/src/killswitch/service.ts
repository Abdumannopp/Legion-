import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { AuditLog } from "../audit.js";
import { chainHash, GENESIS, lockChain } from "../chain.js";
import type { BehaviorMonitor } from "../behavior/monitor.js";
import { toIdentity, type CutOff, type Identity, type IdentityStore } from "../store.js";
import type { ToolGateway } from "../tools/gateway.js";
import type { ExternalPrincipal, HumanPrincipal, MachineKind } from "../types.js";

/** How sure the person (or monitor) stopping the agent is that it was taken over. */
export type Compromise = "none" | "suspected" | "confirmed";
export type SecurityEventKind = "agent_killed" | "agent_suspended" | "agent_revoked" | "agent_auto_suspended";
export type Severity = "medium" | "high" | "critical";

export interface SecurityEventRow {
  seq: string;
  eventId: string;
  occurredAt: string;
  tenantId: string;
  kind: SecurityEventKind;
  severity: Severity;
  identityId: string;
  identityKind: MachineKind;
  identityName: string;
  actorType: string;
  actorId: string;
  compromise: Compromise;
  reason: string | null;
  details: {
    previousStatus: string;
    status: string;
    cutOff: CutOff;
  };
}

/** What administrators are sent. The host decides how (email, Slack, pager). */
export interface AdminNotice {
  notificationId: string;
  tenantId: string;
  subject: string;
  severity: Severity;
  createdAt: string;
  events: Omit<SecurityEventRow, "seq">[];
}

export type NotificationStatus = "pending" | "sent" | "failed" | "undeliverable";

export interface KillSwitchResult {
  activatedAt: string;
  compromise: Compromise;
  /** Identities this call stopped (or, for an already-suspended one, cut off further). */
  affected: {
    identityId: string;
    name: string;
    kind: MachineKind;
    previousStatus: string;
    status: string;
    cutOff: CutOff;
    eventId: string;
  }[];
  /** Already stopped; nothing left to withdraw. */
  unchanged: { identityId: string; status: string }[];
  notFound: string[];
  /** Tool executions stopped on this instance (others stop within the watchdog interval). */
  executionsAborted: number;
  notification: { id: string; status: NotificationStatus } | null;
}

const COLUMNS: [Exclude<keyof SecurityEventRow, "seq">, string][] = [
  ["eventId", "event_id"], ["occurredAt", "occurred_at"], ["tenantId", "tenant_id"], ["kind", "kind"],
  ["severity", "severity"], ["identityId", "identity_id"], ["identityKind", "identity_kind"], ["identityName", "identity_name"],
  ["actorType", "actor_type"], ["actorId", "actor_id"], ["compromise", "compromise"], ["reason", "reason"], ["details", "details"],
];

const AUDIT_ACTION: Record<SecurityEventKind, string> = {
  agent_killed: "killswitch.activated",
  agent_suspended: "identity.suspended",
  agent_revoked: "identity.revoked",
  agent_auto_suspended: "identity.suspended",
};

const MAX_ATTEMPTS = 10;
const NOTIFY_TIMEOUT_MS = 5_000;

export function severityOf(kind: SecurityEventKind, compromise: Compromise): Severity {
  if (compromise === "confirmed") return "critical";
  if (compromise === "suspected" || kind === "agent_killed" || kind === "agent_auto_suspended") return "high";
  return "medium";
}

/**
 * The emergency stop. Every way an agent is stopped — the kill switch, a
 * routine suspension or revocation, the behaviour monitor — runs through
 * activate(), so each one has the same effect:
 *
 *   1. in one transaction: the identity is marked stopped; its access tokens,
 *      unused tool tickets and pending requests to other agents are withdrawn
 *      (and on a confirmed compromise its credentials and people's
 *      delegations); the reason is audited; a security event is appended to
 *      a hash-chained log; and an administrator notification is queued;
 *   2. then: tool executions it is running here are aborted (other instances
 *      abort theirs within a second), and the notification is delivered.
 *
 * What makes it stick on every path is not this class but the checks it
 * relies on: the principal resolver refuses revoked tokens and inactive
 * identities, the firewall re-reads the identity's status at every
 * decision, tool tickets are refused for inactive agents, and running
 * executions re-check status.
 */
export class KillSwitch {
  constructor(
    private readonly o: {
      pool: Pool;
      store: IdentityStore;
      audit: AuditLog;
      tools: ToolGateway;
      behavior?: BehaviorMonitor;
      log: (msg: string, err?: unknown) => void;
      /** Delivers a notice to the tenant's administrators. Throw to have it retried. */
      notifyAdmins?: (notice: AdminNotice) => void | Promise<void>;
      /** Called once per security event after it is committed. */
      onSecurityEvent?: (e: Omit<SecurityEventRow, "seq">) => void | Promise<void>;
    },
  ) {}

  async activate(input: {
    tenantId: string;
    /** Identities to stop, or "all_agents" for every active AI agent in the tenant. */
    identityIds: string[] | "all_agents";
    reason: string | null;
    compromise: Compromise;
    actor: HumanPrincipal | ExternalPrincipal;
    kind?: SecurityEventKind;
    /** "revoked" is final; default "suspended". */
    status?: "suspended" | "revoked";
    /** Restrict to one kind (the per-kind management routes). */
    onlyKind?: MachineKind;
    requestId?: string;
    ip?: string;
    userAgent?: string;
  }): Promise<KillSwitchResult> {
    const kind = input.kind ?? "agent_killed";
    const target = input.status ?? (kind === "agent_revoked" ? "revoked" : "suspended");
    const confirmed = input.compromise === "confirmed";
    const severity = severityOf(kind, input.compromise);
    const activatedAt = new Date().toISOString();
    const result: KillSwitchResult = {
      activatedAt, compromise: input.compromise, affected: [], unchanged: [], notFound: [], executionsAborted: 0, notification: null,
    };
    const events: Omit<SecurityEventRow, "seq">[] = [];

    await this.o.store.tx(async (c) => {
      // Locked in id order so two concurrent activations cannot deadlock.
      const rows = input.identityIds === "all_agents"
        ? (await c.query(
            `SELECT * FROM machine_identities WHERE tenant_id = $1 AND kind = 'ai_agent' AND status = 'active' ORDER BY id FOR UPDATE`,
            [input.tenantId],
          )).rows
        : (await c.query(
            `SELECT * FROM machine_identities WHERE tenant_id = $1 AND id = ANY($2::uuid[]) ${input.onlyKind ? "AND kind = $3" : ""} ORDER BY id FOR UPDATE`,
            input.onlyKind ? [input.tenantId, input.identityIds, input.onlyKind] : [input.tenantId, input.identityIds],
          )).rows;
      const found: Identity[] = rows.map(toIdentity);
      if (input.identityIds !== "all_agents") {
        const ids = new Set(found.map((i) => i.id));
        result.notFound = input.identityIds.filter((id) => !ids.has(id));
      }

      for (const current of found) {
        let cutOff: CutOff;
        let status = current.status;
        const opts = { revokeCredentials: confirmed, revokeDelegations: confirmed, by: input.actor.id };
        if (current.status === "revoked") {
          result.unchanged.push({ identityId: current.id, status: current.status });
          continue;
        }
        if (current.status !== target) {
          const changed = await this.o.store.changeStatus(c, current.id, target, input.reason?.slice(0, 500) ?? null, opts);
          cutOff = changed.cutOff;
          status = changed.identity.status;
        } else {
          // Already suspended: sweep again (and escalate on a confirmed
          // compromise). If there was nothing left to withdraw, this is a
          // repeat and records nothing.
          cutOff = await this.o.store.cutOff(c, current.id, opts);
          if (Object.values(cutOff).every((n) => n === 0)) {
            result.unchanged.push({ identityId: current.id, status: current.status });
            continue;
          }
        }

        await this.o.audit.record({
          principal: input.actor,
          tenantId: input.tenantId,
          action: AUDIT_ACTION[kind],
          outcome: "success",
          resourceType: current.kind,
          resourceId: current.id,
          reason: input.reason ?? undefined,
          requestId: input.requestId,
          ip: input.ip,
          userAgent: input.userAgent,
          details: { compromise: input.compromise, previousStatus: current.status, status, cutOff, securityEvent: kind },
        }, c);

        const event: Omit<SecurityEventRow, "seq"> = {
          eventId: randomUUID(),
          occurredAt: new Date().toISOString(),
          tenantId: input.tenantId,
          kind,
          severity,
          identityId: current.id,
          identityKind: current.kind,
          identityName: current.name,
          actorType: input.actor.type,
          actorId: input.actor.id,
          compromise: input.compromise,
          reason: input.reason?.slice(0, 500) ?? null,
          details: { previousStatus: current.status, status, cutOff },
        };
        await this.appendEvent(c, event);
        events.push(event);
        result.affected.push({
          identityId: current.id, name: current.name, kind: current.kind, previousStatus: current.status, status, cutOff, eventId: event.eventId,
        });
      }

      if (events.length) {
        const subject = events.length === 1
          ? `[Legion] ${kind === "agent_revoked" ? "Revoked" : "Suspended"} ${events[0]!.identityKind === "ai_agent" ? "AI agent" : "service account"} "${events[0]!.identityName}"${input.compromise !== "none" ? ` — ${input.compromise} compromise` : ""}`
          : `[Legion] Kill switch: ${events.length} identities suspended${input.compromise !== "none" ? ` — ${input.compromise} compromise` : ""}`;
        const n = await c.query(
          `INSERT INTO security_notifications (tenant_id, event_ids, subject, body) VALUES ($1, $2, $3, $4) RETURNING id`,
          [input.tenantId, events.map((e) => e.eventId), subject, JSON.stringify({ severity, activatedAt, events })],
        );
        result.notification = { id: n.rows[0].id, status: "pending" };
      }
    });

    // After commit: stop what is running here, drop cached state.
    const stoppedIds = result.affected.map((a) => a.identityId);
    if (stoppedIds.length) {
      result.executionsAborted = this.o.tools.abortFor(stoppedIds, `${input.actor.displayName}: ${input.reason ?? kind}`.slice(0, 300));
      for (const id of stoppedIds) this.o.behavior?.invalidate(id);
      this.o.log(`KILL SWITCH (${kind}, ${input.compromise}) by ${input.actor.type}:${input.actor.id} — ${stoppedIds.length} identity(ies): ${stoppedIds.join(", ")}; ${result.executionsAborted} execution(s) aborted`);
    }
    if (this.o.onSecurityEvent) {
      for (const e of events) {
        Promise.resolve(this.o.onSecurityEvent(e)).catch((err) => this.o.log("onSecurityEvent hook failed", err));
      }
    }
    if (result.notification) {
      result.notification.status = await this.deliver(result.notification.id);
    }
    return result;
  }

  private async appendEvent(c: PoolClient, row: Omit<SecurityEventRow, "seq">): Promise<void> {
    const prev = await lockChain(c, "security_events", row.tenantId);
    await c.query(
      `INSERT INTO security_events (chain_key, ${COLUMNS.map(([, col]) => col).join(", ")}, prev_hash, hash)
       VALUES ($1, ${COLUMNS.map((_, i) => `$${i + 2}`).join(", ")}, $${COLUMNS.length + 2}, $${COLUMNS.length + 3})`,
      [row.tenantId, ...COLUMNS.map(([k]) => (k === "details" ? JSON.stringify(row[k]) : row[k])), prev, chainHash(prev, row)],
    );
  }

  // ---- Notifications --------------------------------------------------------

  /**
   * Delivers one queued notice now. A failure is kept for retry with
   * backoff (deliverPending); without a notifier the notice is marked
   * undeliverable and logged loudly — it stays readable in the API.
   */
  async deliver(id: string): Promise<NotificationStatus> {
    const [row] = await this.claim("id = $1", [id]);
    if (!row) {
      const r = await this.o.pool.query("SELECT status FROM security_notifications WHERE id = $1", [id]);
      return (r.rows[0]?.status as NotificationStatus) ?? "failed";
    }
    return this.send(row);
  }

  /** Retries due notices (run every minute or so; also POST /kill-switch/notifications/retry). */
  async deliverPending(tenantId?: string, limit = 50): Promise<{ sent: number; failed: number; undeliverable: number }> {
    const rows = tenantId ? await this.claim("tenant_id = $1", [tenantId], limit) : await this.claim("true", [], limit);
    const out = { sent: 0, failed: 0, undeliverable: 0 };
    for (const r of rows) out[await this.send(r)]++;
    return out;
  }

  /**
   * Claims due notices so two instances never send the same one twice at
   * once: the row is pushed into the future and its attempt counted before
   * the (slow, external) send begins.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private async claim(where: string, args: unknown[], limit = 1): Promise<any[]> {
    const res = await this.o.pool.query(
      `UPDATE security_notifications SET attempts = attempts + 1, next_attempt_at = now() + interval '2 minutes'
        WHERE id IN (
          SELECT id FROM security_notifications
           WHERE ${where} AND status IN ('pending', 'failed') AND next_attempt_at <= now()
           ORDER BY next_attempt_at LIMIT ${Math.max(1, Math.min(limit, 500))} FOR UPDATE SKIP LOCKED)
        RETURNING *`,
      args,
    );
    return res.rows;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private async send(row: any): Promise<"sent" | "failed" | "undeliverable"> {
    const body = row.body as { severity: Severity; events: AdminNotice["events"] };
    if (!this.o.notifyAdmins) {
      this.o.log(`ADMIN NOTICE NOT DELIVERED (no notifier configured): ${row.subject}`);
      await this.o.pool.query(
        "UPDATE security_notifications SET status = 'undeliverable', last_error = 'no notifier configured' WHERE id = $1",
        [row.id],
      );
      return "undeliverable";
    }
    const notice: AdminNotice = {
      notificationId: row.id, tenantId: row.tenant_id, subject: row.subject, severity: body.severity,
      createdAt: new Date(row.created_at).toISOString(), events: body.events,
    };
    try {
      await Promise.race([
        Promise.resolve(this.o.notifyAdmins(notice)),
        new Promise((_, rej) => setTimeout(() => rej(new Error("notifier timed out")), NOTIFY_TIMEOUT_MS).unref()),
      ]);
      await this.o.pool.query("UPDATE security_notifications SET status = 'sent', sent_at = now(), last_error = NULL WHERE id = $1", [row.id]);
      return "sent";
    } catch (err) {
      // Notifier errors can echo mail-server logins or tokens; keep the reason, drop the secret.
      const message = redactSecrets(err instanceof Error ? err.message : String(err)).slice(0, 500);
      const final = row.attempts >= MAX_ATTEMPTS;
      this.o.log(`admin notice ${final ? "given up" : "failed; will retry"}: ${row.subject}`, err);
      await this.o.pool.query(
        `UPDATE security_notifications SET status = $2, last_error = $3,
           next_attempt_at = now() + make_interval(secs => $4) WHERE id = $1`,
        [row.id, final ? "undeliverable" : "failed", message, Math.min(3600, 30 * 2 ** Math.max(0, row.attempts - 1))],
      );
      return final ? "undeliverable" : "failed";
    }
  }

  async notifications(tenantId: string, limit = 100) {
    const res = await this.o.pool.query(
      `SELECT id, event_ids, subject, status, attempts, created_at, next_attempt_at, sent_at, last_error
         FROM security_notifications WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [tenantId, Math.min(Math.max(limit, 1), 500)],
    );
    return res.rows.map((r) => ({
      id: r.id as string, eventIds: r.event_ids as string[], subject: r.subject as string, status: r.status as NotificationStatus,
      attempts: r.attempts as number, createdAt: new Date(r.created_at).toISOString(),
      nextAttemptAt: new Date(r.next_attempt_at).toISOString(), sentAt: r.sent_at ? new Date(r.sent_at).toISOString() : null,
      lastError: r.last_error as string | null,
    }));
  }

  // ---- Security events ------------------------------------------------------

  async events(tenantId: string, f: { identityId?: string; before?: string; limit?: number } = {}): Promise<SecurityEventRow[]> {
    const args: unknown[] = [tenantId];
    const where = ["tenant_id = $1"];
    if (f.identityId) { args.push(f.identityId); where.push(`identity_id = $${args.length}`); }
    if (f.before) { args.push(f.before); where.push(`seq < $${args.length}`); }
    args.push(Math.min(Math.max(f.limit ?? 100, 1), 500));
    const res = await this.o.pool.query(`SELECT * FROM security_events WHERE ${where.join(" AND ")} ORDER BY seq DESC LIMIT $${args.length}`, args);
    return res.rows.map(toRow);
  }

  async verifyChain(tenantId: string): Promise<{ ok: true; rows: number } | { ok: false; brokenAtSeq: string; rows: number }> {
    const res = await this.o.pool.query("SELECT * FROM security_events WHERE chain_key = $1 ORDER BY seq", [tenantId]);
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
function toRow(r: any): SecurityEventRow {
  const out = { seq: String(r.seq) } as SecurityEventRow;
  for (const [k, c] of COLUMNS) (out as unknown as Record<string, unknown>)[k] = r[c];
  out.occurredAt = new Date(r.occurred_at).toISOString();
  return out;
}

/** Removes URL credentials and key=value secrets from an error message before it is stored. */
export function redactSecrets(message: string): string {
  return message
    .replace(/\/\/[^/\s:@]+:[^/\s@]+@/g, "//[redacted]@")
    .replace(/\b(?:Bearer|Basic)\s+\S+/gi, "[redacted]")
    .replace(/\b(pass(?:word)?|pwd|token|secret|api[_-]?key|authorization)\s*[=:]\s*\S+/gi, "$1=[redacted]");
}
