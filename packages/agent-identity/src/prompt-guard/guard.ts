import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import type { Principal } from "../types.js";
import { PromptAssembly, type SystemPromptId } from "./assembly.js";
import { classifyContent, type ClassifyInput } from "./detectors.js";
import { IngestionLog } from "./log.js";
import type { Classification, ContentRiskSummary, ContentSource, FieldHint } from "./types.js";

export interface IngestContext {
  /** Tenant the content belongs to (the principal's, or explicit for external systems). */
  tenantId: string;
  /** Who the content reached: the agent, service account or person whose model will read it. */
  principal: Principal;
  requestId?: string;
}

export interface IngestResult {
  classification: Classification;
  /** Set when the content was flagged and recorded. */
  eventId: string | null;
}

/**
 * The one place external content enters Legion's AI paths. It classifies,
 * records flagged content against the principal it reached (which is what
 * raises that principal's risk in the agent firewall), and builds prompts
 * that keep the content in the data channel.
 */
export class PromptInjectionGuard {
  readonly log: IngestionLog;

  constructor(pool: Pool, private readonly logger: (msg: string, err?: unknown) => void) {
    this.log = new IngestionLog(pool);
  }

  /** Pure classification, nothing recorded. */
  classify(input: ClassifyInput): Classification {
    return classifyContent(input);
  }

  /**
   * Classifies external content and records it against `ctx.principal` —
   * whatever the verdict. Throws if it cannot be recorded: the caller must
   * then not feed the content onward.
   *
   * Clean content used not to be recorded. That left the firewall blind to
   * the fact that an agent had just read attacker-controllable text, so a
   * poisoned alert the classifier missed could steer the agent's next
   * actions. The record is what the untrusted-content hold is built on.
   */
  async ingest(ctx: IngestContext, source: ContentSource, content: string, meta: { sourceId?: string; fieldHint?: FieldHint } = {}): Promise<IngestResult> {
    const classification = classifyContent({ source, content, fieldHint: meta.fieldHint });
    return { classification, eventId: await this.record(ctx, source, content, meta, classification) };
  }

  /** Records one piece of external content read by `ctx.principal`, any verdict. */
  async record(
    ctx: IngestContext,
    source: ContentSource,
    content: string,
    meta: { sourceId?: string; fieldHint?: FieldHint },
    classification: Classification,
  ): Promise<string> {
    const eventId = randomUUID();
    try {
      await this.log.record(IngestionLog.build(ctx, { eventId, source, content, classification, ...meta }));
    } catch (err) {
      this.logger("could not record external content", err);
      throw new Error("External content could not be recorded; refusing to pass it on.", { cause: err });
    }
    if (classification.verdict === "malicious") {
      this.logger(`prompt injection: malicious ${source} content reached ${ctx.principal.type} ${ctx.principal.id} (${classification.findings.map((f) => f.id).join(", ")})`);
    }
    return eventId;
  }

  /**
   * Records only flagged content. Used for agent-to-agent message payloads,
   * which have their own controls (a request must be cited and stays within
   * the permission it asked for); everything an agent reads as tool output
   * or external data goes through record() instead.
   */
  async recordIfFlagged(
    ctx: IngestContext,
    source: ContentSource,
    content: string,
    meta: { sourceId?: string; fieldHint?: FieldHint },
    classification: Classification,
  ): Promise<string | null> {
    if (classification.verdict === "clean") return null;
    return this.record(ctx, source, content, meta, classification);
  }

  /**
   * A PromptAssembly that records every external item it is given against
   * `ctx.principal`. Call `await assembly.settle()` before sending the
   * prompt; it rejects if any flagged item could not be recorded.
   */
  createAssembly(ctx: IngestContext, systemPromptId: SystemPromptId): RecordedAssembly {
    return new RecordedAssembly(systemPromptId, this, ctx);
  }

  summary(tenantId: string, principalId: string, suspiciousWindowSeconds: number, untrustedHoldSeconds = 0): Promise<ContentRiskSummary> {
    return this.log.summary(tenantId, principalId, suspiciousWindowSeconds, untrustedHoldSeconds);
  }

  acknowledge(c: PoolClient, tenantId: string, principalId: string, by: string, reason: string) {
    return this.log.acknowledge(c, tenantId, principalId, by, reason);
  }
}

export class RecordedAssembly extends PromptAssembly {
  private readonly pending: Promise<string | null>[] = [];

  constructor(id: SystemPromptId, private readonly guard: PromptInjectionGuard, private readonly ctx: IngestContext) {
    super(id);
  }

  override addUntrustedContent(source: ContentSource, content: string, meta: { sourceId?: string; fieldHint?: FieldHint } = {}): Classification {
    const c = super.addUntrustedContent(source, content, meta);
    // Every item, not only flagged ones: the agent has now read it.
    const p: Promise<string | null> = this.guard.record(this.ctx, source, content, meta, c);
    p.catch(() => {}); // surfaced by settle()
    this.pending.push(p);
    return c;
  }

  /** Waits for recording. Rejects if any flagged item was not recorded — do not send the prompt then. */
  async settle(): Promise<string[]> {
    const ids = await Promise.all(this.pending);
    return ids.filter((x): x is string => x !== null);
  }
}
