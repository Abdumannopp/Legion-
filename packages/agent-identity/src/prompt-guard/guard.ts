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
   * Classifies external content and, if it is suspicious or malicious,
   * records it against `ctx.principal`. Throws if a flagged event cannot be
   * recorded: the caller must then not feed the content onward, because
   * the risk it carries would go unnoticed.
   */
  async ingest(ctx: IngestContext, source: ContentSource, content: string, meta: { sourceId?: string; fieldHint?: FieldHint } = {}): Promise<IngestResult> {
    const classification = classifyContent({ source, content, fieldHint: meta.fieldHint });
    return { classification, eventId: await this.recordIfFlagged(ctx, source, content, meta, classification) };
  }

  async recordIfFlagged(
    ctx: IngestContext,
    source: ContentSource,
    content: string,
    meta: { sourceId?: string; fieldHint?: FieldHint },
    classification: Classification,
  ): Promise<string | null> {
    if (classification.verdict === "clean") return null;
    const eventId = randomUUID();
    try {
      await this.log.record(IngestionLog.build(ctx, { eventId, source, content, classification, ...meta }));
    } catch (err) {
      this.logger("could not record flagged external content", err);
      throw new Error("Flagged external content could not be recorded; refusing to pass it on.", { cause: err });
    }
    if (classification.verdict === "malicious") {
      this.logger(`prompt injection: malicious ${source} content reached ${ctx.principal.type} ${ctx.principal.id} (${classification.findings.map((f) => f.id).join(", ")})`);
    }
    return eventId;
  }

  /**
   * A PromptAssembly that records every flagged external item against
   * `ctx.principal`. Call `await assembly.settle()` before sending the
   * prompt; it rejects if any flagged item could not be recorded.
   */
  createAssembly(ctx: IngestContext, systemPromptId: SystemPromptId): RecordedAssembly {
    return new RecordedAssembly(systemPromptId, this, ctx);
  }

  summary(tenantId: string, principalId: string, suspiciousWindowSeconds: number): Promise<ContentRiskSummary> {
    return this.log.summary(tenantId, principalId, suspiciousWindowSeconds);
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
    const p = this.guard.recordIfFlagged(this.ctx, source, content, meta, c);
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
