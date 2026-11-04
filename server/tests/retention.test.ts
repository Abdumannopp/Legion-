/**
 * Audit P2-16: delivered alert emails (recipient + alert text) do not pile up
 * forever. Undelivered ones are never touched.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { pruneDeliveredEmails } from "../src/outbox.js";

let tA: string, tB: string;
const row = (tenant: string, status: string, sentDaysAgo: number | null, createdDaysAgo = 60) => query(
  `INSERT INTO notification_outbox (id, tenant_id, kind, dedupe_key, recipient, payload, status, max_attempts, created_at, sent_at)
   VALUES ($1, $2, 'alert_email', $3, 'soc@example.com', '{"title":"x"}', $4, 8, now() - make_interval(days => $5), $6)`,
  [randomUUID(), tenant, randomUUID(), status, createdDaysAgo, sentDaysAgo === null ? null : new Date(Date.now() - sentDaysAgo * 86_400_000)],
);
const left = async () => (await query("SELECT tenant_id, status FROM notification_outbox WHERE kind = 'alert_email' ORDER BY tenant_id, status")).rows;

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  tA = randomUUID(); tB = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A'), ($2, 'B')", [tA, tB]);
});

describe("delivered alert emails expire", () => {
  it("removes sent emails older than the retention, in every workspace, and nothing else", async () => {
    await row(tA, "sent", 45); await row(tB, "sent", 31);   // expired
    await row(tA, "sent", 5);                                // recent: kept
    await row(tA, "pending", null); await row(tA, "dead", null); await row(tB, "sending", null); // owed: kept
    expect(await pruneDeliveredEmails(30)).toBe(2);
    const rest = await left();
    expect(rest).toHaveLength(4);
    expect(rest.filter((r) => r.status === "sent")).toHaveLength(1);
  });

  it("0 keeps everything", async () => {
    await row(tA, "sent", 400);
    expect(await pruneDeliveredEmails(0)).toBe(0);
    expect(await left()).toHaveLength(1);
  });
});
