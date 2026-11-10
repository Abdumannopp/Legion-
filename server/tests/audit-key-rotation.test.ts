/**
 * F-06: the SOC audit key can be rotated without breaking the chain, a rotation is itself recorded,
 * an unlisted key still fails closed, and production requires an explicit key of its own.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, afterEach } from "vitest";
import { randomUUID } from "node:crypto";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config, socAuditKeyProblems } from "../src/config.js";
import { appendAuditEventNow, AuditKeyMismatch, currentAuditKeyId, verifyAuditChain } from "../src/audit/events.js";

let tenant: string;
const saved = { key: config.socAuditKey, prev: config.socAuditPreviousKeys };
const ev = (n: number) => appendAuditEventNow(tenant, { category: "controls", event: "rotation.test", actor: { kind: "system" }, detail: { n } });
const KEY_A = "a".repeat(8) + randomUUID() + randomUUID();
const KEY_B = "b".repeat(8) + randomUUID() + randomUUID();

beforeAll(async () => { await migrate(); });
afterAll(async () => { config.socAuditKey = saved.key; config.socAuditPreviousKeys = saved.prev; await closePool(); });
afterEach(() => { config.socAuditKey = saved.key; config.socAuditPreviousKeys = saved.prev; });
beforeEach(async () => {
  await truncateAll();
  await query("DELETE FROM chain_prune_anchors WHERE table_name = 'soc_audit_events'");
  tenant = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'T')", [tenant]);
});

describe("SOC audit key rotation", () => {
  it("a key listed as previous keeps the chain valid; the rotation is a chained event of its own", async () => {
    config.socAuditKey = KEY_A; config.socAuditPreviousKeys = [];
    for (let i = 0; i < 3; i++) await ev(i);
    const idA = currentAuditKeyId();

    config.socAuditKey = KEY_B; config.socAuditPreviousKeys = [KEY_A];
    await ev(3);
    const rows = (await query("SELECT seq, event, key_id, detail FROM soc_audit_events WHERE tenant_id = $1 ORDER BY seq", [tenant])).rows;
    expect(rows.map((r) => r.event)).toEqual(["rotation.test", "rotation.test", "rotation.test", "audit_key.rotated", "rotation.test"]);
    expect(rows[3]).toMatchObject({ key_id: currentAuditKeyId(), detail: { from_key_id: idA, to_key_id: currentAuditKeyId() } });
    expect(await verifyAuditChain(tenant)).toMatchObject({ ok: true, events: 5 });
    await ev(4);                                                     // only one rotation event
    expect((await query("SELECT count(*)::int n FROM soc_audit_events WHERE tenant_id = $1 AND event = 'audit_key.rotated'", [tenant])).rows[0].n).toBe(1);

    // Once the old key is dropped, the events it signed can no longer be verified — said plainly.
    config.socAuditPreviousKeys = [];
    expect(await verifyAuditChain(tenant)).toMatchObject({ ok: false, broken_at: 1, reason: expect.stringMatching(/neither SOC_AUDIT_KEY nor in SOC_AUDIT_PREVIOUS_KEYS/) });
  });

  it("a key that is not listed still fails closed: nothing is appended", async () => {
    config.socAuditKey = KEY_A; config.socAuditPreviousKeys = [];
    await ev(0);
    config.socAuditKey = KEY_B;
    await expect(ev(1)).rejects.toBeInstanceOf(AuditKeyMismatch);
    expect((await query("SELECT count(*)::int n FROM soc_audit_events WHERE tenant_id = $1", [tenant])).rows[0].n).toBe(1);
  });

  it("an install that never set SOC_AUDIT_KEY moves to its own key with SOC_AUDIT_PREVIOUS_KEYS=jwt", async () => {
    config.socAuditKey = ""; config.socAuditPreviousKeys = [];
    for (let i = 0; i < 2; i++) await ev(i);
    expect(currentAuditKeyId()).toMatch(/^jwt-/);
    config.socAuditKey = KEY_A; config.socAuditPreviousKeys = ["jwt"];
    await ev(2);
    expect(currentAuditKeyId()).toMatch(/^cfg-/);
    expect(await verifyAuditChain(tenant)).toMatchObject({ ok: true, events: 4 });
  });

  it("production requires its own key", () => {
    const jwt = "j".repeat(8) + randomUUID() + randomUUID();
    expect(socAuditKeyProblems({ socAuditKey: "", socAuditPreviousKeys: [], jwtSecret: jwt }).join()).toMatch(/SOC_AUDIT_KEY is required.*SOC_AUDIT_PREVIOUS_KEYS=jwt/);
    expect(socAuditKeyProblems({ socAuditKey: "changeme", socAuditPreviousKeys: [], jwtSecret: jwt }).join()).toMatch(/long random/);
    expect(socAuditKeyProblems({ socAuditKey: jwt, socAuditPreviousKeys: [], jwtSecret: jwt }).join()).toMatch(/its own value/);
    expect(socAuditKeyProblems({ socAuditKey: KEY_A, socAuditPreviousKeys: [KEY_A], jwtSecret: jwt }).join()).toMatch(/must not contain/);
    expect(socAuditKeyProblems({ socAuditKey: KEY_A, socAuditPreviousKeys: ["jwt"], jwtSecret: jwt })).toEqual([]);
  });
});
