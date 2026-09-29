/**
 * The webhook signature must be compared with crypto.timingSafeEqual.
 *
 * A wrong comparison returns the same answers — only its timing differs — so
 * ordinary tests cannot tell. This one spies on the primitive itself and
 * proves every authentication attempt that gets as far as a signature goes
 * through it, with equal-length digests, whether the signature is right or
 * wrong, and whether or not the key id exists.
 */
import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from "vitest";
import { randomUUID } from "node:crypto";

const calls: { a: number; b: number }[] = [];
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    timingSafeEqual: (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => {
      calls.push({ a: a.byteLength, b: b.byteLength });
      return actual.timingSafeEqual(a, b);
    },
  };
});

const { app } = await import("../src/index.js");
const { closePool, migrate, query } = await import("../src/db/pool.js");
const { truncateAll } = await import("../src/seed.js");
const { issueCredential, sendSigned } = await import("./helpers/webhook.js");

let cred: Awaited<ReturnType<typeof issueCredential>>;
const body = { provider: "wazuh", event: { id: "ct-1", rule: { description: "x", level: 5 } } };

beforeAll(async () => { await migrate(); });
afterAll(async () => { await closePool(); });
beforeEach(async () => {
  await truncateAll();
  const tenant = randomUUID();
  await query("INSERT INTO tenants (id, name) VALUES ($1, 'A')", [tenant]);
  cred = await issueCredential(tenant);
  calls.length = 0;
});

describe("signature comparison", () => {
  it("uses timingSafeEqual on 32-byte digests when the signature is right", async () => {
    await sendSigned(app, cred, body).expect(202);
    expect(calls.filter((c) => c.a === 32 && c.b === 32).length).toBeGreaterThanOrEqual(1);
    expect(calls.every((c) => c.a === c.b)).toBe(true);
  });

  it("and when it is wrong", async () => {
    await sendSigned(app, cred, body, { signWithSecret: "whs_" + "A".repeat(43) }).expect(401);
    expect(calls.filter((c) => c.a === 32 && c.b === 32)).toHaveLength(1);
  });

  it("and when the key id does not exist, so that path costs the same work", async () => {
    await sendSigned(app, cred, body, { keyId: "whk_" + "Z".repeat(22) }).expect(401);
    expect(calls.filter((c) => c.a === 32 && c.b === 32)).toHaveLength(1);
  });
});
