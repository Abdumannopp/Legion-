/**
 * Kill-switch admin notices are retried automatically.
 *
 * The retry logic (durable rows, backoff, max attempts, SKIP LOCKED claims)
 * already existed, but ran only when the host called deliverPending() on a
 * timer — and nothing did. A notice that failed once stayed unsent.
 * startBackgroundJobs() now owns that timer.
 */
import request from "supertest";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AdminNotice } from "../src/index.js";
import { redactSecrets } from "../src/killswitch/service.js";
import { agentWithToken, as, makeApp, resetDb, TENANT_A, TENANT_B, type TestApp } from "./helpers.js";

let t: TestApp;
let stop: (() => void) | null = null;
let failuresLeft = 0;
let failWith = "smtp down";
const notices: AdminNotice[] = [];

beforeEach(async () => {
  if (t) await t.pool.end();
  notices.length = 0;
  failuresLeft = 0;
  failWith = "smtp down";
  t = await makeApp({
    extra: {
      notifyAdmins: (n) => {
        if (failuresLeft > 0) { failuresLeft--; throw new Error(failWith); }
        notices.push(n);
      },
    },
  });
  await resetDb(t.pool);
  await t.identity.migrate();
  t.host.add("alice", TENANT_A, "admin");
  t.host.add("bob", TENANT_B, "admin");
});
afterEach(() => { stop?.(); stop = null; });
afterAll(async () => { await t?.pool.end(); });

const suspend = async (admin: string) => {
  const a = await agentWithToken(t, admin);
  await request(t.app).post(`/agents/${a.agent.id}/suspend`).set(as(admin)).send({ reason: "test" }).expect(200);
  return a;
};
const noticeRows = async () =>
  (await t.pool.query("SELECT tenant_id, status, attempts, last_error FROM security_notifications ORDER BY created_at")).rows;
const makeDue = () => t.pool.query("UPDATE security_notifications SET next_attempt_at = now() WHERE status IN ('pending','failed')");
const waitFor = async (cond: () => Promise<boolean>, ms = 3000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await cond()) return true; await new Promise((r) => setTimeout(r, 25)); }
  return false;
};

describe("without anyone calling deliverPending()", () => {
  it("a notice that failed is delivered once the notifier recovers", async () => {
    failuresLeft = 1;
    await suspend("alice");
    expect((await noticeRows())[0]).toMatchObject({ status: "failed", attempts: 1 });

    stop = t.identity.startBackgroundJobs({ noticeRetryMs: 30 });
    await makeDue(); // stands in for the backoff delay passing
    expect(await waitFor(async () => (await noticeRows())[0].status === "sent")).toBe(true);
    expect(notices).toHaveLength(1);
    expect((await noticeRows())[0].attempts).toBe(2);
  });

  it("keeps failing notices on backoff and eventually gives up, visibly", async () => {
    failuresLeft = 1000;
    await suspend("alice");
    stop = t.identity.startBackgroundJobs({ noticeRetryMs: 20 });
    const gaveUp = await waitFor(async () => {
      await makeDue();
      return (await noticeRows())[0].status === "undeliverable";
    }, 8000);
    expect(gaveUp).toBe(true);
    expect(notices).toHaveLength(0);
  });

  it("stop() really stops the timer", async () => {
    failuresLeft = 1;
    await suspend("alice");
    stop = t.identity.startBackgroundJobs({ noticeRetryMs: 20 });
    stop(); stop = null;
    await makeDue();
    await new Promise((r) => setTimeout(r, 150));
    expect((await noticeRows())[0].status).toBe("failed");
  });
});

describe("each organisation's notices stay its own", () => {
  it("retries deliver each notice to its own tenant", async () => {
    failuresLeft = 2;
    await suspend("alice");
    await suspend("bob");
    stop = t.identity.startBackgroundJobs({ noticeRetryMs: 20 });
    await makeDue();
    expect(await waitFor(async () => (await noticeRows()).every((r) => r.status === "sent"))).toBe(true);
    expect(notices.map((n) => n.tenantId).sort()).toEqual([TENANT_A, TENANT_B].sort());
  });
});

describe("the stored failure reason", () => {
  it("does not keep credentials a notifier error echoed back", async () => {
    failuresLeft = 1;
    failWith = "connect failed smtp://mailer:Hunter2pass@mail.corp password=Hunter2pass Authorization: Bearer abc.def";
    await suspend("alice");
    const { last_error } = (await noticeRows())[0];
    expect(last_error).not.toContain("Hunter2pass");
    expect(last_error).not.toContain("abc.def");
    expect(last_error).toContain("connect failed");
  });

  it("redactSecrets leaves ordinary messages alone", () => {
    expect(redactSecrets("421 try again later")).toBe("421 try again later");
  });
});
