/**
 * A live-alert socket lives no longer than the session behind it.
 *
 * Regression for the finding that a socket, once open, kept streaming a
 * tenant's alerts after the access token that opened it expired and after the
 * user logged out — so a token stolen for minutes gave a feed for as long as
 * the attacker kept the connection up.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import request from "supertest";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import WebSocket from "ws";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { app, httpServer, socketGrantsStillValid } from "../src/index.js";
import { closePool, migrate, query } from "../src/db/pool.js";
import { truncateAll } from "../src/seed.js";
import { config } from "../src/config.js";
import * as store from "../src/store.js";
import * as realtime from "../src/realtime.js";
import type { User } from "../src/types.js";

const FRONT = "http://localhost:3000";
let user: User;
let server: ReturnType<typeof httpServer.listen>; let port = 0;

const tokenFor = (u: User, seconds: number) =>
  jwt.sign({ sub: u.id, tenant_id: u.tenant_id, token_version: u.token_version }, config.jwtSecret, { algorithm: "HS256", expiresIn: seconds });

type Tap = { ws: WebSocket; closed: Promise<number> };
const open = (tok: string) => new Promise<Tap | number>((resolve) => {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws/alerts`, { headers: { cookie: `legion_token=${tok}`, origin: FRONT } });
  const closed = new Promise<number>((r) => ws.on("close", (code) => r(code)));
  ws.on("open", () => resolve({ ws, closed }));
  ws.on("unexpected-response", (_q, res) => { resolve(res.statusCode ?? 0); res.resume(); });
  ws.on("error", () => resolve(0));
});
const within = <T>(p: Promise<T>, ms: number) => Promise.race([p, new Promise<"timeout">((r) => setTimeout(() => r("timeout"), ms))]);

beforeAll(async () => { await migrate(); server = httpServer.listen(0); port = (server.address() as AddressInfo).port; });
afterAll(async () => { server.close(); await closePool(); });
beforeEach(async () => {
  await truncateAll();
  const t = randomUUID();
  await query("INSERT INTO tenants (id, name, trial_ends_at) VALUES ($1, 'T', now() + interval '14 days')", [t]);
  user = await store.insertUser({ email: `u-${randomUUID()}@t.io`, password_hash: await bcrypt.hash("password123", 4), tenant_id: t, role: "admin", status: "active" });
});

describe("socket lifetime", () => {
  it("closes when the access token that opened it expires (4401), even if nothing else happens", async () => {
    const tap = await open(tokenFor(user, 2)) as Tap;
    expect(typeof tap).toBe("object");
    expect(await within(tap.closed, 5_000)).toBe(realtime.CLOSE_SESSION_REVOKED);
  });

  it("revalidation also closes an expired grant (the backstop if a timer was lost)", async () => {
    const tap = await open(tokenFor(user, 1)) as Tap;
    await new Promise((r) => setTimeout(r, 1_200));
    await realtime.revalidateOnce(socketGrantsStillValid);
    expect(await within(tap.closed, 1_000)).toBe(realtime.CLOSE_SESSION_REVOKED);
  });

  it("logout closes the sockets opened with that browser's token — and not the user's other devices", async () => {
    const laptop = tokenFor(user, 900);
    const phone = jwt.sign({ sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version, d: "phone" }, config.jwtSecret, { algorithm: "HS256", expiresIn: 900 });
    const a = await open(laptop) as Tap;
    const b = await open(phone) as Tap;
    await request(app).post("/auth/logout").set("Cookie", `legion_token=${laptop}`).set("Origin", FRONT).expect(204);
    expect(await within(a.closed, 2_000)).toBe(realtime.CLOSE_SESSION_REVOKED);
    expect(await within(b.closed, 300)).toBe("timeout");
    b.ws.close();
  });

  it("a token that has already expired cannot open one", async () => {
    const expired = jwt.sign({ sub: user.id, tenant_id: user.tenant_id, token_version: user.token_version, exp: Math.floor(Date.now() / 1000) - 5 }, config.jwtSecret, { algorithm: "HS256" });
    expect(await open(expired)).toBe(401);
  });

  it("a live session keeps working: after a refresh the client reconnects with the new cookie", async () => {
    const first = await open(tokenFor(user, 1)) as Tap;
    expect(await within(first.closed, 4_000)).toBe(realtime.CLOSE_SESSION_REVOKED);
    // What the dashboard does next: an HTTP request refreshes the session, and the reconnect uses the new cookie.
    const renewed = await open(tokenFor(user, 900)) as Tap;
    expect(renewed.ws.readyState).toBe(WebSocket.OPEN);
    renewed.ws.close();
  });
});
