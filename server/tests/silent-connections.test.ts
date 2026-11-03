/**
 * Connections that never send a request (edge.ts limitSilentConnections).
 * Measured by ops/tests/ddos-resilience.mjs: 3,000 sockets that connected and
 * said nothing were still open 100 s later — Node has no deadline for them,
 * and enough of them use up the file descriptors.
 */
import { afterEach, describe, expect, it } from "vitest";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { limitSilentConnections } from "../src/edge.js";

let server: http.Server;
const open: net.Socket[] = [];
afterEach(async () => { for (const s of open.splice(0)) s.destroy(); await new Promise<void>((r) => server.close(() => r())); });

async function serve(ms: number) {
  server = http.createServer((_req, res) => res.end("ok"));
  server.on("upgrade", (_req, socket) => {
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: test\r\nConnection: Upgrade\r\n\r\n");
    // An upgraded socket is not in flowing mode; without this the close of the client is never seen.
    socket.resume();
    // http.Server keeps sockets half-open: close ours when the client closes (the ws library does this in the app).
    socket.on("end", () => socket.end());
    socket.on("error", () => {});
  });
  limitSilentConnections(server, ms);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}
const connect = (port: number) => new Promise<net.Socket>((resolve) => {
  const s = net.connect({ host: "127.0.0.1", port }, () => resolve(s));
  open.push(s);
});
const closedWithin = (s: net.Socket, ms: number) => new Promise<boolean>((resolve) => {
  if (s.destroyed) return resolve(true);
  const t = setTimeout(() => resolve(false), ms);
  s.once("close", () => { clearTimeout(t); resolve(true); });
});
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const GET = "GET / HTTP/1.1\r\nHost: legion\r\n\r\n";

describe("silent connections", () => {
  it("a connection that sends nothing is closed at the deadline", async () => {
    const port = await serve(150);
    const s = await connect(port);
    expect(await closedWithin(s, 1_000)).toBe(true);
  });

  it("a connection that trickles half a request is closed too (headers must arrive promptly)", async () => {
    const port = await serve(150);
    const s = await connect(port);
    s.write("GET / HTTP/1.1\r\nHost: legion\r\n");
    expect(await closedWithin(s, 1_000)).toBe(true);
  });

  it("a connection that makes a request in time is answered and not cut afterwards (keep-alive is Node's business)", async () => {
    const port = await serve(150);
    const s = await connect(port);
    let received = "";
    s.on("data", (d) => { received += d; });
    await sleep(40);
    s.write(GET);
    await sleep(400);                       // well past the 150 ms first-request deadline
    expect(received).toContain("200 OK");
    expect(s.destroyed).toBe(false);
    received = "";
    s.write(GET);                           // the same connection still works
    await sleep(100);
    expect(received).toContain("200 OK");
  });

  it("a WebSocket-style upgrade is not cut at the deadline", async () => {
    const port = await serve(150);
    const s = await connect(port);
    let received = "";
    s.on("data", (d) => { received += d; });
    s.write("GET /ws HTTP/1.1\r\nHost: legion\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n");
    await sleep(400);
    expect(received).toContain("101 Switching Protocols");
    expect(s.destroyed).toBe(false);
  });

  it("0 turns the deadline off", async () => {
    const port = await serve(0);
    const s = await connect(port);
    await sleep(300);
    expect(s.destroyed).toBe(false);
  });
});
