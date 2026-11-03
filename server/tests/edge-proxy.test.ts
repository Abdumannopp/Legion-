/**
 * Who is the client? — proxy trust, spoofed X-Forwarded-For, and the parsing of
 * the settings that decide it. Real HTTP against tiny Express apps configured
 * through the same function the server uses, so what passes here is what runs.
 */
import { describe, it, expect, afterEach } from "vitest";
import express from "express";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { applyTrustedProxies, clientAddress } from "../src/edge.js";
import { parseOrigins, parseTrustedProxies } from "../src/edge-parse.js";

const servers: http.Server[] = [];
afterEach(() => { for (const s of servers.splice(0)) s.close(); });

/** An app that reports both req.ip and what the WebSocket path would compute. */
async function serve(spec: string): Promise<number> {
  const app = express();
  applyTrustedProxies(app, spec);
  app.get("/ip", (req, res) => res.json({ ip: req.ip }));
  const server = http.createServer(app);
  server.on("upgrade", (req, socket) => {
    socket.end(`HTTP/1.1 200 OK\r\nContent-Length: ${clientAddress(app, req).length}\r\nConnection: close\r\n\r\n${clientAddress(app, req)}`);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

function get(port: number, headers: Record<string, string> = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: "/ip", headers }, (res) => {
      let body = ""; res.on("data", (c) => (body += c)); res.on("end", () => resolve(JSON.parse(body).ip));
    }).on("error", reject);
  });
}

/** The address the WebSocket handshake path derives, for the same headers. */
function upgradeAddress(port: number, headers: Record<string, string> = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: "/ws", headers: { Connection: "Upgrade", Upgrade: "websocket", ...headers } });
    req.on("response", (res) => { let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve(b)); });
    req.on("error", reject);
    req.end();
  });
}

const LOOPBACK = /^(127\.0\.0\.1|::1)$/;

describe("spoofed X-Forwarded-For", () => {
  it("with no trusted proxy, the client is the TCP peer whatever the header says", async () => {
    const port = await serve("none");
    const ip = await get(port, { "X-Forwarded-For": "6.6.6.6" });
    expect(ip).toMatch(/127\.0\.0\.1$/);
    expect(await upgradeAddress(port, { "X-Forwarded-For": "6.6.6.6" })).toMatch(/127\.0\.0\.1$/);
  });

  it("a forged left-hand entry cannot displace the address the trusted proxy appended", async () => {
    // nginx appends the real peer on the right. The client controls everything left of it.
    const port = await serve("loopback");
    const headers = { "X-Forwarded-For": "6.6.6.6, 9.9.9.9, 203.0.113.7" };
    // 127.0.0.1 (peer) is trusted; 203.0.113.7 is not, so it is the client.
    expect(await get(port, headers)).toBe("203.0.113.7");
    expect(await upgradeAddress(port, headers)).toBe("203.0.113.7");
  });

  it("a hop count of 1 reads exactly one entry from the right", async () => {
    const port = await serve("1");
    const headers = { "X-Forwarded-For": "1.1.1.1, 2.2.2.2" };
    expect(await get(port, headers)).toBe("2.2.2.2");
    expect(await upgradeAddress(port, headers)).toBe("2.2.2.2");
  });

  it("a malformed header falls back safely instead of crashing", async () => {
    const port = await serve("loopback");
    const ip = await get(port, { "X-Forwarded-For": ",,, ,not an ip" });
    expect(typeof ip).toBe("string");
    expect(ip.length).toBeGreaterThan(0);
  });
});

describe("trusted proxy", () => {
  it("honours X-Forwarded-For when the peer is a listed proxy", async () => {
    const port = await serve("127.0.0.1,::1,::ffff:127.0.0.1");
    expect(await get(port, { "X-Forwarded-For": "198.51.100.4" })).toBe("198.51.100.4");
    expect(await upgradeAddress(port, { "X-Forwarded-For": "198.51.100.4" })).toBe("198.51.100.4");
  });

  it("the default (unset) trusts loopback, which is where the bundled nginx runs", async () => {
    const port = await serve("");
    expect(await get(port, { "X-Forwarded-For": "198.51.100.4" })).toBe("198.51.100.4");
  });

  it("without any header the peer is the client", async () => {
    const port = await serve("loopback");
    expect(await get(port)).toMatch(LOOPBACK);
    expect(await upgradeAddress(port)).toMatch(LOOPBACK);
  });
});

describe("untrusted proxy", () => {
  it("ignores X-Forwarded-For from a peer outside the trusted range", async () => {
    // Only 10.0.0.0/8 is trusted; the test client is 127.0.0.1.
    const port = await serve("10.0.0.0/8");
    expect(await get(port, { "X-Forwarded-For": "198.51.100.4" })).toMatch(/127\.0\.0\.1$/);
    expect(await upgradeAddress(port, { "X-Forwarded-For": "198.51.100.4" })).toMatch(/127\.0\.0\.1$/);
  });
});

describe("TRUSTED_PROXIES / CORS_ORIGINS parsing", () => {
  it("refuses every form of 'trust everyone'", () => {
    for (const bad of ["true", "*", "all", "any", "0.0.0.0/0", "::/0", "11", "0.0.0.0/33", "not-an-ip", "loopback,nope"]) {
      expect(parseTrustedProxies(bad).ok, bad).toBe(false);
    }
  });

  it("accepts the documented forms", () => {
    expect(parseTrustedProxies("")).toMatchObject({ ok: true, trust: { setting: ["loopback"] } });
    expect(parseTrustedProxies("none")).toMatchObject({ ok: true, trust: { setting: false } });
    expect(parseTrustedProxies("2")).toMatchObject({ ok: true, trust: { setting: 2, byHopCount: true } });
    expect(parseTrustedProxies("10.0.0.0/8, loopback, 172.16.0.5")).toMatchObject({ ok: true, trust: { setting: ["10.0.0.0/8", "loopback", "172.16.0.5"] } });
  });

  it("origins are exact http(s) origins — no wildcard, no null, no paths smuggled in", () => {
    for (const bad of ["*", "null", "https://*.example.com", "ftp://example.com", "example.com", "https://a.example.com, *"]) {
      expect(parseOrigins(bad).ok, bad).toBe(false);
    }
    expect(parseOrigins("https://app.example.com/, http://localhost:3000")).toEqual({ ok: true, origins: ["https://app.example.com", "http://localhost:3000"] });
    expect(parseOrigins("")).toEqual({ ok: true, origins: [] });
  });
});

describe("boot refuses unsafe edge settings", () => {
  const bootWith = async (env: Record<string, string>) => {
    const { vi } = await import("vitest");
    vi.resetModules();
    for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
    try { await import("../src/config.js"); return null; } catch (e) { return (e as Error).message; }
    finally { vi.unstubAllEnvs(); vi.resetModules(); }
  };

  it("TRUSTED_PROXIES=* (trust every client's claim) does not start", async () => {
    expect(await bootWith({ TRUSTED_PROXIES: "*" })).toMatch(/Refusing to start.*TRUSTED_PROXIES/s);
  });
  it("CORS_ORIGINS=* does not start", async () => {
    expect(await bootWith({ CORS_ORIGINS: "*" })).toMatch(/Refusing to start.*CORS_ORIGINS/s);
  });
  it("a traversal-style REFRESH_COOKIE_PATH does not start", async () => {
    expect(await bootWith({ REFRESH_COOKIE_PATH: "/auth/../" })).toMatch(/REFRESH_COOKIE_PATH/);
  });
  it("sane values start", async () => {
    expect(await bootWith({ TRUSTED_PROXIES: "10.0.0.0/8,loopback", CORS_ORIGINS: "https://a.example.com", REFRESH_COOKIE_PATH: "/api/auth" })).toBeNull();
  });
});
