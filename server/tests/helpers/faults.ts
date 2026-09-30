/**
 * Failure injection for the real-process reliability tests.
 *
 *  - FaultProxy: a TCP proxy between the API and Postgres (or anything). cut()
 *    drops every live connection and refuses new ones — what a database
 *    restart or a network partition looks like to the application; heal()
 *    brings it back on the same port.
 *  - FakeSmtp: a minimal SMTP server that can be "up", "failing" (421 to every
 *    message) or "hung" (accepts the connection, never answers). It records
 *    each delivered message's Message-ID, so duplicates are countable.
 *  - startApi(): the real server (src/index.ts) as a child process, which can
 *    be stopped gracefully or killed with SIGKILL mid-work.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, connect, type AddressInfo, type Server, type Socket } from "node:net";
import { join } from "node:path";

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** Diagnostics appended to every timeout (e.g. the API processes' logs). */
export const diagnostics: Array<() => string> = [];
export async function until(cond: () => boolean | Promise<boolean>, ms = 15_000, what = "condition"): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    // Each probe is bounded too: a request that hangs must not hang the wait.
    try { if (await Promise.race([Promise.resolve(cond()), sleep(Math.min(5_000, Math.max(100, end - Date.now()))).then(() => false)])) return; } catch { /* keep waiting */ }
    await sleep(100);
  }
  const extra = diagnostics.map((d) => { try { return d(); } catch { return ""; } }).filter(Boolean).join("\n");
  throw new Error(`timed out after ${ms} ms waiting for ${what}${extra ? `\n--- diagnostics ---\n${extra.slice(-4000)}` : ""}`);
}
export const freePort = () => new Promise<number>((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => { const { port } = s.address() as AddressInfo; s.close(() => resolve(port)); });
});

export class FaultProxy {
  private server: Server | null = null;
  private readonly sockets = new Set<Socket>();
  port = 0;
  constructor(private readonly targetHost: string, private readonly targetPort: number) {}

  async start(port = 0): Promise<this> {
    await new Promise<void>((resolve, reject) => {
      const server = createServer((client) => {
        const upstream = connect(this.targetPort, this.targetHost);
        for (const s of [client, upstream]) { this.sockets.add(s); s.on("close", () => this.sockets.delete(s)); s.on("error", () => { client.destroy(); upstream.destroy(); }); }
        client.pipe(upstream); upstream.pipe(client);
      });
      server.once("error", reject);
      server.listen(port, "127.0.0.1", () => { this.port = (server.address() as AddressInfo).port; resolve(); });
      this.server = server;
    });
    return this;
  }
  /** The database "restarts": every open connection dies, new ones are refused. */
  async cut(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    this.sockets.clear();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
    this.server = null;
  }
  /** It is back, on the same address. */
  async heal(): Promise<void> { await this.start(this.port); }
  async stop(): Promise<void> { await this.cut(); }
}

export type SmtpMode = "up" | "failing" | "hung";
export class FakeSmtp {
  private server: Server | null = null;
  private readonly sockets = new Set<Socket>();
  mode: SmtpMode = "up";
  port = 0;
  /** Message-IDs of every message accepted, in order (duplicates included). */
  readonly accepted: string[] = [];

  async start(): Promise<this> {
    await new Promise<void>((resolve) => {
      this.server = createServer((s) => this.session(s)).listen(0, "127.0.0.1", () => {
        this.port = (this.server!.address() as AddressInfo).port; resolve();
      });
    });
    return this;
  }
  private session(s: Socket): void {
    this.sockets.add(s); s.on("close", () => this.sockets.delete(s)); s.on("error", () => {});
    if (this.mode === "hung") return; // connected, never greeted
    if (this.mode === "failing") { s.end("421 4.3.2 Service not available, try later\r\n"); return; }
    s.write("220 fake.smtp ESMTP\r\n");
    let buf = ""; let inData = false; let data = "";
    s.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      for (;;) {
        if (inData) {
          const end = buf.indexOf("\r\n.\r\n");
          if (end === -1) { data += buf; buf = ""; return; }
          data += buf.slice(0, end); buf = buf.slice(end + 5); inData = false;
          const id = /^Message-ID:\s*(\S+)/im.exec(data)?.[1] ?? "(none)";
          this.accepted.push(id); data = "";
          s.write("250 2.0.0 queued\r\n");
          continue;
        }
        const nl = buf.indexOf("\r\n"); if (nl === -1) return;
        const line = buf.slice(0, nl); buf = buf.slice(nl + 2);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === "EHLO" || verb === "HELO") s.write("250-fake.smtp\r\n250 8BITMIME\r\n");
        else if (verb === "DATA") { inData = true; s.write("354 go ahead\r\n"); }
        else if (verb === "QUIT") { s.end("221 bye\r\n"); return; }
        else s.write("250 OK\r\n"); // MAIL, RCPT, RSET, NOOP
      }
    });
  }
  /** Drops connections that are open (e.g. hung ones) so a new mode applies at once. */
  resetConnections(): void { for (const s of this.sockets) s.destroy(); this.sockets.clear(); }
  async stop(): Promise<void> { this.resetConnections(); await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r())); }
}

export interface ApiProcess { proc: ChildProcess; port: number; url: string; log: () => string; exited: Promise<number | null> }

const SERVER_DIR = join(__dirname, "..", "..");
export async function startApi(env: Record<string, string>): Promise<ApiProcess> {
  const port = await freePort();
  let out = "";
  const proc = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: SERVER_DIR,
    env: { ...process.env, NODE_ENV: "development", PORT: String(port), SEED_DEMO_DATA: "false", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  proc.stdout!.on("data", (d) => (out += d)); proc.stderr!.on("data", (d) => (out += d));
  const exited = new Promise<number | null>((r) => proc.once("exit", (code) => r(code)));
  const url = `http://127.0.0.1:${port}`;
  diagnostics.push(() => `[api :${port}] ${out.slice(-1500)}`);
  await until(async () => (await fetch(`${url}/health`)).status < 600, 60_000, `the API to start\n${out.slice(-2000)}`);
  return { proc, port, url, log: () => out, exited };
}
/** A crash: no shutdown handler runs, nothing is flushed. */
export async function killApi(api: ApiProcess): Promise<void> {
  api.proc.kill("SIGKILL");
  await api.exited;
}
export async function stopApi(api: ApiProcess): Promise<void> {
  if (api.proc.exitCode !== null) return;
  api.proc.kill("SIGTERM");
  await Promise.race([api.exited, sleep(12_000).then(() => api.proc.kill("SIGKILL"))]);
}
