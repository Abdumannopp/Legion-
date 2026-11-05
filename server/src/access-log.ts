/**
 * Audit P1-10: a request ID on every request, and one structured access-log
 * line per request.
 *
 * - The ID is ours, never the client's (a client-chosen value would let anyone
 *   forge log correlation); it is returned as `x-request-id` so a person can
 *   quote it when something fails.
 * - The logged path is the ROUTE PATTERN (`/auth/invite/:token`), never the
 *   URL: URLs carry invitation and reset tokens. No query string, no body, no
 *   headers, no alert text.
 * - One JSON object per line, so any log shipper can parse it.
 */
import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import { recordRequest } from "./http-stats.js";

type Line = { t: string; msg: "http"; rid: string; method: string; route: string; status: number; ms: number; tenant: string | null };

let sink: (line: string) => void = (line) => process.stdout.write(`${line}\n`);
/** For tests: capture lines instead of writing them. */
export function setAccessLogSink(fn: ((line: string) => void) | null): void {
  sink = fn ?? ((line) => process.stdout.write(`${line}\n`));
}

export function accessLog(enabled: () => boolean) {
  return function requestContext(req: Request, res: Response, next: NextFunction): void {
    const rid = randomUUID();
    req.requestId = rid;
    res.setHeader("x-request-id", rid);
    const started = process.hrtime.bigint();
    res.on("finish", () => {
      // Counted whether or not the access log is on: monitoring must not depend on a log switch.
      try { recordRequest(res.statusCode, Number(process.hrtime.bigint() - started) / 1e9); } catch { /* never break a response */ }
      if (!enabled()) return;
      const route = req.route?.path ? `${req.baseUrl}${String(req.route.path)}` : "(unmatched)";
      const tenant = (req as Request & { user?: { tenant_id?: string } }).user?.tenant_id ?? req.principal?.tenantId ?? null;
      const line: Line = {
        t: new Date().toISOString(), msg: "http", rid, method: req.method, route: route.slice(0, 200),
        status: res.statusCode, ms: Math.round(Number(process.hrtime.bigint() - started) / 1e5) / 10,
        tenant: typeof tenant === "string" ? tenant : null,
      };
      try { sink(JSON.stringify(line)); } catch { /* logging must never break a response */ }
    });
    next();
  };
}
