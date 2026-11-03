/**
 * Text that reaches the database. PostgreSQL cannot store a NUL character
 * (U+0000) in a text column: the write fails, and the request becomes a 500.
 * For a sensor that is worse than one lost event: a 500 reads as "try again
 * later", so the sensor re-sends the same event forever and, in order, holds
 * back everything queued behind it. Text from sensors is therefore cleaned,
 * never refused; text typed into the API is refused (a zod refine, e.g. the
 * payment check and the block reason): changing what a person or a program
 * meant, especially an account number, would be worse than saying no.
 */

// eslint-disable-next-line no-control-regex
const NUL = /\u0000/g;

export function stripNul(value: string): string {
  return value.includes("\u0000") ? value.replace(NUL, "") : value;
}


/** True if any string in a parsed request body (or any key) contains NUL. Bounded depth; Buffers (raw sensor bodies) are skipped. */
export function containsNul(value: unknown, depth = 0): boolean {
  if (typeof value === "string") return value.includes("\u0000");
  if (value === null || typeof value !== "object" || depth > 20 || Buffer.isBuffer(value)) return false;
  if (Array.isArray(value)) return value.some((v) => containsNul(v, depth + 1));
  for (const [k, v] of Object.entries(value)) {
    if (k.includes("\u0000") || containsNul(v, depth + 1)) return true;
  }
  return false;
}

/**
 * One rule for the whole API: a NUL character anywhere a person or a program
 * can put text (the path, the query, the body, a cookie) is a 400, before any
 * route runs. Without it each of the ~170 routes would need its own check, and
 * the ones that forgot answered 500 (some, like password reset, before sign-in).
 * Sensor bodies are raw here and are cleaned, not refused (see cleanFinding).
 */
export function rejectNul(req: import("express").Request, res: import("express").Response, next: import("express").NextFunction): void {
  if (/%00/i.test(req.originalUrl) || containsNul(req.body) || /%00/i.test(req.headers.cookie ?? "")) {
    res.status(400).json({ detail: "Invalid request" });
    return;
  }
  next();
}
