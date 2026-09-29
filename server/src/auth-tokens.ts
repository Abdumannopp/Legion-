/**
 * One-time links: password reset, invitation, e-mail verification.
 *
 * The token (256 random bits) goes into the e-mailed link and nowhere else.
 * The database keeps its SHA-256, so a copy of the database is not a set of
 * working links. SHA-256 rather than bcrypt: there is nothing to brute-force in
 * 256 random bits, and a fast hash lets the lookup be a plain indexed query.
 */
import { createHash, randomBytes } from "node:crypto";

export function newOneTimeToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashOneTimeToken(token) };
}

/** Hex SHA-256 — byte-for-byte what schema.sql computes when it converts old plaintext tokens. */
export function hashOneTimeToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
