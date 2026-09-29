/**
 * Mints tokens exactly as the server does (auth-jwt.ts: per-purpose key,
 * issuer, audience, key id), so tests skip bcrypt without skipping any check.
 * A test that forges a token on purpose signs it some other way.
 */
import type { SignOptions } from "jsonwebtoken";
import { signToken, type TokenKind } from "../../src/auth-jwt.js";

export function mint(claims: Record<string, unknown>, opts: { expiresIn?: SignOptions["expiresIn"]; kind?: TokenKind; algorithm?: string } = {}): string {
  return signToken(opts.kind ?? "access", claims, opts.expiresIn);
}
