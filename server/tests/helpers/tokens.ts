/**
 * Mints tokens exactly as the server does (auth-jwt.ts: per-purpose key,
 * issuer, audience, key id), so tests skip bcrypt without skipping any check.
 * A test that forges a token on purpose signs it some other way.
 */
import type { SignOptions } from "jsonwebtoken";
import { signToken, type TokenKind } from "../../src/auth-jwt.js";

export function mint(claims: Record<string, unknown>, opts: { expiresIn?: SignOptions["expiresIn"]; kind?: TokenKind; algorithm?: string } = {}): string {
  // An access token minted for a test stands for a person who just signed in (auth_time = now), so the
  // routes that need a recent sign-in (recentAuth in index.ts) accept it. Pass auth_time: undefined
  // explicitly — or use mintStale — to test the refusal.
  const kind = opts.kind ?? "access";
  const withAuthTime = kind === "access" && !("auth_time" in claims) ? { ...claims, auth_time: Math.floor(Date.now() / 1000) } : claims;
  const clean = Object.fromEntries(Object.entries(withAuthTime).filter(([, v]) => v !== undefined));
  return signToken(kind, clean, opts.expiresIn);
}
