/**
 * Signed tokens: one key per PURPOSE, derived from JWT_SECRET, and rotatable.
 *
 * Previously every token (the session's access token, the half-authenticated
 * MFA challenge, the Paddle checkout context) was signed with JWT_SECRET
 * itself, and told apart only by a `purpose` claim every verifier had to
 * remember to check. Now:
 *
 *  - each purpose has its own HKDF-derived key and its own audience, so a
 *    token minted for one purpose does not even verify as another — the claim
 *    check stays, as a second line;
 *  - every token names its issuer, audience and key (`kid`), and all three are
 *    checked;
 *  - JWT_PREVIOUS_SECRETS keeps older secrets valid for VERIFICATION, so the
 *    signing secret can be rotated without signing everyone out: add the old
 *    value there, set a new JWT_SECRET, and remove the old one once the longest
 *    token lifetime has passed.
 *
 * Access tokens issued before this change (signed with the raw secret) are
 * refused; they live 15 minutes and the dashboard renews them from the refresh
 * cookie transparently.
 */
import { createHash, hkdfSync } from "node:crypto";
import jwt, { type JwtPayload } from "jsonwebtoken";
import { config } from "./config.js";

export type TokenKind = "access" | "mfa" | "checkout";

export const ISSUER = "legion";
export const AUDIENCE: Record<TokenKind, string> = {
  access: "legion-api",
  mfa: "legion-mfa-challenge",
  checkout: "legion-paddle-checkout",
};
const TYP: Record<TokenKind, string> = { access: "at+jwt", mfa: "mfa+jwt", checkout: "checkout+jwt" };

interface Key { kid: string; key: Buffer }
const cache = new Map<string, Key>();

function derive(secret: string, kind: TokenKind): Key {
  const id = `${kind}\u0000${secret}`;
  let k = cache.get(id);
  if (!k) {
    const key = Buffer.from(hkdfSync("sha256", secret, "legion-jwt-v2", `purpose:${kind}`, 32));
    k = { key, kid: `${kind}-${createHash("sha256").update(key).digest("hex").slice(0, 16)}` };
    if (cache.size > 64) cache.clear();
    cache.set(id, k);
  }
  return k;
}

/** Signing uses the current secret; verification also accepts previous ones. */
const verificationKeys = (kind: TokenKind): Key[] =>
  [config.jwtSecret, ...config.jwtPreviousSecrets].map((s) => derive(s, kind));

export function signToken(kind: TokenKind, claims: Record<string, unknown>, expiresIn?: jwt.SignOptions["expiresIn"]): string {
  const { key, kid } = derive(config.jwtSecret, kind);
  return jwt.sign(claims, key, {
    algorithm: "HS256", issuer: ISSUER, audience: AUDIENCE[kind],
    ...(expiresIn === undefined ? {} : { expiresIn }),
    header: { alg: "HS256", typ: TYP[kind], kid },
  });
}

export interface VerifyOptions {
  /** Accept an expired token (the checkout context — see index.ts), bounded by maxAge. */
  ignoreExpiration?: boolean;
  /** Oldest acceptable `iat`, e.g. "8d". */
  maxAge?: string;
}

/** The claims, or null for anything not a valid token OF THIS KIND. Never throws. */
export function verifyTokenOf<T extends JwtPayload = JwtPayload>(kind: TokenKind, raw: string | undefined, opts: VerifyOptions = {}): T | null {
  if (!raw || raw.length > 4096) return null;
  let kid: unknown;
  try { kid = (jwt.decode(raw, { complete: true }) as { header?: { kid?: unknown; typ?: unknown } } | null)?.header?.kid; }
  catch { return null; }
  const key = verificationKeys(kind).find((k) => k.kid === kid);
  if (!key) return null;
  try {
    const claims = jwt.verify(raw, key.key, {
      algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE[kind],
      ignoreExpiration: opts.ignoreExpiration ?? false, maxAge: opts.maxAge,
    });
    return typeof claims === "object" ? claims as T : null;
  } catch {
    return null;
  }
}

/**
 * A checkout token minted before per-purpose keys existed (raw JWT_SECRET,
 * purpose "paddle_checkout"). Accepted for the same bounded age as a current
 * one, so a payment made just before an upgrade is still attributed.
 */
export function verifyLegacyCheckoutToken(raw: string, maxAge: string): JwtPayload | null {
  for (const secret of [config.jwtSecret, ...config.jwtPreviousSecrets]) {
    try {
      const c = jwt.verify(raw, secret, { algorithms: ["HS256"], ignoreExpiration: true, maxAge });
      if (typeof c === "object" && c.purpose === "paddle_checkout") return c;
    } catch { /* try the next secret */ }
  }
  return null;
}
