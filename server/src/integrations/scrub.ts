/**
 * What an error stored on a connection (and shown on the dashboard) may say about a credential: nothing.
 * Audit A-8: removing only the exact secret value missed the forms a provider's or library's message
 * actually echoes. Removed here, in this order:
 *  - each stored secret, as typed AND in the shapes it travels in: base64 (a Basic header is base64 of
 *    "email:token"), URL-encoded, JSON-escaped, and any two secrets joined with ":" (user:password);
 *  - the query string of any URL (signatures and keys travel there);
 *  - webhook URLs of the chat/automation hosts we deliver to (the URL itself is the credential);
 *  - everything the platform-wide credential rules know (Bearer/Basic headers, JWTs, cloud and vendor
 *    keys, password=… fields, private keys, URL user:password@) — the same rules that guard text sent to an AI.
 * Short secrets (under 6 characters) are not matched literally: they would shred ordinary words.
 */
import { redactSecrets } from "../ai-safety.js";

const MIN_LITERAL = 6;

function forms(value: string): string[] {
  const out = new Set<string>([value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1)]);
  for (const v of [...out]) out.add(Buffer.from(v).toString("base64")).add(Buffer.from(v).toString("base64url"));
  return [...out].filter((v) => v.length >= MIN_LITERAL);
}

export function scrubError(text: string, secrets: Record<string, string> = {}, max = 300): string {
  const values = Object.values(secrets).filter((v): v is string => typeof v === "string" && v.length > 0);
  const candidates = new Set<string>();
  for (const v of values) for (const f of forms(v)) candidates.add(f);
  for (const a of values) for (const b of values) if (a !== b) for (const f of forms(`${a}:${b}`)) candidates.add(f);
  let s = String(text ?? "");
  // Longest first, so a secret that contains another is removed whole.
  for (const c of [...candidates].sort((x, y) => y.length - x.length)) s = s.split(c).join("[redacted]");
  s = s.replace(/(https?:\/\/[^\s?#"']+)[?#]\S*/gi, "$1?[redacted]");
  s = s.replace(/https:\/\/(?:hooks\.slack\.com|[a-z0-9.-]+\.webhook\.office\.com|[a-z0-9.-]+\.logic\.azure\.com|[a-z0-9.-]+\.powerplatform\.com|events\.pagerduty\.com)\/[^\s"']*/gi, "[redacted-url]");
  s = redactSecrets(s).text;
  return s.replace(/\s+/g, " ").slice(0, max);
}
