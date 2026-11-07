import { SUPPORT_EMAIL } from "@/content/legal/privacy";

export const dynamic = "force-dynamic";

/** RFC 9116. Published only when the operator has set a contact address: a made-up one would send reports nowhere. */
export function GET(): Response {
  if (SUPPORT_EMAIL.endsWith(".invalid")) return new Response(null, { status: 404 });
  const expires = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();
  // i18n-ignore: a machine-readable file (RFC 9116), not interface text
  const body = `Contact: mailto:${SUPPORT_EMAIL}\nExpires: ${expires}\nPreferred-Languages: en\n`;
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "public, max-age=3600" } });
}
