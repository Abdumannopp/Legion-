/** Fields Legion reads out of a sensor's log line. */

/**
 * Who a log line is about. Legion stores no separate user field, but the
 * sensor's log line names the account (sshd, sudo, PAM, Windows). This reads
 * the common forms and nothing else; anything it does not recognise stays
 * unknown rather than guessed. The text comes from whoever wrote the log, so
 * the result is bounded and only ever treated as data.
 */
const NAME = "([A-Za-z0-9._@\\$-]{1,64})";
const USER_PATTERNS: RegExp[] = [
  new RegExp(`\\b(?:Failed|Accepted) [a-z-]+ for (?:invalid user )?${NAME} from\\b`, "i"),
  new RegExp(`\\bInvalid user ${NAME} from\\b`, "i"),
  new RegExp(`\\bsession (?:opened|closed) for user ${NAME}`, "i"),
  new RegExp(`\\bsudo:\\s+${NAME}\\s*:`, "i"),
  new RegExp(`\\btarget ?user ?name"?\\s*[:=]\\s*"?${NAME}`, "i"),
  // Microsoft 365 / Entra audit records: "UserId": "dana@acme.example"
  new RegExp(`\\buser ?(?:id|principal ?name)"?\\s*[:=]\\s*"?${NAME}`, "i"),
  new RegExp(`\\buser(?:name)?"?\\s*[:=]\\s*"?${NAME}`, "i"),
];
const NOT_A_USER = new Set(["unknown", "null", "(null)", "none", "from", "for", "-", "n/a"]);

export function userFromLog(text: string | null | undefined): string | null {
  const t = String(text ?? "").slice(0, 4_000);
  for (const re of USER_PATTERNS) {
    const m = re.exec(t);
    const name = m?.[1]?.replace(/[.,;:]+$/, "");
    if (name && !NOT_A_USER.has(name.toLowerCase())) return name;
  }
  return null;
}

