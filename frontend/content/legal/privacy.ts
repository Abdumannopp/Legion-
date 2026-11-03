import { Locale } from "@/lib/i18n/translations";

export type LegalSection = { heading: string; body: string[] };
export type LegalDoc = {
  title: string;
  effectiveDate: string;
  intro: string;
  sections: LegalSection[];
};

/**
 * Legion is self-hosted software: the organisation running this installation
 * is the one whose privacy policy this is, and it is not the vendor. Nothing
 * in this codebase can know that organisation's name, so it is supplied at
 * deploy time and substituted into the text by `resolveLegalDoc` below.
 *
 * The fallback is deliberately conspicuous rather than a plausible-looking
 * default: an unconfigured install should look unfinished, not look like it
 * belongs to someone else.
 */
export const OPERATOR =
  process.env.NEXT_PUBLIC_OPERATOR_NAME || "[the organisation running this installation]";

export const SUPPORT_EMAIL =
  process.env.NEXT_PUBLIC_SUPPORT_EMAIL || "support-not-configured@example.invalid";

/** Fills `{operator}` / `{supportEmail}` in a legal document before rendering. */
export function resolveLegalDoc(doc: LegalDoc, operator: string = OPERATOR): LegalDoc {
  const fill = (text: string) =>
    text.replace(/\{operator\}/g, operator).replace(/\{supportEmail\}/g, SUPPORT_EMAIL);

  return {
    ...doc,
    intro: fill(doc.intro),
    sections: doc.sections.map((section) => ({
      heading: fill(section.heading),
      body: section.body.map(fill),
    })),
  };
}

export const privacyContent: Record<Locale, LegalDoc> = {
  en: {
    title: "Privacy Policy",
    effectiveDate: "August 25, 2026",
    intro:
      "This Legion installation is operated by {operator} on infrastructure {operator} controls. Legion is software that {operator} installed; the company that makes Legion does not run this system, cannot log in to it, and receives no data from it. This policy describes what this installation stores, where that data goes, and who to contact about it.",
    sections: [
      {
        heading: "1. What This Installation Stores",
        body: [
          "Account records: your name, work email address, role, and your password — stored only as a bcrypt hash, never as text that can be read back.",
          "Two-factor records, if you enable it: the shared secret your authenticator app uses, and your recovery codes, which are themselves stored hashed.",
          "Session records: for each active sign-in, the IP address and browser user-agent it started from, and its expiry time. This is what lets you see and revoke your own sessions.",
          "An audit log: who performed which administrative action, when, and from which IP address.",
          "Security data from your own systems: alerts, source IP addresses, hostnames, and the asset inventory built from them. This is the material Legion exists to analyse, and its content is determined by what your systems send in.",
        ],
      },
      {
        heading: "2. Where That Data Goes",
        body: [
          "Into the PostgreSQL database on this server, and nowhere else. Legion contains no analytics, no telemetry, no usage reporting, and no automatic update check. It makes no network connection to its vendor at any point, so there is no channel through which your data could reach them.",
          "There are exactly two ways data can leave this server, and {operator} chooses whether either is switched on. Both are off unless configured.",
          "Optional AI analysis: {operator} may supply an API key for an external AI service — Legion supports OpenRouter and Groq — in which case the text of an alert is sent to that service for analysis and the result is stored here. When no key is set, no such request is ever made, and this is the shipped default. Where it is enabled, that service becomes a processor of whatever the alert text contains, and {operator} can tell you which one is in use. Legion sends it the alert text and nothing else — not the address of this installation, and not who is signed in.",
          "Optional email notification: if {operator} configures an outgoing mail server, alert notifications are delivered through that server — one chosen by {operator}, not by the vendor.",
        ],
      },
      {
        heading: "3. Cookies",
        body: [
          "This installation sets three cookies, all of them first-party and all of them necessary to keep you signed in: legion_token (your current session), legion_refresh (renews it without asking for your password again), and legion_session (a marker the dashboard reads to know a session exists).",
          "There are no advertising cookies, no analytics cookies, and no third-party cookies. Nothing here tracks you across other websites.",
        ],
      },
      {
        heading: "4. How Long Data Is Kept",
        body: [
          "Sessions expire on their own, and expired ones are cleared out.",
          "Alerts, assets, and the audit log are kept indefinitely — this software does not delete them on a schedule. If a retention limit applies to {operator}, whether by law or by policy, {operator} is responsible for enforcing it directly in the database.",
          "Because all data sits in a database {operator} controls, {operator} can delete any of it at any time.",
        ],
      },
      {
        heading: "5. Who Can See Your Data",
        body: [
          "People {operator} has given accounts on this installation, according to the role assigned to each of them.",
          "Anyone with administrative access to the server or to its database, which is a matter of how {operator} secures that machine.",
          "The vendor cannot. Support may ask {operator} for logs or screenshots to diagnose a problem, and anything shared that way is shared because {operator} decided to share it.",
        ],
      },
      {
        heading: "6. Security",
        body: [
          "Passwords are hashed with bcrypt. Session tokens are stored hashed, and reusing an old one revokes the whole session family. Two-factor authentication is available and codes cannot be replayed.",
          "These measures protect the software. They cannot protect a server that is left unpatched, unencrypted, or reachable from the internet without HTTPS — that part belongs to {operator}, and the operations guide shipped with Legion sets out what it involves.",
        ],
      },
      {
        heading: "7. Your Rights",
        body: [
          "Requests to access, correct, export, or delete your data go to {operator}, who holds the data and is the only party able to act on such a request.",
          "The company that makes Legion cannot answer these requests, not as a matter of policy but as a matter of fact: it has no copy of the data and no access to this system.",
        ],
      },
      {
        heading: "8. Changes",
        body: [
          "{operator} may update this policy. The effective date above shows when the version you are reading was published.",
        ],
      },
    ],
  },
};
