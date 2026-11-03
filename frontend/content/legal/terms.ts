import { Locale } from "@/lib/i18n/translations";
import { LegalDoc } from "./privacy";

/**
 * These are the terms on which the operator offers *this installation* to the
 * people who log into it — not a service agreement with the vendor. The
 * commercial relationship between the operator and the vendor lives in the
 * LICENSE file at the root of the repository, and the two must not be
 * confused: the earlier version of this page described a hosted subscription
 * that does not exist in a self-hosted deployment.
 *
 * `{operator}` is substituted by `resolveLegalDoc`.
 */
export const termsContent: Record<Locale, LegalDoc> = {
  en: {
    title: "Terms of Use",
    effectiveDate: "August 25, 2026",
    intro:
      "This is a Legion installation operated by {operator}. These terms govern your use of it as someone {operator} has given an account. They are not an agreement with the company that makes Legion — that company does not run this system and is not a party to your use of it.",
    sections: [
      {
        heading: "1. What This Is",
        body: [
          "Legion is a security platform that collects alerts from your organisation's monitoring systems, groups and prioritises them, and helps analysts decide what to act on.",
          "It is a tool for trained people, not a replacement for them. Its analysis — including anything produced with AI assistance — can be incomplete or wrong, and no security product can guarantee that every threat is detected. Decisions remain yours.",
        ],
      },
      {
        heading: "2. Your Account",
        body: [
          "{operator} decides who gets an account and what each account may do. Accounts are personal: keep your password and your two-factor device to yourself, and do not let anyone else use your account.",
          "Tell {operator} promptly if you think someone else has used your account, or if you no longer need it.",
          "Everything done through your account is recorded in an audit log with the time and originating IP address.",
        ],
      },
      {
        heading: "3. Acceptable Use",
        body: [
          "Use this installation only for {operator}'s security work, and only within the access you have been given.",
          "Do not attempt to reach data belonging to accounts or areas you have not been granted, interfere with the system's operation, or use it to gain unauthorised access to anything else.",
          "The data here describes real systems and real incidents. Treat it as confidential to {operator} and do not copy it out except as {operator}'s own policies allow.",
        ],
      },
      {
        heading: "4. Data",
        body: [
          "The security events, alerts, and account records in this installation belong to {operator} and sit in a database {operator} controls.",
          "How that data is handled, how long it is kept, and who may see it are described in the Privacy Policy for this installation.",
        ],
      },
      {
        heading: "5. Availability",
        body: [
          "This installation runs on {operator}'s own infrastructure. Its uptime, backups, and maintenance windows are {operator}'s responsibility, and no availability is guaranteed here.",
          "Legion should not be relied on as the only means of detecting a security incident.",
        ],
      },
      {
        heading: "6. The Software Itself",
        body: [
          "The Legion software is licensed to {operator} by its vendor under a separate agreement, which is supplied with the software as the LICENSE file. That agreement governs {operator}'s right to run, copy, and modify Legion.",
          "Nothing on this page grants you any right in the software beyond using this installation as {operator} permits.",
        ],
      },
      {
        heading: "7. Changes and Access",
        body: [
          "{operator} may change these terms, change what your account can do, or withdraw your access — for example when your role changes or you leave the organisation.",
          "Questions about these terms, about your access, or about the data held here go to {operator} at {supportEmail}.",
        ],
      },
    ],
  },
};
