# Languages: English, Русский, O'zbekcha

Legion ships in three languages. Every screen, every server message, every
email and the AI answers follow the language the user picks in the switcher.

## Where text lives

| What | Where |
|---|---|
| Dashboard and website text | `ns/<screen>.ts` — one file per screen, all three languages side by side |
| Words used on many screens (buttons, severity, status, roles, "5m ago") | `ns/common.ts` |
| Dates and relative times | `format.ts` (`formatDate`, `formatDateTime`, `timeAgo`) |
| Legal pages | `content/legal/*.ts` |
| API error messages and confirmations | `server/src/i18n.ts` → `CATALOG` |
| Emails (confirm, reset, invite, alert, test) | `server/src/mailer.ts` |

## Adding or changing text

1. Put the English text in the screen's `ns/*.ts` file, then the Russian and
   Uzbek text under the same key. Use it as `t.<screen>.<key>`.
2. Text with a number or a name in it is a function:
   `trialLeft: (n: number) => \`${n} days left\``. Russian counts use
   `plural("ru", n, { one, few, many, other })`.
3. Run `npm run check`. It fails when:
   - a language is missing a key or has an extra one (TypeScript);
   - text is written straight into a component instead of `t.…`
     (`frontend/scripts/check-i18n.mjs`). Brand names and identifiers that must
     stay in English take an `i18n-ignore` comment.
4. A new server message: add it to `CATALOG` in `server/src/i18n.ts`.
   `server/tests/i18n.test.ts` fails otherwise.

## How the language travels

- The switcher stores the choice in a cookie (`legion-locale`), so the server
  renders the next page in that language straight away, and in localStorage.
- Every API request carries it in `Accept-Language`. The server translates
  `detail` / `message` in its JSON answers, writes emails in it, and tells the
  AI model to answer in it.
- Alert emails go to a shared address, so they use the organisation's own
  setting (Settings → Notifications → Email language), which starts as the
  language the organisation signed up in.
- Stored AI explanations remember their language; a reader in another language
  gets a fresh one.

## What is not translated, on purpose

Data from the customer's systems — alert titles and summaries from Wazuh,
host names, rule text — is shown exactly as it arrived. Product names
(Legion, Oracle, Copilot, the agent names, Wazuh, Paddle) stay as they are.
Paddle's payment window has no Uzbek; Uzbek users see it in English.
