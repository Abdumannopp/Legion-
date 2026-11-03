# Language: English only

Legion is built for the global market and ships in English only. The server
answers in English whatever `Accept-Language` says, emails are English, and
there is no language switcher.

## Where text lives

| What | Where |
|---|---|
| Dashboard and website text | `ns/<screen>.ts` — one file per screen (English) |
| Words used on many screens | `ns/common.ts` |
| Dates and relative times | `format.ts` |
| Legal pages | `content/legal/*.ts` |
| API error messages | written in English in the routes |
| Emails | `server/src/mailer.ts` |

Put new text in the screen's `ns/*.ts` file and use it as `t.<screen>.<key>`.
`npm run lint` fails when text is written straight into a component.

The `Locale` plumbing (`defineMessages({ en })`, the provider) is kept on
purpose: adding a language later means widening `Locale` and adding the
translations, not rewriting the screens.
