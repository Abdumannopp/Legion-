# AI providers: OpenRouter and Groq

Legion's Oracle explanations and Copilot assistant can use an AI model. This is
**optional**: with no key, both use local, deterministic analysis and **nothing
leaves the server**.

## Setup

Set whichever key you have — the one present is used:

```env
OPENROUTER_API_KEY=sk-or-…     # choose a model at openrouter.ai/models
OPENROUTER_MODEL=              # empty = the default model of your OpenRouter account

GROQ_API_KEY=gsk-…             # alternative
AI_PROVIDER=                   # if both keys are set: write groq to use Groq
```

OpenRouter gives access to many vendors' models with one key, including **free
models**, so AI can be tried without paying.

Steps:

1. Sign up at [openrouter.ai](https://openrouter.ai/) and get a key.
2. Put it after `OPENROUTER_API_KEY=` in `server/.env`.
3. Restart Legion.
4. Open an alert and click "Oracle".

If it does not work, the server log says why (for example "no credit" or
"unknown model"). Check what is active: `curl http://localhost:8000/health` →
`ai_provider`.

## Two deliberate decisions

**1. No default model for OpenRouter.**
OpenRouter's model list changes. A model name written into the code today could
be removed in six months, and from that day **AI would stop working on every
customer's installation**. With the field empty, no model is sent and OpenRouter
uses the default model of the customer's own account; the customer chooses a
model where they can see its price.

**2. A wrong setting switches AI off — it never falls back to another provider.**
If `AI_PROVIDER=openrouter` is set without an OpenRouter key but a Groq key is
present, many programs would quietly switch to Groq. Legion does not: AI is
switched off and the log says why. The customer **chooses** which company sees
their security data; naming one and sending to another is the worst kind of
mistake. This case is covered by a test.

Also: OpenRouter accepts an `HTTP-Referer` header, but Legion does **not** send
it — it would reveal the customer's internal server address. Only the name
"Legion" is sent.

## AI safety

**AI only advises.** Requests to the provider contain no `tools`/`functions`, so
the model cannot *do* anything: its answer is text a person reads. In the
dashboard, incident page and Copilot, every model answer is labelled
**"AI suggestion"**; text written by Legion's own rules is labelled
**"Legion analysis"**.

| Protection | How |
|---|---|
| Alert text is untrusted data | Only in the user message, inside a fence with a random boundary per request; invisible characters and chat-template tokens are removed |
| Host names, IPs, MITRE IDs, IDs | If the format does not match, the model sees `(non-standard value omitted)` instead |
| Secrets never reach the provider | Passwords, tokens, API keys, JWTs, private keys, credentials in URLs and the server's own secrets become `[REDACTED:…]` before sending |
| Data minimisation | Fields are shortened; **strict mode** replaces IPs, emails and host names with `IP_1`, `HOST_1`… and maps them back in the answer |
| Output | JSON/structure is validated, HTML and images removed, links defanged (`hxxps://x[.]y`), secrets masked, length limited; an answer that echoes the request's own boundary is refused |
| Time and errors | `AI_TIMEOUT_MS`, 256 KB response limit, no redirects; a circuit breaker after repeated failures. Any error returns the deterministic local analysis |
| Organisation control | `GET/PATCH /ai/settings` and the "AI analysis" card in Settings → Profile (administrators only). When off, nothing is sent for agent skills either |
| Audit | `alert.explained` / `copilot.chat` records only the provider, size, number of redacted secrets, timing and error reason — never the prompt, the answer or a key |

**In hosted (SaaS) mode AI is OFF by default** — an organisation's data does not
go to a third party until its administrator turns it on. In self-hosted mode it
is on. Change it with `AI_TENANT_DEFAULT=on|off`.

Tests: `server/tests/ai-hardening.test.ts` (attack scenarios),
`server/tests/ai-safety.test.ts`.

## Privacy

With a key, the alert title, summary, host names and IP addresses (after the
redaction above) are sent to the chosen provider. That is the operator's
decision; take your obligations to your own customers into account, and sign a
DPA with the provider or use a zero-retention option where available.
