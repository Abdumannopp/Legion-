# Global UX and onboarding — 2026-09-30

Goal: a person who has never used Wazuh understands Legion on their own.
Target path: **Sign up → Connect → Protected**. On the first screen they can
see what is protected, what threats exist, what Legion blocked, why it
blocked it, and what their AI agents can and cannot do.

Everything below was checked in a real browser (Chromium) against the built
API and the built dashboard: `ops/tests/e2e-journeys.mjs`, now part of CI.

---

## 1. What a new user saw before, and what they see now

| Before | Now |
|---|---|
| An empty alert list after sign-up. Nothing said what to do next. | The first screen says **"Not connected yet"**, explains why in one sentence, and offers **Connect a sensor**. Below that is a getting-started checklist: connect, first event, alert email, then optionally team and AI agent. |
| Wazuh could only be connected through the API (`POST /security-events/credentials`, hand-edited `ossec.conf`). | **Connect** page with a three-step Wazuh wizard: (1) create a key, (2) copy one ready-made config block that already contains the key and this workspace's address, (3) the page waits for the first event and says so when it arrives. A **Send a test alert** button shows what an alert looks like. Technical details are collapsed. |
| A "Security score" computed from all alerts, including resolved ones: it could read 0% with nothing open. | An honest status computed from real data: **Not connected yet / Connected — waiting for the first event / Needs your attention / Protected**, each with the reasons (e.g. "There are open high-severity threats."). |
| Alerts labelled "Sentinel", "Hunter", "Oracle" (internal persona names). | Alerts show where they came from: **Wazuh**, **Test alert** (with a *Test* badge), **AI agent protection**, **Legion monitoring**. Reports group detections by source. |
| No interface for AI agents at all. | **AI agents** section: add an agent, see what it can do, what it asks first, what it can't do, what it did and why Legion stopped it, approve or deny its requests, pause, resume, emergency stop. |
| Errors were the server's sentence and nothing else ("Forbidden", "Not found"). | Every error says **what happened, why, and what you can do**, with the one useful action (sign in, open Billing, go to the right region, try again). |
| Landing page: "a console for teams running Wazuh". | Wazuh is one integration ("Wazuh today, more on the way"). The pitch is about computers and AI agents being protected. |
| Billing during a trial: "You're not subscribed yet". | "Free trial — 14 days left (ends on Oct 14, 2026). Everything works until then." Members are told only admins can change the plan. |

## 2. The main journeys, validated

`E2E_ADMIN_DATABASE_URL=… node ops/tests/e2e-journeys.mjs` creates a fresh
database, starts the built API in hosted mode and the built dashboard, and
drives Chromium through each journey. It checks **the text a person reads**,
not only API responses. Last run: **all 77 checks passed** across the 14 journeys.

| # | Journey | What the test checks |
|---|---|---|
| 1 | Sign up | Form → "We sent a confirmation link" → link from the log → confirmed → sign in |
| 2 | First screen | "Not connected yet", the reason, the checklist; no security score; no persona names |
| 3 | Workspace creation | "New workspace" in the sidebar → the new workspace opens with its own empty status → switch back |
| 4 | Connect integration | Wizard opens by itself; key shown once with a warning; the config block contains the key and the API address; **the real `custom-legion.py` delivers an event with that key**; the page changes to "Connected" by itself; test alert sent and labelled |
| 5 | First alert | Status becomes "Needs your attention" because a high threat is open; source shows "Receiving events"; the alert shows its source; the test alert carries a *Test* badge; the expanded alert shows **What to do** |
| 6 | Incident review | Full details → source in plain words → Investigate |
| 7 | First agent | Empty state explains; the "Triage assistant" preset shows in words what it can do and what no agent can ever do; ID and secret shown once with where the agent signs in |
| 8 | Agent permission change | Change → tick "Read databases" → "Saved. The change applies to the agent's next action." |
| 9 | Allow (confirmation) | An admin makes alert status changes ask first; the agent's attempt is held; the dashboard shows the request in words ("Change alert status…", "exactly this, once"); **Approve once**; the agent's retry goes through once |
| 10 | Block (quarantine) | The agent tries to read another workspace's data; Legion blocks it and pauses the agent; the page says "Paused — it can't do anything until an admin resumes it"; activity shows **"Blocked — agent paused"**, **Why**: "It tried to reach data that belongs to another workspace.", **What to do**: "…keep the agent paused and check who controls it"; rule ids stay under *Technical details*; the dashboard's "What Legion blocked" names the agent and the reason |
| 11 | Resume / kill switch | Resume → "Working"; Emergency stop → two plain choices ("I'm not sure yet" / "It's compromised") and a required reason → "Stopped. Admins have been notified." → the old key no longer works |
| 12 | Billing / plan | "Free trial — N days left (ends on …)"; what the plan includes |
| 13 | An error | A missing agent → "We couldn't find that" / Why / What you can do |
| 14 | Another language | Russian dashboard and Russian block explanation; the browser runs in Asia/Tashkent and times show in that zone |

It also checks that the browser logged no uncaught errors.

Screenshots from the run (`E2E_SCREENSHOTS=<dir>`) were reviewed for layout
problems. Two were fixed. An action a person approved had been shown as
"Allowed, flagged — unusual"; it is now "Allowed — a person approved it". The
agent name was being truncated in the dashboard's "blocked" card.

## 3. AI security, in words

| Legion's decision | What the person sees | What it means |
|---|---|---|
| ALLOW | **Allowed** | Within the agent's permissions and looked normal |
| WARN | **Allowed, flagged** (or **Allowed — a person approved it**) | Allowed but noted |
| CONFIRM | **Asked for approval** + an entry under *Waiting for you* | The agent stopped and asked; nothing happens until a person says yes, and a yes covers exactly that action, once |
| BLOCK | **Blocked** | Refused; the agent carries on otherwise |
| QUARANTINE | **Blocked — agent paused** | Refused and paused: it looked like an attack or a leak |
| KILL | **Blocked — agent stopped** | Refused and stopped at once: it tried to use Legion's own secrets |

More than a hundred firewall rule ids are grouped into 15 plain explanations, each with
**Why** and **What to do** (`frontend/lib/agentRules.ts`). Examples: another
workspace's data; a secret leaving; instructions hidden in content it read
(prompt injection); a tampered tool; an address it may not reach; a database
query, command or file it may not use; no permission; needs approval;
unusual behaviour; paused; agent-to-agent misuse. The exact rule id stays
under *Technical details*.

**Permissions** are listed by what they do ("Read alerts", "Run commands on a
computer", "Send email"). Each has a risk label: *Read-only*, *Reaches
outside* or *Makes changes*. An agent's page shows three columns:

- **Can do**
- **Asks you first** — from the workspace's own policy
- **Can't do**

Under them is **No agent can ever**: invite, remove or change people; change
workspace or security settings; export data; billing; cut computers off the
network. These are the tier-3 permissions, which the server refuses to grant
whatever an administrator asks.

**Controls**:

- **Pause** keeps the key, so the agent can be resumed.
- **Resume** is admin-only.
- **Emergency stop** asks one question in plain words — "I'm not sure yet"
  (keeps the key) or "It's compromised" (also cancels the agent's keys and the
  permissions people gave it) — and a reason for the security record.

## 4. Safe defaults (no security knowledge needed)

- New agents start from **Read-only analyst** (read alerts, devices,
  statistics and vulnerabilities). "Triage assistant" adds commenting and
  status changes. Anything else is an explicit choice.
- Out of the box, every tool write (web, API, database, files, email, GitHub,
  Slack, MCP, cloud) and every shell command **asks a person first**. This
  comes from the existing server policy; the dashboard shows it rather than
  restating it.
- Out of the box, reaching another workspace, a secret leaving, and prompt
  injection **pause the agent**. Touching Legion's own secrets **stops it**.
- An agent can never do more than the person responsible for it (enforced by
  the server; said on the permission screen).
- Keys and agent secrets are shown once, with a warning, and never again.
- The test alert is admin-only, capped at 10 per hour, labelled, and never
  counted as the sensor's first event.

No security control was loosened to make any of this work.

## 5. Errors

`frontend/lib/errors.ts` + `components/ErrorNotice.tsx`. The server's own
message (already in the reader's language) is kept as the detail. The
explanation is chosen by status and code, so it also fits messages the
dashboard has never seen:

| Situation | What happened | What you can do (action) |
|---|---|---|
| No connection | Legion can't be reached | Check the connection, try again (Try again) |
| 401 | You've been signed out | Sign in again (Sign in) |
| 402, trial over | This workspace's plan isn't active | Admin: choose a plan (Open Billing). Member: ask an admin |
| 402, past due | Payment is overdue | Admin: update the payment method (Open Billing). Member: ask an admin |
| 421 | This workspace is in another region | Open it from its region (Go there) |
| 403 / 404 / 409 / 400 | No permission / not found / changed meanwhile / invalid input | Ask an admin / check the workspace / refresh / correct and retry |
| 429 | Too many attempts | Wait N seconds (from Retry-After) |
| 5xx | Something went wrong on our side | Try again in a minute; contact support if it continues |

It is used on the dashboard, incidents, incident review, Connect, AI agents,
billing and sign-up. The server now returns a machine-readable `code` on its
402 and 421 responses (`subscription_inactive`, `subscription_past_due`,
`wrong_region`), in addition to the message, which is unchanged.

## 6. Global readiness

- **English first, translation-ready.** New screens add four namespaces
  (`overview`, `connect`, `agents`, `errors`), about 300 strings, in English,
  Russian and Uzbek. TypeScript refuses a build where a language is missing a
  key. `scripts/check-i18n.mjs` refuses hard-coded interface text. A unit test
  checks that every permission the server can grant has a name in every
  language. The server's new message is in its translation catalogue.
- **Time zones.** Times show in the viewer's own zone (or their chosen one,
  Settings → Regional). The journey test runs the browser in Asia/Tashkent.
- **Dates and numbers** go through the existing locale formatters. Counts on
  the new screens use `formatNumber`.
- **Currency.** New `formatMoney(minorUnits, currency, locale)` uses each
  currency's own decimals (USD 2, JPY 0). The plan price now comes from
  Paddle's minor-unit total, written the way the viewer's language writes
  money, instead of Paddle's own string.

## 7. Server changes

All additive; no existing response shape changed.

- `GET /overview`: status and reasons; what is protected (sources and their
  health, devices, agents); open threats by severity; what Legion blocked in
  7 days; the onboarding checklist. Every number is a query on the
  workspace's own rows.
- `GET /agent-permissions`: the permission catalogue with tiers, which ones
  this workspace's policy makes ask first, and the never-grantable list.
- `POST /security-events/test`: admin-only labelled test alert, capped per
  hour, written in the sender's language.
- A `code` added to the 402 and 421 bodies.

Tests: `server/tests/overview.test.ts` covers the status progression, a
silent sensor, blocks isolated per workspace, and the test alert (admin-only,
labelled, capped, not a first event).

## 8. Tests added

Full runs at the end of this change:

- server: 46 files, 1070 tests, with `LEGION_REQUIRE_FAILURE_INJECTION=1`
- frontend: lint (types and i18n), 154 unit tests, production build
- `ops/tests/e2e-wazuh.mjs`: 34 checks
- `ops/tests/e2e-journeys.mjs`: 77 checks
- CI gate self-check

| Where | What |
|---|---|
| `server/tests/overview.test.ts` | 5 tests (above) |
| `frontend/lib/errors.test.ts` | 20: each error class, actions, admin vs member, Retry-After, retryable, every language, money formatting |
| `frontend/lib/agentRules.test.ts` | 5: rule grouping (including every default quarantine and kill rule), explanations present in every language, every grantable permission named in every language |
| `ops/tests/e2e-journeys.mjs` | The 14 journeys above in Chromium; added to CI's `app` job |

## 9. Known limits

- **The Wazuh integration files** (`custom-legion`, `custom-legion.py`) still
  have to be copied from the Legion package to the Wazuh server; the wizard
  says where they are and gives the commands. Serving them from the dashboard
  would need them in the dashboard's build, which it does not have today.
- **Firewall policy editing** (allowed hosts, which permissions ask first,
  custom rules) is still API-only (`PUT /firewall/policy`). The dashboard
  shows the effect of the policy everywhere, but does not edit it.
- **Viewers** cannot open the AI agents pages: the agent registry is for
  admins and analysts. They get the explained "You don't have permission"
  message.
- **Other integrations** (AWS, Azure, Google Cloud, GitHub, Microsoft 365)
  are listed as *Coming soon*, matching the server's catalogue.
- **The Billing page** still shows the operator's "Paddle isn't configured"
  hint when Paddle keys are missing, which only happens on a misconfigured
  install.
