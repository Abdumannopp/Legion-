# Integrations — what is built, what is not

Legion takes security data in through **adapters** (`server/src/integrations/`): one file per source, one `register()` call. Every adapter produces the same `Finding`; one shared path stores it (idempotent, tenant-isolated, with mail and realtime). Nothing outside `src/integrations` knows a vendor's format.

| # | Integration | Status | How it connects |
|---|---|---|---|
| 0 | **Wazuh** | built (earlier) | `POST /security-events/webhook`, signed |
| 1 | **Generic JSON webhook** (also Elastic Security, Splunk) | **built, tested with sample payloads** | `POST /security-events/webhook/generic`, signed, JSON |
| 2 | **Syslog / CEF** | **built, tested with sample lines** | `POST /security-events/webhook/cef`, signed, `text/plain` |
| 3a | **Slack** (notification) | **built, tested with a simulated provider** | outbound, incoming-webhook URL |
| 3b | **Jira Cloud** (ticket) | **built, tested with a simulated provider** | outbound, e-mail + API token |
| 3 | **Microsoft Defender XDR** | **built, tested with a simulated Graph** | pull, Entra app, `SecurityAlert.Read.All` |
| 4 | **AWS GuardDuty** | **built, tested with a simulated API; SigV4 checked against AWS's published test vector** | pull, IAM access key (read only) |
| 5 | Elastic / Splunk dedicated pull adapters | optional later; the generic webhook already receives their alerts | |

## Authentication (all push routes)

Same as the Wazuh webhook: a **sensor credential** (Settings → Sensor credentials) signs `timestamp + nonce + raw body` with HMAC-SHA256. The signature is checked on the raw bytes **before** anything is parsed; replays are refused; repeated failures from one address are throttled. The workspace is whatever the credential belongs to — nothing in the body or headers can choose it. Not subject to the subscription gate (late invoices must not drop telemetry).

Headers: `x-legion-key-id`, `x-legion-timestamp`, `x-legion-nonce`, `x-legion-signature` (see `webhook-auth.ts`; `integrations/wazuh/custom-legion.py` is a reference signer).

## Generic JSON webhook

Body: one object, an array, or `{"events":[…]}` (up to 200). First matching field wins:

| Meaning | Fields |
|---|---|
| title (required) | `title`, `name`, `alert_name`, `rule.name`, `kibana.alert.rule.name`, `search_name`, `message`, `description` |
| severity | `severity`, `level`, `priority`, `event.severity`, `kibana.alert.severity`, `kibana.alert.risk_score`, `urgency` — words (low…critical) or numbers (0–10, or 0–100 above 10). Unknown → **medium**, never low |
| id (dedupe) | `id`, `event_id`, `uuid`, `alert_id`, `kibana.alert.uuid`, `sid` — otherwise a hash of the content |
| time | `timestamp`, `@timestamp`, `time`, `occurred_at`, `kibana.alert.start`, `_time` (ignored if before 2000 or in the future) |
| source address | `source_ip`, `src_ip`, `source.ip`, `client.ip`, `src`, `result.src_ip` (only valid IPs) |
| host | `host`, `hostname`, `host.name`, `agent.name`, `dest`, `result.host` |

An event with no title is skipped, never invented.

**Elastic Security:** Kibana → Rules → Actions → *Webhook* connector, POST to the URL above with the rule's alert document as the body; a small signing proxy (or Logstash/Vector with an HMAC step) adds the headers. **Splunk:** *Webhook* alert action, same approach. Neither has been tested against a real Elastic or Splunk instance — only against sample payloads of their documented shape.

## Syslog / CEF

Legion **does not open a syslog port**: an unauthenticated UDP/TCP listener would be a new attack surface. Run a collector you already have (rsyslog `omhttp`, syslog-ng `http()`, Vector, Fluent Bit, Logstash) that batches lines and POSTs them as `text/plain`, one event per line (up to 200 lines of 4 KB).

- **CEF** (with or without a syslog header): `CEF:0|vendor|product|version|signature|name|severity|extension`. Severity 0–3 low, 4–6 medium, 7–8 high, 9–10 critical. Escaped `\|` and `\=` are handled. Used: `src`, `dst`, `dhost`/`shost`, `msg`, `act`, `suser`, `duser`, `rt`/`end`/`start`, `externalId`.
- **Plain syslog** (`<PRI>…`): kept only when syslog severity is *error or worse* (0–3); routine lines are skipped on purpose.

## Safety

- All text is untrusted data: control and bidirectional characters removed, lengths bounded, IPs validated, no field is ever read as an instruction.
- Adapters never throw on hostile input (tested with malformed headers, huge lines, NULs).
- These sources feed detection and — **only if a workspace opted in** ([PROTECTION.md](PROTECTION.md)) — automatic blocking of public addresses. A source address in a log can be forged: confirm from a second source before trusting it.

## Honest limits

- Tested with sample payloads and lines, **not** against real Elastic, Splunk, ArcSight or rsyslog installations.


## Outbound connectors: Slack (notification) and Jira (ticket)

```
 alert stored ──(same DB transaction)──▶ notification_outbox  kind=integration_message
   (ingest)                               one row per (alert, connection), dedupe key
                                                   │  worker: claim ▸ lease ▸ attempt (60 s cap)
                                                   ▼
                              integration-notify.ts ─ opens the connection's sealed secrets
                                                   │
                         ┌─────────────────────────┴──────────────────────────┐
                         ▼                                                    ▼
              slack.ts → hooks.slack.com                    jira.ts → <site>.atlassian.net
                         │                                                    │
        success ─▶ sent (+ ticket key kept)       5xx / 429 / timeout ─▶ retry with backoff (≤ max attempts)
        4xx (revoked, bad login) ─▶ dead letter at once, shown on the connection (last_error, failures)
```

**Set up (customer, administrator):** Settings → Integrations (API: `POST /integrations`).

| | Slack | Jira Cloud |
|---|---|---|
| Create in the vendor | Slack app → *Incoming Webhooks* → add to one channel → copy the URL | Atlassian account (a bot user) → *API token*; note the project key (e.g. `SEC`) |
| `kind` | `slack` | `jira` |
| `config` | `{"min_severity":"high"}` | `{"site":"acme","project_key":"SEC","issue_type":"Task","min_severity":"high"}` (`acme` = acme.atlassian.net) |
| `secrets` | `{"webhook_url":"https://hooks.slack.com/services/…"}` | `{"email":"bot@acme.io","api_token":"…"}` |

Secrets are sealed (AES-256-GCM, bound to the workspace and connection), never returned, never logged, and an error that echoes one is scrubbed before it is stored. `min_severity` defaults to `high`. At most `ALERT_EMAIL_HOURLY_CAP` (default 100) messages per connection per hour.

**SaaS vs self-hosted:** no new environment variables. The Legion server must reach `hooks.slack.com:443` and `*.atlassian.net:443` over HTTPS; on a self-hosted install with an egress firewall, allow exactly those. Legion calls no other host and never a URL a customer typed (redirects are refused, the site is a name, not a URL).

**Health:** the connection shows `last_success_at`, `last_error` and `failures`; after 10 consecutive failures it goes to `error` and stops receiving until resumed. Queue depth, retries and dead letters appear in `/metrics` under the outbox kind `integration_message`.

**Provider downtime:** messages wait in the outbox and are retried with exponential backoff (cap 1 h) up to `NOTIFY_MAX_ATTEMPTS`; then they are dead-lettered, never silently dropped. A revoked Slack webhook or a Jira 401/403/404 is not retried (retrying cannot help). A removed connection drops its pending messages without error; a paused one keeps them until the retry budget ends.

**Tickets are idempotent:** before creating, Legion searches the project for the label `legion-<alert id>`; a retry or a crash after creation finds the first ticket. Jira's search index can lag by seconds, so a retry within that window can, rarely, open a second ticket.

**They cannot act:** these connectors only notify or open tickets. A test fails if an outbound adapter declares a "respond" capability or imports blocklist/action/approval code. The only things Legion can do in a customer's environment remain the two executors in [PROTECTION.md](PROTECTION.md), which need an administrator's opt-in, and everything privileged still waits for a person.

**Verified:** `tests/integrations-outbound.test.ts` (17 tests, simulated Slack/Jira): delivery, filtering by severity, duplicate suppression, markup/mention neutralisation, 503→retry→delivered, 429 retry, revoked webhook dead-lettered with health shown, paused/removed connections, secrets never in responses/URLs/rows/errors, tenant isolation (workspace B's channel never receives A's alerts; A cannot touch B's connection), idempotent tickets.
**Not verified:** a real Slack workspace or Jira Cloud site (only simulated providers), Jira Data Center / Server, Slack bot tokens (only incoming webhooks), 


## Pull connectors: Microsoft Defender XDR and AWS GuardDuty

Added in the dashboard under **Connect → Connections** (administrators), or `POST /integrations`. Polled every 5 minutes by whichever instance holds the lease; ingestion is idempotent, so a repeated poll never doubles an alert. A failing poll backs off (up to 1 h) and, after 10 failures in a row, the connection shows *Stopped after repeated errors* until an administrator resumes it.

| | Defender XDR (`m365`) | GuardDuty (`guardduty`) |
|---|---|---|
| Vendor side | Entra ID → App registration → API permission **SecurityAlert.Read.All** (application) → grant admin consent → create a client secret | IAM user with only the policy below; create an access key |
| `config` | `{"directory_id":"<GUID>","client_id":"<GUID>"}` | `{"regions":["eu-west-1"],"role_arn":"arn:aws:iam::<account>:role/LegionGuardDutyRead","external_id":"…"}` (`role_arn`/`external_id` optional, recommended) |
| `secrets` | `{"client_secret":"…"}` | `{"access_key_id":"…","secret_access_key":"…"}` |
| Hosts Legion calls | `login.microsoftonline.com`, `graph.microsoft.com` | `guardduty.<region>.amazonaws.com`, `sts.amazonaws.com` (with a role) |
| Reads | Graph `security/alerts_v2`, by `lastUpdateDateTime` | detectors → findings by `updatedAt` |

GuardDuty IAM policy (read only): `guardduty:ListDetectors`, `guardduty:ListFindings`, `guardduty:GetFindings` on `*`.

**Cross-account role (recommended):** put that policy on a role in the customer's account whose trust policy allows Legion's IAM user with a condition `sts:ExternalId = <external_id>`; the stored key then needs only `sts:AssumeRole` on that role. Legion assumes it for 15 minutes per poll (`sts.amazonaws.com`) and never stores the session credentials.

Firewall for self-hosted installs: allow outbound 443 to the hosts above, plus `hooks.slack.com` and `*.atlassian.net` for Slack and Jira. No other environment variable is needed.

**Verified (simulated providers):** field mapping, severity bands, cursor and paging, a paging link to any host but Graph is refused, wrong secret / missing consent / 403 give a clear error that never contains the secret, an outage backs off and recovers, alerts land only in the owning workspace, secrets are sealed and never returned, region names cannot inject hosts (`tests/integrations-cloud.test.ts`).
**Not verified:** a real Entra tenant or AWS account. Limits: a Microsoft alert or GuardDuty finding is stored once by its id (later updates of the same object do not raise a new Legion alert); Defender severity "high" is the top Microsoft level, so Defender alerts are never "critical"; Security Hub is not built.

## Definition of done: where each item stands

| Item | Status |
|---|---|
| Connectors pass integration tests | yes (simulated providers); in CI as part of `test:security` |
| SaaS and self-hosted configuration documented | yes (this file; egress hosts, no new variables) |
| Secrets protected | sealed per connection, never returned, scrubbed from errors (tested) |
| Tenant isolation verified | yes, for pull, push and outbound (tested) |
| Events correctly correlated | all sources use the same ingestion and campaign correlation (`campaigns.ts`); correlation across vendors is covered by the shared path, not by a vendor-specific test |
| Notification delivery / ticket creation verified | with simulated Slack/Jira; not against real services |
| Failure and recovery tested | provider 5xx/429, revoked credentials, outage then recovery, paused/removed connections |
| No privileged response action without approval | connectors cannot respond (tested); the only executors remain the opt-in ones in PROTECTION.md |
| End-to-end attack investigation demonstration | `tests/e2e-integrations-scenario.test.ts`: Defender XDR (pull) + firewall CEF + Elastic alert for one attacker → one `rapid_chain` campaign → Slack messages and Jira tickets (ticket shown on the alert) → five agents investigate → Vanguard proposes a block → a person approves → simulated, no real block, audit chain verifies (simulated providers) |


**On the alert page** (`/incident/<id>`) a *Sent to* block shows where the alert went and links the Jira ticket (`GET /alerts/:id/deliveries`, tenant-scoped; ticket URLs are only shown when they point to `*.atlassian.net/browse/`).
