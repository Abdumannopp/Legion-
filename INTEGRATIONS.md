# Integrations — what is built, what is not

Legion takes security data in through **adapters** (`server/src/integrations/`): one file per source, one `register()` call. Every adapter produces the same `Finding`; one shared path stores it (idempotent, tenant-isolated, with mail and realtime). Nothing outside `src/integrations` knows a vendor's format.

| # | Integration | Status | How it connects |
|---|---|---|---|
| 0 | **Wazuh** | built (earlier) | `POST /security-events/webhook`, signed |
| 1 | **Generic JSON webhook** (also Elastic Security, Splunk) | **built, tested with sample payloads** | `POST /security-events/webhook/generic`, signed, JSON |
| 2 | **Syslog / CEF** | **built, tested with sample lines** | `POST /security-events/webhook/cef`, signed, `text/plain` |
| 3 | Microsoft Defender XDR | planned (`m365` pull adapter: Graph `alerts_v2`) | Entra app, `SecurityAlert.Read.All` |
| 4 | AWS GuardDuty | planned (`aws` pull adapter: Security Hub/GuardDuty findings) | cross-account IAM role + external id |
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
- No dashboard form yet for these (credentials are created in Settings; the catalogue lists the integrations).
- Defender XDR and GuardDuty are not built; they are pull adapters needing real tenant/account access to be verified.
