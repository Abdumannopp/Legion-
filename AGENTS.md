# Legion's five agents and their skills

Legion has five agents. Each has its own job and its own skills.
In the dashboard you see them on the **Legion team** page.

| Agent | Job | Skills |
|---|---|---|
| **Sentinel** (watches) | Watches sign-ins, accounts and events from your servers | `threat_detection`, `account_activity_watch`, `sensitive_access_watch` |
| **Hunter** (hunts) | Connects separate events into one attack, looks for data theft | `attack_investigation`, `threat_intelligence`, `data_exfiltration_hunt` |
| **Guardian** (protects) | Finds what is open to attack before anyone attacks it, tests Legion's own defences | `vulnerability_analysis`, `ai_security_red_team`, `exposure_review`, `threat_coverage`, `secret_exposure_check` |
| **Oracle** (explains) | Explains an alert in plain words and says what to look at first | `alert_analysis`, `security_reporting`, `triage_priority`, `response_sla_review` |
| **Executor** (prepares the response) | Prepares the next step with its evidence; **a person approves it** | `incident_response`, `containment_candidates`, `payment_fraud_review` |

## Detection skills

| Skill | What it does |
|---|---|
| `account_activity_watch` (Sentinel) | Spots stolen or guessed accounts: a sign-in after many failures, one account used from many addresses, one address trying many accounts (password spraying), new privileges or a new account right after a sign-in |
| `data_exfiltration_hunt` (Hunter) | Finds data being collected (a database dump, an archive) and then sent out, with the volume and the external address. Collection alone (for example a nightly backup) is not reported |
| `exposure_review` (Guardian) | Ranks assets by exposure: reachable from the internet, known weaknesses, whether a fixed version exists. Cheapest fixes first |
| `threat_coverage` (Guardian) | For the seven most dangerous attack types: what Legion detected, what it is watching, and where it is blind because data never arrives ([THREATS.md](THREATS.md)) |
| `triage_priority` (Oracle) | Orders open alerts into now / today / this week, each score with its reasons |
| `containment_candidates` (Executor) | Attacker addresses worth blocking, with evidence. Private addresses go into a "cannot block" list. Warns when an attack comes from many addresses and blocking will not help |

## Skills for business customers (B2B)

| Skill | What it does |
|---|---|
| `secret_exposure_check` (Guardian) | Finds passwords, keys, card numbers (Luhn-checked) and bank accounts (IBAN, mod-97-checked) that ended up in logs. Reports the **kind and the place**, **never the value**, and what to do (rotate the key, etc.) |
| `sensitive_access_watch` (Sentinel) | Watches **who opens** customer data, payroll, contracts, keys and backups. Flags one account opening 10+ different sensitive files or appearing on 3+ machines |
| `response_sla_review` (Oracle) | Compares open alerts against response targets (default: critical 4 h, high 24 h, medium 3 days, low 7 days; you can change them). Lists late ones and the on-time percentage — the answer to your partners' question "how fast do you respond to a security incident?" |
| `payment_fraud_review` (Executor) | Reviews the payment check: how many payments were allowed or held, **which one has waited how many hours for a phone confirmation**, and patterns that look like fraud (repeated attempts to one account, a retry after a rejection, one requester asking for several new accounts). Never shows an account number (only the last 4 characters) |

`payment_fraud_review` needs a new permission: **`payments:read`** (read-only,
lowest tier). Choosing a skill grants nothing; the page shows it as a missing
permission.

## Giving a skill to an AI agent

1. Dashboard → **AI agents** → open the agent → **Skills** tab.
2. Tick the skill (administrators only).
3. The agent also needs the permissions the skill reads with (for example
   `alerts:read`). Choosing a skill **grants no permission**. If one is missing,
   the page says which; grant it in the **What it can do** tab.
4. The agent calls the skill:

```
POST /agent/v1/skills/triage_priority/invoke
Authorization: Bearer <the agent's short-lived token>
{"input": {"windowHours": 24}}
```

## Safety rules (cannot be changed)

- Skills **only read and recommend**. No skill blocks, deletes or changes
  anything — not even Executor's. Every recommendation comes with
  `executed: false`; a person approves and carries it out (for example,
  blocking on the Dashboard → **Defense** page).
- A skill reads your own organisation's data, never another organisation's
  (the server checks again after every row).
- Event text may have been written by an attacker. It is read as **data**,
  never as instructions. An attempt to manipulate the AI is detected, raises
  the score and is flagged.
- Every call is written to the audit log (not the request text or the answer).

## Honest limits

- **The user name comes from the log text.** Legion does not store a separate
  "user" field. The name is extracted from familiar lines in sshd, sudo, PAM and
  Windows logs; on an unfamiliar line it stays unknown and is not guessed.
  Whoever wrote the log chose the name, so it is used only as data.
- **Exposure is estimated.** An asset with a public IP is treated as "open to the
  internet". A private address stays "unknown" (not "internal"): it may be
  exposed through NAT or a load balancer.
- **Legion does not measure network volume.** Data volume is known only if the
  event recorded it. Backups and migrations also look like "collect and send";
  the result is a direction to check, not proof.
- **Agents call the skills.** Legion does not run them on a schedule. Legion's
  own detection and automatic blocking run separately ([WAZUH.md](WAZUH.md),
  "Automatic response").
- **Ranking is based on evidence, not business value.** A high score on a test
  server can rank above a medium one on the payment system.
- An address in a log may be forged. Confirm from a second source before blocking.
- **`response_sla_review` does not know when alerts were closed.** Legion does
  not record when an alert was resolved, so it measures only how long open ones
  have waited. The targets are your choice; the defaults are not a legal or
  contractual standard.
- **`sensitive_access_watch` sees only file access the sensors report.** If file
  or database access events (Wazuh syscheck, audit, database audit) are not
  connected, it says "0", not "safe". It recognises sensitive data by name
  (customers, payroll, backup…); data stored under an ordinary name is not seen.
- **`secret_exposure_check` finds only familiar formats.** A home-made secret or
  an unusual format is missed; guesses based on words like "password=" can be
  wrong. It cannot tell whether a secret is still valid.
