# The seven most dangerous attack types: what Legion does, and what it cannot do

Dashboard → **Defense** shows a status for each type:

- **Detected** — a sign was found in the last 7 days (with evidence).
- **Watching** — the needed data arrives and no sign was found.
- **Blind** — the needed data **does not reach** Legion. The page says what to
  connect. A quiet dashboard means nothing when no data arrives — so we say so openly.
- **Partial** — only for AI deception (see below).

When a sign is found, Legion raises one alert straight away (the Hunter agent,
in the "Attack campaigns" list) and says what to do.

| # | Attack | What Legion catches | What must be connected for Legion to see it |
|---|---|---|---|
| 1 | **Ransomware** | Shadow copies deleted (`vssadmin delete shadows`), recovery disabled (`bcdedit`, `wbadmin`), a ransom note, mass file encryption, **50+ file changes on one server in 10 minutes**. Severity: critical. | Wazuh file integrity monitoring (syscheck), process events |
| 2 | **BEC** (business email compromise) | A mailbox rule that forwards or hides mail, an app granted mailbox access (OAuth), second-factor protection (MFA) switched off, changed bank details. Grouped by account. | Microsoft 365 or Google Workspace audit logs (Wazuh office365 module) |
| 3 | **Phishing** | Word/Excel/Outlook launching a script (PowerShell etc.), macros, a malicious link clicked | Mail security gateway, process events from computers (Sysmon) |
| 4 | **DDoS** | Flood signs in logs; many-address (`swarm`) and burst (`velocity`) campaigns. Legion **itself** is protected against DDoS ([EDGE-SECURITY.md](EDGE-SECURITY.md)) | Web server, firewall or WAF logs |
| 5 | **AI attacks** (deepfakes, fake voice/video) | Text written into logs to steer an AI; the changes **after** a fake call (new bank details, mail forwarding, events mentioning "voice cloning") | Mail audit logs + an organisational rule (see below) |
| 6 | **Cyber espionage** | On one server over **6+ hours**: persistence + credential theft (mimikatz, lsass) or a command channel (beacon, DNS tunnel). Severity: critical | Process, PowerShell and DNS/firewall events |
| 7 | **Supply-chain attack** | A signature or checksum error, a malicious package (typosquatting, dependency confusion), attacker activity (reverse shell, beacon) **within 60 minutes of a package install** | Package install and software update events |

All these rules work the same way: one campaign = one alert (not one per
event), and each organisation sees only its own. Automatic IP blocking does
**not** apply to these rules — they are about a server or an account, not an
address; the right response is isolating the server and recovering the account
(written in the alert).

## Guardian skill: `threat_coverage`

A skill you can give to your AI agents: it returns the same status for the seven
types (detected / watching / blind) with evidence. See [AGENTS.md](AGENTS.md).

## Honest limits

- **Legion sees only the data that reaches it.** Without mail logs it cannot
  see BEC or phishing — the page says "Blind".
- **A deepfake call or video never reaches Legion.** No log system hears a fake
  voice on a phone. Legion sees only the changes that follow. The best defence is
  an **organisational rule**: when payment details change or an urgent transfer
  is requested, call back on a number you already had — never one from the email
  or given by the caller.
- **Legion does not stop a DDoS on your website.** That needs an edge service
  such as Cloudflare. Legion sees it in logs and protects itself.
- **Signs are based on log text.** An attacker can write log text; a finding is
  a direction to check, not proof. Backups and planned updates sometimes look similar.
- **Ransomware is detected early, not blocked.** Legion cannot stop files from
  being encrypted; it alerts within minutes — isolating the server and keeping
  backups offline is up to you. An offline backup is the most reliable defence
  against ransomware.
- **Espionage is deliberately slow and quiet.** Legion links stages within
  7 days; activity spread over longer, or visible only in network traffic, may be missed.
- **Supply chain:** Legion does not analyse the code inside a new package; it
  notices a signature error, a known malicious package name, or suspicious
  activity after the install. Legion's **own** libraries are checked in CI every
  time (a release stops if a vulnerability is found).

## Stopping: where Legion stops an attack

Detection is not enough — where Legion can reach, it stops the attack:

| Attack | How it is stopped |
|---|---|
| **Unauthorised access** (password guessing, spraying) | 10+ failures or 5+ different accounts tried from one address in 10 minutes → `credential_attack`. With automatic response on, the address is **blocked** through Wazuh ([WAZUH.md](WAZUH.md), "Automatic response"). |
| **Compromised account** | The same address signed in after the failures → `account_compromise` (critical). The attacker's address is **blocked**; the alert says to change the password, end sessions and turn on second-factor protection. |
| **Financial attack** (BEC, fake CEO, stolen account) | **Payment check**: the payment software asks before sending money; a suspicious payment is **held** until a person confirms it by phone ([PAYMENT-CHECK.md](PAYMENT-CHECK.md)). |
| **Phishing** | Phishing aims at a password or money. A sign-in with a stolen password → the blocking above; a request for money → the payment check. An Office document launching a script → an immediate alert. |

Honest boundary: stopping the phishing email itself before it reaches the
mailbox is the job of a mail security gateway (Microsoft Defender for Office,
Google Workspace, Proofpoint, etc.); Legion does not manage your mail server.
Automatic blocking is **off** by default — an administrator turns it on in the
Defense page. Private addresses and allowlisted ones are never blocked.
