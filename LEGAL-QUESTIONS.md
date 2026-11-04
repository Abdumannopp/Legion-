# Legal questions for counsel

For the person who will review Legion before it is sold. It is written so you
can hand it to a lawyer as it is: first **what the product actually does** (so
nobody advises on a guess), then **the questions**, each with why it matters and
what engineering needs back.

It is not legal advice and makes no claim about what any law requires. Where a
specific law is named, it is only because it is worth asking about.

Attach with it: `frontend/content/legal/` (terms, privacy, refunds — the live
texts), `LICENSE` (a draft), `NOTICE` (open-source licences), `PRICING.md`,
`TENANT-ISOLATION.md`, `RECOVERY.md`.

---

## 1. Facts counsel needs (what the code does today)

**What Legion is.** A security console. A customer's Wazuh sensors send
security events to Legion; Legion groups them, explains them, can block an
attacker's address, can hold a suspicious payment, and can supervise the
customer's own AI agents. Sold as hosted SaaS (monthly/yearly subscription) and
as a self-hosted licence.

**What personal data it holds.** Not chosen by us — it arrives inside the
customer's logs: IP addresses, host names, user names and email addresses
inside log lines, sign-in activity, file names. Plus our own users' account
data (email, password hash, role, sign-in and audit history).

| Data | Where it lives | How long it is kept today |
|---|---|---|
| Alerts and assets | Database | Hosted: resolved alerts are deleted after the plan's period (Starter 30 days, Professional 90, Business 180, Enterprise 365). Open alerts are never deleted. Self-hosted: forever. |
| Audit log (who did what in the workspace; includes user emails and IPs) | Database | **Forever.** The database refuses UPDATE and DELETE on it (append-only on purpose, as evidence). |
| Agent audit log and firewall decisions (includes the person's email as display name, IPs, user agents) | Database | **Forever**, append-only by trigger. |
| Alert emails (recipient + alert text) | Database | Deleted 30 days after delivery. Undelivered ones are kept. |
| Sign-in sessions | Database | Expire and are cleaned up. |
| Payment checks | Database | Account number is **never stored**: only a per-customer keyed hash and the last four characters; beneficiary name, amount, requester and reference are stored. Kept indefinitely. |
| Billing | Paddle | Paddle is the Merchant of Record and keeps card and tax data. Legion keeps only the subscription status and Paddle's identifiers. |
| Backups | Encrypted files off the server | Daily 14, weekly 8, **monthly 12** (configurable). A deleted record can therefore survive in a backup for up to about a year. |

**Who else touches the data (sub-processors).** Hosting provider (location is
configurable and stated on the privacy page); Paddle (payments, independent
seller of record); an AI provider (OpenRouter or Groq) **only** when AI is
switched on — alert titles, summaries, host names and IPs are then sent there
(AI is off by default on the hosted service; secrets are redacted first; a
"strict" mode replaces IPs, emails and host names with placeholders); an email
provider (SMTP, e.g. Resend) that carries alert emails containing alert text;
Cloudflare if the operator puts it in front (it sees traffic); Cloudflare
Turnstile if enabled.

**What is not collected.** No analytics, telemetry or advertising cookies. Only
session cookies. Customer data is not sold.

**What the live legal texts promise today** (so the reviewer can find the gaps):
workspace locked, not erased, after a subscription ends; deletion on request
**within 30 days**; deleted data in backups for **up to 14 days**; refunds of
the first payment within **14 days**; terms changes with **30 days'** notice;
liability excluded for lost data "that proper backups would have preserved";
"as is" warranty.

**Where the product acts on its own** (relevant to liability): it can block an
IP address on the customer's Wazuh agents (off by default; allowlist; hourly
limits; blocks expire), and it can tell a payment system to hold a payment
(the payment system must ask; a person releases it after a phone check).

---

## 2. Questions

Priority: **A** = decide before the first paying customer · **B** = before the
first enterprise or EU customer · **C** = when convenient.

### 2.1 Retention and deletion  *(this is the open engineering item)*

| # | Question | Why it matters | What engineering needs back | Pri. |
|---|---|---|---|---|
| 1 | For each data type in the table above, how long may or must we keep it, and what is the legal basis (contract, legitimate interest, legal obligation)? | We cannot build deletion until we know what to delete and when. Today most things are kept forever. | One number per row (or "keep while the account exists") | A |
| 2 | **Backups.** The live text says deleted data stays in backups "up to 14 days". The real schedule keeps monthly backups for 12 months. Which do we change: the text (say "up to 12 months") or the backup schedule (keep only 14 daily)? Is a longer backup retention acceptable if restored data is re-deleted after a restore? | A published promise that the system does not keep is a misrepresentation risk. It is also the single clearest gap in the file. | The chosen number, and approved wording | A |
| 3 | What counts as "deleted"? Removing the workspace's rows, or also personal data inside append-only logs? | The audit logs are append-only by design (the workspace audit log, the agent audit log, the firewall decisions, the content-ingestion log). Erasing one row of them breaks the integrity chain that makes them evidence. | Decision: (a) keep them with pseudonymised people (emails replaced by a random id, a separate lookup table that can be deleted), (b) delete the whole workspace's log as a unit, or (c) keep them and justify why | A |
| 4 | After a subscription ends, how long may we keep a locked workspace before we must delete it? Do we delete automatically? | Today: "locked, not erased", indefinitely. | A period (e.g. N days after the end) and whether it is automatic | A |
| 5 | Who may request deletion: only the workspace administrator, or also an individual whose data is in the logs (a person whose name appears in a customer's log)? How do we verify them? | We are mostly a processor for the customer's logs; an individual normally goes to the customer. | The rule and the response we give | B |
| 6 | Export: what must we hand over on request (format and scope)? | A tenant export does not exist yet. | Scope and format (e.g. JSON/CSV of alerts, assets, audit log) | B |
| 7 | Legal holds and authority requests: what do we do when a court, police or regulator asks for a customer's data? Do we tell the customer? | We have no procedure. | A written policy and who decides | B |
| 8 | Should account numbers and beneficiary names in payment checks have a shorter retention than other data? | They are financial and personal. | A number | B |

### 2.2 Roles, contracts and transfers

| # | Question | Why it matters | Pri. |
|---|---|---|---|
| 9 | Confirm our role: are we a **processor** for customer log data and a **controller** for our own users' account data? Are Paddle and the customer independent controllers of what they hold? | Decides which obligations apply and what the privacy text must say. | A |
| 10 | Do we need a **data processing agreement** (DPA) for customers? If yes, who drafts it and is it accepted in the sign-up flow or signed separately for Enterprise? | Business customers will ask for it first. Today there is none. | A |
| 11 | **Sub-processors.** The privacy page lists Paddle, the hosting provider, an email delivery provider and an AI provider, by category and not by name (Cloudflare was missing and has been added). Must each be listed by name? Do customers get notice and a right to object when we add one? | Names make the list checkable by the customer. | A |
| 12 | International transfers: the AI provider, email provider and Paddle may be outside the customer's country. What transfer mechanism and wording do we need? | Needed before EU / UK customers. | B |
| 13 | Do we need an EU/UK **representative**, a **data protection officer**, or registrations, given where we are established and who we sell to? | Obligations can attach to selling to EU residents even without an office there. | B |

### 2.3 Where the data lives

| # | Question | Why it matters | Pri. |
|---|---|---|---|
| 14 | We run one region and state it on the privacy page. Which region is right for our target customers? Does any customer group require data to stay in a country (EU, UK, Russia, China, Uzbekistan and others)? | Some countries restrict where their residents' personal data may be stored. **Please check specifically whether the law of the country where we are established, and of the countries we sell into, requires local storage or registration of a personal-data database.** | A |
| 15 | If a customer demands a specific region, may we decline, or must we offer one? Is a per-region contract term acceptable? | The product can run in a region per workspace, but we do not operate several. | B |

### 2.4 AI

| # | Question | Why it matters | Pri. |
|---|---|---|---|
| 16 | Sending alert text (host names, IPs, usernames) to an AI provider: what consent, notice or contract with the provider do we need? Is a zero-retention commitment from the provider required? | Off by default for hosted customers; once a customer's admin turns it on, their data leaves for a third party. | A |
| 17 | Are there transparency or labelling duties for AI-generated explanations (we label them "AI suggestion")? Does the AI-agent supervision feature fall under any AI-specific regulation? | We supervise customers' own agents, and we are not the AI's author. | B |

### 2.5 Liability and the licence

| # | Question | Why it matters | Pri. |
|---|---|---|---|
| 18 | **Missed attack.** Our product's job is detection. What limitation of liability and warranty disclaimer is enforceable in the markets we sell to? Is a cap tied to fees paid appropriate? | The draft `LICENSE` and the terms use "as is" and exclude lost profits and data. A court may not enforce a broad version. This is the central risk of the business. | A |
| 19 | **Automatic action.** The product can block an address on the customer's systems and hold a payment. Who is liable if a block cuts off a legitimate user, or a held payment costs the customer money? Do we need the customer to authorise these actions explicitly and in writing (a checkbox when they turn auto-blocking on)? | These are the actions where harm from our product is most direct. Both are off or opt-in by design; the question is what wording covers them. | A |
| 20 | The `LICENSE` is a draft in the name of an entity that does not exist yet. What entity, jurisdiction and governing law? Is "all rights reserved, internal use, one installation" the right self-hosted grant? May the customer's affiliates and contractors use it? | Cannot be sold under it. | A |
| 21 | Open-source: `NOTICE` lists 327 packages. Three need a lawyer's eye: sharp/libvips (LGPL), lightningcss (MPL), caniuse-lite (CC-BY). Do they affect how we distribute or sell? | Our engineering reading is "no", not a legal conclusion. | A |
| 22 | Security software and **export controls / sanctions**: does it restrict whom we may sell to or how we deliver (encryption, offensive-capable tools)? | We detect and block; we ship encryption. | B |

### 2.5b Commercial terms

| # | Question | Why it matters | Pri. |
|---|---|---|---|
| 23 | Paddle is Merchant of Record; we are the seller. Does being an individual (not a company) matter for Paddle, for tax and for liability? Should we register a company first? | The owner may start as an individual. | A |
| 24 | Taxes on our own income from Paddle payouts, in our country. (Paddle handles buyer-side VAT / sales tax only.) | Not our engineering's area; it affects pricing. | A |
| 25 | Refunds: 14 days for the first payment. Does consumer or business law in our markets require more? Is a 14-day trial that locks (not deletes) the workspace compliant? | Live text. | B |
| 26 | Enterprise **SLA**: what uptime, response and credit terms may we offer, given we run on one host? What may we promise about incident response time and breach notification? | `response_sla_review` and the pricing page make speed claims. | B |
| 27 | Self-hosted licence: it costs the same per year as the SaaS plan but the software does not check a key. Is a licence that is a contract only (no technical lock) enforceable and sufficient? Audit rights? | Product choice: the customer owns the server. | B |
| 28 | Changes to prices and terms: the terms promise 30 days' notice. Is that enough for existing subscribers when plan limits change? | Recent plan limits (admins, retention) apply to existing trial customers. | B |

### 2.6 Product-specific risks

| # | Question | Why it matters | Pri. |
|---|---|---|---|
| 29 | **Monitoring people.** The logs we process identify employees (user names, emails, what files they opened). Whose job is it to tell employees — the customer's? Do we need to put that on the customer in the terms or the DPA? | Employee monitoring has its own rules in many countries. | B |
| 30 | **Cards and bank numbers in logs.** One skill finds card numbers and IBANs in logs and reports kind and place, never the value. Does processing them pull us into card-industry (PCI) obligations? | We do not store the numbers, but the logs we receive may contain them. | B |
| 31 | **Breach duties.** If Legion is breached, what must we tell customers and regulators, and how fast? Do we need a published security contact and a vulnerability disclosure policy (safe harbour for researchers)? | We have the incident tooling but no policy text. | A |
| 32 | **Marketing claims.** "Your data is isolated in its own workspace", "never sold", "audited", "defends against…". Which words could be read as a guarantee, and which compliance claims (SOC 2, ISO 27001, GDPR-compliant) must we avoid until we have them? | An advertised protection that is not delivered is a misrepresentation risk. | A |
| 33 | The payment check says "allow" or "hold". Does a "hold" amount to financial advice, a service regulated in our markets, or interference with a payment? Which disclaimer? | We never see the bank. A person releases a hold. | B |

---

## 3. What to bring back to engineering

A table is enough:

| Decision | Answer | Needed for |
|---|---|---|
| Retention per data type (Q1, 4, 8) | | automatic deletion jobs |
| Backup retention or text (Q2) | | `ops/prune-backups.sh` or the legal text |
| How the append-only logs are treated at deletion (Q3) | | the deletion design |
| Tenant export scope (Q6) | | export tool |
| Sub-processor list (Q11) | | privacy page |
| Region (Q14) | | hosting choice |
| Wording for automatic blocking and payment holds (Q19, 33) | | consent screen + terms |
| Entity, jurisdiction, liability cap (Q18, 20, 23) | | `LICENSE` and terms |
| Breach/security contact (Q31) | | `/support`, `security.txt` |

## 4. A suggested order

1. **Q2** first: it is a published promise the system does not keep, and it is one number.
2. **Q18–20, 23, 31, 32**: they decide whether the product can be sold at all.
3. **Q1, 3, 4, 9–11, 14, 16**: they unlock deletion, the DPA and the privacy text.
4. The rest before the first enterprise or EU customer.
