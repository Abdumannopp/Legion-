# Legion — architecture decisions (ADR)

**Date:** 2026-08-24
**Context:** section 26 of the production audit (2026-08-24) listed 10 open decisions.
They had to be closed **before** writing code, because each one shapes the work that follows.

For each decision: what the code did at the time, the options, the recommendation, and who decides.

> This is a historical record. Some decisions have since been made; where that
> is the case, a note at the top of the section says so.

> **Legend**
> 🔧 — technical decision, engineering can recommend
> 💼 — business/legal decision, the owner decides
> ⛔ — blocks other work

---

## ADR-001 ⛔💼 Identity: one person = one organisation?

**In the code at the time:** `users.email` was **globally unique**, and every user
had one `tenant_id`. `user.tenant_id` was used in **44 places** in `index.ts`.

Practical consequence: one person could not belong to two Legion workspaces. An
MSSP analyst watching three customers, or a consultant working for two
companies, **could not exist** in that model. The invitation flow also returned
`400 — this email is already in use`.

| Option | Meaning | Cost |
|---|---|---|
| **A. Keep as is** | 1 email = 1 organisation | None. But the MSSP market is closed |
| **B. `identities` + `memberships`** | 1 email = N organisations, a separate role in each | Large: auth, RBAC, invitations, sessions and 44 query sites |

**Recommendation:** this is a **sales decision, not a technical one**. The answer
depends on "who buys?":

- If the buyer is an **SMB that runs Wazuh and has no SOC team** → **A** is enough for now.
- If the buyer is an **MSSP or consulting firm** → **B** is required, and should be
  done **now**. Doing it later means rewriting 44 places, plus a migration with
  live customer data.

> Later: multi-workspace membership was added (Settings → Workspaces).

---

## ADR-002 ⛔🔧 Durable queue: what do we use?

**In the code at the time:** no queue. Alert ingestion wrote to the database, sent
email and called the AI inside the HTTP request. A slow vendor = a slow webhook =
a Wazuh timeout.

Redis was already used by `ratelimit.ts` and `realtime.ts`.

| Option | Benefit | Drawback |
|---|---|---|
| **Redis Streams** | Consumer groups, ack, DLQ — with the existing Redis | Redis must be made durable |
| **Managed queue** (SQS, Pub/Sub) | No operational load, guaranteed durability | A new vendor, cloud lock-in |
| **Postgres outbox + poller** | No new infrastructure, transactional guarantee | Pressure on the database under high load |

**Recommendation at the time: Redis Streams.**

> ⚠️ In `docker-compose.yml`, Redis ran as
> `redis-server --save "" --appendonly no` — persistence deliberately off,
> because it was added only for rate-limit counters. A queue on that Redis would
> **lose jobs on restart**; it needs AOF or a separate instance.

> Later: notifications were moved to a **Postgres outbox** (`server/src/outbox.ts`),
> which needs no new infrastructure and commits together with the alert.

---

## ADR-003 ✅ How is the webhook secret stored?

> **Decided (2026-09-29):** a random 256-bit secret per credential
> (`webhook_credentials`), encrypted with AES-256-GCM; the KEK is the
> `WEBHOOK_ENCRYPTION_KEY` env var (derived from `JWT_SECRET` with HKDF if absent).
> The tenant is identified from the credential itself (`x-legion-key-id`), the
> signature is HMAC-SHA256 over `v2.<ts>.<nonce>.<raw body>`, nonces are remembered
> in Postgres (replay), rotation has an overlap, revocation is immediate.
> Remaining: the KEK is not yet in a secret manager/KMS (stage 2 of the
> recommendation below). The text below is the state when the decision was taken.

**In the code at the time:** `HMAC(GLOBAL_SECRET, tenantId)` — one global secret
derived a credential for each tenant. Anyone who knew the global secret could
create a credential **for any tenant**.

Important nuance: the secret must be **read back** to check an HMAC, so it cannot
be hashed like a password — it has to be encrypted.

| Option | Assessment |
|---|---|
| A random secret per credential, in plain text in the database | Solves the global-secret problem, but a database leak exposes everything |
| **Envelope encryption (with a KEK)** | A database leak does not expose secrets. The KEK lives in a secret manager |
| Asymmetric signatures (sensor holds a private key) | Strongest, but complicated on the Wazuh side |

**Recommendation:** envelope encryption, in stages: first the KEK as an env var
supplied by a secret manager, later a real KMS. For the Wazuh integration this is
just new headers — `WAZUH.md` is updated.

---

## ADR-004 🔧💼 What happens to a tenant that has not paid?

**In the code:** states `ok` / `readonly` / `blocked`. An important choice: **the
Wazuh webhook is outside the access gate** — a blocked tenant's telemetry
**keeps being written**.

This is deliberate: leaving a hole in a customer's security history that can
never be filled, because a payment was late, is wrong. But it is a **cost** — an
unpaid customer keeps using your disk and (if AI is on) your API budget.

**Recommendation:** keep the current logic, with two limits:

1. For a `blocked` tenant, ingestion is **stored but not processed** — no AI
   explanations and no emails (cost drops to zero, no data is lost).
2. A quota in the `blocked` state (e.g. 30 days or N events), after which new
   events are refused with a clear message to the customer.

💼 The exact numbers (how many days, how many events) are the owner's decision,
and they must be written in the Terms.

---

## ADR-005 💼 Plans and quota catalogue

**In the code at the time:** no quotas at all. Every tenant had unlimited alerts,
AI requests and emails.

To decide: what to limit by — event count, retention, AI requests, users, assets?

**Recommendation (technical shape):** quotas as **versioned entitlements in the
database**, not in code. Otherwise every plan change needs a deploy, and an
individual limit for one customer is impossible.

💼 The values themselves are pricing strategy.

---

## ADR-006 💼⚖️ Where is the data stored?

**In the code:** one `DATABASE_URL`. The data lives wherever that is.

An EU customer asks this first. In several jurisdictions it is a legal requirement.

| Option | Assessment |
|---|---|
| **One region** | Simplest. State openly "data is stored in X" |
| Regional tenancy | A separate deployment per region. A large operational cost |

**Recommendation:** pick **one region** for launch and state it openly on the
site (`NEXT_PUBLIC_DATA_LOCATION`). Build regional tenancy only when a customer
who needs it is ready to pay for it.

⚖️ Which region needs legal advice for your target market and your customers'
jurisdictions.

---

## ADR-007 💼 RPO / RTO — how much loss is acceptable?

**In the code at the time:** `ops/backup.sh`, a daily dump. So **RPO ≈ 24 hours** —
a disaster loses one day of customer telemetry.

**Recommendation:** enable PITR on a managed PostgreSQL → RPO drops to minutes.
It is an hour's work and much stronger than a daily dump.

💼 The official target (what you promise customers) is the owner's decision.
Measure **before** promising. See [RECOVERY.md](RECOVERY.md).

---

## ADR-008 🔧 Can support staff see customer data?

**In the code:** **no** admin/support access mechanism. The operator cannot see a
customer's dashboard.

That is the safest state today, but it becomes a problem at the first
"something is not working" ticket.

**Recommendation:** build **nothing** for now. When needed, build it on a JIT
(just-in-time) model: time-limited access that requires MFA, forces a written
reason, and leaves an audit record that cannot be deleted.

The worst option is quietly adding a "super admin" flag. That raises questions
in a SOC 2 audit straight away and costs customer trust.

---

## ADR-009 🔧 CSP strategy

**In the code at the time:** `frontend/next.config.mjs` set no security headers:

```js
const nextConfig = { reactStrictMode: true, output: "standalone" };
```

No CSP, HSTS or `frame-ancestors`. The backend had `helmet`, but that applies to
API responses; the browser page is served by the frontend.

Complication: Paddle checkout loads a script from Paddle's CDN through
`@paddle/paddle-js` and opens the checkout in an iframe, so a CSP allowlist is needed.

**Recommendation:** Next.js's official nonce pattern + a minimal Paddle allowlist.
Ship it first as `Content-Security-Policy-Report-Only`, watch the reports, then
enforce. Enforcing straight away may break checkout, and only a paying customer
would notice.

> Later: security headers were added (see [EDGE-SECURITY.md](EDGE-SECURITY.md)).

---

## ADR-010 ⚖️ Sending customer data to AI

**In the code at the time** (`ai.ts`): the alert title, `summary` (up to 2000
characters), `source_ip`, `target` (host name) and MITRE technique were sent to
Groq. Copilot also sent the last 30 alerts as context.

So **the customer's security telemetry was sent to a third-party AI provider**.
Host names and IP addresses are personal data in many jurisdictions.

It was not disclosed anywhere, and the customer could not turn it off.

**Recommendation:**

1. State it **openly** in the privacy policy: which provider, what data, how long it is kept.
2. Give a tenant-level **off switch** (when off, the deterministic fallback runs —
   it already exists).
3. Sign a DPA with the provider or confirm a zero-retention mode.

⚖️ This is serious under GDPR — customer data goes to a sub-processor. Consult a lawyer.

> Later: AI is **off by default** in hosted (SaaS) mode, there is a per-organisation
> switch, secrets are redacted before sending, and the privacy policy names the
> providers. See [AI-PROVIDERS.md](AI-PROVIDERS.md).

---

## Summary: what had to be decided first

| Decision | Who | Why urgent |
|---|---|---|
| **ADR-001** identity | 💼 owner | Most expensive. Later means rewriting 44 places |
| **ADR-006** region | ⚖️ owner + lawyer | Shapes the deployment |
| **ADR-010** AI policy | ⚖️ owner + lawyer | Was running undisclosed |
| ADR-002 queue | 🔧 recommended | Other P0 work builds on it |
| The rest | mixed | After the above |
