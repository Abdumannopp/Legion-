# Legion

**A security operations console that turns Wazuh alerts into clear decisions, and helps stop attacks before they cost money.**

Legion runs on your own server. Your security data stays in your network unless you choose to connect an AI provider.

- Takes in Wazuh events in real time, ranks them, and explains each alert in plain language with the next step to take
- Links separate events into one attack ("campaign"): brute force, account takeover, ransomware, mailbox takeover, phishing, supply-chain installs, slow intrusions, AI-driven attacks
- Can block an attacker's IP automatically through Wazuh active response (off by default, with an allowlist, limits and expiry)
- **Payment check:** your payment software asks Legion before paying, and a payment that looks like fraud is held until a person confirms it by phone
- Five AI agents (Sentinel, Hunter, Guardian, Oracle, Executor) with read-only skills you can also give to your own AI agents
- Security controls for AI agents: identity, permissions, prompt-injection detection and an audit trail for every tool call
- Teams, roles (admin / analyst / viewer), two-factor sign-in (TOTP) and a full audit log
- Self-hosted or run as a multi-tenant SaaS

---

## What Legion protects against

| Threat | What Legion does |
|---|---|
| Brute force, stolen passwords | Detects many failed sign-ins and a success after failures, and can block the source IP |
| Account takeover | Flags an account used from many addresses or after a password-guessing attack |
| Business email compromise and payment fraud | Holds payments to new accounts, or payments requested while a mailbox is under attack |
| Ransomware | Detects mass file changes and the steps that come before encryption |
| Phishing | Detects a malicious attachment or link being opened and run |
| Supply-chain attacks | Detects a new package or update followed by suspicious activity |
| AI-driven and automated attacks | Detects attack chains that move faster than a person could, and attempts to manipulate AI agents |
| Data theft | Detects data being collected and then sent out |

The dashboard's **Defense** page shows, for each threat, what Legion detected, what it is watching, and where it is blind because the data it needs never arrives.

**Limits:**
- Blocking an IP does not stop an attack spread across thousands of addresses (a botnet).
- A DDoS on your own website needs an edge service such as Cloudflare.
- The payment check works only when your payment software asks Legion before paying.
- Legion does not filter email. Stopping the phishing message itself is your mail gateway's job.

---

## Installation

**You need:** Node.js 20.9+ and PostgreSQL 14+. Docker is optional. 2 GB of RAM is enough.

```bash
git clone <repo> legion && cd legion
npm install
npm run setup      # creates the database, writes secrets, applies the schema
npm run build && npm start
```

`npm run setup` finds PostgreSQL on its own. If it cannot, it asks for the host and the superuser password. Legion then creates its own restricted database role and does not run as a superuser.

When it finishes, open http://localhost:3000 and **create the first administrator account straight away**. Until it exists, the first person to reach the page becomes the admin. After that, sign-up closes automatically and others join only by invitation (Settings → Team).

By default the API listens only on `127.0.0.1` (`LEGION_BIND_ADDRESS` in `.env`). To reach it from outside, put an HTTPS reverse proxy in front: see [deploy/nginx.conf](deploy/nginx.conf). Then set `COOKIE_SECURE=true` in `.env`. Do not set it without HTTPS, because sign-in will stop working.

**Windows:** `.\start-legion.ps1` does all of the above.

Full guide for customers: [INSTALL.md](INSTALL.md).

---

## Connecting your systems

| Task | Guide |
|---|---|
| Try Legion on your own computer | [TRY-LOCALLY.md](TRY-LOCALLY.md) · Docker: [DOCKER-WINDOWS.md](DOCKER-WINDOWS.md) · Windows: [WINDOWS-NODE.md](WINDOWS-NODE.md) |
| Install and run Legion (full customer guide) | [INSTALL.md](INSTALL.md) |
| Put Legion online (VPS + domain + HTTPS + Cloudflare) | [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md) |
| Run it as a paid SaaS (sign-up, trial, Paddle, email) | [SAAS.md](SAAS.md) · [EMAIL-PADDLE.md](EMAIL-PADDLE.md) |
| Connect Wazuh (events in, automatic blocking out) | [WAZUH.md](WAZUH.md) |
| Payment check (stop payment fraud) | [PAYMENT-CHECK.md](PAYMENT-CHECK.md) |
| The seven most dangerous attack types | [THREATS.md](THREATS.md) |
| The five agents and their skills | [AGENTS.md](AGENTS.md) |
| AI providers and AI safety | [AI-PROVIDERS.md](AI-PROVIDERS.md) |
| Proxies, origins, cookies and headers | [EDGE-SECURITY.md](EDGE-SECURITY.md) |
| How organisations are kept apart (multi-tenant) | [TENANT-ISOLATION.md](TENANT-ISOLATION.md) |
| Backup and disaster recovery | [RECOVERY.md](RECOVERY.md) · [BACKUP.md](BACKUP.md) |
| Architecture decisions | [ADR.md](ADR.md) |
| CI and the release security gate | [.github/CI.md](.github/CI.md) |

---

## AI (optional)

The Oracle explanations and the Copilot assistant are **optional**. Without an API key, both still work using local, deterministic analysis, and **no data leaves your server**.

To use a model, set one provider in `.env`:

```env
OPENROUTER_API_KEY=sk-or-…     # one key, many vendors (models: https://openrouter.ai/models)
OPENROUTER_MODEL=              # empty = your OpenRouter account's default model

GROQ_API_KEY=gsk-…             # alternative
```

With a key, the alert title, summary, host names and IP addresses are sent to that provider for analysis. That is your decision; take your obligations to your own customers into account. If both keys are set, OpenRouter is used (`AI_PROVIDER=groq` changes that). If a provider is named without a key, AI is switched **off**, so data never goes to a company you did not choose.

Check what is active: `curl http://localhost:8000/health` → `ai_provider`.

---

## Day-to-day operation

Run Legion under a process supervisor. A systemd example is in [deploy/legion.service](deploy/legion.service).

```bash
sudo systemctl status legion
sudo systemctl restart legion
journalctl -u legion -f
```

### Updating

```bash
DATABASE_URL=... ./ops/backup.sh    # always back up first
git pull
npm install
npm run build
sudo systemctl restart legion
```

Schema changes are applied automatically and keep your data. Your secrets in `.env` do not change. Copy backups off the server regularly.

### Troubleshooting

```bash
curl http://localhost:8000/health    # expect {"status":"ok","database":"up"}
```

| Symptom | Cause |
|---|---|
| `database: down` | PostgreSQL is not running, or `DATABASE_URL` is wrong |
| Server will not start, "JWT_SECRET" error | `.env` is missing or broken: run `npm run setup` |
| Correct password but cannot sign in | `COOKIE_SECURE=true` needs HTTPS |
| Password-reset email never arrives | SMTP is not configured, so the link is written to the server log |
| No Wazuh alerts arrive | See the checks in [WAZUH.md](WAZUH.md) |

---

## Security

- Passwords hashed with bcrypt (cost 12)
- Session token in an HttpOnly cookie, refreshed every 15 minutes, valid for 30 days
- MFA: TOTP plus one-time recovery codes (only hashes are stored)
- Every organisation's data is separated, and every query is scoped to its tenant
- Every important action is written to the audit log
- Sensors sign their requests (HMAC with timestamp and nonce); each signed request is bound to its purpose
- Payment account numbers are never stored, only a keyed hash and the last four characters
- The API connects to PostgreSQL with its own least-privilege role

If you find a vulnerability, report it privately rather than opening a public issue.

---

## Project layout

```text
legion/
├── server/                    Express + TypeScript API
│   ├── src/db/                PostgreSQL schema and migrations
│   ├── scripts/setup.mjs      installer (creates secrets, sets up the database)
│   └── tests/                 API test suite
├── frontend/                  Next.js dashboard and website
├── packages/agent-identity/   AI-agent identity, permissions, prompt guard and agent skills
├── integrations/              Wazuh integration (sensor script, rules, active response)
├── ops/                       backup, restore, verification and end-to-end tests
├── deploy/                    nginx and systemd examples
├── LICENSE                    licence — STILL A DRAFT, have a lawyer review it before giving it to a customer
└── NOTICE                     licences of the open-source packages used
```

## Before giving Legion to a customer

1. Read the warning block at the top of `LICENSE`. Its `[BRACKETED]` fields are filled in once the company is registered, and a lawyer must review it.
2. `NEXT_PUBLIC_OPERATOR_NAME` and `NEXT_PUBLIC_SUPPORT_EMAIL` in `.env` are filled in by the **customer**. If they are empty, the privacy page says so openly.
3. Regenerate `NOTICE` after dependencies change:
   `npx license-checker-rseidelsohn --excludePrivatePackages --csv`

## Development

```bash
npm run dev      # dashboard + API
npm test         # test suites (needs PostgreSQL)
npm run check    # TypeScript and interface-text checks
```

Tests connect to `TEST_DATABASE_URL` and empty the tables before each test, so **use a separate database**.

The interface is English only (see [frontend/lib/i18n/README.md](frontend/lib/i18n/README.md)).

## CI and release gate

Every push and pull request runs the security tests and the attack scenarios separately. A release is **blocked** if a security test fails, if any attack of Critical or High severity is "NOT DEFENDED", if a required scenario is missing, or if the result file is broken or not tied to the exact code version. Details: [.github/CI.md](.github/CI.md).
