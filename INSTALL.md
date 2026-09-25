# Running Legion

Legion is software you install on your own server. Nothing in it reports back
to us: there is no telemetry, no analytics, and no licence check that phones
home. Your security data stays in a database you control.

This guide is for the person who will install and look after that server. It
assumes ordinary Linux administration and no prior knowledge of Legion.

---

## 1. What you need

| | Minimum | Comfortable |
|---|---|---|
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 4 GB |
| Disk | 20 GB | 50 GB+, growing with alert volume |
| OS | Linux (any current distribution). Windows works for evaluation. |
| Node.js | 20.9 or newer |
| PostgreSQL | 14 or newer |

Two things drive the numbers above:

- **Disk grows and is never trimmed for you.** Legion does not delete old
  alerts on a schedule. Section 9 covers what to do about that before it
  becomes urgent.
- **RAM is dominated by PostgreSQL**, not by Legion. A busy Wazuh feed wants
  more of it than a quiet one.

Redis is optional. You need it only when you run more than one Legion instance
behind a load balancer — see section 11.

---

## 2. Before you install

Decide these four things now; changing them later means an extra restart.

1. **The address people will type.** A hostname (`legion.example.com`) is
   better than an IP, because certificates attach to names.
2. **Whether it will be reachable from the internet.** If yes, you need HTTPS
   before you let anyone log in — section 6, and it is not optional.
3. **Where PostgreSQL will live.** The same machine is simplest and is what
   the installer sets up. A managed database elsewhere is supported; see
   section 11.
4. **Who the first administrator will be.** That person creates the very first
   account, and registration closes behind them.

---

## 3. Install

### With Node.js and PostgreSQL already present

```bash
git clone <your-legion-repository> legion
cd legion
npm install
npm run setup        # creates the database, generates secrets, applies the schema
npm run build
npm start
```

`npm run setup` looks for PostgreSQL on its own. If it cannot find it, it asks
for the host and the superuser password and does the rest itself. It writes
`.env` with a freshly generated signing secret and a database password.

**Back up `.env` immediately, and keep it private.** Losing `JWT_SECRET` signs
everyone out; losing the database password locks Legion out of its own data.
The file is created readable only by its owner — keep it that way.

### With Docker

```bash
git clone <your-legion-repository> legion
cd legion
./install.sh
```

The script generates the same secrets, writes `.env`, and starts everything.

### On Windows

```powershell
.\start-legion.ps1
```

This is the evaluation path: it installs what is missing and starts Legion.
For a server that people depend on, use Linux.

---

## 4. First run

Open the address you chose — `http://localhost:3000` by default — and create
the first account. That account becomes the administrator.

**Registration closes the moment that account exists.** Everyone else joins by
invitation from Settings → Team. This is deliberate: even if you put the server
on the open internet, a stranger cannot sign themselves up.

Fill in your organisation's details while you are there:

```bash
NEXT_PUBLIC_OPERATOR_NAME=Example Ltd
NEXT_PUBLIC_SUPPORT_EMAIL=security@example.com
```

These go in `frontend/.env.local` on the Node.js path, or in `.env` if you
installed with Docker. They appear on the built-in privacy and terms pages,
which describe **your** deployment — you operate it, so those pages name you,
not us. Leave them empty and the pages say so in plain sight rather than
quietly naming the wrong party.

Both values are compiled into the dashboard rather than read at startup, so
run `npm run build` (or `./install.sh`) again after changing them.

Then check that Legion is healthy:

```bash
curl http://localhost:8000/health
```

```json
{"status":"ok","runtime":"node","version":"1.0.0","mode":"self-hosted","database":"up","ai":false}
```

`"database":"up"` is the part that matters — the check queries PostgreSQL
rather than just confirming the process is alive.

---

## 5. Connecting your alert source

Legion is built around Wazuh. [WAZUH.md](WAZUH.md) has the integration and a
section on verifying that events are actually arriving.

Anything that can POST JSON to `/security-events/webhook` works too. Set
`SECURITY_EVENT_WEBHOOK_SECRET` in `.env`; until you do, the endpoint is off
and answers 503. Each request then carries two headers — `x-tenant-id` and
`x-security-event-secret`, the latter being `HMAC-SHA256(secret, tenant_id)`.
A wrong or missing value is rejected with 401, and the comparison is
constant-time. Treat that header value as a password: it is per-tenant and
does not change between requests.

---

## 6. HTTPS

Legion serves plain HTTP by default, because many installations sit on an
internal network where that is a reasonable choice.

**If the server is reachable from the internet, HTTPS is required.** Without
it, session cookies and passwords cross the network in the clear.

1. Put a reverse proxy in front of Legion. `deploy/nginx.conf` is a working
   example; point it at your certificate.
2. Set `FRONTEND_URL=https://legion.example.com` and `COOKIE_SECURE=true`
   in `.env`.
3. Restart (`npm run build && npm start`, or `./install.sh`).

Two failure modes are worth knowing in advance, because Legion treats them
differently on purpose:

- `COOKIE_SECURE=true` **without** working HTTPS locks everyone out. The
  browser refuses to send the cookie and nobody can log in. Get the proxy
  working first.
- `FRONTEND_URL=https://…` **with** `COOKIE_SECURE=false` refuses to start at
  all, and says why. That combination hands out an unprotected session cookie
  on a site the user believes is encrypted, which is the one thing HTTPS is
  supposed to prevent — so Legion will not run that way rather than run
  insecurely and stay quiet about it.

---

## 7. Email (optional)

Without SMTP, Legion still works, but password-reset and invitation links are
printed to the server log instead of being sent. Someone has to read the log
and pass the link along.

```bash
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=legion@example.com
SMTP_PASSWORD=…
SMTP_FROM=Legion <no-reply@example.com>
ALERT_EMAIL_MIN_SEVERITY=high     # critical | high | medium | low | off
```

---

## 8. AI analysis (optional, off by default)

With no API key set, the Oracle and Copilot features run on built-in
deterministic analysis and **no alert data leaves your server**. This is the
shipped default and it stays that way until you choose otherwise.

Two providers are supported. Set exactly one key:

```bash
# Either — one key, many vendors' models, including free ones.
OPENROUTER_API_KEY=sk-or-…
OPENROUTER_MODEL=                 # optional; empty uses your account default

# Or
GROQ_API_KEY=gsk-…
```

Pick an OpenRouter model at <https://openrouter.ai/models>. Leaving
`OPENROUTER_MODEL` empty is deliberate and safe: the request omits the field
and OpenRouter applies your account's default, so no Legion upgrade can leave
you pointed at a model that has since retired.

If both keys are set, OpenRouter is used. Set `AI_PROVIDER=groq` to override.
Naming a provider whose key is missing turns AI **off** rather than falling
back to the other one — your alert text should never reach a company you did
not choose.

Confirm what is actually in effect:

```bash
curl http://localhost:8000/health
```

`"ai_provider"` names the third party, or is `null` when nothing is sent
anywhere. The server also states this once in its log at startup.

**What changes when you turn this on.** Alert titles, descriptions, hostnames,
and IP addresses are sent to that provider for analysis. That is a third-party
processor handling your security data. Legion sends the provider nothing else —
in particular, it does not pass on the address of your own console.

Decide it deliberately. If you are subject to data-protection rules or have
told your own customers where their data goes, that promise covers this too,
and your privacy page (section 4) should name whichever provider you chose.

---

## 9. Backups and retention

### Backups

[BACKUP.md](BACKUP.md) has the full procedure. The short version:

```bash
./ops/backup.sh           # dump the database
./ops/verify-backup.sh    # prove the dump restores — run this, not just the backup
./ops/restore.sh <file>   # restore
```

A backup nobody has ever restored is a guess. `verify-backup.sh` exists so it
does not have to stay a guess; run it on a schedule alongside the backup
itself.

Back up `.env` too, separately and privately. A database dump without the
signing secret still restores, but every session is invalidated.

### Retention

Legion keeps alerts, assets, and the audit log **indefinitely**. Sessions
expire on their own; nothing else does.

If a retention limit applies to you — by law, by contract, or because the disk
is finite — enforce it yourself. For example, to drop resolved alerts older
than a year:

```sql
DELETE FROM alerts
WHERE created_at < now() - interval '1 year'
  AND status = 'resolved';
```

Take a backup first, run it on a schedule, and keep the audit log longer than
the alerts if you are ever asked to reconstruct who did what.

---

## 10. Upgrading

```bash
./ops/backup.sh          # first, always
git pull
npm install
npm run build
npm start                # or ./install.sh for Docker
```

Schema changes apply automatically on start and preserve data. Your secrets in
`.env` are left alone.

Multiple instances can start at once safely: schema changes run under a
database lock, so one applies them and the others wait.

---

## 11. Larger deployments

**A database on another host.** Set `DATABASE_URL` and `DB_SSL=true`. If your
provider uses a certificate Node cannot verify against a public root, supply
the CA with `DB_SSL_CA` — a path or the PEM contents.

There is a `DB_SSL_INSECURE=true` escape hatch that skips certificate
verification. Against a remote database Legion refuses to start with it set,
and that is intentional: such a connection is encrypted but not authenticated,
so anything between Legion and the database can impersonate the database and
read everything. Use `DB_SSL_CA`.

**More than one Legion instance.** Set `REDIS_URL` on all of them. Redis does
two jobs: it makes rate limits count across instances rather than per-instance,
and it fans out live alert updates so a browser connected to instance A still
sees an event that arrived at instance B. Without it, both quietly degrade.

**Tuning.** `DB_POOL_MAX` (default 10) per instance, `AUTH_RATE_LIMIT`
(10/window) and `API_RATE_LIMIT` (300/window).

---

## 12. Who is responsible for what

Legion handles:

- Passwords hashed with bcrypt; session tokens stored hashed, never in the clear
- Refresh-token rotation with reuse detection — presenting an old token
  revokes the whole family rather than trusting it
- Optional two-factor authentication (TOTP), with codes that cannot be replayed
- Roles (admin / analyst / viewer) and an audit log of administrative actions
- Refusing to start on configurations that cannot be safe

You handle:

- Keeping the operating system, Node.js, and PostgreSQL patched
- HTTPS, firewall, and who can reach the server at all
- Backups, and testing that they restore
- Retention (section 9)
- Disk and database capacity
- Who has an account, and removing people when they leave

The split is not a disclaimer. A patched Legion on an unpatched server with no
backups is not secure, and no amount of work on our side changes that.

---

## 13. Removing Legion

Legion writes to three places and nowhere else:

1. The PostgreSQL database named in `DATABASE_URL`
2. The directory you cloned it into
3. `.env` inside that directory

Export anything you want to keep first:

```bash
pg_dump "$DATABASE_URL" > legion-final-export.sql
```

Then stop the service, `DROP DATABASE legion;`, and delete the directory. No
registry keys, no files elsewhere on the system, and nothing to cancel with us.

---

## 14. When something is wrong

Start here:

```bash
curl http://localhost:8000/health
```

| What you see | What it means |
|---|---|
| `"database":"down"` | PostgreSQL is not reachable. Check it is running and that `DATABASE_URL` is right. |
| Refuses to start, mentions `JWT_SECRET` | `.env` is missing or damaged. Re-run `npm run setup`. |
| Refuses to start, mentions `COOKIE_SECURE` | `FRONTEND_URL` is https but the cookie is not marked Secure. Section 6. |
| Refuses to start, mentions `DB_SSL_INSECURE` | Certificate verification is off against a remote database. Section 11. |
| Correct password, cannot log in | `COOKIE_SECURE=true` without working HTTPS. Section 6. |
| Reset email never arrives | SMTP is not configured; the link is in the server log. |
| No alerts appearing | [WAZUH.md](WAZUH.md), verification section. |

Legion refusing to start is a designed behaviour, not a crash. A security tool
that boots in a configuration it knows is unsafe is worse than one that stops
and explains itself, so the error message names the setting and what to do.

---

## 15. Support and security reports

General questions and installation help: the address in your agreement.

**Found a vulnerability?** Report it privately, not in a public issue tracker.
Include what you did, what happened, and the version from `/health`. You will
get an acknowledgement, and we will tell you when a fix ships.

Please do not send us your alert data, database dumps, or `.env` with a support
request. We do not need them and should not have them — a redacted log extract
is almost always enough.
