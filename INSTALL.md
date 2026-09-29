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

Legion runs directly on Node.js — no Docker or container runtime required.

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
`.env` with a freshly generated signing secret and a database password, and
creates a dedicated, non-superuser database role for Legion (see "Database
privileges" below).

**Back up `.env` immediately, and keep it private.** Losing `JWT_SECRET` signs
everyone out; losing the database password locks Legion out of its own data.
The file is created readable only by its owner — keep it that way.

**Network exposure.** Bind the dashboard and API to `127.0.0.1`
(`LEGION_BIND_ADDRESS`, or simply don't set it — that's the default) and put
the HTTPS reverse proxy from section 6 in front of them on the same machine.
Only bind `0.0.0.0` on a trusted internal network with its own firewall, and
understand that it also exposes the first-run page: until the first
administrator exists, whoever reaches it first becomes the administrator.

### Database privileges

`npm run setup` creates a role for Legion that is **not** the Postgres
superuser: it owns Legion's own database and nothing else — it cannot read
or write files on the server, create other roles, create other databases, or
reach any database beyond its own. In production mode the API refuses to
start if it is ever connected as a role with superuser, `CREATEROLE`,
`CREATEDB`, `BYPASSRLS` or `REPLICATION` privileges (`DB_ALLOW_PRIVILEGED_ROLE=true`
overrides this).

`ops/verify-backup.sh`, which restores a backup into a throwaway database to
prove it works, needs a connection that **can** create a database — pass one
with `DATABASE_ADMIN_URL` (see section 9) rather than widening the role the
API itself connects as.

For a further-hardened setup — a role that doesn't even own its own database,
just the specific tables it needs — run the optional provisioning tool once
after `npm run setup`:

```bash
DATABASE_ADMIN_URL=postgresql://legion:<POSTGRES_PASSWORD>@localhost:5432/legion \
APP_DB_USER=legion_app APP_DB_PASSWORD=$(openssl rand -hex 24) \
  node server/dist/db/provision-cli.js
```

then point `DATABASE_URL` in `.env` at that role instead. It's idempotent and
safe to re-run: it re-checks (and strips) any privilege that drifted since
the last run, and on an existing installation transfers ownership of Legion's
tables to the new role automatically. In production mode, the API refuses to
start if it is ever connected as a role with superuser, `CREATEROLE`,
`CREATEDB`, `BYPASSRLS` or `REPLICATION` privileges, unless you explicitly
set `DB_ALLOW_PRIVILEGED_ROLE=true`.

### On Windows

```powershell
.\start-legion.ps1
```

This is the evaluation path: it installs what is missing and starts Legion.
For a server that people depend on, use Linux.

### Keeping it running

`npm start` runs in the foreground. For a server that must stay up across
crashes and reboots, use a process supervisor — [deploy/legion.service](deploy/legion.service)
is a working systemd unit (`sudo systemctl enable --now legion` after
adjusting the paths in it); a Node process manager such as pm2 works too.

---

## 4. First run

Open the address you chose — `http://localhost:3000` by default. A new
installation shows the **first-run setup** screen, which asks for a one-time
**setup token**. The server prints it in a boxed banner when it starts:

```text
  FIRST-RUN SETUP
  ...
    lst_Xk3…
```

It is also saved, readable only by you, in `server/.legion-setup-token`. The
token is what proves you have access to the server itself, so a stranger who
finds the page before you cannot claim the installation. It works once, stops
working the moment the administrator exists, and is stored in the database
only as a hash.

If several requests try to create the first administrator at the same time,
exactly one succeeds.

**Registration closes the moment that account exists.** Everyone else joins by
invitation from Settings → Team. This is deliberate: even if you put the server
on the open internet, a stranger cannot sign themselves up.

Fill in your organisation's details while you are there:

```bash
NEXT_PUBLIC_OPERATOR_NAME=Example Ltd
NEXT_PUBLIC_SUPPORT_EMAIL=security@example.com
```

These go in `frontend/.env.local`. They appear on the built-in privacy and
terms pages, which describe **your** deployment — you operate it, so those
pages name you, not us. Leave them empty and the pages say so in plain sight
rather than quietly naming the wrong party.

Both values are compiled into the dashboard rather than read at startup, so
run `npm run build` again after changing them.

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

## Encryption keys

Legion stores two kinds of secret it must be able to read back — two-factor
(TOTP) seeds and webhook signing secrets — encrypted with AES-256-GCM under a
key used for nothing else:

```env
LEGION_ENCRYPTION_KEYS=k1:<64 hex characters>     # openssl rand -hex 32
```

`npm run setup` generates it (and keeps it on a re-run). **The server refuses to
start without it**, except with `NODE_ENV=development` or `test`.

- **Back it up with `.env`, not with the database.** Someone with a database
  dump but not this key cannot read the secrets. Someone who loses this key
  locks out every user with two-factor sign-in: MFA is never switched off
  automatically — sign-in is refused (recovery codes still work) until the key
  is restored.
- **Rotate** by putting a new key first and keeping the old one after it —
  `LEGION_ENCRYPTION_KEYS=k2:<new>,k1:<old>` — then restarting. Every secret is
  re-encrypted under `k2` at boot. When `npm run secrets -w server -- status`
  shows nothing left under `k1`, remove it.
- Everything that only needs to be *compared* is hashed instead, never
  encrypted: passwords and recovery codes (bcrypt); reset, invitation and
  e-mail-verification links, refresh tokens and API credentials (SHA-256 of 256
  random bits). Reset links last one hour, invitations `INVITE_DAYS`; each works
  once.
- Without SMTP, reset and invitation links are **not** written to the log.
  On a development machine, `DEV_LOG_AUTH_LINKS=true` prints them (ignored in
  production). An administrator inviting someone without SMTP still gets the
  invitation link in the API response, outside production only.

### Upgrading from a version that stored these in plaintext

1. **Add `LEGION_ENCRYPTION_KEYS` before starting the new version** (re-run
   `npm run setup`, or add it by hand). Without it the new version will not start.
2. **Back up the database first.** The upgrade rewrites the reset/invitation
   token columns and the two-factor seeds; a restore is the only way back.
3. Start it. Existing reset and invitation links keep working (they are hashed
   in place). Two-factor seeds are encrypted at the first start; the log says
   how many. Every user keeps MFA, with the same authenticator app.
4. Check: `npm run secrets -w server -- status` should show `mfa_plaintext: 0`
   and `plaintext_tokens: 0`.
5. **Several instances:** upgrade them all together if you can. While an old
   instance is still running, its password-reset and invitation requests fail
   (the database no longer accepts a plaintext token) — they succeed again on
   the new version. Two-factor keeps working throughout.
6. **Rolling back** to the old version after the upgrade: the old version does
   not understand hashed tokens or encrypted seeds, so outstanding reset and
   invitation links stop working and **users with MFA cannot sign in**. Restore
   the database backup from step 2 instead of downgrading in place.

---

## 5. Connecting your alert source

Legion is built around Wazuh. [WAZUH.md](WAZUH.md) has the integration and a
section on verifying that events are actually arriving.

Anything that can POST JSON to `/security-events/webhook` works too. Each
organisation has its **own random webhook credentials** (`KEY_ID:SECRET`), which
an administrator creates — there is no shared secret and no `x-tenant-id` to
guess. Until an organisation has one, nothing can authenticate for it.

```bash
# from the server: prints the credential ONCE
npm run webhook:credential -w server -- create --tenant <tenant-uuid> --label "wazuh-manager-1"
```

(or `POST /security-events/credentials` as an administrator). Put the printed
`whk_…:whs_…` in ossec.conf's `<api_key>`. Every request is signed; the secret
never crosses the network:

```text
x-legion-key-id:     whk_…   (public id; Legion learns the organisation from this)
x-legion-timestamp:  <Unix time, seconds>
x-legion-nonce:      <random, new for every request, 16–64 chars [A-Za-z0-9_-]>
x-legion-signature:  v2=<hex HMAC-SHA256(secret, "v2.<timestamp>.<nonce>." + exact body bytes)>
```

Legion verifies the signature over the raw body before parsing it, and refuses
(401) a changed body, a signature from another message or credential, a
timestamp further than `WEBHOOK_MAX_SKEW_SECONDS` (default 300) from its clock,
a **nonce it has already seen (replay)**, a revoked or expired credential, a
non-JSON body, and the earlier `x-tenant-id` / fixed-secret schemes. The
organisation is always the one the credential belongs to; an `x-tenant-id` header
is ignored (and if present, must match). `integrations/custom-legion.py` does all
of this; keep the sender's clock synced (NTP). It also retries a connection
failure, timeout, 408, 429 or 5xx (4 attempts, 1 s / 2 s / 4 s apart, each
re-signed with a fresh nonce); Legion answers 2xx only after the alert is
committed, and de-duplicates the retries.

**Rotate** (no outage): `POST /security-events/credentials/<id>/rotate` (or the
CLI's `rotate`) issues a new credential and keeps the old one working for
`overlap_hours` (default `WEBHOOK_ROTATION_OVERLAP_HOURS`, 24). Update
`<api_key>`, restart `wazuh-manager`, done. **Revoke** at once with
`DELETE /security-events/credentials/<id>` (CLI: `revoke`, or `revoke-all` for
an incident). Secrets are stored encrypted with `WEBHOOK_ENCRYPTION_KEY`; keep
that key out of database backups.

**Upgrading from a version that used `TENANT_ID:SECRET`:** those credentials
stop working. Create a credential per organisation, update `<api_key>`, and
install the current `custom-legion.py`. The old script is answered with a
message saying exactly that.

One limit remains: every tenant's key derives from one server-wide secret. See
"Known limitations" in [WAZUH.md](WAZUH.md).

---

## 6. HTTPS

Legion serves plain HTTP by default, because many installations sit on an
internal network where that is a reasonable choice.

**If the server is reachable from the internet, HTTPS is required.** Without
it, session cookies and passwords cross the network in the clear.

1. Put a reverse proxy in front of Legion. `deploy/nginx.conf` is a working
   config for one domain (dashboard at `/`, API at `/api/`); `certbot --nginx`
   adds the certificate. `npm run setup -- --domain legion.example.com` writes
   the matching `FRONTEND_URL`, `COOKIE_SECURE` and dashboard API address.
   Full walkthrough for a fresh Ubuntu server: [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md).
2. Set `FRONTEND_URL=https://legion.example.com` and `COOKIE_SECURE=true`
   in `.env`.
3. Restart (`npm run build && npm start`).

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

### Alert emails are never silently lost

An alert's email is saved in the database **in the same step as the alert
itself**, then delivered by a background worker. If the mail server is down or
rejects the message, the email waits and is retried — after 30 s, 1 min,
2 min, 4 min … (never more than an hour apart) — until it is delivered or the
attempt limit is reached. A restart does not lose queued emails.

```bash
NOTIFY_MAX_ATTEMPTS=8           # attempts before giving up (≈ 2 hours with the defaults)
NOTIFY_RETRY_BASE_SECONDS=30    # first retry delay; doubles each time, capped at 1 hour
NOTIFY_POLL_SECONDS=15          # how often the worker looks for due emails
```

An email that exhausts its attempts is kept with status `dead` and the last
error (with any SMTP login or password removed). Administrators see their own
organisation's deliveries at `GET /notifications/deliveries`; check it after
any mail outage. Every retry of one email carries the same Message-ID, so if a
crash makes the worker send it twice, mail systems can recognise the copy.

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
(Run this on the server itself: through nginx, or from any other machine,
`/health` answers only `{"status":"ok","database":"up"}` unless the request
carries `Authorization: Bearer <HEALTH_METRICS_TOKEN>`.)

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

**[RECOVERY.md](RECOVERY.md) is the current procedure** — encrypted backups, off-server copy, retention,
monitoring, secrets, and the exact restore steps. (BACKUP.md is the older description.) The short version:

```bash
DATABASE_URL=... ./ops/backup.sh           # dump the database, checked for readability
DATABASE_URL=... ./ops/verify-backup.sh    # prove a dump actually restores
DATABASE_URL=... ./ops/restore.sh <file> --yes   # restore, in place, inside one transaction
```

`DATABASE_URL` is the same value in `.env`. `verify-backup.sh` restores into a
throwaway database to check it, which needs a role that can create a database
— the role `npm run setup` creates deliberately cannot (see "Database
privileges" above), so pass `DATABASE_ADMIN_URL` (the superuser connection)
for that one script instead of widening what the API itself connects as.

A backup nobody has ever restored is a guess. `verify-backup.sh` exists so it
does not have to stay a guess; run it on a schedule alongside the backup
itself — see [BACKUP.md](BACKUP.md) for cron examples.

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
DATABASE_URL=... ./ops/backup.sh    # first, always
git pull
npm install
npm run build
npm start
```

Schema changes apply automatically on start and preserve data. Your secrets in
`.env` are left alone.

Multiple instances can start at once safely: schema changes run under a
database lock, so one applies them and the others wait.

---

## 10a. AI agents (optional)

AI agents and scripts get their own identities instead of borrowing a
person's login. An administrator creates one (`POST /agents`) with only the
permissions it needs. The agent then works through `/agent/v1/…`: it can read
alerts and assets and change an alert's status. It can also run the
security skills (threat detection, alert analysis, incident response, threat
intelligence, attack investigation, vulnerability analysis, reporting, and a
red-team self-test) that an administrator assigns to it.

Every agent action passes the agent firewall and is audited. An agent that
has just read alert text cannot change anything until a person reviews what
it read (`POST /prompt-guard/acknowledge`). A suspended agent stops at once.
Details: `packages/agent-identity/README.md`.

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
