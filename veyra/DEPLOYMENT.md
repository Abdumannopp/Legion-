# VEYRA deployment guide

The application starts with `npm run prod`, reads the platform-provided `PORT`, serves `/api/health` for health checks, and requires a persistent SQLite path. The first production startup creates one admin from the `INITIAL_ADMIN_*` variables. Development demo accounts and sample shipments are not seeded in production.

## Render

1. Push this project to a Git repository and create a Render Blueprint from it.
2. Review `render.yaml`; change `INITIAL_ADMIN_EMAIL` to the admin email you will use.
3. Deploy the service. The Blueprint provisions a Starter web service and a persistent disk at `/var/data`.
4. In the Render dashboard, retrieve the generated `INITIAL_ADMIN_PASSWORD` and store it in a password manager. Do not put it in the repo.
5. Add a custom domain in Render. HTTPS is provisioned by Render.

The Render disk keeps SQLite data across deploys, but it is a single-instance setup. Do not increase instance count while using SQLite.

## Railway

1. Push the project to GitHub and create a Railway project from the repository.
2. Add a Railway Volume mounted at `/data`.
3. Add these service variables in Railway:

```env
NODE_ENV=production
DATABASE_PATH=/data/veyra.db
JWT_SECRET=<generate a long random secret>
INITIAL_ADMIN_NAME=VEYRA Administrator
INITIAL_ADMIN_EMAIL=admin@your-domain.com
INITIAL_ADMIN_PASSWORD=<unique password of at least 12 characters>
```

4. Deploy. `railway.json` sets the build, start command, health check, and restart policy.
5. Add a Railway domain or custom domain. Store all generated secrets outside source control.

The volume is persistent but SQLite remains a single-instance database. For multiple replicas, migrate to PostgreSQL first.

## VPS with systemd and Caddy

Use Ubuntu/Debian with Node.js 20 or newer and a domain pointed at the VPS.

1. Install Node.js and Caddy, then create the service account and application directory:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin veyra
sudo mkdir -p /opt/veyra /etc/veyra
sudo chown veyra:veyra /opt/veyra
```

2. Copy the project to `/opt/veyra` (excluding `node_modules`, `.env`, and local database files), then install production dependencies:

```bash
cd /opt/veyra
sudo -u veyra npm ci --omit=dev
```

3. Create `/etc/veyra/veyra.env` with `JWT_SECRET`, `INITIAL_ADMIN_NAME`, `INITIAL_ADMIN_EMAIL`, and a unique `INITIAL_ADMIN_PASSWORD` of at least 12 characters. Protect it:

```bash
sudo chmod 600 /etc/veyra/veyra.env
```

4. Copy `deploy/veyra.service` to `/etc/systemd/system/veyra.service`. Copy `deploy/Caddyfile` to `/etc/caddy/Caddyfile` and replace `veyra.example.com` with your domain.
5. Start both services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now veyra
sudo systemctl reload caddy
```

`StateDirectory=veyra` creates `/var/lib/veyra` for the persistent SQLite database. Caddy obtains and renews HTTPS certificates automatically. Check app logs with `sudo journalctl -u veyra -f`.

## Local production smoke test

On a new database, set a strong JWT secret and first admin values before running:

```powershell
$env:NODE_ENV='production'
$env:JWT_SECRET='replace-with-a-long-random-secret'
$env:INITIAL_ADMIN_NAME='VEYRA Administrator'
$env:INITIAL_ADMIN_EMAIL='admin@example.com'
$env:INITIAL_ADMIN_PASSWORD='replace-with-a-unique-password'
$env:DATABASE_PATH='./data/production-test.db'
npm run prod
```

Verify `http://localhost:3000/api/health` returns `{"status":"ok"}`. Delete only the disposable test DB when the process is stopped.

## Region and team settings

- `WEIGHT_UNIT` (`kg` or `lb`) and `CURRENCY` (ISO code such as `USD`, `EUR`, `UZS`, `KZT`) set how loads and prices are shown. For large-number currencies raise `MAX_RATE` (for `UZS`, e.g. `10000000000`).
- Sign-up is **closed** in production. The first administrator signs in with the `INITIAL_ADMIN_*` account and adds the team from **Dashboard → Operations Console → Team Access → Add user**, where roles can also be changed and accounts disabled (takes effect immediately).
- To let people sign up themselves, set `REGISTRATION_INVITE_CODE` (they need the code and become operators) or, for demos only, `ALLOW_OPEN_REGISTRATION=true`.

## AI, SMS / WhatsApp and GPS (optional)

All three are off until configured, and the app works without them.

- **AI (FLOW)**: create a key at openrouter.ai, set `OPENROUTER_API_KEY`. Optionally pick a model in `OPENROUTER_MODEL`; empty uses your OpenRouter account default. Use is limited per person (`AI_RATE_LIMIT_PER_HOUR`) and logged under Analytics → AI agents.
- **SMS / WhatsApp (RELAY)**: in a Twilio account get the Account SID, Auth Token and a sender number (and an approved WhatsApp sender for WhatsApp). Set `MESSAGING_PROVIDER=twilio`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_SMS_FROM` and/or `TWILIO_WHATSAPP_FROM`. Phone numbers on loads must be in international format (+998…).
- **Each company uses its own Twilio account** (Dashboard -> Integrations -> Connect Twilio). The token is checked with Twilio, stored encrypted with `SECRETS_KEY` and never shown again. The server-wide Twilio settings above belong to the first company only, unless `MESSAGING_SHARED_ALL_TENANTS=true`. Set `SECRETS_KEY` once and keep it: if it (or `JWT_SECRET`, when `SECRETS_KEY` is empty) changes, saved Twilio settings can no longer be read and must be entered again.
- **Orders by email**: an administrator opens Integrations -> Email inbox -> Create address. The address is a web address that an email service posts incoming mail to: Postmark (inbound stream), Mailgun (route, "forward to URL"; plain messages) or Zapier / Make (new email -> webhook POST). SendGrid Inbound Parse sends multipart forms and is not supported directly; use Zapier / Make in between. The address contains a secret, so treat it like a password (it can appear in your email provider's settings and logs; create a new one if it leaks). Set the allowed senders so strangers cannot use the address: other senders are stored as blocked and never reach the AI.
- **Documents**: CMR, proof of delivery and other files (PDF, JPG, PNG, WebP, up to `DOC_MAX_MB`) are stored inside the database file, so the database backup covers them. Reading CMR files with AI needs a model that can read images or PDFs: set `OPENROUTER_MODEL` to one if the account default cannot.
- **GPS**: an administrator opens Dashboard → Integrations → Create GPS token and gives the provider the address `https://<your-domain>/api/integrations/gps` and the token. The provider sends positions with the truck plate; plates are matched ignoring spaces and dashes.

## NEXUS (the orchestrator)

NEXUS reacts to events (an order email arrives, a load reaches Sourcing, a truck is booked, a document is uploaded, a truck goes quiet) and leaves **tasks** under Inbox & tasks. It prepares things: reads emails, ranks carriers, drafts messages, compares documents with the load. It never sends a message, books a truck, creates a load or changes a status: every one of those waits for a person to press the button. Trucks with no location update for `STALE_TRACKING_HOURS` get a drafted "where are you?" message (checked every 10 minutes). `NEXUS_ENABLED=false` switches it off.

## Before real traffic

- Change the example admin email and all generated placeholder values.
- Keep SQLite on persistent storage and configure backups. SQLite is suitable for one app instance; use PostgreSQL before horizontal scaling.
- Configure `ALLOWED_ORIGIN` only if a separate trusted frontend domain needs cross-origin API access. Same-origin hosting does not require it.
- Add monitoring and restore-test your backups.
