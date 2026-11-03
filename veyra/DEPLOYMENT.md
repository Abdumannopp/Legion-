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

## Before real traffic

- Change the example admin email and all generated placeholder values.
- Keep SQLite on persistent storage and configure backups. SQLite is suitable for one app instance; use PostgreSQL before horizontal scaling.
- Configure `ALLOWED_ORIGIN` only if a separate trusted frontend domain needs cross-origin API access. Same-origin hosting does not require it.
- Add monitoring and restore-test your backups.
