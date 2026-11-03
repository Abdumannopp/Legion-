# Putting Legion online

At the end of this guide Legion runs at an address such as
`https://legion.yourdomain.com`, over HTTPS, and starts by itself when the
server reboots. It takes about 30–60 minutes. Copying the commands is enough.

> **Why not Vercel or Netlify?** Legion needs an always-on server, a PostgreSQL
> database and live connections (WebSocket). "Serverless" services do not offer
> these. An ordinary virtual server (VPS) is the right choice.

---

## 0. What you need

| | |
|---|---|
| **Server (VPS)** | Ubuntu 24.04, at least 2 CPUs, 4 GB RAM, 40 GB disk. Any provider: Hetzner, DigitalOcean, Contabo, a local host — it makes no difference. After buying, you get an **IP address** and a **root password** (or SSH key). |
| **Domain** | For example `yourdomain.com`. We use a separate subdomain for Legion: `legion.yourdomain.com`. |
| **Project files** | The `Legion-….zip` (or the Git repository). |

Everywhere below, replace `legion.yourdomain.com` with **your own domain** and
`SERVER_IP` with your server's IP address.

---

## 1. Point the domain at the server

In the DNS settings where you bought the domain, add a record:

| Type | Name | Value |
|---|---|---|
| `A` | `legion` | `SERVER_IP` |

Check (on your own computer): `ping legion.yourdomain.com` — the reply should
come from `SERVER_IP`. Sometimes you need to wait 5–30 minutes.
**HTTPS in step 7 will not work until this does.**

---

## 2. Connect to the server

PowerShell on Windows, Terminal on Mac/Linux:

```bash
ssh root@SERVER_IP
```

All remaining commands run **on the server**.

---

## 3. Install the required software

```bash
apt update && apt upgrade -y
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt install -y nodejs postgresql nginx certbot python3-certbot-nginx unzip git

# Firewall: only SSH and web (80/443) open
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable
```

Check: `node --version` → `v22…`.

Set the PostgreSQL administrator password (choose one and **write it down** —
step 5 asks for it, and backup verification needs it too):

```bash
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'PUT-A-STRONG-PASSWORD-HERE'"
```

---

## 4. Put the Legion files in place

Legion runs as a separate, unprivileged `legion` user.

**From a zip file** — upload it from your own computer (not the server!):

```bash
scp Legion-*.zip root@SERVER_IP:/opt/
```

Then on the server:

```bash
cd /opt && unzip -q Legion-*.zip && rm Legion-*.zip   # creates the /opt/legion folder
```

**From Git**: `git clone <repository-url> /opt/legion`

Then (either way):

```bash
adduser --system --group --home /opt/legion --no-create-home legion
chown -R legion:legion /opt/legion
```

---

## 5. Configure and build

```bash
cd /opt/legion
sudo -u legion npm install
sudo -u legion npm run setup -- --domain legion.yourdomain.com
sudo -u legion npm run build
```

`npm run setup` asks for the PostgreSQL password — enter the one from step 3
(just press Enter for Host, Port and Superuser name). It creates the database,
Legion's own (non-superuser) role and all secrets. Thanks to `--domain`, the
addresses are written as `https://…` straight away.

Your organisation's name appears on the privacy and terms pages — fill in
`NEXT_PUBLIC_OPERATOR_NAME` and `NEXT_PUBLIC_SUPPORT_EMAIL` in
`/opt/legion/frontend/.env.local`, then run `sudo -u legion npm run build` again.

> Running `npm run setup` again later is safe: settings you added (SMTP,
> AI key, domain) are not removed.

---

## 6. Keep it running (systemd)

```bash
cp /opt/legion/deploy/legion.service /etc/systemd/system/legion.service
systemctl daemon-reload
systemctl enable --now legion
systemctl status legion        # should show "active (running)"
```

Legion now starts by itself after a reboot or a crash.

---

## 7. nginx and HTTPS

```bash
cp /opt/legion/deploy/nginx.conf /etc/nginx/sites-available/legion
sed -i 's/legion.example.com/legion.yourdomain.com/' /etc/nginx/sites-available/legion
ln -s /etc/nginx/sites-available/legion /etc/nginx/sites-enabled/legion
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

certbot --nginx -d legion.yourdomain.com
```

Certbot asks for an email and agreement to its terms. It gets a free SSL
certificate, adds HTTPS to nginx, redirects `http://` to `https://`, and renews
the certificate automatically.

---

## 8. The first administrator

Open in a browser: **https://legion.yourdomain.com/setup**

It asks for a one-time **setup token**. Get it on the server:

```bash
cat /opt/legion/server/.legion-setup-token
```

Enter your email, password and organisation name — you become the administrator
and sign-up closes. Others join by invitation through Settings → Team.

**Do this straight away:** until an administrator exists, anyone who knows the
token can take over the page (the token is only on the server, so the risk is
low, but do not delay).

---

## 9. Connect Wazuh

Follow [WAZUH.md](WAZUH.md); only the `hook_url` is now:

```xml
<hook_url>https://legion.yourdomain.com/api/security-events/webhook</hook_url>
```

`api_key` needs a `KEY_ID:SECRET` (`whk_…:whs_…`) — each organisation's own
random credential. An administrator creates it (the secret is shown only once):

```bash
cd /opt/legion && npm run webhook:credential -w server -- create --tenant TENANT_ID --label "wazuh-1"
```

The tenant ID is on the Settings page. `SECURITY_EVENT_WEBHOOK_SECRET` is no
longer used for authentication. Keep `WEBHOOK_ENCRYPTION_KEY` from `.env`
**separately** from database backups.

---

## 10. Backups (required)

```bash
mkdir -p /var/log/legion && chown legion:legion /var/log/legion
crontab -u legion -e
```

Add at the end of the file that opens (every night at 03:00):

```cron
0 3 * * * cd /opt/legion && DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' server/.env)" ./ops/backup.sh >> /var/log/legion/backup.log 2>&1
```

Backups go to `/opt/legion/backups/`. **Copy them off the server too** — if the
server is lost, the backups on it are lost with it. Once a month, check that a
backup really restores ([RECOVERY.md](RECOVERY.md), [BACKUP.md](BACKUP.md)):

```bash
cd /opt/legion && DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' server/.env)" \
  DATABASE_ADMIN_URL="postgresql://postgres:PASSWORD-FROM-STEP-3@localhost/postgres" \
  ./ops/verify-backup.sh
```

---

## 11. Updating

```bash
cd /opt/legion
sudo -u legion env DATABASE_URL="$(sed -n 's/^DATABASE_URL=//p' server/.env)" ./ops/backup.sh
# put the new files in place (git pull, or unzip the new archive over it)
chown -R legion:legion /opt/legion
sudo -u legion npm install
sudo -u legion npm run build
systemctl restart legion
```

The database schema updates itself; data and secrets are kept.

---

## 12. DDoS protection (Cloudflare, recommended)

The server alone cannot stop everything: if an attacker fills your connection
(Gbit/s), the site goes down before a request even reaches Legion. Only a
service **in front of** the server (a CDN) solves that. The simplest option is
Cloudflare's free plan. Legion and nginx are prepared to work correctly behind
it (ready-made scripts in `ops/` and `deploy/`).

**Why this step matters.** Behind Cloudflare, nginx sees every visitor as a
Cloudflare address. "Too many attempts from one address" limits then become
**one** counter for everybody: a single attacker locks everyone out. The real
address arrives in the `CF-Connecting-IP` header, but that header can be trusted
only when the request really comes from Cloudflare. The steps below set this up.

### 12.1. Move the domain to Cloudflare

1. Create a free account at cloudflare.com, add your domain, and change the
   nameservers where you bought the domain to the ones Cloudflare gives you.
2. In DNS, make the `legion` record **proxied** (orange cloud).
3. In **SSL/TLS → Overview** choose **Full (strict)**. (This needs a real
   certificate on the server — `certbot` in step 7 provides it. Get the
   certificate **before 12.4**.)

### 12.2. Let nginx take the real address from Cloudflare

```bash
cd /opt/legion
sudo ops/update-cloudflare-ips.sh --reload
```

The script downloads Cloudflare's official address list, validates it (refusing
wrong or overly wide ranges, so nginx never trusts the whole internet), writes
`/etc/nginx/legion-cloudflare.conf`, tests with `nginx -t` and reloads. If
anything is wrong, the old file stays in place.

Then, in `/etc/nginx/sites-available/legion`, remove the `#` from this line and
reload nginx:

```
    include /etc/nginx/legion-cloudflare.conf;
```

```bash
nginx -t && systemctl reload nginx
```

Cloudflare's addresses change over time, so enable the timer that refreshes the
list weekly:

```bash
cp /opt/legion/deploy/legion-cloudflare-ips.service /etc/systemd/system/
cp /opt/legion/deploy/legion-cloudflare-ips.timer   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now legion-cloudflare-ips.timer
```

> Nothing needs to be added to Legion (`server/.env`): it trusts only the nginx
> on this server and takes the client address from the header nginx sets.
> Do not change `TRUSTED_PROXIES`.

### 12.3. Check it

Open the site in a browser and sign in. Then one script checks everything (it
changes nothing, it only reads):

```bash
# on the server itself — nginx, the timer, the firewall, real IPs in the logs:
sudo /opt/legion/ops/check-cloudflare-setup.sh --domain legion.yourdomain.com --local

# from ANOTHER computer (e.g. your own) — DNS, HTTPS, the Wazuh webhook,
# and that the server cannot be reached directly by its IP:
ops/check-cloudflare-setup.sh --domain legion.yourdomain.com --server-ip SERVER_IP
```

Each line is `OK`, `WARN` or `FAIL`; a `FAIL` line says what to do. All `OK`
means the setup is right. Send the output to your technical support if
something is unclear. (Until you do 12.4, the `--server-ip` check reports
`FAIL` — that is expected.)

### 12.4. Close the server to direct attacks (origin lockdown)

An attacker can bypass Cloudflare and send traffic straight to the server's IP.
To prevent that, open ports 80/443 to Cloudflare only:

```bash
sudo ops/update-cloudflare-ips.sh --ufw            # shows the plan first (changes nothing)
sudo ops/update-cloudflare-ips.sh --ufw --apply    # adds the rules
ufw status numbered
ufw delete allow 'Nginx Full'                      # remove the open-to-everyone rule
```

The SSH rule is untouched. Check: `curl -m 5 http://SERVER_IP/` must **not
answer**, while `https://legion.yourdomain.com` must work.

Note: after this, the Wazuh manager must send to Legion **by domain, not by IP**
(`https://legion.yourdomain.com/api/security-events/webhook`), otherwise it hits
the block. When Cloudflare adds a new range, the timer updates the nginx list,
but you must re-run the `ufw` rules **by hand** (`--ufw --apply` — it adds only
the missing rules, no duplicates).

### 12.5. Rules in the Cloudflare dashboard

(Menu names change over time; the free plan limits the number of rules.)

- **Security → WAF → Rate limiting rules**: for the `/api/auth/` path, about 30
  requests per minute from one address, block above that. (Legion and nginx
  have their own limits; Cloudflare's stops the request before it reaches the server.)
- **Security → Settings**: you can enable *Bot Fight Mode*. During an attack,
  temporarily turn on **"I'm Under Attack"** mode.
- **The Wazuh webhook.** Cloudflare may send non-browser clients (the Wazuh
  script) to a bot challenge. `check-cloudflare-setup.sh` detects this
  ("Cloudflare blocks the webhook"). Then add a rule in *Security → WAF → Custom
  rules*: **URI Path equals `/api/security-events/webhook` → Skip** (Bot Fight /
  Rate limiting). This rule has **not been tested** on a Cloudflare account
  (it depends on the dashboard's current layout) — re-run the script after adding it.
  While blocked, events are **not lost**: the Wazuh script recognises the
  Cloudflare block, keeps the event in its spool, writes the exact reason to the
  log (`/var/ossec/logs/integrations.log`) and re-sends automatically once the
  block is lifted. The webhook is still protected by its own signature: badly
  signed requests are refused and throttled.
- WebSocket (live alerts) works on every Cloudflare plan.

### 12.6. Scaling up (if the attack is large)

Legion can run as several instances: a shared PostgreSQL and Redis
(`REDIS_URL` in `server/.env`; details in [GLOBAL-SAAS-ARCHITECTURE.md](GLOBAL-SAAS-ARCHITECTURE.md))
and one more `server` line in nginx's `upstream legion_api`.
Tunable values (`server/.env`):

| Variable | Meaning |
|---|---|
| `PASSWORD_HASH_WORKERS` | number of password-checking threads (default: automatic; measurements showed no significant difference between 1 and 3) |
| `HTTP_FIRST_REQUEST_TIMEOUT_SECONDS` | close a connection that has not sent its first request (default 15 s, `0` disables) |
| `PASSWORD_HASH_MAX_PRIORITY` | size of the reserved queue for known devices (12.8; default — equal to the normal queue) |

### 12.7. Turnstile (CAPTCHA) on sign-in forms — optional

Turnstile is Cloudflare's free "are you human?" check. Usually a person clicks
nothing (the check passes by itself), while bots cannot pass. When enabled,
**sign-in, sign-up, first setup and password reset** requests are not accepted
without it — checked **before** the password is verified (the most expensive
operation) and before any email is sent.

1. In the Cloudflare dashboard: **Turnstile → Add widget**. Domain:
   `legion.yourdomain.com`, mode: **Managed**. You get two keys:
   a **Site key** (public) and a **Secret key** (private).
2. On the server, add them to both files:

   ```bash
   # server/.env  (secret key — show it to no one)
   TURNSTILE_SECRET_KEY=0x4AAAA...your-secret-key

   # frontend/.env.local  (public key)
   NEXT_PUBLIC_TURNSTILE_SITE_KEY=0x4AAAA...your-site-key
   ```
3. Rebuild and restart the dashboard (the public key is written into the page
   at build time):

   ```bash
   cd /opt/legion && sudo -u legion npm run build && systemctl restart legion
   ```
4. Check: the sign-in page shows the check box; the "Sign in" button stays
   disabled until it passes.

Good to know:
- Both keys are needed **together**. Only on the server — every sign-in is
  refused with `captcha_required`; only in the dashboard — the check appears,
  but the server does not require it.
- If Cloudflare's verification service cannot be reached, sign-in returns `503`
  for a while (**it fails closed** — so the door is not left open during an
  attack). The rest of the API keeps working.
- Once enabled, you cannot sign in to `/auth/login` with a password from a
  script or terminal (that is the point). The Wazuh sensor and AI agents use
  keys — they are not affected.
- If a browser ad/content blocker blocks the check, the page says so clearly.
- Legion's side was tested in a browser (`ops/tests/e2e-turnstile.mjs`), but
  not against Cloudflare's real service (the test environment could not reach
  it) — sign in once yourself after enabling it.

### 12.8. Known devices can sign in even during an attack (automatic)

If the password-checking queue fills during an attack, new sign-ins get `503`.
But for a person who has previously signed in **fully** (password + 2FA) from
the same browser, Legion keeps a separate queue the attack cannot fill. Nothing
to configure: after a successful sign-in, the browser receives a signed 90-day
cookie (`legion_device`).

- The cookie works only for **the account it names** and does not replace the
  password — the password is still fully checked.
- A stolen cookie only speeds up sign-in to that one account, at most 10 times
  per minute.
- Measured (on one machine): during a sign-in attack, 12 of 15 attempts from a
  new browser got `503`; a known browser signed in 5/5 times.

### 12.9. Measuring on your own server

The numbers above came from a test machine. To find out what your server can
handle, run the same test **on your own server**. It starts a separate temporary
database and a separate Legion instance — it does not touch the running Legion
or its data, but it **keeps the whole CPU busy** for about 5 minutes. Run it
when there are no users (or before going live).

```bash
cd /opt/legion
sudo -u legion npm run build              # if not built since the last update
sudo E2E_ADMIN_DATABASE_URL="postgresql://postgres:POSTGRES-PASSWORD@127.0.0.1:5432/postgres" \
  node ops/tests/ddos-resilience.mjs --json /root/legion-dos.json 2>&1 | tee /root/legion-dos.txt
```

(`POSTGRES-PASSWORD` is the administrator password from step 3.) If it ends with
`N passed, 0 failed`, the system behaves as expected under attack.
Lines to look at in the result:

- `responses: {... "per_second": …, "api_cpu_percent_of_one_core": …}` —
  how many useless requests per second one Legion instance absorbed;
- `legitimate traffic by phase` — how much ordinary users and the sensor slowed
  down during the attack (`p95`, milliseconds);
- `sign-in from a known device` — signing in from a known device.

This test runs **only against this server itself** (the attack targets
`127.0.0.1`). Never use it against anyone else's server. Send
`/root/legion-dos.txt` to your technical support to help size the capacity
(CPU, number of instances).

### 12.10. Honest limits

- **A large (volumetric) attack** — an L3/L4 attack that fills the connection —
  can only be stopped in front of the network, by a service like Cloudflare.
  Without one, you rely on your hosting provider's own protection.
- **Slow, "human-like"** requests from thousands of different addresses (an L7
  botnet) get around per-address limits. Legion softens this (counter memory is
  bounded, the system stays up, sensor events are not lost, reading works), but
  password sign-in from a **new** browser — the most expensive operation — can
  return `503` while the attack lasts. Known devices (12.8) can sign in;
  Turnstile (12.7), Cloudflare rules and Bot Fight Mode cover the rest.
- The measurements were taken on one machine (`ops/tests/ddos-resilience.mjs`);
  they show the system's **behaviour**, not your server's capacity. Results:
  [PRODUCTION-VALIDATION-2026-10-01.md](PRODUCTION-VALIDATION-2026-10-01.md).
- The Cloudflare account itself (DNS proxy, WAF rules, the real Turnstile
  service) was not tested here — that needs an account. That is why the check
  script in 12.3 exists: it checks your real setup.

---

## When something does not work

| Symptom | Cause and fix |
|---|---|
| `502 Bad Gateway` | Legion is not running: `systemctl status legion`, logs: `journalctl -u legion -n 50` |
| Certbot fails | DNS does not point at the server yet (step 1) or port 80 is closed (`ufw status`) |
| Correct password but cannot sign in | The site was opened over `http://` — use `https://` |
| The page opens but shows no data | `NEXT_PUBLIC_API_URL` in `frontend/.env.local` is not `https://DOMAIN/api` — fix it and run `npm run build` |
| The server will not start, mentions `JWT_SECRET` | `server/.env` is missing — `sudo -u legion npm run setup -- --domain …` |
| Status | `curl https://legion.yourdomain.com/api/health` → `"database":"up"` |

---

## One decision: who is it for?

By default Legion serves **one organisation** (`DEPLOYMENT_MODE=self-hosted`):
sign-up closes after the first administrator. This is the model of installing a
separate Legion on each customer's own server.

If you want a service (SaaS) where **many customers sign up themselves** on one
site and buy a subscription: use `npm run setup -- --saas --domain …` in step 5
and follow [SAAS.md](SAAS.md) (email — Resend, payments — Paddle).
