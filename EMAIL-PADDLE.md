# Setting up email (SMTP) and Paddle Billing

Both are **optional** in self-hosted mode. Without them Legion works normally —
no emails are sent, and the billing page says "not configured".
(In SaaS mode email is required — see [SAAS.md](SAAS.md).)

---

# 1. Email (SMTP)

## Why you need it

| Feature | Without SMTP | With SMTP |
|---|---|---|
| Password reset | The link appears only in the server log | The user gets an email |
| Alert notifications | None | Important alerts are emailed |
| `/notifications/test` | "skipped" | A real test email |

## Setup

In `server/.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_SECURE=false
SMTP_FROM=Legion <you@gmail.com>
ALERT_EMAIL_MIN_SEVERITY=high
```

| Key | Notes |
|---|---|
| `SMTP_HOST` | **If empty, email is switched off entirely** |
| `SMTP_PORT` | `587` (STARTTLS) or `465` (SSL) |
| `SMTP_SECURE` | `true` for `465`, `false` for `587` |
| `SMTP_USER` / `SMTP_PASSWORD` | If left empty, connects without authentication |
| `ALERT_EMAIL_MIN_SEVERITY` | `critical` \| `high` \| `medium` \| `low` \| `off` |

### Gmail

Your normal password does not work. Turn on 2FA in your Google account, then
create an **App Password** and put it in `SMTP_PASSWORD`.

### Other services

| Service | Host | Port |
|---|---|---|
| SendGrid | `smtp.sendgrid.net` | 587 |
| Mailgun | `smtp.mailgun.org` | 587 |
| Resend | `smtp.resend.com` | 587 |
| Amazon SES | `email-smtp.<region>.amazonaws.com` | 587 |

## Where alert emails go

Dashboard → **Settings** → notification email. If empty, nothing is sent.

Restart Legion, then click **Settings → Send test**.

## Checking

```bash
curl -X POST http://localhost:8000/notifications/test -b cookie.txt
```

| Response | Meaning |
|---|---|
| `{"status":"sent to ..."}` | It worked |
| `skipped: SMTP is not configured` | `SMTP_HOST` is empty |
| `Set a notification email address first` | No address in Settings |
| `SMTP connection failed: ...` | Wrong host, port or password |

---

# 2. Paddle Billing

## Important

A subscription is activated **only through the webhook**. Without the webhook a
customer pays, but the subscription never becomes active.

## 2.1 Getting the keys from Paddle

Paddle Dashboard → **Developer Tools**:

| What | Where |
|---|---|
| API key (`pdl_...`) | Authentication → API keys |
| Client token | Authentication → Client-side tokens |
| Price ID (`pri_...`) | Catalog → Prices |
| Webhook secret (`pdl_ntfset_...`) | Notifications → when creating a new destination |

## 2.2 Server settings

`server/.env`:

```env
PADDLE_API_KEY=pdl_sdbx_...
PADDLE_WEBHOOK_SECRET=pdl_ntfset_...
PADDLE_ENVIRONMENT=sandbox
```

## 2.3 Frontend settings

`frontend/.env.local`:

```env
NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=test_...
NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
NEXT_PUBLIC_PADDLE_PRICE_ID=pri_...
```

`PADDLE_ENVIRONMENT` and `NEXT_PUBLIC_PADDLE_ENVIRONMENT` **must match**.
A sandbox key never matches a production webhook.

## 2.4 Registering the webhook address

Paddle → Notifications → **New destination**:

- URL: `https://your-domain.com/api/billing/webhook` (behind the nginx setup in
  [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md); the API itself serves `/billing/webhook`)
- Select these events:
  - `subscription.created`
  - `subscription.updated`
  - `subscription.activated`
  - `subscription.canceled`
  - `subscription.past_due`
  - `subscription.paused`
  - `subscription.resumed`

> Paddle requires an HTTPS address reachable from the internet.
> For local testing, run `ngrok http 8000` and use the address it gives you.

## 2.5 How the tenant is identified

```
The user clicks "Upgrade"
  → Legion creates a checkout_token (a signed JWT containing the tenant_id)
  → Paddle.js passes it to the checkout in custom_data
  → Paddle returns it in the webhook
  → Legion verifies the token and links the subscription to the right tenant
```

So a browser cannot steal another tenant's subscription — the tenant ID comes
from the signed token, not from the browser.

## 2.6 Webhook responses

| Response | Meaning |
|---|---|
| `202 processed` | Subscription updated |
| `202 ignored` | An event unrelated to subscriptions (e.g. `transaction.completed`) |
| `202 skipped, stale event` | An older event arrived later — ignored |
| `202 skipped, no valid checkout_token` | No token in `custom_data`, or it is invalid |
| `401 Invalid signature` | Wrong `PADDLE_WEBHOOK_SECRET` |
| `401 Signature timestamp outside tolerance` | The server clock is wrong (set up NTP) |
| `503 Paddle webhook secret is not configured` | No secret in `.env` |

---

## Security

- Paddle's signature is verified over the **raw bytes**. If the JSON were
  re-serialised, the signature would never match.
- The comparison uses `timingSafeEqual` — protected against timing attacks.
- Signatures older than 5 minutes are refused (against replay).
- SMTP errors are never returned to the user and never stop alert ingestion.
- In production, the password-reset link is **never** written to the log.
