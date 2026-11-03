# Running Legion as a paid online service (SaaS)

At the end of this guide:

- `https://legion.yourdomain.com` has a product page, pricing and terms;
- anyone can sign up, confirm their email and use Legion **free for 14 days**;
- then they buy a **monthly subscription** by card (Visa/Mastercard, in dollars) —
  **Paddle** takes the payment and handles tax and invoices;
- if they do not pay, the workspace is locked (data is not deleted); when they pay, it reopens.

The code side is ready and tested. Below are **only the things you have to do
yourself**: open accounts, get keys and write them into two files.

> Legal note: the terms, privacy and refund policy texts are samples written to
> match how the software actually works. They are not legal advice — have a
> lawyer review them before going live. Check the tax on your own income with an
> accountant (Paddle handles only the buyer-side VAT/sales tax).

---

## Step 1. Install the server in SaaS mode

Follow steps 0–7 of [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md), but in step 5 add
`--saas` to the `setup` command:

```bash
sudo -u legion npm run setup -- --saas --domain legion.yourdomain.com
```

This writes the required empty fields into `server/.env` and
`frontend/.env.local`. **Do not build yet** — first fill in the values from
steps 2–4. The server deliberately refuses to start until email is configured
(a SaaS that cannot send confirmation emails is a SaaS that does not work).

Note: in SaaS mode, step 8 (the setup token) is not needed — you open your own
account through `/signup`, like any customer.

---

## Step 2. Email — Resend

Confirmation, password-reset, invitation and alert emails go through it.
Resend's free plan allows 3,000 emails a month (100 a day), offers SMTP and adds
no advertising to emails. When you grow, move to a paid plan; the settings stay
the same.

1. Sign up at <https://resend.com>.
2. **Domains → Add domain** → `yourdomain.com` (or `mail.yourdomain.com`).
3. Resend shows several DNS records (TXT, MX) — add them to your domain's DNS
   **exactly** as shown. Also add one TXT record (so emails do not land in spam):

   | Type | Name | Value |
   |---|---|---|
   | TXT | `_dmarc` | `v=DMARC1; p=none;` |

4. Click **Verify** in Resend — wait until everything is green (minutes to hours).
5. **API Keys → Create API key** (Sending access) → copy the key (`re_…`).
6. On the server, in `/opt/legion/server/.env`:

   ```env
   SMTP_PASSWORD=re_…your_key
   SMTP_FROM=Legion <no-reply@yourdomain.com>
   ```

   The domain in `SMTP_FROM` must be the one verified in step 4.
   The remaining SMTP lines (`smtp.resend.com`, `465`, `resend`) are already written.

---

## Step 3. Site details

`/opt/legion/frontend/.env.local`:

```env
NEXT_PUBLIC_OPERATOR_NAME=First Last          # your legal name (or company name), as on your ID
NEXT_PUBLIC_SUPPORT_EMAIL=support@yourdomain.com
NEXT_PUBLIC_DATA_LOCATION=Germany (Hetzner)   # the country of your server — shown in the privacy policy
NEXT_PUBLIC_PRICE_LABEL=49 USD                # optional; do not use the "$" sign
```

Paddle's domain review requires the **seller's real name** in the terms — that is
why `NEXT_PUBLIC_OPERATOR_NAME` matters. You must be able to receive mail at
`support@…` (Resend only sends; set up a mailbox or email forwarding on your domain).

---

## Step 4. Payments — Paddle (test first, then live)

Paddle has two separate environments: **sandbox** (fake cards, no money) and
**live** (real money). Test everything in the sandbox first.

### 4a. Sandbox

1. Sign up at <https://sandbox-login.paddle.com/signup>.
2. **Catalog → Products → New product**: name `Legion`. Inside it,
   **New price**: e.g. 49 USD, **recurring, monthly**. Save and copy the price
   ID (`pri_…`).
3. **Developer tools → Authentication**:
   - create an **API key** → `PADDLE_API_KEY` (server, secret);
   - create a **Client-side token** → `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` (web page).
4. **Developer tools → Notifications → New destination**:
   - URL: `https://legion.yourdomain.com/api/billing/webhook`
   - Events: all `subscription.*` (created, updated, activated, canceled,
     past_due, paused, resumed);
   - save and copy the **secret key** → `PADDLE_WEBHOOK_SECRET`.
5. **Checkout → Checkout settings → Default payment link**:
   `https://legion.yourdomain.com/billing`
6. Write the values:

   `server/.env`:
   ```env
   PADDLE_ENVIRONMENT=sandbox
   PADDLE_API_KEY=…
   PADDLE_WEBHOOK_SECRET=…
   ```

   `frontend/.env.local`:
   ```env
   NEXT_PUBLIC_PADDLE_ENVIRONMENT=sandbox
   NEXT_PUBLIC_PADDLE_CLIENT_TOKEN=…
   NEXT_PUBLIC_PADDLE_PRICE_ID=pri_…
   ```

7. Build and restart:

   ```bash
   cd /opt/legion && sudo -u legion npm run build && systemctl restart legion
   journalctl -u legion -n 20     # "Paddle is in SANDBOX mode" — this is normal
   ```

### 4b. Test the whole cycle

1. `https://legion.yourdomain.com` → **Start free trial** → sign up.
2. Click **Confirm email** in the email → sign in. The dashboard opens.
3. **Billing → Subscribe now** → the Paddle window. Test card:
   `4242 4242 4242 4242`, any future date, any CVC.
4. After a few seconds the Billing page shows **Active**.
5. **Manage subscription** → cancel → at the end of the period the workspace
   locks, while Billing stays open.

If these five steps work, everything is connected correctly.

### 4c. Real money (live)

1. Open a **live** account at <https://login.paddle.com/signup> (separate from the sandbox).
2. Pass the checks:
   - **Identity verification** — a passport (a company is not required: Paddle
     also works with individual sellers);
   - **Checkout → Website approval** — `https://legion.yourdomain.com`.
     Paddle checks that the site has a product description, price, terms,
     privacy and refund policy — all of these are ready
     (`/`, `/pricing`, `/terms`, `/privacy`, `/refunds`);
   - a bank account or Payoneer to receive payouts.
3. Once approved, repeat items 2–5 of 4a in the **live** account
   (product, price, keys, webhook, default payment link — all new).
4. In both files change `sandbox` → `production`, write the new keys, then build
   and restart.
5. Buy once yourself with a real card, then **Refund** it.

---

## How it works (in short)

| State | What the customer sees |
|---|---|
| Signed up, email not confirmed | Cannot sign in; there is a "resend link" button |
| Trial (14 days) | Everything works |
| Trial ended, no subscription | Workspace locked, data kept, Billing open |
| Subscription active | Everything works |
| Payment failed (past due) | Read-only; nothing can be changed |
| Subscription cancelled | Works until the end of the period, then locks |

- Each customer's data is in a separate workspace — others cannot see it.
- A subscription is activated only by a webhook signed by Paddle; a browser
  cannot fake "I paid".
- If the server is down, Paddle keeps retrying for hours — no payment is lost.

## Still done by hand

- **Account deletion requests** — the customer writes, you delete from the
  database (the terms say "within 30 days").
- **List of all customers** — there is no separate admin panel; see the Paddle
  dashboard (payments) or the database.
- **Email limit** — Resend's free plan sends 100 emails a day. Move to a paid
  plan as you grow.
- **Backups** — step 10 of [DEPLOY-ONLINE.md](DEPLOY-ONLINE.md); this is now
  your customers' data, so copy it off the server too.

## When something does not work

| Symptom | Cause |
|---|---|
| The server will not start: `SMTP_PASSWORD is empty` | Step 2 not done |
| The confirmation email does not arrive | The domain is not verified in Resend, or `SMTP_FROM` uses another domain; errors show in Resend → Emails |
| Emails land in spam | Check that the `_dmarc` TXT record and all of Resend's DNS records are added |
| Billing shows "Paddle isn't configured" | The Paddle values in `frontend/.env.local` are empty, or it was not rebuilt |
| Paid, but it did not become "Active" | Paddle → Notifications → destination → check the response in the logs; check the URL `/api/billing/webhook` and the secret. Server log: `journalctl -u legion \| grep Paddle` |
| The price shows "—" | `NEXT_PUBLIC_PADDLE_PRICE_ID` or the client token is missing, or `PRICE_LABEL` uses `$` |
