# Legion — follow-up audit

**Date:** 2026-08-25
**Scope:** everything changed since the last audit — self-hosted mode, the new
install scripts, automatic port selection, test mode
**Method:** code review + **measuring every finding on a running system**

---

## Summary

Two real findings. Both come from **one root cause** — and this root cause had
now appeared in this project for the **third time**.

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Session cookie unprotected while running behind HTTPS | High | ✅ fixed |
| 2 | Connecting to a remote database without certificate verification was allowed | High | ✅ fixed |

Closed (checked, not a problem): the test-database password, the `/billing`
block, changing the mode through a request, secrets in the repository.

---

## Root cause: protections tied to `NODE_ENV`

In `config.ts`, the security checks were inside an `if (isProduction)` block,
and `isProduction` meant `NODE_ENV === "production"`.

**Customers never set `NODE_ENV` to "production".** They just run `npm start` or
`docker compose up`. So every protection in that block **did not run at all** on
a self-hosted installation.

The pattern appeared three times:

1. **The JWT secret** — the server would start with a publicly known default secret
2. **The demo account** — `admin@legion.demo` / `legion123` was created on the customer's server
3. **The two findings below** — this audit

Each time one was fixed, with the note "if another such place remains, it will
follow the same pattern". This audit checked exactly that and found the remaining two.

---

## 1. HTTPS + an unprotected cookie

**Situation:** with `FRONTEND_URL=https://legion.customer.example` and
`COOKIE_SECURE=false`, the server started without any warning.

**Why it matters:** a cookie without the `Secure` flag is sent by the browser
even over a plain HTTP request to the same domain. So a customer who set up
HTTPS would unknowingly leave the session token unprotected — exactly what
HTTPS is meant to prevent.

**Why it slipped through:** the README told the customer "put it behind HTTPS
and set `COOKIE_SECURE=true`". The second step is easy to forget, and the system
did not notice.

**Fix:** the server refuses to start with this combination. The message gives
the exact reason.

**Measured:** `FRONTEND_URL=https://…` + `COOKIE_SECURE=false` → stopped.
`COOKIE_SECURE=true` → started. An HTTP installation on an internal network and
local testing (`npm run try`) still work.

---

## 2. Connecting to a remote database without verification

**Situation:** `DB_SSL_INSECURE=true` only printed a warning and the server kept
running — even when the database was on another server.

**Why it matters:** the connection is encrypted but **not authenticated**.
Anyone between the database and the application can pretend to be the database.
That defeats the purpose of encryption.

**Fix:** if the database is **remote** and verification is off, the server does
not start. If the database is **on the same machine**, it is allowed — nobody is
in between, and it is needed for local experiments.

**Measured:** remote host → stopped. `localhost` → worked.

---

## Checked and closed as not a problem

**The test-database password is in the code.** The `npm run try` database uses
the password `legion-local-test`. Where it listens was measured: according to
`/proc/net/tcp`, **only `127.0.0.1`**, and a connection attempt from an external
IP was refused. It is not reachable from the network — no risk.

**The `/billing` block.** In self-hosted mode every billing route returns 404.
The guard is registered before the first billing route, so the webhook is
covered too. Confirmed by tests.

**Changing the mode through a request.** `deploymentMode` is read only from an
environment variable; no endpoint can change it.

**Secrets in the repository.** A search found nothing.

---

## Measured state

| Check | Result |
|---|---|
| Tests | **119 passed** (109 + 10 new) |
| Server typecheck | clean |
| Frontend typecheck | clean |
| `npm audit` (server) | 0 vulnerabilities |
| `npm audit` (frontend) | 0 vulnerabilities |

The 10 new tests cover exactly the two guards above — so they cannot silently
break. Previously these checks were not protected by any test.

---

## Not done

- **Testing with a real Wazuh** — not available at the time. Still the biggest
  untested area.
- **A real test on Windows** — everything was measured on Linux.
- **The older P0 items from the audit** (RLS, durable queue, observability) —
  they were for a multi-tenant SaaS and did not apply to the self-hosted direction.

---

## Conclusion

The code is in good shape. But the main result of this audit is not the findings
themselves but the **pattern**: when adding a security check to this project, the
first question must be "does this also run on the customer's installation?",
because customers do not mark their environment as "production".

The new checks were taken out of this pattern: they do not look at `NODE_ENV` at
all, only at the configuration itself.
