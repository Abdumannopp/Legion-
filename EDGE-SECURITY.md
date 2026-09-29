# Network edge: proxies, origins, cookies, headers

What Legion believes about a request's origin, and how to configure it.

## Client address and trusted proxies

`req.ip` (rate limits, audit log, session records) and the WebSocket handshake
take the client address from `X-Forwarded-For` **only when the TCP peer is a
proxy you named**.

| `TRUSTED_PROXIES` | Meaning |
|---|---|
| *(unset)* | `loopback` — a proxy on the same machine (the bundled nginx). |
| `none` | Trust nobody; the client is the TCP peer. Use with no proxy. |
| `10.0.0.0/8,loopback` | Trust these addresses / CIDRs / keywords (`loopback`, `linklocal`, `uniquelocal`). |
| `1` … `10` | Trust the last N hops by position. Only safe if nothing but the proxy can reach the API port. Cloud load balancers with changing addresses. |

`*`, `true`, `all` and `/0` ranges are refused at boot. The chain is walked from
the peer outward and stops at the first untrusted address, so a forged
left-hand entry never wins.

**Upgrading:** previously the API trusted exactly one hop (`trust proxy = 1`).
With the bundled nginx on the same host nothing changes. If your proxy is on
another machine or in another container, set `TRUSTED_PROXIES` to its
address/CIDR — otherwise every user shares the proxy's address (and its rate
limit bucket).

## Origins

`FRONTEND_URL` plus `CORS_ORIGINS` (comma-separated exact origins) form one
allow-list, used for CORS, the Origin check on state-changing requests, and the
WebSocket handshake. No wildcards. Non-production also accepts the
`localhost`/`127.0.0.1` twin.

- A disallowed origin gets no CORS headers; a state-changing request from one is `403`.
- Requests without an Origin (curl, sensors, agents) are not browsers and are not blocked. Webhook endpoints are exempt.
- WebSocket: wrong Origin → `403`; missing Origin → `403` unless `WS_ALLOW_MISSING_ORIGIN=true`; MFA challenge tokens are not sessions; handshakes are limited to 60/min per client address.

## Rate limits

Login and MFA are limited by address **and** by account (failures only):
20 failed logins / 15 min per account, 5 wrong MFA codes / 5 min per user.
Counting is always done in bounded local memory (`RATE_LIMIT_MAX_KEYS`, default
50 000; overflow shares one bucket rather than evicting live counters) and
mirrored to Redis when available. A dead, slow or frozen Redis costs at most
`RATE_LIMIT_REDIS_TIMEOUT_MS` (250) once per 5 s and never removes the limit.
Trade-off: someone who knows an address can burn that account's failure budget
and make its owner wait out the window.

## Cookies

`legion_token`, `legion_refresh`: HttpOnly; `Secure` when `COOKIE_SECURE=true`
(required in production); access cookie `SameSite=Lax`, refresh cookie
`SameSite=Strict` scoped to `REFRESH_COOKIE_PATH`.

**`REFRESH_COOKIE_PATH` must be the path the browser sees.** Behind the bundled
nginx (`/api` is stripped) that is `/api/auth`; `npm run setup -- --domain …`
writes it. Directly exposed API: `/auth` (default). Changing it: the old cookie
path is cleared at logout; users simply sign in again.

## Headers

API: `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `nosniff`,
`Permissions-Policy`, COOP/CORP, `Cache-Control: no-store`, and
`Strict-Transport-Security` **only** in production over HTTPS
(`HSTS_MAX_AGE_SECONDS`, `HSTS_PRELOAD=true` to add `preload`).
Dashboard (`frontend/next.config.mjs`): CSP limited to itself, the API/WS origins
from `NEXT_PUBLIC_API_URL` and Paddle; HSTS when that URL is https.
The dashboard CSP keeps `'unsafe-inline'` for scripts (Next.js bootstrap); nonces would need per-request rendering.
