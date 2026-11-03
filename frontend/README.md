# Legion dashboard

The Legion web app: the public website (product, pricing, legal pages) and the
dashboard (alerts, incidents, assets, Defense, AI agents, Legion team, settings,
billing). Built with Next.js, React and Tailwind CSS; it talks to the Express
API in `../server`.

## Running it

From the repository root, `npm run dev` starts the API and the dashboard together.
To run only the dashboard:

```bash
npm install
cp .env.local.example .env.local   # NEXT_PUBLIC_API_URL and the optional Paddle/Turnstile keys
npm run dev
```

Open http://localhost:3000. On a fresh installation, create the first
administrator at `/setup` (self-hosted) or `/signup` (SaaS). There is no demo
account.

Legion needs an always-on server, PostgreSQL and WebSocket connections, so it is
deployed on a VPS rather than a serverless host — see
[DEPLOY-ONLINE.md](../DEPLOY-ONLINE.md).

## Checks

```bash
npm run lint    # TypeScript + check that no interface text is hard-coded in components
npm test        # unit tests (vitest)
```

## Layout

| Path | What |
|---|---|
| `app/` | Pages (App Router): `page.tsx` dashboard, `incidents/`, `incident/`, `assets/`, `defense/`, `agents/`, `team/`, `connect/`, `settings/`, `billing/`, auth pages, public pages |
| `components/` | Shared components (sidebar, site header, agent skills, …) |
| `lib/api.ts` | Every call to the API |
| `lib/i18n/` | Interface text, one file per screen in `ns/` ([README](lib/i18n/README.md)) |
| `content/legal/` | Terms, privacy and refund policy text |
| `scripts/check-i18n.mjs` | The hard-coded-text check run by `npm run lint` |

## How it works

- The session is an HttpOnly cookie set by the API; the dashboard never stores a
  token in `localStorage`.
- Live alerts arrive over WebSocket.
- Every request is sent with credentials to `NEXT_PUBLIC_API_URL`; errors are
  shown with what happened, why, and what to do.
